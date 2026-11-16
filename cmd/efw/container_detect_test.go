package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// fakeDockerScript 模拟 Docker：network ls -q 输出 ID，inspect 输出 Docker 的 IPAM JSON。
const fakeDockerScript = `#!/bin/sh
case "$1 $2" in
  "network ls") printf 'id1\nid2\n'; exit 0 ;;
  "network inspect") printf '[{"IPAM":{"Config":[{"Subnet":"172.17.0.0/16"},{"Subnet":"fd00:dead::/64"}]}},{"IPAM":{"Config":[{"Subnet":"172.17.0.0/16"},{"Subnet":"not-a-cidr"}]}}]'; exit 0 ;;
esac
exit 1
`

// fakePodmanScript 模拟 Podman（netavark）：子网在 subnets 数组里。
const fakePodmanScript = `#!/bin/sh
case "$1 $2" in
  "network ls") printf 'podman\nmynet\n'; exit 0 ;;
  "network inspect") printf '[{"subnets":[{"subnet":"10.88.0.0/16"},{"subnet":"fd00:beef::/64"}]},{"subnets":[]}]'; exit 0 ;;
esac
exit 1
`

// fakePodmanCNIScript 模拟 Podman 3.x（CNI）：子网藏在 plugins[].ipam.ranges。
const fakePodmanCNIScript = `#!/bin/sh
case "$1 $2" in
  "network ls") printf 'podman\n'; exit 0 ;;
  "network inspect") printf '[{"plugins":[{"type":"bridge","ipam":{"ranges":[[{"subnet":"10.88.0.0/16","gateway":"10.88.0.1"}]]}}]}]'; exit 0 ;;
esac
exit 1
`

// fakeBrokenScript 模拟运行时存在但命令失败（如 daemon 不可用）。
const fakeBrokenScript = `#!/bin/sh
exit 1
`

// fakeInspectFailScript 模拟能列出网络但 inspect 失败。
const fakeInspectFailScript = `#!/bin/sh
case "$1 $2" in
  "network ls") printf 'id1\n'; exit 0 ;;
esac
exit 1
`

// fakeBadJSONScript 模拟 inspect 输出不是 JSON。
const fakeBadJSONScript = `#!/bin/sh
case "$1 $2" in
  "network ls") printf 'id1\n'; exit 0 ;;
  "network inspect") printf 'not json'; exit 0 ;;
esac
exit 1
`

// writeFakeRuntimes 在一个 PATH 目录里放置多个运行时替身。
func writeFakeRuntimes(t *testing.T, scripts map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, script := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestDetectContainerNets(t *testing.T) {
	t.Run("没有容器运行时", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if nets := detectContainerNets(io.Discard, true); len(nets) != 0 {
			t.Fatalf("无运行时应返回空，实际: %v", nets)
		}
	})

	t.Run("docker 探测并去重", func(t *testing.T) {
		dir := writeFakeRuntimes(t, map[string]string{"docker": fakeDockerScript})
		t.Setenv("PATH", dir+":/bin:/usr/bin")
		nets := detectContainerNets(io.Discard, true)
		want := []string{"172.17.0.0/16", "fd00:dead::/64"}
		if !slices.Equal(nets, want) {
			t.Fatalf("网段不符: want %v, got %v", want, nets)
		}
	})

	t.Run("podman netavark", func(t *testing.T) {
		dir := writeFakeRuntimes(t, map[string]string{"podman": fakePodmanScript})
		t.Setenv("PATH", dir+":/bin:/usr/bin")
		nets := detectContainerNets(io.Discard, true)
		want := []string{"10.88.0.0/16", "fd00:beef::/64"}
		if !slices.Equal(nets, want) {
			t.Fatalf("网段不符: want %v, got %v", want, nets)
		}
	})

	t.Run("podman CNI", func(t *testing.T) {
		dir := writeFakeRuntimes(t, map[string]string{"podman": fakePodmanCNIScript})
		t.Setenv("PATH", dir+":/bin:/usr/bin")
		nets := detectContainerNets(io.Discard, true)
		want := []string{"10.88.0.0/16"}
		if !slices.Equal(nets, want) {
			t.Fatalf("网段不符: want %v, got %v", want, nets)
		}
	})

	t.Run("docker 与 podman 合并去重排序", func(t *testing.T) {
		dir := writeFakeRuntimes(t, map[string]string{"docker": fakeDockerScript, "podman": fakePodmanScript})
		t.Setenv("PATH", dir+":/bin:/usr/bin")
		nets := detectContainerNets(io.Discard, true)
		want := []string{"10.88.0.0/16", "172.17.0.0/16", "fd00:beef::/64", "fd00:dead::/64"}
		if !slices.Equal(nets, want) {
			t.Fatalf("网段不符: want %v, got %v", want, nets)
		}
	})

	t.Run("单个运行时失败只告警", func(t *testing.T) {
		dir := writeFakeRuntimes(t, map[string]string{"docker": fakeBrokenScript, "podman": fakePodmanScript})
		t.Setenv("PATH", dir+":/bin:/usr/bin")
		var stderr bytes.Buffer
		nets := detectContainerNets(&stderr, false)
		want := []string{"10.88.0.0/16", "fd00:beef::/64"}
		if !slices.Equal(nets, want) {
			t.Fatalf("podman 网段应保留: want %v, got %v", want, nets)
		}
		if !strings.Contains(stderr.String(), "docker 网络探测失败") || !strings.Contains(stderr.String(), "无法列出网络") {
			t.Fatalf("缺少 docker 告警: %s", stderr.String())
		}
	})

	t.Run("inspect 失败只告警", func(t *testing.T) {
		dir := writeFakeRuntimes(t, map[string]string{"podman": fakeInspectFailScript})
		t.Setenv("PATH", dir+":/bin:/usr/bin")
		var stderr bytes.Buffer
		if nets := detectContainerNets(&stderr, false); len(nets) != 0 {
			t.Fatalf("探测失败应返回空，实际: %v", nets)
		}
		if !strings.Contains(stderr.String(), "无法读取网络子网") {
			t.Fatalf("缺少 inspect 告警: %s", stderr.String())
		}
	})

	t.Run("inspect 输出非 JSON 只告警", func(t *testing.T) {
		dir := writeFakeRuntimes(t, map[string]string{"docker": fakeBadJSONScript})
		t.Setenv("PATH", dir+":/bin:/usr/bin")
		var stderr bytes.Buffer
		if nets := detectContainerNets(&stderr, false); len(nets) != 0 {
			t.Fatalf("解析失败应返回空，实际: %v", nets)
		}
		if !strings.Contains(stderr.String(), "无法解析网络信息") {
			t.Fatalf("缺少解析告警: %s", stderr.String())
		}
	})

	t.Run("quiet 抑制告警", func(t *testing.T) {
		dir := writeFakeRuntimes(t, map[string]string{"podman": fakeBrokenScript})
		t.Setenv("PATH", dir+":/bin:/usr/bin")
		var stderr bytes.Buffer
		if nets := detectContainerNets(&stderr, true); len(nets) != 0 {
			t.Fatalf("探测失败应返回空，实际: %v", nets)
		}
		if stderr.Len() != 0 {
			t.Fatalf("--quiet 时不应告警，实际: %s", stderr.String())
		}
	})
}
