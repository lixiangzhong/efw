package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fakeDockerScript = `#!/bin/sh
case "$1 $2" in
  "network ls") printf 'id1\nid2\n'; exit 0 ;;
  "network inspect") printf '172.17.0.0/16\nfd00:dead::/64\n172.17.0.0/16\nnot-a-cidr\n\n'; exit 0 ;;
esac
exit 1
`

const failingDockerScript = `#!/bin/sh
exit 1
`

func writeFakeDocker(t *testing.T, script string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDetectDockerNets(t *testing.T) {
	t.Run("没有 docker", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		if nets := detectDockerNets(io.Discard, true); len(nets) != 0 {
			t.Fatalf("无 docker 时应返回空，实际: %v", nets)
		}
	})

	t.Run("探测并去重排序", func(t *testing.T) {
		dir := writeFakeDocker(t, fakeDockerScript)
		t.Setenv("PATH", dir+":/bin:/usr/bin")
		nets := detectDockerNets(io.Discard, true)
		want := []string{"172.17.0.0/16", "fd00:dead::/64"}
		if len(nets) != len(want) || nets[0] != want[0] || nets[1] != want[1] {
			t.Fatalf("网段不符: want %v, got %v", want, nets)
		}
	})

	t.Run("daemon 不可用只告警", func(t *testing.T) {
		dir := writeFakeDocker(t, failingDockerScript)
		t.Setenv("PATH", dir+":/bin:/usr/bin")
		var stderr bytes.Buffer
		if nets := detectDockerNets(&stderr, false); len(nets) != 0 {
			t.Fatalf("探测失败应返回空，实际: %v", nets)
		}
		if !strings.Contains(stderr.String(), "无法列出网络") {
			t.Fatalf("缺少告警: %s", stderr.String())
		}
	})
}
