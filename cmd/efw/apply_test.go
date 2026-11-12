package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeNftScript 是测试用 nft 替身：记录调用、模拟校验/查询/应用。
const fakeNftScript = `#!/bin/sh
log="${FAKE_NFT_LOG:?}"
printf '%s\n' "$*" >> "$log"
if [ "$1" = "list" ]; then
  if [ "${FAKE_NFT_EXISTS:-0}" = "1" ]; then exit 0; fi
  echo "No such file or directory" >&2
  exit 1
fi
if [ "$1" = "-c" ]; then
  cat > "${FAKE_NFT_CHECK_IN:-/dev/null}"
  if [ "${FAKE_NFT_CHECK_EXIT:-0}" != "0" ]; then
    echo "netlink: Error: cache initialization failed: Operation not permitted" >&2
    exit 1
  fi
  exit 0
fi
if [ "$1" = "-f" ]; then
  cat > "${FAKE_NFT_APPLY_IN:?}"
  if [ "${FAKE_NFT_APPLY_EXIT:-0}" != "0" ]; then
    echo "boom: nft apply failed" >&2
    exit 1
  fi
  exit 0
fi
exit 0
`

type fakeNft struct {
	dir string
	log string
}

// newFakeNft 创建 fake nft，并把测试进程的 PATH 指向它。
func newFakeNft(t *testing.T) fakeNft {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(fakeNftScript), 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "calls.log")
	t.Setenv("PATH", dir+":/bin:/usr/bin")
	t.Setenv("FAKE_NFT_LOG", logPath)
	t.Setenv("FAKE_NFT_APPLY_IN", filepath.Join(dir, "apply.stdin"))
	t.Setenv("FAKE_NFT_CHECK_IN", filepath.Join(dir, "check.stdin"))
	return fakeNft{dir: dir, log: logPath}
}

func writeACL(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.acl")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func readFileOrEmpty(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

// TestApplyCreateAndOverwrite 首次创建 vs 已存在时覆盖（delete+create 批次）。
func TestApplyCreateAndOverwrite(t *testing.T) {
	aclPath := writeACL(t, validACL)

	t.Run("首次创建", func(t *testing.T) {
		nft := newFakeNft(t)
		t.Setenv("FAKE_NFT_EXISTS", "0")
		var stdout, stderr bytes.Buffer
		exit := run([]string{"apply", aclPath}, strings.NewReader(""), &stdout, &stderr)
		if exit != 0 {
			t.Fatalf("退出码 = %d, stderr:\n%s", exit, stderr.String())
		}
		if stdout.Len() != 0 {
			t.Fatalf("apply 不应写 stdout，实际:\n%s", stdout.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("apply 成功时应静默，stderr:\n%s", stderr.String())
		}
		applyIn := readFileOrEmpty(t, os.Getenv("FAKE_NFT_APPLY_IN"))
		if !strings.Contains(applyIn, "table inet efw {") {
			t.Fatalf("apply 输入缺少 table:\n%s", applyIn)
		}
		if strings.HasPrefix(applyIn, "delete table") {
			t.Fatalf("首次创建不应 delete table:\n%s", applyIn)
		}
		calls := readFileOrEmpty(t, nft.log)
		if !strings.Contains(calls, "-c -f -") || !strings.Contains(calls, "-f -") {
			t.Fatalf("nft 调用序列不符:\n%s", calls)
		}
	})

	t.Run("已存在则覆盖", func(t *testing.T) {
		nft := newFakeNft(t)
		t.Setenv("FAKE_NFT_EXISTS", "1")
		var stdout, stderr bytes.Buffer
		exit := run([]string{"apply", aclPath}, strings.NewReader(""), &stdout, &stderr)
		if exit != 0 {
			t.Fatalf("退出码 = %d, stderr:\n%s", exit, stderr.String())
		}
		if stderr.Len() != 0 {
			t.Fatalf("apply 成功时应静默，stderr:\n%s", stderr.String())
		}
		applyIn := readFileOrEmpty(t, os.Getenv("FAKE_NFT_APPLY_IN"))
		if !strings.HasPrefix(applyIn, "delete table inet efw\n") {
			t.Fatalf("覆盖时应先 delete table:\n%s", applyIn)
		}
		if strings.Count(applyIn, "table inet efw {") != 1 {
			t.Fatalf("apply 输入应只有一份 table 定义:\n%s", applyIn)
		}
		_ = nft
	})
}

// TestApplyFailures apply 的环境/执行失败路径。
func TestApplyFailures(t *testing.T) {
	aclPath := writeACL(t, validACL)

	t.Run("nft 不存在", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		var stdout, stderr bytes.Buffer
		exit := run([]string{"apply", aclPath}, strings.NewReader(""), &stdout, &stderr)
		if exit != 2 || !strings.Contains(stderr.String(), "E104") ||
			!strings.Contains(stderr.String(), "找不到 nft") {
			t.Fatalf("exit=%d stderr:\n%s", exit, stderr.String())
		}
	})

	t.Run("权限/校验失败", func(t *testing.T) {
		newFakeNft(t)
		t.Setenv("FAKE_NFT_CHECK_EXIT", "1")
		var stdout, stderr bytes.Buffer
		exit := run([]string{"apply", aclPath}, strings.NewReader(""), &stdout, &stderr)
		if exit != 2 || !strings.Contains(stderr.String(), "E104") ||
			!strings.Contains(stderr.String(), "需要 root 或 CAP_NET_ADMIN") {
			t.Fatalf("exit=%d stderr:\n%s", exit, stderr.String())
		}
	})

	t.Run("nft 应用失败", func(t *testing.T) {
		newFakeNft(t)
		t.Setenv("FAKE_NFT_APPLY_EXIT", "1")
		var stdout, stderr bytes.Buffer
		exit := run([]string{"apply", aclPath}, strings.NewReader(""), &stdout, &stderr)
		if exit != 2 || !strings.Contains(stderr.String(), "E104") ||
			!strings.Contains(stderr.String(), "旧表保持不变") ||
			!strings.Contains(stderr.String(), "boom") {
			t.Fatalf("exit=%d stderr:\n%s", exit, stderr.String())
		}
	})

	t.Run("编译失败不调用 nft", func(t *testing.T) {
		badPath := writeACL(t, "v6-bootstrap off\naccept { 1.1.1.1 -> tcp *:80 }\n") // 缺少兜底
		nft := newFakeNft(t)
		var stdout, stderr bytes.Buffer
		exit := run([]string{"apply", badPath}, strings.NewReader(""), &stdout, &stderr)
		if exit != 1 || !strings.Contains(stderr.String(), "E100") {
			t.Fatalf("exit=%d stderr:\n%s", exit, stderr.String())
		}
		if _, err := os.Stat(nft.log); err == nil {
			t.Fatalf("编译失败时不应调用 nft")
		}
	})

	t.Run("apply 拒绝 -o", func(t *testing.T) {
		newFakeNft(t)
		var stdout, stderr bytes.Buffer
		exit := run([]string{"apply", "-o", "/tmp/x.nft", aclPath}, strings.NewReader(""), &stdout, &stderr)
		if exit != 2 || !strings.Contains(stderr.String(), "E103") {
			t.Fatalf("exit=%d stderr:\n%s", exit, stderr.String())
		}
	})
}

// TestApplyFromStdinAndFileFlag stdin 与 -f 两种入口。
func TestApplyFromStdinAndFileFlag(t *testing.T) {
	aclPath := writeACL(t, validACL)

	t.Run("-f 指定文件", func(t *testing.T) {
		newFakeNft(t)
		var stdout, stderr bytes.Buffer
		exit := run([]string{"apply", "-f", aclPath}, strings.NewReader(""), &stdout, &stderr)
		if exit != 0 {
			t.Fatalf("exit=%d stderr:\n%s", exit, stderr.String())
		}
	})

	t.Run("stdin 输入", func(t *testing.T) {
		newFakeNft(t)
		var stdout, stderr bytes.Buffer
		exit := run([]string{"apply"}, strings.NewReader(validACL), &stdout, &stderr)
		if exit != 0 {
			t.Fatalf("exit=%d stderr:\n%s", exit, stderr.String())
		}
	})
}

// TestApplyInjectsDockerNets apply 时应把探测到的 Docker 网段写进来源放行集合。
func TestApplyInjectsDockerNets(t *testing.T) {
	aclPath := writeACL(t, validACL)
	nft := newFakeNft(t)
	dockerScript := `#!/bin/sh
case "$1 $2" in
  "network ls") echo id1; exit 0 ;;
  "network inspect") echo 172.17.0.0/16; exit 0 ;;
esac
exit 1
`
	if err := os.WriteFile(filepath.Join(nft.dir, "docker"), []byte(dockerScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_NFT_EXISTS", "0")
	var stdout, stderr bytes.Buffer
	exit := run([]string{"apply", aclPath}, strings.NewReader(""), &stdout, &stderr)
	if exit != 0 {
		t.Fatalf("退出码 = %d, stderr:\n%s", exit, stderr.String())
	}
	applyIn := readFileOrEmpty(t, os.Getenv("FAKE_NFT_APPLY_IN"))
	if !strings.Contains(applyIn, "172.17.0.0/16") {
		t.Fatalf("产物缺少 Docker 网段:\n%s", applyIn)
	}
	if strings.Contains(applyIn, "192.168.0.0/16") {
		t.Fatalf("RFC1918 不应默认放行:\n%s", applyIn)
	}
	if stderr.Len() != 0 {
		t.Fatalf("apply 成功时应静默，stderr:\n%s", stderr.String())
	}
}
