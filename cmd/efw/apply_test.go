package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeNftScript 是测试用 nft 替身：记录调用、模拟版本/校验/查询/应用。
const fakeNftScript = `#!/bin/sh
log="${FAKE_NFT_LOG:?}"
printf '%s\n' "$*" >> "$log"
if [ "$1" = "--version" ]; then
  echo "nftables ${FAKE_NFT_VERSION:-v1.0.6} (test)"
  exit 0
fi
if [ "$1" = "list" ]; then
  if [ "${FAKE_NFT_EXISTS:-0}" = "1" ]; then
    echo "table inet ${FAKE_NFT_TABLE:-efw}"
  fi
  exit 0
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
		if !strings.Contains(calls, "-c -f /dev/stdin") || !strings.Contains(calls, "-f /dev/stdin") ||
			!strings.Contains(calls, "list tables") {
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
		checkIn := readFileOrEmpty(t, os.Getenv("FAKE_NFT_CHECK_IN"))
		if checkIn != applyIn {
			t.Fatalf("校验批次应与应用批次一致\n--- check ---\n%s\n--- apply ---\n%s", checkIn, applyIn)
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

	t.Run("编译失败不应用规则", func(t *testing.T) {
		badPath := writeACL(t, "v6-bootstrap off\naccept { 1.1.1.1 -> tcp *:80 }\n") // 缺少兜底
		nft := newFakeNft(t)
		var stdout, stderr bytes.Buffer
		exit := run([]string{"apply", badPath}, strings.NewReader(""), &stdout, &stderr)
		if exit != 1 || !strings.Contains(stderr.String(), "E100") {
			t.Fatalf("exit=%d stderr:\n%s", exit, stderr.String())
		}
		// 版本探测是只读的；不应出现校验或应用调用。
		calls := readFileOrEmpty(t, nft.log)
		if strings.Contains(calls, "-c -f") || strings.Contains(calls, "-f /dev/stdin") {
			t.Fatalf("编译失败时不应校验/应用规则:\n%s", calls)
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

// TestApplyCompat 验证 apply 对 <1.0 nft 自动启用兼容产物，现代版本保持原产物。
func TestApplyCompat(t *testing.T) {
	// 省略协议的端口规则：现代产物用 th dport，兼容产物拆成 tcp/udp 两条。
	aclPath := writeACL(t, "v6-bootstrap off\naccept { 1.1.1.1 -> 80 }\ndrop { * }\n")

	t.Run("自动判定 0.8", func(t *testing.T) {
		newFakeNft(t)
		t.Setenv("FAKE_NFT_VERSION", "v0.8 (Joe Btfsplk)")
		var stdout, stderr bytes.Buffer
		exit := run([]string{"apply", aclPath}, strings.NewReader(""), &stdout, &stderr)
		if exit != 0 {
			t.Fatalf("exit=%d stderr:\n%s", exit, stderr.String())
		}
		applyIn := readFileOrEmpty(t, os.Getenv("FAKE_NFT_APPLY_IN"))
		if !strings.Contains(applyIn, "priority 0;") {
			t.Fatalf("compat 产物应使用数字 priority:\n%s", applyIn)
		}
		if strings.Contains(applyIn, "th dport") {
			t.Fatalf("compat 产物不应出现 th dport:\n%s", applyIn)
		}
		if !strings.Contains(applyIn, "tcp dport 80 accept") || !strings.Contains(applyIn, "udp dport 80 accept") {
			t.Fatalf("compat 产物应拆成 tcp/udp 两条:\n%s", applyIn)
		}
	})

	t.Run("显式 --compat", func(t *testing.T) {
		newFakeNft(t)
		var stdout, stderr bytes.Buffer
		exit := run([]string{"apply", "--compat", aclPath}, strings.NewReader(""), &stdout, &stderr)
		if exit != 0 {
			t.Fatalf("exit=%d stderr:\n%s", exit, stderr.String())
		}
		applyIn := readFileOrEmpty(t, os.Getenv("FAKE_NFT_APPLY_IN"))
		if strings.Contains(applyIn, "th dport") || !strings.Contains(applyIn, "priority 0;") {
			t.Fatalf("显式 --compat 产物不符:\n%s", applyIn)
		}
	})

	t.Run("现代 nft 保持原产物", func(t *testing.T) {
		newFakeNft(t)
		var stdout, stderr bytes.Buffer
		exit := run([]string{"apply", aclPath}, strings.NewReader(""), &stdout, &stderr)
		if exit != 0 {
			t.Fatalf("exit=%d stderr:\n%s", exit, stderr.String())
		}
		applyIn := readFileOrEmpty(t, os.Getenv("FAKE_NFT_APPLY_IN"))
		if !strings.Contains(applyIn, "priority filter;") || !strings.Contains(applyIn, "th dport 80") {
			t.Fatalf("现代版本产物不符:\n%s", applyIn)
		}
	})
}

// TestNftInputPath 验证 /dev/stdin 优先与临时文件回退。
func TestNftInputPath(t *testing.T) {
	ruleset := []byte("table inet x {\n}\n")

	preferred := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(preferred, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path, cleanup, err := nftInputPath(ruleset, preferred)
	if err != nil {
		t.Fatalf("优先路径失败: %v", err)
	}
	defer cleanup()
	if path != preferred {
		t.Fatalf("应优先使用 %s，得到 %s", preferred, path)
	}

	missing := filepath.Join(t.TempDir(), "missing")
	path, cleanup, err = nftInputPath(ruleset, missing)
	if err != nil {
		t.Fatalf("回退临时文件失败: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取临时文件失败: %v", err)
	}
	if string(data) != string(ruleset) {
		t.Fatalf("临时文件内容不符: %q", data)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("cleanup 应删除临时文件 %s", path)
	}
}

// TestNftNeedsCompat 验证 nft --version 解析与版本边界。
func TestNftNeedsCompat(t *testing.T) {
	const script = "#!/bin/sh\ncat <<'EOF'\n%sEOF\n"
	cases := []struct {
		name   string
		output string
		want   bool
	}{
		{name: "0.8 CentOS 7", output: "nftables v0.8 (Joe Btfsplk)\n", want: true},
		{name: "0.9 老版本", output: "nftables v0.9.8 (E.D.S.)\n", want: true},
		{name: "1.0.6 Debian 12", output: "nftables v1.0.6 (Lester Gooch #5)\n", want: false},
		{name: "1.1.0", output: "nftables v1.1.0 (Commodore Bullmoose #4)\n", want: false},
		{name: "无法解析", output: "garbage\n", want: false},
	}

	dir := t.TempDir()
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, fmt.Sprintf("nft-%d", i))
			if err := os.WriteFile(path, []byte(fmt.Sprintf(script, tc.output)), 0o755); err != nil {
				t.Fatal(err)
			}
			if got := nftNeedsCompat(path); got != tc.want {
				t.Fatalf("nftNeedsCompat(%q) = %v, want %v", tc.output, got, tc.want)
			}
		})
	}

	t.Run("命令执行失败", func(t *testing.T) {
		path := filepath.Join(dir, "nft-fail")
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		if nftNeedsCompat(path) {
			t.Fatal("命令失败时应返回 false")
		}
	})
}
