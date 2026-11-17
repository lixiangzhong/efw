package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validACL = "v6-bootstrap off\naccept { 1.1.1.1 -> 80 }\ndrop { * }\n"

// TestNft08Compile 验证旧方言：数字 priority、拆 th dport。
func TestNft08Compile(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exit := run([]string{"compile"}, strings.NewReader(validACL), &stdout, &stderr)
	if exit != 0 {
		t.Fatalf("exit=%d stderr:\n%s", exit, stderr.String())
	}
	text := stdout.String()
	for _, want := range []string{"priority 0;", "tcp dport 80 accept", "udp dport 80 accept"} {
		if !strings.Contains(text, want) {
			t.Fatalf("产物缺少 %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "th dport") {
		t.Fatalf("nft 0.8 产物不应出现 th dport:\n%s", text)
	}
}

// TestNft08MasqueradeRejected nft 0.8 不支持 inet 族 NAT。
func TestNft08MasqueradeRejected(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exit := run([]string{"compile"}, strings.NewReader("masquerade { eth0 }\naccept { * }\n"), &stdout, &stderr)
	if exit != 1 || !strings.Contains(stderr.String(), "E102") || !strings.Contains(stderr.String(), "masquerade") {
		t.Fatalf("exit=%d stderr:\n%s", exit, stderr.String())
	}
}

// TestNft08NoCompatFlag 旧方言固定启用，不再接受 --compat。
func TestNft08NoCompatFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exit := run([]string{"compile", "--compat"}, strings.NewReader(validACL), &stdout, &stderr)
	if exit != 2 || !strings.Contains(stderr.String(), "E103") {
		t.Fatalf("exit=%d stderr:\n%s", exit, stderr.String())
	}
}

// TestNft08Version 版本输出带自己的命令名。
func TestNft08Version(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exit := run([]string{"--version"}, strings.NewReader(""), &stdout, &stderr)
	if exit != 0 || !strings.Contains(stdout.String(), "efw-nft08 version") {
		t.Fatalf("exit=%d stdout:\n%s stderr:\n%s", exit, stdout.String(), stderr.String())
	}
}

// TestNft08ApplyUsesDevStdin apply 走 /dev/stdin 与 list tables。
func TestNft08ApplyUsesDevStdin(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_NFT_LOG"
if [ "$1" = "list" ]; then exit 0; fi
if [ "$1" = "-c" ]; then cat >/dev/null; exit 0; fi
if [ "$1" = "-f" ]; then cat >/dev/null; exit 0; fi
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "calls.log")
	t.Setenv("PATH", dir+":/bin:/usr/bin")
	t.Setenv("FAKE_NFT_LOG", logPath)

	var stdout, stderr bytes.Buffer
	exit := run([]string{"apply"}, strings.NewReader(validACL), &stdout, &stderr)
	if exit != 0 {
		t.Fatalf("exit=%d stderr:\n%s", exit, stderr.String())
	}
	calls, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("读取调用日志失败: %v", err)
	}
	if !strings.Contains(string(calls), "-c -f /dev/stdin") || !strings.Contains(string(calls), "-f /dev/stdin") {
		t.Fatalf("nft 调用序列不符:\n%s", calls)
	}
}
