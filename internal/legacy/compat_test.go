package legacy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lixiangzhong/efw/internal/legacy"
)

// TestNft08Rendering 验证 nft 0.8 的两个方言差异：数字 priority、拆分 th dport。
func TestNft08Rendering(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(goldenDir, "04_anyproto_ports.acl"))
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := legacy.Compile(src, testOptions("testdata/golden/04_anyproto_ports.acl"))
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	text := string(out)
	if !strings.Contains(text, "priority -99;") {
		t.Fatalf("应使用数字 priority:\n%s", text)
	}
	if strings.Contains(text, "th dport") {
		t.Fatalf("不应出现 th dport:\n%s", text)
	}
	if !strings.Contains(text, "tcp dport") || !strings.Contains(text, "udp dport") {
		t.Fatalf("省略协议的端口规则应拆成 tcp/udp 两条:\n%s", text)
	}
}

// TestMasqueradeRejected nft 0.8 不支持 inet 族 NAT，masquerade 直接报 E102。
func TestMasqueradeRejected(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(goldenDir, "35_masquerade.acl"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = legacy.Compile(src, testOptions("testdata/golden/35_masquerade.acl"))
	if err == nil {
		t.Fatal("应拒绝 masquerade")
	}
	if !strings.Contains(err.Error(), "E102") || !strings.Contains(err.Error(), "masquerade") {
		t.Fatalf("错误码/信息不符: %v", err)
	}
}

// TestDnatRejected nft 0.8 不支持 inet 族 NAT，dnat/redirect 直接报 E102。
func TestDnatRejected(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(goldenDir, "39_dnat.acl"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = legacy.Compile(src, testOptions("testdata/golden/39_dnat.acl"))
	if err == nil {
		t.Fatal("应拒绝 dnat")
	}
	if !strings.Contains(err.Error(), "E102") || !strings.Contains(err.Error(), "dnat") {
		t.Fatalf("错误码/信息不符: %v", err)
	}
}

// TestForwardDNAT forward 链仍使用 ct status dnat 与 ct original。
func TestForwardDNAT(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(goldenDir, "01_basic.acl"))
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := legacy.Compile(src, testOptions("testdata/golden/01_basic.acl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ct status dnat", "ct original proto-dst"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("产物缺少 %q:\n%s", want, out)
		}
	}
}
