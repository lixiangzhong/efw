package compiler_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lixiangzhong/efw/internal/compiler"
)

// compileGolden 编译黄金用例，可指定 compat 模式；返回产物文本。
func compileGolden(t *testing.T, name string, compat bool) (string, error) {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(goldenDir, name+".acl"))
	if err != nil {
		t.Fatalf("读取输入失败: %v", err)
	}
	opts := testOptions("testdata/golden/" + name + ".acl")
	opts.Compat = compat
	out, _, err := compiler.Compile(src, opts)
	return string(out), err
}

// TestCompatRendering 验证 compat 产物的两个差异：数字 priority、拆分 th dport。
func TestCompatRendering(t *testing.T) {
	compat, err := compileGolden(t, "04_anyproto_ports", true)
	if err != nil {
		t.Fatalf("compat 编译失败: %v", err)
	}
	if !strings.Contains(compat, "priority 0;") {
		t.Fatalf("compat 产物应使用数字 priority:\n%s", compat)
	}
	if strings.Contains(compat, "th dport") {
		t.Fatalf("compat 产物不应出现 th dport:\n%s", compat)
	}
	if !strings.Contains(compat, "tcp dport") || !strings.Contains(compat, "udp dport") {
		t.Fatalf("省略协议的端口规则应拆成 tcp/udp 两条:\n%s", compat)
	}

	modern, err := compileGolden(t, "04_anyproto_ports", false)
	if err != nil {
		t.Fatalf("默认编译失败: %v", err)
	}
	if !strings.Contains(modern, "priority filter;") || !strings.Contains(modern, "th dport") {
		t.Fatalf("默认产物应保持关键字 priority 与 th dport:\n%s", modern)
	}

	again, err := compileGolden(t, "04_anyproto_ports", true)
	if err != nil {
		t.Fatalf("二次 compat 编译失败: %v", err)
	}
	if again != compat {
		t.Fatal("compat 产物不确定")
	}
}

// TestCompatKeepsForward 验证 compat 不影响 forward 链（ct original 在 0.8 可用）。
func TestCompatKeepsForward(t *testing.T) {
	out, err := compileGolden(t, "01_basic", true)
	if err != nil {
		t.Fatalf("compat 编译失败: %v", err)
	}
	for _, want := range []string{"ct status dnat", "ct original proto-dst"} {
		if !strings.Contains(out, want) {
			t.Fatalf("compat 产物缺少 forward 匹配 %q:\n%s", want, out)
		}
	}
}

// TestCompatRejectsMasquerade 验证 compat 模式明确拒绝 masquerade（inet 族 NAT 不可用）。
func TestCompatRejectsMasquerade(t *testing.T) {
	_, err := compileGolden(t, "35_masquerade", true)
	if err == nil {
		t.Fatal("compat 模式应拒绝 masquerade")
	}
	if !strings.Contains(err.Error(), "E102") || !strings.Contains(err.Error(), "masquerade") {
		t.Fatalf("错误码/信息不符: %v", err)
	}
}
