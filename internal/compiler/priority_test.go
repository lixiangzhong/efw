package compiler_test

import (
	"strings"
	"testing"

	"github.com/lixiangzhong/efw/internal/compiler"
)

// TestPriorityDirective priority 文件头指令同时作用于 input 与 forward 链。
func TestPriorityDirective(t *testing.T) {
	out := string(compileOK(t, "priority 10\nv6-bootstrap off\naccept { 1.1.1.1 }\ndrop\n"))
	for _, want := range []string{
		"type filter hook input priority 10; policy accept;",
		"type filter hook forward priority 10; policy accept;",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("缺少 %q:\n%s", want, out)
		}
	}
}

// TestPriorityDirectiveNormalized 关键字大小写不敏感，产物统一小写。
func TestPriorityDirectiveNormalized(t *testing.T) {
	out := string(compileOK(t, "priority FILTER\nv6-bootstrap off\naccept { 1.1.1.1 }\ndrop\n"))
	for _, want := range []string{
		"type filter hook input priority filter; policy accept;",
		"type filter hook forward priority filter; policy accept;",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("缺少 %q:\n%s", want, out)
		}
	}
}

// TestPriorityDefault 未写指令时，input 与 forward 默认都是 -99。
func TestPriorityDefault(t *testing.T) {
	out := string(compileOK(t, "v6-bootstrap off\naccept { 1.1.1.1 }\ndrop\n"))
	for _, want := range []string{
		"type filter hook input priority -99; policy accept;",
		"type filter hook forward priority -99; policy accept;",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("缺少 %q:\n%s", want, out)
		}
	}
}

// TestPriorityExplicitWins 显式 --priority 优先于 ACL 指令（input 与 forward 都用显式值）。
func TestPriorityExplicitWins(t *testing.T) {
	src := []byte("priority filter\nv6-bootstrap off\naccept { 1.1.1.1 }\ndrop\n")
	opts := testOptions("<test>")
	opts.Priority = "0"
	opts.PrioritySet = true

	out, _, err := compiler.Compile(src, opts)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	text := string(out)
	for _, want := range []string{
		"type filter hook input priority 0; policy accept;",
		"type filter hook forward priority 0; policy accept;",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("缺少 %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "priority filter;") {
		t.Fatalf("ACL 的 priority 指令不应覆盖显式 --priority:\n%s", text)
	}
}

// TestPriorityDirectiveErrors 覆盖取值非法、超出 int32、重复与块内出现。
func TestPriorityDirectiveErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"非关键字非整数", "priority bogus\nv6-bootstrap off\naccept { 1.1.1.1 }\ndrop\n", "32 位整数"},
		{"超出 int32", "priority 2147483648\nv6-bootstrap off\naccept { 1.1.1.1 }\ndrop\n", "32 位整数"},
		{"重复", "priority 10\npriority 20\nv6-bootstrap off\naccept { 1.1.1.1 }\ndrop\n", "priority 指令重复"},
		{"块内出现", "v6-bootstrap off\naccept {\npriority 10\n}\ndrop\n", "指令不能出现在块内"},
		{"出现在规则之后", "v6-bootstrap off\naccept { 1.1.1.1 }\npriority 10\ndrop\n", "必须位于所有规则之前"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list := compileErrors(t, tc.src)
			if !strings.Contains(list.Error(), tc.want) {
				t.Fatalf("期望包含 %q 的错误，实际: %s", tc.want, list.Error())
			}
		})
	}
}
