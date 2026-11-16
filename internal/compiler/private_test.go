package compiler_test

import (
	"strings"
	"testing"
)

// TestPrivateStandalone private 独立成行，表示私有源地址（RFC1918 + RFC4193）。
func TestPrivateStandalone(t *testing.T) {
	out := string(compileOK(t, "accept {\n  private\n}\ndrop\n"))
	for _, want := range []string{
		"set private4 {",
		"elements = { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 }",
		"set private6 {",
		"elements = { fc00::/7 }",
		"ip saddr @private4 accept",
		"ip6 saddr @private6 accept",
		"ct status dnat ip saddr @private4 accept",
		"ct status dnat ip6 saddr @private6 accept",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("产物缺少 %q:\n%s", want, out)
		}
	}
}

// TestPrivateLog private 支持 log 修饰（大小写不敏感）。
func TestPrivateLog(t *testing.T) {
	out := string(compileOK(t, "accept {\n  PRIVATE log\n}\ndrop\n"))
	for _, want := range []string{
		`ip saddr @private4 log prefix "efw: " level info accept`,
		`ip6 saddr @private6 log prefix "efw: " level info accept`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("产物缺少 %q:\n%s", want, out)
		}
	}
}

// TestPrivateRejectsCombination private 不能与目的地址/协议/端口组合。
func TestPrivateRejectsCombination(t *testing.T) {
	cases := []struct{ name, src string }{
		{"箭头组合", "accept {\n  private -> 3306\n}\ndrop\n"},
		{"协议组合", "accept {\n  tcp private -> 80\n}\ndrop\n"},
		{"裸目的地址", "accept {\n  * -> private\n}\ndrop\n"},
		{"目的地址带端口", "accept {\n  * -> private:80\n}\ndrop\n"},
		{"无箭头多余 token", "accept {\n  private 80\n}\ndrop\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compileRaw(tc.src); err == nil || !strings.Contains(err.Error(), "private") {
				t.Fatalf("期望 private 相关错误，实际: %v", err)
			}
		})
	}
}

// TestPrivateOnlySource 目的位置使用 private 必须明确报错。
func TestPrivateOnlySource(t *testing.T) {
	if _, err := compileRaw("accept {\n  * -> private\n}\ndrop\n"); err == nil ||
		!strings.Contains(err.Error(), "不能作为目的地址") {
		t.Fatalf("目的地址使用 private 应报错，实际: %v", err)
	}
}

// TestPrivateSetLaziness 未使用不生成；多条规则共享一份定义。
func TestPrivateSetLaziness(t *testing.T) {
	out := string(compileOK(t, "accept { 1.1.1.1 -> 80 }\ndrop\n"))
	if strings.Contains(out, "set private4") || strings.Contains(out, "set private6") {
		t.Fatalf("未使用 private 时不应生成集合:\n%s", out)
	}

	out = string(compileOK(t, "accept {\n  private\n}\ndrop {\n  private\n}\n"))
	// 两个不同动作的 private 规则会触发 W1，但仍只应生成各一次集合。
	if n := strings.Count(out, "set private4 {"); n != 1 {
		t.Fatalf("private4 应只生成 1 次，实际 %d:\n%s", n, out)
	}
	if n := strings.Count(out, "set private6 {"); n != 1 {
		t.Fatalf("private6 应只生成 1 次，实际 %d:\n%s", n, out)
	}
}

// TestPrivateDedupe 相邻重复的 private 规则去重。
func TestPrivateDedupe(t *testing.T) {
	out := string(compileOK(t, "accept {\n  private\n  private\n}\ndrop\n"))
	if n := strings.Count(out, "\n        ip saddr @private4 accept\n"); n != 1 {
		t.Fatalf("重复 private 规则应去重，实际 %d 条:\n%s", n, out)
	}
	if strings.Contains(out, "# 3: private") {
		t.Fatalf("重复 private 规则不应保留第二条:\n%s", out)
	}
}

// TestPrivateNotFallback 带 private 的规则不匹配一切，不能当兜底。
func TestPrivateNotFallback(t *testing.T) {
	if _, err := compileRaw("accept { private }\n"); err == nil || !strings.Contains(err.Error(), "缺少兜底规则") {
		t.Fatalf("private 不能充当兜底，实际: %v", err)
	}
}

// TestPrivateExplicitAction 块内显式动作与块头一致时可接受。
func TestPrivateExplicitAction(t *testing.T) {
	if _, err := compileRaw("accept {\n  private accept\n}\ndrop\n"); err != nil {
		t.Fatalf("显式 accept 应可编译: %v", err)
	}
	if _, err := compileRaw("accept {\n  private drop\n}\ndrop\n"); err == nil ||
		!strings.Contains(err.Error(), "动作必须与块头一致") {
		t.Fatalf("动作不一致应报错，实际: %v", err)
	}
}
