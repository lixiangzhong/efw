package compiler_test

import (
	"strings"
	"testing"

	"github.com/lixiangzhong/efw/internal/errs"
)

// TestNamedSetMixedFamilies DSL 一个块可混写 v4/v6，产物按族拆成 NAME_v4 / NAME_v6。
func TestNamedSetMixedFamilies(t *testing.T) {
	out := string(compileOK(t, "ABC {\n1.1.1.1\n2001:db8::1\n2001:db8::2\n}\naccept {\n@ABC -> 80\n}\ndrop\n"))
	for _, want := range []string{
		"set ABC_v4 {",
		"elements = { 1.1.1.1 }",
		"set ABC_v6 {",
		"elements = { 2001:db8::1, 2001:db8::2 }",
		"ip saddr @ABC_v4 meta l4proto { tcp, udp } th dport 80 accept",
		"ip6 saddr @ABC_v6 meta l4proto { tcp, udp } th dport 80 accept",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("产物缺少 %q：\n%s", want, out)
		}
	}
}

// TestNamedSetSingleFamily 只有一族时只生成该族的集合与规则；单行块写法等价。
func TestNamedSetSingleFamily(t *testing.T) {
	out := string(compileOK(t, "ABC { 2001:db8::/64 }\naccept {\n@ABC\n}\ndrop\n"))
	if strings.Contains(out, "ABC_v4") {
		t.Fatalf("v6-only 集合不应生成 v4 集合：\n%s", out)
	}
	for _, want := range []string{
		"set ABC_v6 {",
		"elements = { 2001:db8::/64 }",
		"ip6 saddr @ABC_v6 accept",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("产物缺少 %q：\n%s", want, out)
		}
	}
}

// TestNamedSetMerge 元素在编译期去重与归并，避免 nft interval 集合因重叠拒绝加载。
func TestNamedSetMerge(t *testing.T) {
	out := string(compileOK(t, "ABC {\n1.1.1.0/25\n1.1.1.22\n10.0.0.0/25\n10.0.0.128/25\n}\naccept {\n@ABC -> 22\n}\ndrop\n"))
	for _, want := range []string{"elements = { 1.1.1.0/25, 10.0.0.0/24 }"} {
		if !strings.Contains(out, want) {
			t.Fatalf("元素未归并：缺少 %q\n%s", want, out)
		}
	}
}

// TestNamedSetForward 命名集合在 forward 链同样按族展开，端口用宿主发布端口。
func TestNamedSetForward(t *testing.T) {
	out := string(compileOK(t, "ABC {\n1.1.1.1\n2001:db8::1\n}\naccept {\n@ABC -> 8080\n}\ndrop\n"))
	fwd := forwardSection([]byte(out))
	for _, want := range []string{
		"ct status dnat ip saddr @ABC_v4 meta l4proto tcp ct original proto-dst 8080 accept",
		"ct status dnat ip6 saddr @ABC_v6 meta l4proto tcp ct original proto-dst 8080 accept",
	} {
		if !strings.Contains(fwd, want) {
			t.Fatalf("forward 链缺少 %q：\n%s", want, fwd)
		}
	}
}

// TestNamedSetPinnedFamily 规则钉死地址族时只展开匹配的腿，不生成永不命中的规则。
func TestNamedSetPinnedFamily(t *testing.T) {
	out := string(compileOK(t, "ABC {\n1.1.1.1\n2001:db8::1\n}\naccept {\n@ABC tcp4 -> 22\n@ABC -> 1.2.3.4:80\n}\ndrop\n"))
	if strings.Contains(out, "@ABC_v6") {
		t.Fatalf("单栈协议或 v4 目的地址不应展开 v6 腿：\n%s", out)
	}
}

// TestNamedSetUnused 未被引用的集合只告警、不产出。
func TestNamedSetUnused(t *testing.T) {
	codes := warningCodes(t, "ABC {\n1.1.1.1\n}\ndrop\n")
	if !codes[errs.CodeUnusedSet] {
		t.Fatalf("未使用的集合应产生 %s 告警：%v", errs.CodeUnusedSet, codes)
	}
	out := string(compileOK(t, "ABC {\n1.1.1.1\n}\ndrop\n"))
	if strings.Contains(out, "set ABC") {
		t.Fatalf("未引用的集合不应产出：\n%s", out)
	}
}

// TestNamedSetErrors 覆盖定义与引用的错误路径。
func TestNamedSetErrors(t *testing.T) {
	cases := []struct{ name, src, want string }{
		{"未定义引用", "accept {\n@ABC -> 80\n}\ndrop\n", "未定义的命名集合"},
		{"漏写 @", "ABC {\n1.1.1.1\n}\naccept {\nABC -> 80\n}\ndrop\n", "要加 @ 前缀"},
		{"大小写不同视为未定义", "ABC {\n1.1.1.1\n}\naccept {\n@abc -> 80\n}\ndrop\n", "未定义的命名集合"},
		{"重复定义", "ABC {\n1.1.1.1\n}\nABC {\n2.2.2.2\n}\ndrop\n", "重复定义"},
		{"保留名", "private {\n1.1.1.1\n}\ndrop\n", "保留字"},
		{"空集合", "ABC {\n}\ndrop\n", "至少需要一个地址"},
		{"set 关键字", "set ABC {\n1.1.1.1\n}\ndrop\n", "不需要 set 关键字"},
		{"动作块内定义", "accept {\nABC {\n1.1.1.1\n}\n}\ndrop\n", "必须定义在动作块之外"},
		{"目的位置", "ABC {\n1.1.1.1\n}\naccept {\n@ABC -> @ABC:80\n}\ndrop\n", "只能作为源地址"},
		{"v6 集合配单栈 v4 协议", "ABC {\n2001:db8::1\n}\naccept {\n@ABC tcp4 -> 80\n}\ndrop\n", "协议 tcp4 与源地址族不一致"},
		{"非法元素", "ABC {\n1.1.1.1\nnot-an-address\n}\ndrop\n", "集合元素必须是 IPv4/IPv6 地址或 CIDR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileRaw(tc.src)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("期望错误包含 %q，实际 %v", tc.want, err)
			}
		})
	}
}
