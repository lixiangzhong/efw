package compiler_test

import (
	"strings"
	"testing"
)

// forwardSection 取出产物中 forward 链的文本（不含末尾大括号）。
func forwardSection(out []byte) string {
	text := string(out)
	start := strings.Index(text, "chain forward {")
	if start < 0 {
		return ""
	}
	return text[start:]
}

// TestForwardChain 默认同时生成 input 与 forward 链；forward 只匹配 DNAT 流量。
func TestForwardChain(t *testing.T) {
	out := compileOK(t, "v6-bootstrap off\n1.1.1.0/24 -> 8080 accept\ndrop\n")
	text := string(out)

	for _, want := range []string{
		"chain input {",
		"chain forward {",
		"type filter hook forward priority -10; policy accept;",
		"ct status dnat ip saddr 1.1.1.0/24 meta l4proto tcp ct original proto-dst 8080 accept",
		"ct status dnat ip saddr 1.1.1.0/24 meta l4proto udp ct original proto-dst 8080 accept",
		"ct status dnat drop",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("产物缺少 %q:\n%s", want, text)
		}
	}
	// input 链仍使用目的端口（post-stack），不带 dnat 语义。
	if !strings.Contains(text, "ip saddr 1.1.1.0/24 meta l4proto { tcp, udp } th dport 8080 accept") {
		t.Fatalf("input 链端口匹配缺失:\n%s", text)
	}
}

// TestForwardProtoAndAddressMatch forward 侧的协议族 / 目的地址（DNAT 前）匹配。
func TestForwardProtoAndAddressMatch(t *testing.T) {
	out := compileOK(t, "v6-bootstrap off\nforward auto\ntcp4 1.1.1.1 -> 8443 accept\n1.1.1.2 -> 10.0.0.1:80 accept\ndrop\n")
	fwd := forwardSection(out)
	for _, want := range []string{
		"ct status dnat ip saddr 1.1.1.1 meta nfproto ipv4 meta l4proto tcp ct original proto-dst 8443 accept",
		"ct status dnat ip saddr 1.1.1.2 ct original ip daddr 10.0.0.1 meta l4proto tcp ct original proto-dst 80 accept",
		"ct status dnat ip saddr 1.1.1.2 ct original ip daddr 10.0.0.1 meta l4proto udp ct original proto-dst 80 accept",
	} {
		if !strings.Contains(fwd, want) {
			t.Fatalf("forward 链缺少 %q:\n%s", want, fwd)
		}
	}
}

// TestForwardOff 文件头 forward off 时不生成 forward 链。
func TestForwardOff(t *testing.T) {
	out := compileOK(t, "forward off\nv6-bootstrap off\n1.1.1.0/24 -> 22 accept\ndrop\n")
	if strings.Contains(string(out), "chain forward {") {
		t.Fatalf("forward off 下不应生成 forward 链:\n%s", out)
	}
	if !strings.Contains(string(out), "chain input {") {
		t.Fatalf("input 链缺失:\n%s", out)
	}
}

// TestForwardEstablishedAndV6Bootstrap established/v6-bootstrap 只按各自规则注入。
func TestForwardEstablishedAndV6Bootstrap(t *testing.T) {
	// established off：两条链都不注入 ct state 放行。
	out := compileOK(t, "established off\nv6-bootstrap off\n1.1.1.0/24 -> 22 accept\ndrop\n")
	if strings.Contains(string(out), "ct state established,related accept") {
		t.Fatalf("established off 下不应注入状态放行:\n%s", out)
	}

	// 默认 auto + default deny：NDP/DHCPv6 只出现在 input 链，不进入 forward。
	out = compileOK(t, "1.1.1.0/24 -> 22 accept\ndrop\n")
	if n := strings.Count(string(out), "nd-neighbor-solicit"); n != 1 {
		t.Fatalf("NDP 规则应只出现 1 次（input），实际 %d 次:\n%s", n, out)
	}
	if strings.Contains(forwardSection(out), "nd-neighbor-solicit") {
		t.Fatalf("forward 链不应包含 NDP:\n%s", out)
	}
}

// TestForwardDirectiveErrors forward 指令的取值/重复错误。
func TestForwardDirectiveErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"非法值", "forward maybe\n1.1.1.1 -> 80 accept\ndrop\n", "forward 只接受 auto 或 off"},
		{"重复", "forward off\nforward auto\n1.1.1.1 -> 80 accept\ndrop\n", "forward 指令重复"},
		{"缺少参数", "forward\n1.1.1.1 -> 80 accept\ndrop\n", "需要一个参数"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list := compileErrors(t, tc.src)
			if !strings.Contains(list.Error(), tc.want) {
				t.Fatalf("期望错误包含 %q，实际: %s", tc.want, list.Error())
			}
		})
	}
}

// TestForwardPortSplitting forward 侧不能生成内联多值端口集合或协议集合：
// ct original proto-dst 在 apply 后会出现 invalid type，必须拆分。
func TestForwardPortSplitting(t *testing.T) {
	out := compileOK(t, "v6-bootstrap off\n1.1.1.1 -> tcp 80,443 accept\n1.1.1.2 -> 8080 accept\ndrop\n")
	fwd := forwardSection(out)
	if strings.Contains(fwd, "ct original proto-dst {") {
		t.Fatalf("forward 不应生成内联端口集合:\n%s", fwd)
	}
	for _, want := range []string{
		"ct status dnat ip saddr 1.1.1.1 meta l4proto tcp ct original proto-dst 80 accept",
		"ct status dnat ip saddr 1.1.1.1 meta l4proto tcp ct original proto-dst 443 accept",
		"ct status dnat ip saddr 1.1.1.2 meta l4proto tcp ct original proto-dst 8080 accept",
		"ct status dnat ip saddr 1.1.1.2 meta l4proto udp ct original proto-dst 8080 accept",
	} {
		if !strings.Contains(fwd, want) {
			t.Fatalf("forward 缺少拆分后的规则 %q:\n%s", want, fwd)
		}
	}
	if strings.Contains(fwd, "meta l4proto { tcp, udp } ct original") {
		t.Fatalf("forward 不应使用协议集合 + ct original:\n%s", fwd)
	}
}
