package compiler_test

import (
	"strings"
	"testing"
)

// TestProtoFamilies 单地址族协议变体 tcp4/tcp6/udp4/udp6/icmp4/icmp6。
func TestProtoFamilies(t *testing.T) {
	valid := []struct {
		name string
		src  string
		want string
	}{
		{"tcp4 带端口", "v6-bootstrap off\ntcp4 1.1.1.0/24 -> 22 accept\n", "ip saddr 1.1.1.0/24 meta nfproto ipv4 tcp dport 22 accept"},
		{"tcp6 带端口", "v6-bootstrap off\ntcp6 2001:db8::/32 -> 22 accept\n", "ip6 saddr 2001:db8::/32 meta nfproto ipv6 tcp dport 22 accept"},
		{"udp4 带端口", "v6-bootstrap off\nudp4 1.1.1.1 -> 53 accept\n", "ip saddr 1.1.1.1 meta nfproto ipv4 udp dport 53 accept"},
		{"udp6 带端口", "v6-bootstrap off\nudp6 2001:db8::1 -> 53 accept\n", "ip6 saddr 2001:db8::1 meta nfproto ipv6 udp dport 53 accept"},
		{"tcp4 无端口", "v6-bootstrap off\naccept{\n tcp4 *\n}\ndrop\n", "meta nfproto ipv4 meta l4proto tcp accept"},
		{"icmp4", "v6-bootstrap off\nicmp4 1.1.1.2 accept\n", "ip saddr 1.1.1.2 meta nfproto ipv4 meta l4proto icmp accept"},
		{"icmp6", "v6-bootstrap off\nicmp6 2001:db8::2 accept\n", "ip6 saddr 2001:db8::2 meta nfproto ipv6 meta l4proto ipv6-icmp accept"},
		{"tcp4 隐式 * 源 + 多端口", "v6-bootstrap off\naccept{\n tcp4 80 443\n}\ndrop\n", "meta nfproto ipv4 tcp dport { 80, 443 } accept"},
		{"双栈 tcp 不加 nfproto", "v6-bootstrap off\ntcp 1.1.1.3 -> 443 accept\n", "ip saddr 1.1.1.3 tcp dport 443 accept"},
		{"裸协议 tcp4（块内）", "v6-bootstrap off\naccept{\n tcp4\n}\ndrop\n", "meta nfproto ipv4 meta l4proto tcp accept"},
		{"裸协议 tcp6（块内）", "v6-bootstrap off\naccept{\n tcp6\n}\ndrop\n", "meta nfproto ipv6 meta l4proto tcp accept"},
		{"裸协议 icmp6（顶层）", "v6-bootstrap off\nicmp6 accept\ndrop\n", "meta nfproto ipv6 meta l4proto ipv6-icmp accept"},
		{"裸协议 tcp（双栈）", "v6-bootstrap off\ntcp accept\ndrop\n", "meta l4proto tcp accept"},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			out := compileOK(t, tc.src)
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("产物缺少 %q:\n%s", tc.want, out)
			}
		})
	}

	invalid := []struct {
		name string
		src  string
		want string
	}{
		{"tcp4 配 v6 源地址", "tcp4 2001:db8::1 accept\n", "与源地址族不一致"},
		{"tcp6 配 v4 源地址", "tcp6 1.1.1.1 accept\n", "与源地址族不一致"},
		{"tcp4 配 v6 目的地址", "* -> tcp4 [2001:db8::1]:80 accept\n", "与目的地址族不一致"},
		{"icmp4 带端口", "accept{\n icmp4 80\n}\ndrop\n", "不能指定端口"},
		{"icmp6 带端口", "accept{\n icmp6 80\n}\ndrop\n", "不能指定端口"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			list := compileErrors(t, tc.src)
			if !strings.Contains(list.Error(), tc.want) {
				t.Fatalf("期望错误包含 %q，实际: %s", tc.want, list.Error())
			}
		})
	}
}
