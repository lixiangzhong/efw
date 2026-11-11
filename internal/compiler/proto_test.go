package compiler_test

import (
	"strings"
	"testing"
)

// TestProtoPositions 协议 token 可出现在匹配部分的任意位置。
func TestProtoPositions(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"协议在行首", "v6-bootstrap off\ntcp 1.1.1.1 -> 80 accept\n", "ip saddr 1.1.1.1 tcp dport 80 accept"},
		{"协议在箭头后", "v6-bootstrap off\n1.1.1.1 -> tcp 80 accept\n", "ip saddr 1.1.1.1 tcp dport 80 accept"},
		{"协议在源地址后", "v6-bootstrap off\n1.1.1.1 tcp -> 80 accept\n", "ip saddr 1.1.1.1 tcp dport 80 accept"},
		{"协议在端口后", "v6-bootstrap off\n1.1.1.1 -> 80 tcp accept\n", "ip saddr 1.1.1.1 tcp dport 80 accept"},
		{"协议夹在目的地址与端口之间", "v6-bootstrap off\n1.1.1.1 -> 10.0.0.1 tcp 443 accept\n", "ip daddr 10.0.0.1 tcp dport 443 accept"},
		{"协议在块内任意位置", "v6-bootstrap off\naccept {\ntcp 1.1.1.1 -> 80\n}\ndrop\n", "ip saddr 1.1.1.1 tcp dport 80 accept"},
		{"无箭头简写带协议", "v6-bootstrap off\ntcp 1.1.1.1 accept\n", "ip saddr 1.1.1.1 meta l4proto tcp accept"},
		{"icmp 前缀", "v6-bootstrap off\nicmp 1.1.1.1 accept\n", "meta l4proto { icmp, ipv6-icmp } accept"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := compileOK(t, tc.src)
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("产物缺少 %q:\n%s", tc.want, out)
			}
		})
	}
}

// TestProtoPositionErrors 协议位置/重复相关错误。
func TestProtoPositionErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"协议重复（跨箭头）", "1.1.1.1 -> tcp 80 udp accept\n", "协议 token 只能出现一次"},
		{"协议重复（两侧）", "tcp 1.1.1.1 -> tcp 80 accept\n", "协议 token 只能出现一次"},
		{"源地址带端口", "1.1.1.1:80 -> tcp 80 accept\n", "源地址不能带端口"},
		{"未知协议 token", "1.1.1.1 -> sctp 80 accept\n", "未知协议"},
		{"旧 :// 写法", "1.1.1.1 -> tcp://*:80 accept\n", "语法已移除"},
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
