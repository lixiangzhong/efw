package compiler_test

import (
	"strings"
	"testing"
)

// TestBareDestinationImplicit 无箭头写法中带端口的 token 视为隐式 * 源的目的地址。
func TestBareDestinationImplicit(t *testing.T) {
	valid := []struct {
		name string
		src  string
		want string
	}{
		{"裸 v4 dst:port", "v6-bootstrap off\n10.0.0.1:80 accept\n", "ip daddr 10.0.0.1 meta l4proto { tcp, udp } th dport 80 accept"},
		{"协议 + dst:port", "v6-bootstrap off\ntcp 10.0.0.2:443 accept\n", "ip daddr 10.0.0.2 tcp dport 443 accept"},
		{"裸 v6 dst:port", "v6-bootstrap off\n[2001:db8::1]:22 accept\n", "ip6 daddr 2001:db8::1 meta l4proto { tcp, udp } th dport 22 accept"},
		{"地址与端口分写", "v6-bootstrap off\n1.1.1.1 53 accept\n", "ip daddr 1.1.1.1 meta l4proto { tcp, udp } th dport 53 accept"},
		{"*:port", "v6-bootstrap off\n*:8080 accept\n", "th dport 8080 accept"},
		{"块内裸 dst:port", "v6-bootstrap off\naccept{\n10.0.0.3:8443\n}\ndrop\n", "ip daddr 10.0.0.3 meta l4proto { tcp, udp } th dport 8443 accept"},
		{"裸地址仍是源地址", "v6-bootstrap off\n10.0.0.1 accept\n", "ip saddr 10.0.0.1 accept"},
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
		{"端口越界", "10.0.0.1:99999 accept\n", "越界"},
		{"IPv4 非法", "1.2.3.999:80 accept\n", "不是合法的 IPv4/CIDR"},
		{"目的地址重复", "1.1.1.1:80 2.2.2.2 accept\n", "目的地址只能出现一次"},
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

// TestBareDstEqualsExplicit 裸 dst:port 与 `* -> dst:port` 产物等价（去注释比较）。
func TestBareDstEqualsExplicit(t *testing.T) {
	a := stripComments(compileOK(t, "v6-bootstrap off\n10.0.0.1:80 accept\ndrop\n"))
	b := stripComments(compileOK(t, "v6-bootstrap off\n* -> 10.0.0.1:80 accept\ndrop\n"))
	if a != b {
		t.Fatalf("两种写法产物不一致\nA:\n%s\nB:\n%s", a, b)
	}
}
