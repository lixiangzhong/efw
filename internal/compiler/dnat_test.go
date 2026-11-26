package compiler_test

import (
	"strings"
	"testing"
)

// TestDnatEmit 覆盖本机重定向与跨机 DNAT 的产物形态、地址族限定与链位置。
func TestDnatEmit(t *testing.T) {
	out := string(compileOK(t, `dnat {
  iface eth0 udp 20000-50000 -> 443
  * tcp 8080 -> 10.0.0.5:8080
  iface eth0 tcp 8443 -> [2001:db8::5]:8443
  iface eth0 tcp 9090 -> 10.0.0.6
  udp 5000-5100 -> 6000-6100
}
accept { udp * -> 443 6000-6100 }
drop
`))
	for _, want := range []string{
		"chain prerouting {",
		"type nat hook prerouting priority dstnat + 1; policy accept;",
		`iifname "eth0" udp dport 20000-50000 redirect to :443`,
		"meta nfproto ipv4 tcp dport 8080 dnat ip to 10.0.0.5:8080",
		"meta nfproto ipv6 tcp dport 8443 dnat ip6 to [2001:db8::5]:8443",
		"meta nfproto ipv4 tcp dport 9090 dnat ip to 10.0.0.6",
		"udp dport 5000-5100 redirect to :6000-6100",
		"# 2: iface eth0 udp 20000-50000 -> 443",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("产物缺少 %q:\n%s", want, out)
		}
	}

	prerouting := strings.Index(out, "chain prerouting {")
	input := strings.Index(out, "chain input {")
	if prerouting < 0 || input < 0 || prerouting > input {
		t.Fatalf("prerouting 链应位于 input 链之前:\n%s", out)
	}
	if strings.Contains(out[input:], "redirect to :") {
		t.Fatalf("NAT 规则不应出现在 input/forward 链:\n%s", out)
	}
	if n := strings.Count(out, "chain prerouting {"); n != 1 {
		t.Fatalf("prerouting 链应只生成 1 条，实际 %d", n)
	}
}

// TestDnatMatchForms 覆盖匹配部分的常见组合：只有协议、源地址 + 端口、无 iface。
func TestDnatMatchForms(t *testing.T) {
	out := string(compileOK(t, `dnat {
  udp 20000-20010 -> 443
  192.168.0.0/16 udp 5000-5100 -> 6000-6100
  tcp 8080 -> 10.0.0.5:8080
}
accept { udp * -> 443 6000-6100 }
drop
`))
	for _, want := range []string{
		`udp dport 20000-20010 redirect to :443`,
		`ip saddr 192.168.0.0/16 udp dport 5000-5100 redirect to :6000-6100`,
		`meta nfproto ipv4 tcp dport 8080 dnat ip to 10.0.0.5:8080`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("产物缺少 %q:\n%s", want, out)
		}
	}
}

// TestDnatChainLaziness 未写 dnat 时不生成 prerouting 链，现有产物不变。
func TestDnatChainLaziness(t *testing.T) {
	out := string(compileOK(t, "accept { 1.1.1.1 -> 22 }\ndrop\n"))
	if strings.Contains(out, "prerouting") || strings.Contains(out, "redirect") {
		t.Fatalf("未使用 dnat 时不应生成目的 NAT 链:\n%s", out)
	}
}

// TestDnatMultipleBlocks 多个 dnat 块按书写顺序拼接（NAT 首条匹配生效）。
func TestDnatMultipleBlocks(t *testing.T) {
	out := string(compileOK(t, `dnat { udp 20000-20010 -> 443 }
dnat {
  udp 20000-20010 -> 8443
}
accept { udp * -> 443 8443 }
drop
`))
	first := strings.Index(out, "udp dport 20000-20010 redirect to :443")
	second := strings.Index(out, "udp dport 20000-20010 redirect to :8443")
	if first < 0 || second < 0 || first > second {
		t.Fatalf("多个 dnat 块应保持书写顺序:\n%s", out)
	}
}

// TestDnatCaseInsensitive 关键字大小写不敏感，接口名与地址保持原样。
func TestDnatCaseInsensitive(t *testing.T) {
	out := string(compileOK(t, "DNAT {\n  IFACE ETH0 UDP 20000-20010 -> 443\n}\naccept { udp * -> 443 }\ndrop\n"))
	if !strings.Contains(out, `iifname "ETH0" udp dport 20000-20010 redirect to :443`) {
		t.Fatalf("大小写不敏感的产物不正确:\n%s", out)
	}
}

// TestDnatWarningW5 本机重定向的目标端口没有 input 放行时告警；有放行或兜底 accept 时不告警。
func TestDnatWarningW5(t *testing.T) {
	t.Run("未放行", func(t *testing.T) {
		if !warningCodes(t, "dnat {\n  udp 20000-20010 -> 443\n}\ndrop\n")["W5"] {
			t.Fatal("期望出现 W5（目标端口未在 input 放行）")
		}
	})
	t.Run("已放行", func(t *testing.T) {
		codes := warningCodes(t, "dnat {\n  udp 20000-20010 -> 443\n}\naccept {\n  udp * -> 443\n}\ndrop\n")
		if codes["W5"] {
			t.Fatal("目标端口已放行时不应出现 W5")
		}
	})
	t.Run("兜底 accept", func(t *testing.T) {
		if warningCodes(t, "dnat {\n  udp 20000-20010 -> 443\n}\naccept\n")["W5"] {
			t.Fatal("兜底 accept 时不应出现 W5")
		}
	})
	t.Run("跨机不告警", func(t *testing.T) {
		if warningCodes(t, "dnat {\n  tcp 8080 -> 10.0.0.5:8080\n}\ndrop\n")["W5"] {
			t.Fatal("跨机 DNAT 不经过本机 input，不应出现 W5")
		}
	})
}

// TestDnatErrors 覆盖 dnat 块的形式、目标与映射边界。
func TestDnatErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"缺少箭头", "dnat {\n  udp 20000-20010\n}\ndrop\n", "缺少 ->"},
		{"多个箭头", "dnat {\n  udp 20000-20010 -> 443 -> 8443\n}\ndrop\n", "只能有一个 ->"},
		{"右侧缺少目标", "dnat {\n  udp 20000-20010 ->\n}\ndrop\n", "右侧缺少 NAT 目标"},
		{"左侧缺少匹配", "dnat {\n  -> 443\n}\ndrop\n", "左侧缺少匹配部分"},
		{"空分行块", "dnat {\n}\ndrop\n", "至少需要一条规则"},
		{"空单行块", "dnat { }\ndrop\n", "至少需要一条规则"},
		{"嵌套块", "dnat {\n  dnat {\n    udp 80 -> 443\n  }\n}\ndrop\n", "不能嵌套"},
		{"写在动作块内", "accept { dnat }\ndrop\n", "不能写在动作块内"},
		{"块外缺少花括号", "dnat udp 80 -> 443\ndrop\n", "独立块"},
		{"原目的地址不支持", "dnat {\n  1.1.1.1 2.2.2.2 tcp 80 -> 10.0.0.5:8080\n}\ndrop\n", "只能写一个源地址"},
		{"目标为 *", "dnat {\n  udp 80 -> *\n}\ndrop\n", "不能是 *"},
		{"目标为网段", "dnat {\n  udp 80 -> 10.0.0.0/24\n}\ndrop\n", "不能是网段"},
		{"目标多处端口", "dnat {\n  udp 80 -> {443, 8443}\n}\ndrop\n", "只能是一个端口或一个范围"},
		{"范围长度不一致", "dnat {\n  udp 20000-20010 -> 30000-40000\n}\ndrop\n", "长度不一致"},
		{"目标范围缺少匹配范围", "dnat {\n  udp -> 6000-6100\n}\ndrop\n", "必须写明等长的端口范围"},
		{"icmp 带端口", "dnat {\n  icmp 80 -> 443\n}\ndrop\n", "icmp 规则不能指定端口"},
		{"icmp 重定向到端口", "dnat {\n  icmp -> 443\n}\ndrop\n", "icmp 不能重定向到本机端口"},
		{"源与目标族冲突", "dnat {\n  1.1.1.1 tcp 8080 -> [2001:db8::5]:8443\n}\ndrop\n", "地址族不一致"},
		{"协议与目标族冲突", "dnat {\n  tcp4 8080 -> [2001:db8::5]:8443\n}\ndrop\n", "协议 tcp4 与 dnat 目标地址族不一致"},
		{"源用命名集合", "SET_A {\n  1.1.1.1\n}\ndnat {\n  @SET_A tcp 8080 -> 10.0.0.5:8080\n}\ndrop\n", "不支持命名集合"},
		{"目标无法识别", "dnat {\n  udp 80 -> 300.1.1.1\n}\ndrop\n", "无法识别"},
		{"不能当兜底", "dnat {\n  udp 80 -> 443\n}\n", "缺少兜底规则"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compileRaw(tc.src); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("期望错误包含 %q，实际: %v", tc.want, err)
			}
		})
	}
}
