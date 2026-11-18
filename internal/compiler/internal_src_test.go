package compiler_test

import (
	"strings"
	"testing"
)

// TestNoBuiltinSourceTrust 链首只信任 loopback：不再隐式放行任何来源网段
// （RFC1918 / CGNAT / link-local / IPv6 ULA），内网、Tailscale、容器来源都必须显式写规则。
func TestNoBuiltinSourceTrust(t *testing.T) {
	out := string(compileOK(t, "accept { 8.8.8.8 -> 8080 }\ndrop\n"))

	for _, banned := range []string{
		"100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"fc00::/7", "fe80::/10", "::1",
	} {
		if strings.Contains(out, banned) {
			t.Fatalf("不应再内置放行 %q：\n%s", banned, out)
		}
	}
	// 来源放行整行都不应存在（空集合在 nft 里也是语法错误，必须整行省略）。
	for _, banned := range []string{"ip saddr {", "ip6 saddr {"} {
		if strings.Contains(out, banned) {
			t.Fatalf("不应再生成来源放行集合 %q：\n%s", banned, out)
		}
	}

	input := out
	if end := strings.Index(out, "chain forward"); end >= 0 {
		input = out[:end]
	}
	if n := strings.Count(input, `iifname "lo" accept`); n != 1 {
		t.Fatalf("input 链应只有一条 lo 放行，实际 %d：\n%s", n, input)
	}
	loIdx := strings.Index(input, `iifname "lo" accept`)
	ruleIdx := strings.Index(input, "ip saddr 8.8.8.8")
	if loIdx < 0 || ruleIdx < 0 || loIdx > ruleIdx {
		t.Fatalf("lo 放行应位于用户规则之前：\n%s", input)
	}

	fwd := forwardSection([]byte(out))
	if strings.Contains(fwd, `iifname "lo"`) || strings.Contains(fwd, "ip saddr {") || strings.Contains(fwd, "ip6 saddr {") {
		t.Fatalf("forward 链不应有 lo 或来源放行：\n%s", fwd)
	}
}

// TestV6BootstrapInfrastructure v6-bootstrap 除 NDP/DHCPv6 外还要放行 ICMPv6 错误
// （PMTUD 依赖 packet-too-big）与 MLD 查询：链路本地来源不再被隐式信任后，这些是 IPv6 的底座。
func TestV6BootstrapInfrastructure(t *testing.T) {
	out := string(compileOK(t, "accept { 8.8.8.8 -> 8080 }\ndrop\n"))
	for _, want := range []string{
		"destination-unreachable",
		"packet-too-big",
		"time-exceeded",
		"parameter-problem",
		"nd-router-solicit",
		"nd-neighbor-solicit",
		"mld-listener-query",
		"udp dport { 546, 547 } accept",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("v6-bootstrap 缺少 %q：\n%s", want, out)
		}
	}
}
