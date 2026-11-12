package compiler_test

import (
	"strings"
	"testing"

	"github.com/lixiangzhong/efw/internal/compiler"
)

// TestInternalSourceBypass 默认只放行 loopback/CGNAT/link-local 与 IPv6 ULA/link-local；
// RFC1918 不默认放行，Docker 网段通过 Options.DockerNets 注入。
func TestInternalSourceBypass(t *testing.T) {
	out := string(compileOK(t, "v6-bootstrap off\naccept { 8.8.8.8 -> 8080 }\ndrop { * }\n"))
	for _, want := range []string{
		"# auto: 本机/CGNAT/link-local 来源放行",
		"ip saddr { 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16 } accept",
		"ip6 saddr { ::1, fc00::/7, fe80::/10 } accept",
	} {
		if n := strings.Count(out, want); n != 2 { // input + forward 各一份
			t.Fatalf("%q 应出现 2 次，实际 %d\n%s", want, n, out)
		}
	}
	// RFC1918 默认不再放行。
	for _, rfc1918 := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		if strings.Contains(out, rfc1918) {
			t.Fatalf("RFC1918 网段 %s 不应默认放行:\n%s", rfc1918, out)
		}
	}
	// 内网放行必须在用户规则与兜底之前。
	internalIdx := strings.Index(out, "ip saddr { 100.64.0.0/10")
	ruleIdx := strings.Index(out, "ip saddr 8.8.8.8")
	dropIdx := strings.LastIndex(out, "drop\n")
	if internalIdx < 0 || ruleIdx < 0 || dropIdx < 0 || internalIdx > ruleIdx || internalIdx > dropIdx {
		t.Fatalf("内网放行顺序不正确\n%s", out)
	}
	// forward 链的内网放行不带 DNAT 限定（容器互访/hairpin 也要放行）。
	fwd := forwardSection([]byte(out))
	line := "ip saddr { 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16 } accept"
	if !strings.Contains(fwd, line) || strings.Contains(fwd, "ct status dnat "+line) {
		t.Fatalf("forward 内网放行不应带 ct status dnat:\n%s", fwd)
	}
}

// TestDockerNetworksInjected apply 探测到的 Docker 网段应追加到放行集合。
func TestDockerNetworksInjected(t *testing.T) {
	opts := testOptions("<test>")
	opts.DockerNets = []string{"172.17.0.0/16", "fd00:dead::/64", "172.17.0.0/16"}
	out, _, err := compiler.Compile([]byte("v6-bootstrap off\naccept { 8.8.8.8 -> 8080 }\ndrop { * }\n"), opts)
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	text := string(out)
	for _, want := range []string{
		"ip saddr { 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.17.0.0/16 } accept",
		"ip6 saddr { ::1, fc00::/7, fd00:dead::/64, fe80::/10 } accept",
	} {
		if n := strings.Count(text, want); n != 2 { // input + forward
			t.Fatalf("%q 应出现 2 次，实际 %d\n%s", want, n, text)
		}
	}
}
