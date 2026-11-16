package compiler_test

import (
	"strings"
	"testing"
)

// TestIfaceEmit iface 是独立整卡规则：只渲染 iifname，input/forward 都生效。
func TestIfaceEmit(t *testing.T) {
	out := string(compileOK(t, `accept {
  iface eth0
  iface eth1
}
drop
`))
	for _, want := range []string{
		`iifname "eth0" accept`,
		`iifname "eth1" accept`,
		`ct status dnat iifname "eth0" accept`,
		`ct status dnat iifname "eth1" accept`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("产物缺少 %q:\n%s", want, out)
		}
	}
}

// TestIfaceLog iface 规则支持 log 修饰。
func TestIfaceLog(t *testing.T) {
	out := string(compileOK(t, "accept {\n  iface eth0 log\n}\ndrop\n"))
	want := `iifname "eth0" log prefix "efw: " level info accept`
	if !strings.Contains(out, want) {
		t.Fatalf("产物缺少 %q:\n%s", want, out)
	}
}

// TestIfaceRejectsCombinations iface 不再与源/目的/协议/端口组合。
func TestIfaceRejectsCombinations(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"前缀组合", "accept {\n  iface eth0 1.1.1.1 -> 80\n}\ndrop\n", "只支持"},
		{"后缀组合", "accept {\n  1.1.1.1 -> 80 iface eth0\n}\ndrop\n", "只能单独"},
		{"协议组合", "accept {\n  iface eth0 tcp 80\n}\ndrop\n", "只支持"},
		{"无箭头组合", "accept {\n  tcp iface eth0\n}\ndrop\n", "只能单独"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compileRaw(tc.src); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("期望错误包含 %q，实际: %v", tc.want, err)
			}
		})
	}
}

// TestIfaceErrors 缺名、非法名与过长名。
func TestIfaceErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"缺少网卡名", "accept {\n  iface\n}\ndrop\n", "iface 后面缺少网卡名"},
		{"非法网卡名", "accept {\n  iface eth/0\n}\ndrop\n", "网卡名"},
		{"过长网卡名", "accept {\n  iface abcdefghijklmnop\n}\ndrop\n", "网卡名"},
		{"块外使用", "iface eth0\n", "必须写在动作块内"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compileRaw(tc.src); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("期望错误包含 %q，实际: %v", tc.want, err)
			}
		})
	}
}

// TestIfaceWarnings iface 是匹配条件的一部分：同 iface 才可能构成 W1。
func TestIfaceWarnings(t *testing.T) {
	sameIface := `accept {
  iface eth0
}
drop {
  iface eth0
}
`
	if !warningCodes(t, sameIface)["W1"] {
		t.Fatal("同 iface 同整卡规则不同动作应产生 W1")
	}

	diffIface := `accept {
  iface eth0
}
drop {
  iface eth1
}
`
	if warningCodes(t, diffIface)["W1"] {
		t.Fatal("不同 iface 的整卡规则不应产生 W1")
	}
}

// TestIfaceNotFallback 带 iface 的规则不匹配一切，不能当兜底。
func TestIfaceNotFallback(t *testing.T) {
	if _, err := compileRaw("accept { iface eth0 }\n"); err == nil || !strings.Contains(err.Error(), "缺少兜底规则") {
		t.Fatalf("iface 规则不能充当兜底，实际: %v", err)
	}
	if _, err := compileRaw("accept { iface eth0 }\ndrop\n"); err != nil {
		t.Fatalf("iface 规则 + 兜底应编译成功: %v", err)
	}
}

// TestLoopbackAllowedByDefault input 链首应自动放行 lo（本机访问自身地址走 lo）。
func TestLoopbackAllowedByDefault(t *testing.T) {
	out := string(compileOK(t, "accept { 8.8.8.8 -> 80 }\ndrop\n"))
	if n := strings.Count(out, `iifname "lo" accept`); n != 1 {
		t.Fatalf(`iifname "lo" accept 应出现 1 次（仅 input），实际 %d:\n%s`, n, out)
	}

	inputEnd := strings.Index(out, "chain forward")
	if inputEnd < 0 {
		t.Fatalf("缺少 forward 链:\n%s", out)
	}
	if !strings.Contains(out[:inputEnd], `iifname "lo" accept`) {
		t.Fatalf("lo 放行应位于 input 链:\n%s", out)
	}
	if strings.Contains(forwardSection([]byte(out)), `iifname "lo"`) {
		t.Fatalf("forward 链不应放行 lo:\n%s", forwardSection([]byte(out)))
	}

	loIdx := strings.Index(out, `iifname "lo" accept`)
	srcIdx := strings.Index(out, "# auto: 本机/CGNAT/link-local")
	if loIdx < 0 || srcIdx < 0 || loIdx > srcIdx {
		t.Fatalf("lo 放行应在来源放行之前:\n%s", out)
	}
}
