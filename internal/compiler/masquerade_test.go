package compiler_test

import (
	"strings"
	"testing"
)

// TestMasqueradeEmit 覆盖两种 NAT 形式与生成位置：同一 table 内的 postrouting 链，
// priority 90、仅首包匹配、条目顺序保持。
func TestMasqueradeEmit(t *testing.T) {
	out := string(compileOK(t, `accept {
  1.1.1.1 -> 22
}

masquerade {
  eth1
  192.168.1.0/24 -> eth1
  2001:db8:1::/64 -> eth1
  * -> eth2
}
drop
`))
	for _, want := range []string{
		"chain postrouting {",
		"type nat hook postrouting priority 90; policy accept;",
		`oifname "eth1" masquerade`,
		`ip saddr 192.168.1.0/24 oifname "eth1" masquerade`,
		`ip6 saddr 2001:db8:1::/64 oifname "eth1" masquerade`,
		`oifname "eth2" masquerade`,
		"# 6: eth1",
		"# 7: 192.168.1.0/24 -> eth1",
		"# 8: 2001:db8:1::/64 -> eth1",
		"# 9: * -> eth2",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("产物缺少 %q:\n%s", want, out)
		}
	}

	forward := strings.Index(out, "chain forward {")
	postrouting := strings.Index(out, "chain postrouting {")
	if forward < 0 || postrouting < 0 || postrouting < forward {
		t.Fatalf("postrouting 链应位于 forward 链之后:\n%s", out)
	}
	if strings.Contains(out[:postrouting], "masquerade") {
		t.Fatalf("masquerade 不应出现在 input/forward 链:\n%s", out)
	}
	if n := strings.Count(out, "chain postrouting {"); n != 1 {
		t.Fatalf("postrouting 链应只生成 1 条，实际 %d", n)
	}
}

// TestMasqueradePrivate private 作为源地址时展开 v4/v6 两条，并按需生成集合。
func TestMasqueradePrivate(t *testing.T) {
	out := string(compileOK(t, `masquerade {
  private -> eth1
}
accept
`))
	for _, want := range []string{
		"set private4 {",
		"set private6 {",
		`ip saddr @private4 oifname "eth1" masquerade`,
		`ip6 saddr @private6 oifname "eth1" masquerade`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("产物缺少 %q:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "set private4 {"); n != 1 {
		t.Fatalf("private4 应只生成 1 次，实际 %d:\n%s", n, out)
	}
}

// TestMasqueradePrivateSharesSet filter 与 masquerade 同时使用 private 时只生成一份集合。
func TestMasqueradePrivateSharesSet(t *testing.T) {
	out := string(compileOK(t, `accept {
  private
}
masquerade {
  private -> eth1
}
drop
`))
	if n := strings.Count(out, "set private4 {"); n != 1 {
		t.Fatalf("private4 应只生成 1 次，实际 %d:\n%s", n, out)
	}
	for _, want := range []string{
		"ip saddr @private4 accept",
		`ip saddr @private4 oifname "eth1" masquerade`,
		`ip6 saddr @private6 oifname "eth1" masquerade`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("产物缺少 %q:\n%s", want, out)
		}
	}
}

// TestMasqueradeIndependentOfForward masquerade 独立于容器转发链：forward off 仍生成 NAT 链。
func TestMasqueradeIndependentOfForward(t *testing.T) {
	out := string(compileOK(t, "forward off\nmasquerade {\n  192.168.1.0/24 -> eth1\n}\ndrop\n"))
	if strings.Contains(out, "chain forward {") {
		t.Fatalf("forward off 时不应生成转发链:\n%s", out)
	}
	if !strings.Contains(out, "chain postrouting {") {
		t.Fatalf("masquerade 应独立生成 NAT 链:\n%s", out)
	}
}

// TestMasqueradeMultipleBlocks 多个 masquerade 块按书写顺序拼接。
func TestMasqueradeMultipleBlocks(t *testing.T) {
	out := string(compileOK(t, `masquerade { 192.168.1.0/24 -> eth1 }
masquerade {
  192.168.2.0/24 -> eth2
}
accept
`))
	first := strings.Index(out, `ip saddr 192.168.1.0/24 oifname "eth1" masquerade`)
	second := strings.Index(out, `ip saddr 192.168.2.0/24 oifname "eth2" masquerade`)
	if first < 0 || second < 0 || first > second {
		t.Fatalf("多个 masquerade 块应保持书写顺序:\n%s", out)
	}
}

// TestMasqueradeChainLaziness 未写 masquerade 时不生成 NAT 链，现有产物不变。
func TestMasqueradeChainLaziness(t *testing.T) {
	out := string(compileOK(t, "accept { 1.1.1.1 -> 22 }\ndrop\n"))
	if strings.Contains(out, "postrouting") || strings.Contains(out, "masquerade") {
		t.Fatalf("未使用 masquerade 时不应生成 NAT 链:\n%s", out)
	}
}

// TestMasqueradeCaseInsensitive 关键字大小写不敏感，接口名保持原样。
func TestMasqueradeCaseInsensitive(t *testing.T) {
	out := string(compileOK(t, "MASQUERADE {\n  PRIVATE -> ETH1\n}\ndrop\n"))
	if !strings.Contains(out, `ip saddr @private4 oifname "ETH1" masquerade`) {
		t.Fatalf("私网 NAT 产物不正确:\n%s", out)
	}
}

// TestMasqueradeErrors 覆盖 masquerade 块的形式、边界与错误提示。
func TestMasqueradeErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"空分行块", "masquerade {\n}\ndrop\n", "至少需要一条规则"},
		{"空单行块", "masquerade { }\ndrop\n", "至少需要一条规则"},
		{"裸源地址缺少出接口", "masquerade { 192.168.1.0/24 }\ndrop\n", "源地址需要写成"},
		{"裸 token 像写错的地址", "masquerade { 300.1.1.1 }\ndrop\n", "源地址需要写成"},
		{"裸 private 缺少出接口", "masquerade { private }\ndrop\n", "private 需要写成"},
		{"出接口写成地址", "masquerade { 192.168.1.0/24 -> 10.0.0.1 }\ndrop\n", "不能是地址"},
		{"缺少出接口", "masquerade { 192.168.1.0/24 -> }\ndrop\n", "两侧都不能为空"},
		{"缺少源地址", "masquerade { -> eth1 }\ndrop\n", "两侧都不能为空"},
		{"多个箭头", "masquerade { 192.168.1.0/24 -> eth1 -> eth2 }\ndrop\n", "多个 ->"},
		{"出接口多余 token", "masquerade { 192.168.1.0/24 -> eth1 x }\ndrop\n", "出接口只能有一个"},
		{"非法网卡名", "masquerade { 192.168.1.0/24 -> eth/1 }\ndrop\n", "网卡名"},
		{"出接口为关键字", "masquerade { 192.168.1.0/24 -> accept }\ndrop\n", "关键字"},
		{"写入动作块", "accept { masquerade }\ndrop\n", "不能写在动作块内"},
		{"作为源地址", "accept { tcp masquerade -> 80 }\ndrop\n", "不能作为规则的一部分"},
		{"作为目的地址", "accept { * -> masquerade }\ndrop\n", "不能作为规则的一部分"},
		{"块外缺少花括号", "masquerade eth1\ndrop\n", "独立块"},
		{"任意关键字作出接口", "masquerade {\n  masquerade\n}\ndrop\n", "不能作为出接口名"},
		{"块内 iface 语法", "masquerade { iface eth1 }\ndrop\n", "每行只能写一条规则"},
		{"嵌套块", "masquerade {\n  masquerade {\n    eth1\n  }\n}\ndrop\n", "不能嵌套"},
		{"不能当兜底", "masquerade { eth1 }\n", "缺少兜底规则"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := compileRaw(tc.src); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("期望错误包含 %q，实际: %v", tc.want, err)
			}
		})
	}
}
