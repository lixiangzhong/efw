package compiler_test

import (
	"strings"
	"testing"

	"github.com/lixiangzhong/efw/internal/errs"
)

// TestAllowAlias 覆盖 allow 作为 accept 的别名：块头（单行/多行/大写）、
// 块内显式动作、iface 规则、兜底简写与 log 修饰；产物必须与 accept 版本逐字节一致。
func TestAllowAlias(t *testing.T) {
	cases := []struct {
		name   string
		allow  string
		accept string
	}{
		{
			name:   "单行块",
			allow:  "v6-bootstrap off\nallow { 1.1.1.1 -> 80 }\ndrop { * }\n",
			accept: "v6-bootstrap off\naccept { 1.1.1.1 -> 80 }\ndrop { * }\n",
		},
		{
			name:   "多行块",
			allow:  "v6-bootstrap off\nallow {\n1.1.1.1 -> 80\n}\ndrop { * }\n",
			accept: "v6-bootstrap off\naccept {\n1.1.1.1 -> 80\n}\ndrop { * }\n",
		},
		{
			name:   "大写",
			allow:  "v6-bootstrap off\nALLOW { 1.1.1.1 -> 80 }\ndrop { * }\n",
			accept: "v6-bootstrap off\nACCEPT { 1.1.1.1 -> 80 }\ndrop { * }\n",
		},
		{
			name:   "块内显式 accept",
			allow:  "v6-bootstrap off\nallow { 1.1.1.1 -> 80 accept }\ndrop { * }\n",
			accept: "v6-bootstrap off\naccept { 1.1.1.1 -> 80 accept }\ndrop { * }\n",
		},
		{
			name:   "规则尾动作写 allow",
			allow:  "v6-bootstrap off\nallow { 1.1.1.1 -> 80 allow }\ndrop { * }\n",
			accept: "v6-bootstrap off\naccept { 1.1.1.1 -> 80 accept }\ndrop { * }\n",
		},
		{
			name:   "iface 规则",
			allow:  "v6-bootstrap off\nallow { iface eth0 }\ndrop { * }\n",
			accept: "v6-bootstrap off\naccept { iface eth0 }\ndrop { * }\n",
		},
		{
			name:   "兜底简写",
			allow:  "v6-bootstrap off\nallow { 1.1.1.1 -> 80 }\nallow\n",
			accept: "v6-bootstrap off\naccept { 1.1.1.1 -> 80 }\naccept\n",
		},
		{
			name:   "log 兜底简写",
			allow:  "v6-bootstrap off\nallow { 1.1.1.1 -> 80 }\nlog allow\n",
			accept: "v6-bootstrap off\naccept { 1.1.1.1 -> 80 }\nlog accept\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rawAllow := compileOK(t, tc.allow)
			got := stripComments(rawAllow)
			want := stripComments(compileOK(t, tc.accept))
			if got != want {
				t.Fatalf("allow 与 accept 的规则行不一致:\n--- allow ---\n%s\n--- accept ---\n%s", got, want)
			}
			// 产物注释保留用户原文，allow 只允许出现在注释里。
			for _, line := range strings.Split(string(rawAllow), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.Contains(trimmed, "allow") && !strings.HasPrefix(trimmed, "#") {
					t.Fatalf("nft 规则行不应出现 allow: %s", trimmed)
				}
			}
		})
	}
}

// TestAllowFallbackTriggersW3 allow 兜底与 accept 兜底一致：触发 W3（未命中一律放行）。
func TestAllowFallbackTriggersW3(t *testing.T) {
	codes := warningCodes(t, "v6-bootstrap off\nallow { 1.1.1.1 -> 80 }\nallow\n")
	if !codes[errs.CodeFallbackAccept] {
		t.Fatalf("allow 兜底应触发 W3，实际告警: %v", codes)
	}
}

// TestAllowErrors 覆盖别名参与的两个错误面：masquerade 出接口不能是动作词；
// 块内显式动作必须与 allow 块头一致（allow 的裁决就是 accept）。
func TestAllowErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"masquerade 出接口不能用 allow", "masquerade { allow }\ndrop { * }\n", "关键字"},
		{"allow 块内动作不一致", "v6-bootstrap off\nallow { 1.1.1.1 -> 80 drop }\ndrop { * }\n", "动作必须与块头一致"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileRaw(tc.src)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("期望包含 %q 的错误，实际: %v", tc.want, err)
			}
		})
	}
}

// TestAllowIsNotSetName allow 已被动作词占用，不能再用作命名集合名：
// `allow { 1.1.1.1 }` 按动作块解析，而不是集合定义。
func TestAllowIsNotSetName(t *testing.T) {
	out := compileOK(t, "v6-bootstrap off\nallow { 1.1.1.1 }\ndrop { * }\n")
	if !strings.Contains(string(out), "ip saddr 1.1.1.1 accept") {
		t.Fatalf("allow 应按动作块解析:\n%s", out)
	}
	if strings.Contains(string(out), "elements = {") {
		t.Fatalf("allow 不应被当作命名集合:\n%s", out)
	}
}

// TestAllowStillNeedsBlock allow 只是动作别名，不改变「规则必须写在块内」：
// 块外写 `1.1.1.1 -> tcp *:80 allow` 仍报 E101。
func TestAllowStillNeedsBlock(t *testing.T) {
	list := compileErrorsRaw(t, "1.1.1.1 -> tcp *:80 allow\n")
	if !strings.Contains(list.Error(), "必须写在动作块内") {
		t.Fatalf("块外 allow 规则应被拒绝，实际: %s", list.Error())
	}
}
