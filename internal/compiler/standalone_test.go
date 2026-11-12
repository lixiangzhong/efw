package compiler_test

import (
	"strings"
	"testing"
)

// TestStandaloneFallbackShorthand 块外兜底简写：[log] accept|drop|reject ≡ verdict { * }。
func TestStandaloneFallbackShorthand(t *testing.T) {
	base := "v6-bootstrap off\naccept { 1.1.1.1 -> 80 }\n"
	shorthand := base + "drop\n"
	block := base + "drop { * }\n"

	a := stripComments(compileOK(t, shorthand))
	b := stripComments(compileOK(t, block))
	if a != b {
		t.Fatalf("drop 与 drop { * } 产物不一致\nshorthand:\n%s\nblock:\n%s", a, b)
	}

	// log 修饰简写
	out := string(compileOK(t, base+"log drop\n"))
	if !strings.Contains(out, "log prefix \"efw: \" level info drop") {
		t.Fatalf("log drop 简写产物缺少 log/drop:\n%s", out)
	}

	// accept 兜底简写（应触发 W3 告警）
	if !strings.Contains(string(compileOK(t, base+"accept\n")), "accept\n") {
		t.Fatalf("accept 简写产物异常")
	}
	if codes := warningCodes(t, base+"accept\n"); !codes["W3"] {
		t.Fatalf("accept 兜底简写应触发 W3，实际: %v", codes)
	}
}

// TestStandaloneFallbackErrors 简写的错误边界。
func TestStandaloneFallbackErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"单独 log 已移除", "log\n", "单独 log 已移除"},
		{"简写后还有规则", "drop\naccept { 1.1.1.1 -> 80 }\n", "匹配一切的规则必须是展开后的最后一条"},
		{"简写带多余 token", "log drop extra\n", "兜底简写只接受"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list := compileErrorsRaw(t, tc.src)
			if !strings.Contains(list.Error(), tc.want) {
				t.Fatalf("期望包含 %q，实际: %s", tc.want, list.Error())
			}
		})
	}
}
