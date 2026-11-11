package compiler_test

import (
	"strings"
	"testing"

	"github.com/lixiangzhong/efw/internal/compiler"
	"github.com/lixiangzhong/efw/internal/errs"
)

func TestWarnings(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "W1 相同匹配不同动作",
			src:  "v6-bootstrap off\n1.1.1.1 -> tcp *:80 accept\n1.1.1.1 -> tcp *:80 drop\n",
			want: []string{errs.CodeUnreachableRule},
		},
		{
			name: "W2/W3 兜底为 accept",
			src:  "1.1.1.1 -> tcp *:80 accept\naccept\n",
			want: []string{errs.CodeV6BootstrapIdle, errs.CodeFallbackAccept},
		},
		{
			name: "W3 兜底 accept 且关闭 v6-bootstrap",
			src:  "v6-bootstrap off\n1.1.1.1 -> tcp *:80 accept\naccept\n",
			want: []string{errs.CodeFallbackAccept},
		},
		{
			name: "兜底 drop 无告警",
			src:  "v6-bootstrap off\n1.1.1.1 -> tcp *:80 accept\ndrop\n",
			want: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			codes := warningCodes(t, tc.src)
			for _, want := range tc.want {
				if !codes[want] {
					t.Fatalf("缺少告警 %s，实际告警: %v", want, codes)
				}
			}
			if tc.want == nil && len(codes) != 0 {
				t.Fatalf("期望无告警，实际: %v", codes)
			}
		})
	}
}

// TestW1ProductMarker W1 告警必须在产物中留注释标记（SPEC §6）。
func TestW1ProductMarker(t *testing.T) {
	src := "v6-bootstrap off\n1.1.1.1 -> tcp *:80 accept\n1.1.1.1 -> tcp *:80 drop\ndrop\n"
	out, warns, err := compiler.Compile([]byte(src), testOptions("<test>"))
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	var hasW1 bool
	for _, w := range warns {
		if w.Code == errs.CodeUnreachableRule {
			hasW1 = true
		}
	}
	if !hasW1 {
		t.Fatalf("期望 W1 告警，实际: %v", warns)
	}
	if !strings.Contains(string(out), "# W1: unreachable") {
		t.Fatalf("产物缺少 W1 注释标记:\n%s", out)
	}
}

// TestW1LogOnlyNoFalsePositive 单独 log 不裁决，其后同匹配规则仍然可达，不应报 W1。
func TestW1LogOnlyNoFalsePositive(t *testing.T) {
	src := "v6-bootstrap off\n1.1.1.1 -> tcp *:80 log\n1.1.1.1 -> tcp *:80 drop\ndrop\n"
	_, warns, err := compiler.Compile([]byte(src), testOptions("<test>"))
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	for _, w := range warns {
		if w.Code == errs.CodeUnreachableRule {
			t.Fatalf("log-only 前置规则不应触发 W1: %v", w.Msg)
		}
	}
}
