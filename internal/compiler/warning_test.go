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
	src := "v6-bootstrap off\naccept { 1.1.1.1 -> tcp *:80 }\ndrop { 1.1.1.1 -> tcp *:80 }\ndrop { * }\n"
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

// TestBlockOnlyRejectsTopLevel 块外规则、动作行、log-only 一律拒绝（SPEC §2.3）。
func TestBlockOnlyRejectsTopLevel(t *testing.T) {
	for _, src := range []string{
		"v6-bootstrap off\n1.1.1.1 -> tcp *:80 accept\ndrop { * }\n",
		"v6-bootstrap off\naccept { 1.1.1.1 -> tcp *:80 }\n1.1.1.2 -> tcp *:80 accept\n",
		"v6-bootstrap off\n1.1.1.1 log\ndrop { * }\n",
	} {
		list := compileErrorsRaw(t, src)
		if !strings.Contains(list.Error(), "必须写在") {
			t.Fatalf("块外语法应被拒绝，实际: %s", list.Error())
		}
	}
}
