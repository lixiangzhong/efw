package compiler_test

import (
	"strings"
	"testing"
)

// TestBlockInheritance 覆盖 accept/drop/reject 动作块：块内省略 action、继承块动作。
func TestBlockInheritance(t *testing.T) {
	valid := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "accept 块省略动作",
			src:  "v6-bootstrap off\naccept {\n1.1.1.1 -> tcp *:80\n}\n",
			want: "ip saddr 1.1.1.1 tcp dport 80 accept",
		},
		{
			name: "drop 块省略动作",
			src:  "v6-bootstrap off\ndrop {\n1.1.1.1 -> 8080\n}\n",
			want: "ip saddr 1.1.1.1 meta l4proto { tcp, udp } th dport 8080 drop",
		},
		{
			name: "reject 块省略动作",
			src:  "v6-bootstrap off\nreject {\n1.1.1.1 -> tcp *:22\n}\n",
			want: "ip saddr 1.1.1.1 tcp dport 22 reject",
		},
		{
			name: "块内 log 作为修饰符",
			src:  "v6-bootstrap off\naccept {\n1.1.1.1 -> 80 log\n}\n",
			want: `ip saddr 1.1.1.1 meta l4proto { tcp, udp } th dport 80 log prefix "efw: " level info accept`,
		},
		{
			name: "块内只写源地址",
			src:  "v6-bootstrap off\naccept {\n1.1.1.1\n}\n",
			want: "ip saddr 1.1.1.1 accept",
		},
		{
			name: "块内显式相同动作",
			src:  "v6-bootstrap off\naccept {\n1.1.1.1 -> tcp *:80 accept\n}\n",
			want: "ip saddr 1.1.1.1 tcp dport 80 accept",
		},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			out := compileOK(t, tc.src)
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("产物缺少 %q:\n%s", tc.want, out)
			}
		})
	}
}

// TestBlockOrderPreserved 块只是分组语法，规则顺序按文本展开。
func TestBlockOrderPreserved(t *testing.T) {
	src := `v6-bootstrap off
accept {
1.1.1.1 -> tcp *:80
}
1.2.3.4 -> tcp *:81 accept
drop {
5.5.5.5 -> 22
}
`
	text := string(compileOK(t, src))
	i1 := strings.Index(text, "ip saddr 1.1.1.1 tcp dport 80 accept")
	i2 := strings.Index(text, "ip saddr 1.2.3.4 tcp dport 81 accept")
	i3 := strings.Index(text, "ip saddr 5.5.5.5")
	if i1 < 0 || i2 < 0 || i3 < 0 || !(i1 < i2 && i2 < i3) {
		t.Fatalf("块展开顺序错误:\n%s", text)
	}
}

// TestBlockErrors 覆盖块语法的非法形态。
func TestBlockErrors(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"嵌套块", "accept {\ndrop {\n}\n}\n", "不支持嵌套块"},
		{"块未闭合", "accept {\n1.1.1.1 -> 80\n", "块未闭合"},
		{"多余右花括号", "}\n", "多余的 }"},
		{"空块", "accept {\n}\n", "块内至少需要一条规则"},
		{"块内动作不一致", "accept {\n1.1.1.1 -> 80 drop\n}\n", "块内规则动作必须与块头一致"},
		{"块内出现指令", "accept {\ndefault allow\n}\n", "指令不能出现在块内"},
		{"块内出现动作行", "accept {\ndrop\n}\n", "动作行不能出现在块内"},
		{"动作行后开块", "log drop\naccept {\n1.1.1.1\n}\n", "匹配一切的规则必须是展开后的最后一条"},
		{"块头格式错误", "accept extra {\n1.1.1.1 -> 80\n}\n", "块头格式错误"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list := compileErrors(t, tc.src)
			if !strings.Contains(list.Error(), tc.want) {
				t.Fatalf("期望错误包含 %q，实际: %s", tc.want, list.Error())
			}
		})
	}
}

// TestInlineBlocks 单行块：`accept { <一条规则> }`。
func TestInlineBlocks(t *testing.T) {
	valid := []struct {
		name string
		src  string
		want string
	}{
		{"单行 accept 块", "v6-bootstrap off\naccept { tcp 1.1.1.1 -> 80 }\ndrop { * }\n", "ip saddr 1.1.1.1 tcp dport 80 accept"},
		{"单行 drop 块", "v6-bootstrap off\ndrop { 2.2.2.2 -> 22 }\ndrop { * }\n", "ip saddr 2.2.2.2 meta l4proto { tcp, udp } th dport 22 drop"},
		{"单行块带 log", "v6-bootstrap off\naccept { 1.1.1.1 -> 80 log }\ndrop { * }\n", "log prefix \"efw: \" level info accept"},
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
		{"空单行块", "accept { }\ndrop { * }\n", "块内至少需要一条规则"},
		{"单行块内写动作", "accept { drop }\ndrop { * }\n", "动作行不能出现在块内"},
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

// TestBareActionEqualsBlockStar 单独动作行与 `action { * }` 编译结果完全一致。
func TestBareActionEqualsBlockStar(t *testing.T) {
	pairs := [][2]string{
		{"v6-bootstrap off\n1.1.1.1 -> tcp 80 accept\ndrop\n",
			"v6-bootstrap off\n1.1.1.1 -> tcp 80 accept\ndrop { * }\n"},
		{"v6-bootstrap off\n1.1.1.1 -> tcp 80 accept\nlog drop\n",
			"v6-bootstrap off\n1.1.1.1 -> tcp 80 accept\ndrop { * log }\n"},
		{"v6-bootstrap off\ndrop {\n    *\n}\n",
			"v6-bootstrap off\ndrop { * }\n"},
	}
	for _, pair := range pairs {
		a := stripComments(compileOK(t, pair[0]))
		b := stripComments(compileOK(t, pair[1]))
		if a != b {
			t.Fatalf("两种写法产物不一致\nA:\n%s\nB:\n%s", a, b)
		}
	}
}
