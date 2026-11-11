package compiler_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/lixiangzhong/efw/internal/compiler"
	"github.com/lixiangzhong/efw/internal/errs"
)

// compileErrors 取出编译错误列表；要求确实失败。测试输入会自动补兜底规则。
func compileErrors(t *testing.T, src string) errs.Errors {
	t.Helper()
	_, _, err := compiler.Compile([]byte(src), testOptions("<test>"))
	if err == nil {
		t.Fatal("期望编译失败，实际成功")
	}
	var list errs.Errors
	if !errors.As(err, &list) {
		t.Fatalf("错误类型不是 errs.Errors: %T", err)
	}
	return list
}

func TestCompileErrors(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		wantCat  errs.Category
		wantCode string
		wantMsg  string
	}{
		{"icmp 带端口", "1.1.1.1 -> icmp *:80 accept\n", errs.CategorySemantic, errs.CodeSemantic, "icmp 规则不能指定端口"},
		{"地址族混写", "1.1.1.1 -> tcp [2001:db8::1]:80 accept\n", errs.CategorySemantic, errs.CodeSemantic, "地址族不一致"},
		{"V6 带端口未加方括号", "1.1.1.1 -> tcp 2001:db8::1:80 accept\n", errs.CategorySemantic, errs.CodeSemantic, "方括号"},
		{"端口越界", "1.1.1.1 -> tcp *:70000 accept\n", errs.CategorySemantic, errs.CodeSemantic, "越界"},
		{"端口范围倒置", "1.1.1.1 -> tcp *:90-80 accept\n", errs.CategorySemantic, errs.CodeSemantic, "起点大于终点"},
		{"缺少箭头（两个目的地址）", "1.1.1.1 tcp *:80 accept\n", errs.CategorySemantic, errs.CodeSemantic, "目的地址只能出现一次"},
		{"未知动作", "1.1.1.1 -> tcp *:80 allow\n", errs.CategorySyntax, errs.CodeSyntax, "不是合法动作"},
		{"未知协议 token", "1.1.1.1 -> sctp 80 accept\n", errs.CategorySemantic, errs.CodeSemantic, "未知协议"},
		{"花括号不匹配", "1.1.1.1 -> tcp *:{80,443 accept\n", errs.CategorySyntax, errs.CodeSyntax, "花括号不匹配"},
		{"动作行后面还有规则", "1.1.1.1 -> tcp *:80 accept\ndrop\n2.2.2.2 -> tcp *:80 accept\n", errs.CategorySemantic, errs.CodeSemantic, "匹配一切的规则必须是展开后的最后一条"},
		{"多个匹配一切规则", "drop\nreject\n", errs.CategorySemantic, errs.CodeSemantic, "匹配一切的规则必须是展开后的最后一条"},
		{"未知指令", "bogus auto\n1.1.1.1 -> tcp *:80 accept\n", errs.CategorySemantic, errs.CodeDirective, "未知指令"},
		{"default 已移除", "default deny\n1.1.1.1 -> tcp *:80 accept\n", errs.CategorySemantic, errs.CodeDirective, "default 指令已移除"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			list := compileErrors(t, tc.src)
			var found bool
			for _, item := range list {
				if item.Code == tc.wantCode && item.Cat == tc.wantCat && strings.Contains(item.Msg, tc.wantMsg) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("未找到期望错误 code=%s msg 包含 %q，实际错误: %s", tc.wantCode, tc.wantMsg, list.Error())
			}
		})
	}
}

// TestMissingFallback 文件必须以匹配一切的兜底规则结束，否则报错。
func TestMissingFallback(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"只有普通规则", "v6-bootstrap off\n1.1.1.1 -> tcp *:80 accept\n", "缺少兜底规则"},
		{"最后一条是 log-only", "v6-bootstrap off\n1.1.1.1 -> tcp *:80 log\n", "缺少兜底规则"},
		{"空文件", "", "缺少兜底规则"},
		{"块内没有匹配一切", "accept {\n1.1.1.1 -> tcp *:80\n}\n", "缺少兜底规则"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := compileRaw(tc.src)
			if err == nil {
				t.Fatal("期望编译失败，实际成功")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("期望错误包含 %q，实际: %v", tc.want, err)
			}
		})
	}
}

func TestErrorFormat(t *testing.T) {
	list := compileErrors(t, "1.1.1.1 -> icmp *:80 accept\n")
	if want := "<test>:1: semantic: E102: icmp 规则不能指定端口"; list[0].Format() != want {
		t.Fatalf("错误格式不符\nwant: %s\ngot:  %s", want, list[0].Format())
	}
}

// TestLineEndingsAndBOM 验证 CRLF 与 UTF-8 BOM 不影响解析结果。
func TestLineEndingsAndBOM(t *testing.T) {
	lf := "v6-bootstrap off\n1.1.1.1 -> tcp *:80 accept\ndrop\n"
	crlf := "\xef\xbb\xbfv6-bootstrap off\r\n1.1.1.1 -> tcp *:80 accept\r\ndrop\r\n"

	opts := testOptions("<test>")
	gotLF, _, err := compiler.Compile([]byte(lf), opts)
	if err != nil {
		t.Fatalf("LF 输入编译失败: %v", err)
	}
	gotCRLF, _, err := compiler.Compile([]byte(crlf), opts)
	if err != nil {
		t.Fatalf("CRLF+BOM 输入编译失败: %v", err)
	}
	if string(gotLF) != string(gotCRLF) {
		t.Fatalf("CRLF+BOM 与 LF 产物不一致\nLF:\n%s\nCRLF:\n%s", gotLF, gotCRLF)
	}
}

// TestBareLogRejected 单独 log 动作行缺少 verdict。
func TestLogOnlyCatchAllRejected(t *testing.T) {
	list := compileErrors(t, "log\n")
	if !strings.Contains(list.Error(), "动作行缺少动作") {
		t.Fatalf("错误信息不符: %s", list.Error())
	}
}

// TestShorthandForms 覆盖简写及其边界。
func TestShorthandForms(t *testing.T) {
	valid := []struct {
		name string
		src  string
		want string
	}{
		{"省略箭头", "v6-bootstrap off\n1.1.1.2 accept\n", "ip saddr 1.1.1.2 accept"},
		{"只写协议", "v6-bootstrap off\n1.1.1.2 -> tcp accept\n", "ip saddr 1.1.1.2 meta l4proto tcp accept"},
		{"只写端口", "v6-bootstrap off\n1.1.1.2 -> 8080 accept\n", "th dport 8080 accept"},
		{"只写端口范围", "v6-bootstrap off\n1.1.1.2 -> 90-100 accept\n", "th dport { 90-100 } accept"},
		{"只写端口列表", "v6-bootstrap off\n1.1.1.2 -> {80, 443} accept\n", "th dport { 80, 443 } accept"},
		{"协议加端口", "v6-bootstrap off\n1.1.1.2 -> tcp 8443 accept\n", "ip saddr 1.1.1.2 tcp dport 8443 accept"},
		{"省略箭头带 log", "v6-bootstrap off\n1.1.1.2 log drop\n", `ip saddr 1.1.1.2 log prefix "efw: " level info drop`},
		{"ipv6 省略箭头", "v6-bootstrap off\n2001:db8::1 accept\n", "ip6 saddr 2001:db8::1 accept"},
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
		{"简写端口越界", "1.1.1.2 -> 70000 accept\n", "越界"},
		{"简写端口范围倒置", "1.1.1.2 -> 90-80 accept\n", "起点大于终点"},
		{"无箭头但带两个目的地址", "1.1.1.2 tcp *:80 accept\n", "目的地址只能出现一次"},
		{"无箭头缺少动作", "1.1.1.2\n", "不是合法动作"},
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

// TestBarePortLists 覆盖裸逗号端口列表（含带空格写法）。
func TestBarePortLists(t *testing.T) {
	valid := []struct {
		name string
		src  string
		want string
	}{
		{"裸列表", "v6-bootstrap off\n1.1.1.1 -> 80,443 accept\n", "th dport { 80, 443 } accept"},
		{"裸列表带空格", "v6-bootstrap off\n1.1.1.1 -> 80, 443 accept\n", "th dport { 80, 443 } accept"},
		{"裸范围", "v6-bootstrap off\n1.1.1.1 -> 8080-8090 accept\n", "th dport { 8080-8090 } accept"},
		{"裸列表混合范围", "v6-bootstrap off\n1.1.1.1 -> 80,443,8000-8010 accept\n", "th dport { 80, 443, 8000-8010 } accept"},
		{"完整写法裸列表", "v6-bootstrap off\n1.1.1.1 -> tcp *:80,443 accept\n", "tcp dport { 80, 443 } accept"},
		{"多端口 token 空格分隔", "v6-bootstrap off\n1.1.1.1 -> 80 443 accept\n", "th dport { 80, 443 } accept"},
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
		{"裸列表尾逗号", "1.1.1.1 -> 80, accept\n", "端口列表含空元素"},
		{"裸列表双逗号", "1.1.1.1 -> 80,,443 accept\n", "端口列表含空元素"},
		{"裸列表端口越界", "1.1.1.1 -> 0,80 accept\n", "越界"},
		{"完整写法尾逗号", "1.1.1.1 -> tcp *:80, accept\n", "端口列表含空元素"},
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

// TestDirectiveEdgeCases 覆盖文件头指令（established / v6-bootstrap）的边界错误。
func TestDirectiveEdgeCases(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"established 非法值", "established sometimes\n1.1.1.1 -> 80 accept\n", "established 只接受 auto 或 off"},
		{"v6-bootstrap 非法值", "v6-bootstrap maybe\n1.1.1.1 -> 80 accept\n", "v6-bootstrap 只接受 auto 或 off"},
		{"established 重复", "established off\nestablished auto\n1.1.1.1 -> 80 accept\n", "established 指令重复"},
		{"v6-bootstrap 重复", "v6-bootstrap off\nv6-bootstrap auto\n1.1.1.1 -> 80 accept\n", "v6-bootstrap 指令重复"},
		{"指令缺参数", "established\n1.1.1.1 -> 80 accept\n", "需要一个参数"},
		{"指令多余参数", "v6-bootstrap off extra\n1.1.1.1 -> 80 accept\n", "需要一个参数"},
		{"指令在规则之后", "1.1.1.1 -> tcp *:80 accept\nestablished off\n", "必须位于所有规则之前"},
		{"方括号未闭合", "1.1.1.1 -> tcp [2001:db8::1:80 accept\n", "方括号未闭合"},
		{"方括号内是 v4", "1.1.1.1 -> tcp [10.0.0.1]:80 accept\n", "方括号只能用于 IPv6"},
		{"端口列表为空", "1.1.1.1 -> tcp *:{} accept\n", "端口列表为空"},
		{"匹配部分含空格", "1.1.1.1 -> tcp *:80 extra accept\n", "未知协议 token"},
		{"协议重复", "1.1.1.1 -> tcp udp accept\n", "协议 token 只能出现一次"},
		{"多个箭头", "1.1.1.1 -> tcp *:80 -> accept\n", "多个 ->"},
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

// TestAuditFixes 覆盖复核发现的问题：mapped IPv6、未知指令、解析分类、端口错误文案。
func TestAuditFixes(t *testing.T) {
	// P1：IPv4-mapped IPv6 按书写族保留，不折叠成 IPv4。
	out := compileOK(t, "v6-bootstrap off\n::ffff:1.2.3.4 -> tcp *:80 accept\n")
	if !strings.Contains(string(out), "ip6 saddr ::ffff:1.2.3.4") {
		t.Fatalf("mapped IPv6 未被按 IPv6 处理:\n%s", out)
	}

	cases := []struct {
		name string
		src  string
		want string
	}{
		{"未知指令", "bogus auto\n1.1.1.1 -> 80 accept\n", "E100: 未知指令"},
		{":// 语法已移除", "1.1.1.1 -> tcp://*:80 accept\n", "语法已移除"},
		{"简写端口越界文案", "1.1.1.1 -> 100000 accept\n", "越界（1-65535）"},
		{"IPv4 地址非法", "1.1.1.1 -> tcp 1.2.3.999:80 accept\n", "不是合法的 IPv4/CIDR"},
		{"端口非数字", "1.1.1.1 -> tcp *:{80,abc} accept\n", "不是数字"},
		{"端口分隔符错误", "1.1.1.1 -> tcp *:{80 443} accept\n", "不是数字"},
		{"空端口列表", "1.1.1.1 -> {} accept\n", "端口列表为空"},
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

// TestBarePortRule 裸端口行 = 隐式 * 源（等价 `* -> ports`），不是续行。
func TestBarePortRule(t *testing.T) {
	valid := []struct {
		name string
		src  string
		want string
	}{
		{"块内裸端口", "v6-bootstrap off\naccept{\n  80 443\n}\ndrop\n", "meta l4proto { tcp, udp } th dport { 80, 443 } accept"},
		{"块内裸端口带协议", "v6-bootstrap off\naccept{\n  tcp 8080\n}\ndrop\n", "tcp dport 8080 accept"},
		{"块内协议加多端口", "v6-bootstrap off\naccept{\n  tcp 80 443\n}\ndrop\n", "tcp dport { 80, 443 } accept"},
		{"块内裸端口带 log", "v6-bootstrap off\naccept{\n  80 443 log\n}\ndrop\n", `meta l4proto { tcp, udp } th dport { 80, 443 } log prefix "efw: " level info accept`},
		{"顶层裸端口带动作", "v6-bootstrap off\n80 443 accept\ndrop\n", "th dport { 80, 443 } accept"},
		{"等价 * -> 多端口", "v6-bootstrap off\n* -> 80 443 accept\ndrop\n", "th dport { 80, 443 } accept"},
	}
	for _, tc := range valid {
		t.Run(tc.name, func(t *testing.T) {
			out := compileOK(t, tc.src)
			if !strings.Contains(string(out), tc.want) {
				t.Fatalf("产物缺少 %q:\n%s", tc.want, out)
			}
			// 隐式 * 源：不应生成源地址匹配。
			if !strings.Contains(tc.name, "等价 *") && strings.Contains(string(out), "ip saddr") {
				t.Fatalf("裸端口行不应生成源地址匹配:\n%s", out)
			}
		})
	}

	invalid := []struct {
		name string
		src  string
		want string
	}{
		{"顶层裸端口缺动作", "80 443\ndrop\n", "无箭头简写需要动作"},
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
