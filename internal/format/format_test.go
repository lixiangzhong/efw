package format_test

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"unicode"

	"github.com/lixiangzhong/efw/internal/format"
	"github.com/lixiangzhong/efw/internal/ir"
	"github.com/lixiangzhong/efw/internal/parser"
)

// formatCase 是一条格式化用例：in 为原始文本，want 为期望输出。
type formatCase struct {
	name string
	in   string
	want string
}

// formatCases 覆盖缩进、token 间距、端口列表、注释、空行、单行块、CRLF/BOM。
var formatCases = []formatCase{
	{
		name: "缩进与箭头间距",
		in:   "accept{\n        tcp 1.1.1.1->80    # 管理口\n  1.1.1.2   ->   443\n}\ndrop{*}\n",
		want: "accept {\n    tcp 1.1.1.1 -> 80  # 管理口\n    1.1.1.2 -> 443\n}\ndrop { * }\n",
	},
	{
		name: "端口列表与独立规则",
		in:   "accept{\n1.1.1.1->{80,443}\n2.2.2.2 -> { 9000 , 9001 }\n3.3.3.3 -> 80 443\nprivate log\niface br-*\n}\ndrop\n",
		want: "accept {\n    1.1.1.1 -> {80, 443}\n    2.2.2.2 -> {9000, 9001}\n    3.3.3.3 -> 80 443\n    private log\n    iface br-*\n}\ndrop\n",
	},
	{
		name: "命名集合与连续空行",
		in:   "# 头部\n\n\nWEB{\n1.1.1.0/24\n1.1.1.1,2.2.2.2\n}\naccept{\n@WEB->80\n}\n",
		want: "# 头部\n\nWEB {\n    1.1.1.0/24\n    1.1.1.1, 2.2.2.2\n}\naccept {\n    @WEB -> 80\n}\n",
	},
	{
		name: "注释缩进与行内注释",
		in:   "accept {\n# inside\n1.1.1.1# tail\n}\ndrop\n",
		want: "accept {\n    # inside\n    1.1.1.1  # tail\n}\ndrop\n",
	},
	{
		name: "masquerade 块",
		in:   "masquerade{\neth0\n10.0.0.0/8->eth1\n}\n\ndrop{*}\n",
		want: "masquerade {\n    eth0\n    10.0.0.0/8 -> eth1\n}\n\ndrop { * }\n",
	},
	{
		name: "allow 别名与 accept 同样缩进",
		in:   "allow{\n1.1.1.1->80\n}\nALLOW { 2.2.2.2 }\nlog allow\n",
		want: "allow {\n    1.1.1.1 -> 80\n}\nALLOW { 2.2.2.2 }\nlog allow\n",
	},
	{
		name: "CRLF BOM 与末尾空行",
		in:   "\ufeffv6-bootstrap off\r\n\r\n\r\naccept{1.1.1.1}\r\ndrop\r\n",
		want: "v6-bootstrap off\n\naccept { 1.1.1.1 }\ndrop\n",
	},
	{
		name: "单行块内端口列表",
		in:   "accept{1.1.1.1->{80,443}}  # c\n",
		want: "accept { 1.1.1.1 -> {80, 443} }  # c\n",
	},
	{
		name: "地址端口列表连写",
		in:   "accept { 3.3.3.3 -> tcp *:{8080,9090-9095} }\ndrop { * }\n",
		want: "accept { 3.3.3.3 -> tcp *:{8080, 9090-9095} }\ndrop { * }\n",
	},
	{
		name: "制表符与CRLF",
		in:   "established\toff\r\naccept\t{\r\n\tiface\teth0\tlog\r\n\t1.1.1.1\t->\t{ 80 ,\t443 }\r\n}\r\ndrop\t{ * }\r\n",
		want: "established off\naccept {\n    iface eth0 log\n    1.1.1.1 -> {80, 443}\n}\ndrop { * }\n",
	},
	{
		name: "注释堆叠与块头行内注释",
		in:   "# 文件头\n#\n##\n\t# 缩进的注释\n\naccept { # 块头\n\t# 块内注释\n\n\t1.1.1.1 -> 80\t# 行内\n} # 结束\n\n# 尾部\ndrop\n",
		want: "# 文件头\n#\n##\n# 缩进的注释\n\naccept {  # 块头\n    # 块内注释\n\n    1.1.1.1 -> 80  # 行内\n}  # 结束\n\n# 尾部\ndrop\n",
	},
	{
		name: "单行块混杂",
		in:   "drop{*}\nreject{2.2.2.2->22}\naccept { iface eth0 }\naccept{\t1.1.1.1\t->\t{80,443}\t}\ndrop\n",
		want: "drop { * }\nreject { 2.2.2.2 -> 22 }\naccept { iface eth0 }\naccept { 1.1.1.1 -> {80, 443} }\ndrop\n",
	},
	{
		name: "箭头与端口连写",
		in:   "accept{\n1.1.1.1->80\n*->80\n2.2.2.2->tcp 8080\n*->{80,443}\n}\ndrop\n",
		want: "accept {\n    1.1.1.1 -> 80\n    * -> 80\n    2.2.2.2 -> tcp 8080\n    * -> {80, 443}\n}\ndrop\n",
	},
	{
		name: "端口列表多种写法",
		in:   "accept{\n1.1.1.1 -> {80,443}\n1.1.1.2 -> { 80 , 443 }\n1.1.1.3 -> 80,443\n1.1.1.4 -> 80 443\n1.1.1.5 -> 8080-8090,443\n1.1.1.6 -> {80,\t443}\n{80,443}\n}\ndrop\n",
		want: "accept {\n    1.1.1.1 -> {80, 443}\n    1.1.1.2 -> {80, 443}\n    1.1.1.3 -> 80, 443\n    1.1.1.4 -> 80 443\n    1.1.1.5 -> 8080-8090, 443\n    1.1.1.6 -> {80, 443}\n    {80, 443}\n}\ndrop\n",
	},
	{
		name: "IPv6 与方括号端口",
		in:   "accept{\n[2001:db8::1]:443\n2001:db8::2 -> 80\n[2001:db8::3]:{80,443}\n2001:db8::4 tcp6 -> [2001:db8::5]:443\n}\ndrop\n",
		want: "accept {\n    [2001:db8::1]:443\n    2001:db8::2 -> 80\n    [2001:db8::3]:{80, 443}\n    2001:db8::4 tcp6 -> [2001:db8::5]:443\n}\ndrop\n",
	},
	{
		name: "命名集合紧凑与制表符",
		in:   "WEB{1.1.1.0/25,2.2.2.2}\nBOTH {\n\t1.1.1.1\t2001:db8::1\n}\naccept{\n@WEB->80\n@BOTH tcp4 -> 443\n}\ndrop\n",
		want: "WEB { 1.1.1.0/25, 2.2.2.2 }\nBOTH {\n    1.1.1.1 2001:db8::1\n}\naccept {\n    @WEB -> 80\n    @BOTH tcp4 -> 443\n}\ndrop\n",
	},
	{
		name: "masquerade 紧凑与通配",
		in:   "masquerade{eth0}\nmasquerade {\n*->eth1\n10.0.0.0/8\t->\teth2\n\tprivate -> eth3\n}\naccept{1.1.1.1->22}\ndrop\n",
		want: "masquerade { eth0 }\nmasquerade {\n    * -> eth1\n    10.0.0.0/8 -> eth2\n    private -> eth3\n}\naccept { 1.1.1.1 -> 22 }\ndrop\n",
	},
	{
		name: "混合换行与无末尾换行",
		in:   "accept{\r\n1.1.1.1 -> 80\n}\r\ndrop",
		want: "accept {\n    1.1.1.1 -> 80\n}\ndrop\n",
	},
	{
		name: "尾部空白与行尾空格",
		in:   "accept {   \n    1.1.1.1 -> 80   \n}   \ndrop   \n",
		want: "accept {\n    1.1.1.1 -> 80\n}\ndrop\n",
	},
	{
		name: "shebang 与兜底简写",
		in:   "#!/usr/local/bin/efw apply\n# 只有注释\n\nv6-bootstrap\toff\n\nlog drop\n",
		want: "#!/usr/local/bin/efw apply\n# 只有注释\n\nv6-bootstrap off\n\nlog drop\n",
	},
	{
		name: "空输入",
		in:   "",
		want: "",
	},
	{
		name: "纯空行",
		in:   "\n\n\n",
		want: "",
	},
}

// TestSource 逐条比对格式化输出，并校验只改动了空白字符。
func TestSource(t *testing.T) {
	for _, tc := range formatCases {
		t.Run(tc.name, func(t *testing.T) {
			got := string(format.Source([]byte(tc.in)))
			if got != tc.want {
				t.Fatalf("输出不符\n--- got ---\n%q\n--- want ---\n%q", got, tc.want)
			}
			if squash(tc.in) != squash(got) {
				t.Fatalf("格式化改动了非空白字符\n--- in ---\n%q\n--- got ---\n%q", tc.in, got)
			}
		})
	}
}

// TestSourceIdempotent 格式化结果再格式化必须保持不变。
func TestSourceIdempotent(t *testing.T) {
	for _, tc := range formatCases {
		once := format.Source([]byte(tc.in))
		twice := format.Source(once)
		if !bytes.Equal(once, twice) {
			t.Fatalf("%s: 二次格式化结果不一致\n--- once ---\n%q\n--- twice ---\n%q", tc.name, once, twice)
		}
	}
	for _, path := range goldenACLs(t) {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", path, err)
		}
		once := format.Source(src)
		twice := format.Source(once)
		if !bytes.Equal(once, twice) {
			t.Fatalf("%s: 二次格式化结果不一致", path)
		}
	}
}

// TestSourceKeepsSemantics 格式化前后分别解析，除行列与原始文本外的 IR 必须一致。
func TestSourceKeepsSemantics(t *testing.T) {
	inputs := make([]struct {
		name string
		src  []byte
	}, 0, len(formatCases))
	for _, tc := range formatCases {
		inputs = append(inputs, struct {
			name string
			src  []byte
		}{name: tc.name, src: []byte(tc.in)})
	}
	// 黄金用例覆盖真实 DSL 形态（动作块、命名集合、masquerade、iface、private）。
	for _, path := range goldenACLs(t) {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", path, err)
		}
		inputs = append(inputs, struct {
			name string
			src  []byte
		}{name: path, src: src})
	}

	for _, in := range inputs {
		before, beforeErrs := parser.Parse(in.name, in.src)
		if len(beforeErrs) > 0 {
			t.Fatalf("%s: 原始文本无法解析: %v", in.name, beforeErrs)
		}
		formatted := format.Source(in.src)
		after, afterErrs := parser.Parse(in.name, formatted)
		if len(afterErrs) > 0 {
			t.Fatalf("%s: 格式化后无法解析: %v\n%s", in.name, afterErrs, formatted)
		}
		if !reflect.DeepEqual(withoutPositions(before), withoutPositions(after)) {
			t.Fatalf("%s: 格式化改变了语义\n--- before ---\n%+v\n--- after ---\n%+v", in.name, before, after)
		}
	}
}

// goldenACLs 返回全部黄金用例的 DSL 输入路径。
func goldenACLs(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "golden", "*.acl"))
	if err != nil {
		t.Fatalf("glob 黄金用例失败: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("没有找到黄金用例")
	}
	return files
}

// withoutPositions 复制 IR 并清空行列与原始文本，用于跨格式化比较语义。
func withoutPositions(f *ir.File) *ir.File {
	out := *f
	out.Rules = append([]ir.Rule(nil), f.Rules...)
	for i := range out.Rules {
		out.Rules[i].Line = 0
		out.Rules[i].Raw = ""
	}
	out.Sets = append([]ir.NamedSet(nil), f.Sets...)
	for i := range out.Sets {
		out.Sets[i].Line = 0
	}
	out.Masquerades = append([]ir.Masquerade(nil), f.Masquerades...)
	for i := range out.Masquerades {
		out.Masquerades[i].Line = 0
		out.Masquerades[i].Raw = ""
	}
	return &out
}

// squash 去掉 BOM、CRLF 与全部空白字符，验证格式化只改空白。
func squash(s string) string {
	s = strings.TrimPrefix(s, "\ufeff")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}
