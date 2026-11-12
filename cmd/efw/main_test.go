package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validACL = "v6-bootstrap off\naccept { 1.1.1.1 -> tcp *:80 }\ndrop { * }\n"

// fallbackAcceptACL 用于验证默认告警输出与 --quiet（兜底 accept → W3）。
const fallbackAcceptACL = "v6-bootstrap off\naccept { 1.1.1.1 -> tcp *:80 }\naccept { * }\n"

func TestRun(t *testing.T) {
	cases := []struct {
		name       string
		args       []string
		stdin      string
		wantExit   int
		wantStdout string
		wantStderr string
	}{
		{name: "help", args: []string{"--help"}, wantExit: 0, wantStdout: "efw compile [flags] [file]"},
		{name: "version", args: []string{"--version"}, wantExit: 0, wantStdout: "efw version"},
		{name: "无参数", args: nil, wantExit: 2, wantStderr: "E103"},
		{name: "未知命令或文件不存在", args: []string{"foo"}, wantExit: 2, wantStderr: "E103"},
		{name: "stdin 编译", args: []string{"compile"}, stdin: validACL, wantExit: 0, wantStdout: "table inet efw {"},
		{name: "stdin 来源标注", args: []string{"compile"}, stdin: validACL, wantExit: 0, wantStdout: "# source: <stdin>"},
		{name: "编译错误退出码", args: []string{"compile"}, stdin: "v6-bootstrap off\naccept { 1.1.1.1 -> tcp *:80 }\n", wantExit: 1, wantStderr: "E100"},
		{name: "文件不存在", args: []string{"compile", "/nonexistent/efw.acl"}, wantExit: 2, wantStderr: "E103"},
		{name: "非法 hook", args: []string{"compile", "--hook", "forward"}, stdin: validACL, wantExit: 2, wantStderr: "E103"},
		{name: "非法 priority", args: []string{"compile", "--priority", "not-a-priority"}, stdin: validACL, wantExit: 2, wantStderr: "E103"},
		{name: "-o 空路径", args: []string{"compile", "-o", ""}, stdin: validACL, wantExit: 2, wantStderr: "E103"},
		{name: "未知 flag", args: []string{"compile", "--bogus"}, stdin: validACL, wantExit: 2, wantStderr: "E103"},
		{name: "非法 table 名", args: []string{"compile", "--table", "1bad"}, stdin: validACL, wantExit: 2, wantStderr: "E103"},
		{name: "非法 log 前缀", args: []string{"compile", "--log-prefix", "bad\"prefix"}, stdin: validACL, wantExit: 2, wantStderr: "E103"},
		{name: "多余位置参数", args: []string{"compile", "a.acl", "b.acl"}, stdin: validACL, wantExit: 2, wantStderr: "E103"},
		{
			name:       "部署参数透传",
			args:       []string{"compile", "--table", "myt", "--chain", "myc", "--priority", "-10", "--log-prefix", "XX "},
			stdin:      "v6-bootstrap off\ndrop { 1.1.1.1 -> tcp *:80 log }\ndrop { * }\n",
			wantExit:   0,
			wantStdout: "table inet myt {",
		},
		{name: "默认打印告警", args: []string{"compile"}, stdin: fallbackAcceptACL, wantExit: 0, wantStderr: "W3"},
		{name: "quiet 抑制告警", args: []string{"compile", "--quiet"}, stdin: fallbackAcceptACL, wantExit: 0, wantStderr: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			exit := run(tc.args, strings.NewReader(tc.stdin), &stdout, &stderr)
			if exit != tc.wantExit {
				t.Fatalf("退出码不符: want %d, got %d\nstdout:\n%s\nstderr:\n%s", tc.wantExit, exit, stdout.String(), stderr.String())
			}
			if tc.wantStdout != "" && !strings.Contains(stdout.String(), tc.wantStdout) {
				t.Fatalf("stdout 缺少 %q\n实际:\n%s", tc.wantStdout, stdout.String())
			}
			if tc.wantStderr != "" && !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Fatalf("stderr 缺少 %q\n实际:\n%s", tc.wantStderr, stderr.String())
			}
			if tc.name == "quiet 抑制告警" && stderr.Len() != 0 {
				t.Fatalf("--quiet 下 stderr 应为空，实际:\n%s", stderr.String())
			}
		})
	}
}

func TestRunOutputFile(t *testing.T) {
	dir := t.TempDir()
	aclPath := filepath.Join(dir, "rules.acl")
	if err := os.WriteFile(aclPath, []byte(validACL), 0o644); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "rules.nft")

	var stdout, stderr bytes.Buffer
	exit := run([]string{"compile", "-o", outPath, aclPath}, strings.NewReader(""), &stdout, &stderr)
	if exit != 0 {
		t.Fatalf("退出码 %d, stderr: %s", exit, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("-o 模式下 stdout 应为空，实际:\n%s", stdout.String())
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("读取输出文件失败: %v", err)
	}
	if !strings.Contains(string(data), "table inet efw {") {
		t.Fatalf("输出文件内容不符:\n%s", data)
	}
	if !strings.Contains(string(data), "# source: "+aclPath) {
		t.Fatalf("输出文件缺少来源标注:\n%s", data)
	}
}

// TestPriorityNormalization 验证 priority 关键字小写归一与整数放行。
func TestPriorityNormalization(t *testing.T) {
	cases := []struct {
		priority string
		want     string
	}{
		{"FILTER", "priority filter"},
		{"dstnat", "priority dstnat"},
		{"1000", "priority 1000"},
		{"-300", "priority -300"},
	}
	for _, tc := range cases {
		var stdout, stderr bytes.Buffer
		exit := run([]string{"compile", "--priority", tc.priority}, strings.NewReader(validACL), &stdout, &stderr)
		if exit != 0 {
			t.Fatalf("priority %q 应被接受，exit=%d stderr=%s", tc.priority, exit, stderr.String())
		}
		if !strings.Contains(stdout.String(), tc.want) {
			t.Fatalf("priority %q 产物缺少 %q:\n%s", tc.priority, tc.want, stdout.String())
		}
	}
}

func TestRunDeployFlags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exit := run([]string{"compile", "--table", "myt", "--chain", "myc", "--priority", "-10", "--log-prefix", "XX "},
		strings.NewReader("v6-bootstrap off\ndrop { 1.1.1.1 -> tcp *:80 log }\ndrop { * }\n"), &stdout, &stderr)
	if exit != 0 {
		t.Fatalf("退出码 %d, stderr: %s", exit, stderr.String())
	}
	out := stdout.String()
	for _, want := range []string{"table inet myt {", "chain myc {", "priority -10", `log prefix "XX " level info drop`} {
		if !strings.Contains(out, want) {
			t.Fatalf("产物缺少 %q:\n%s", want, out)
		}
	}
}

// TestRunFileFlag 覆盖 -f/--file 与 shebang 调用形态。
func TestRunFileFlag(t *testing.T) {
	dir := t.TempDir()
	aclPath := filepath.Join(dir, "rules.acl")
	// 首行 shebang 由解析器当注释忽略；-f 由 CLI 消费。
	content := "#!/usr/local/bin/efw -f\n\naccept{\n  1.1.1.0/24 -> 22\n}\n\ndrop { * }\n"
	if err := os.WriteFile(aclPath, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name       string
		args       []string
		wantExit   int
		wantStdout string
		wantStderr string
	}{
		{"根命令位置参数", []string{aclPath}, 0, "table inet efw {", ""},
		{"根命令位置参数加编译参数", []string{aclPath, "--table", "myt"}, 0, "table inet myt {", ""},
		{"根命令 -f", []string{"-f", aclPath}, 0, "table inet efw {", ""},
		{"根命令 -f 加编译参数", []string{"-f", aclPath, "--table", "myt"}, 0, "table inet myt {", ""},
		{"compile -f", []string{"compile", "-f", aclPath}, 0, "# source: " + aclPath, ""},
		{"-f 与位置参数冲突", []string{"-f", aclPath, "x.acl"}, 2, "", "E103"},
		{"-f 缺参数", []string{"-f"}, 2, "", "E103"},
		{"-f 文件不存在", []string{"-f", filepath.Join(dir, "nope.acl")}, 2, "", "E103"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			exit := run(tc.args, strings.NewReader(""), &stdout, &stderr)
			if exit != tc.wantExit {
				t.Fatalf("退出码不符: want %d, got %d\nstdout:\n%s\nstderr:\n%s",
					tc.wantExit, exit, stdout.String(), stderr.String())
			}
			if tc.wantStdout != "" && !strings.Contains(stdout.String(), tc.wantStdout) {
				t.Fatalf("stdout 缺少 %q\n实际:\n%s", tc.wantStdout, stdout.String())
			}
			if tc.wantStderr != "" && !strings.Contains(stderr.String(), tc.wantStderr) {
				t.Fatalf("stderr 缺少 %q\n实际:\n%s", tc.wantStderr, stderr.String())
			}
		})
	}
}
