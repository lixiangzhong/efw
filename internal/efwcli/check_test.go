package efwcli_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/lixiangzhong/efw/internal/compiler"
	"github.com/lixiangzhong/efw/internal/efwcli"
	"github.com/lixiangzhong/efw/internal/errs"
)

// runCheckCLI 执行一次带真实编译器的 CLI（-c 需要 Compiler；format 用例不需要）。
func runCheckCLI(t *testing.T, args []string, stdin string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	app := efwcli.App{Name: "efw", Usage: "test", Version: "test", Compiler: compileForTest}
	code := efwcli.Run(app, args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func compileForTest(src []byte, opts efwcli.Options) ([]byte, []errs.Warning, error) {
	return compiler.Compile(src, compiler.Options{
		Table:     opts.Table,
		Chain:     opts.Chain,
		Hook:      opts.Hook,
		Priority:  opts.Priority,
		LogPrefix: opts.LogPrefix,
		Version:   opts.Version,
		Source:    opts.Source,
		Stamp:     opts.Stamp,
		Now:       opts.Now,
	})
}

// TestCheckValidFile -c 校验合法文件：成功静默（stdout/stderr 都为空），exit 0。
func TestCheckValidFile(t *testing.T) {
	path := writeACL(t, "rules.acl", "v6-bootstrap off\nallow { 1.1.1.1 -> 80 }\ndrop\n", 0o644)
	for _, args := range [][]string{
		{"-c", path},
		{"--check", path},
		{"-c", "-f", path},
	} {
		code, out, errOut := runCheckCLI(t, args, "")
		if code != 0 {
			t.Fatalf("%v: 期望 exit 0，实际 %d（stderr: %s）", args, code, errOut)
		}
		if out != "" || errOut != "" {
			t.Fatalf("%v: 成功时应静默，实际 stdout=%q stderr=%q", args, out, errOut)
		}
	}
}

// TestCheckStdin 无文件参数时从 stdin 读取。
func TestCheckStdin(t *testing.T) {
	code, out, errOut := runCheckCLI(t, []string{"-c"}, "v6-bootstrap off\naccept { 1.1.1.1 }\ndrop\n")
	if code != 0 || out != "" || errOut != "" {
		t.Fatalf("期望静默成功，实际 exit=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

// TestCheckSyntaxError 语法错误：exit 1，错误写 stderr，无产物。
func TestCheckSyntaxError(t *testing.T) {
	path := writeACL(t, "bad.acl", "accept {\n1.1.1.1 -> 80\n", 0o644)
	code, out, errOut := runCheckCLI(t, []string{"-c", path}, "")
	if code != 1 {
		t.Fatalf("期望 exit 1，实际 %d（stderr: %s）", code, errOut)
	}
	if out != "" {
		t.Fatalf("检查不应输出产物，实际 stdout=%q", out)
	}
	if !strings.Contains(errOut, "未闭合") && !strings.Contains(errOut, "E101") {
		t.Fatalf("stderr 应包含语法错误，实际: %s", errOut)
	}
}

// TestCheckSemanticError -c 是完整编译校验，缺兜底这类语义错误同样报错（不是只查语法）。
func TestCheckSemanticError(t *testing.T) {
	path := writeACL(t, "nofallback.acl", "v6-bootstrap off\naccept { 1.1.1.1 -> 80 }\n", 0o644)
	code, _, errOut := runCheckCLI(t, []string{"-c", path}, "")
	if code != 1 {
		t.Fatalf("期望 exit 1，实际 %d", code)
	}
	if !strings.Contains(errOut, "缺少兜底规则") {
		t.Fatalf("stderr 应包含缺兜底错误，实际: %s", errOut)
	}
}

// TestCheckWarnings 告警不算失败：exit 0，告警照常写 stderr；--quiet 可抑制。
func TestCheckWarnings(t *testing.T) {
	path := writeACL(t, "fallback-accept.acl", "v6-bootstrap off\naccept { 1.1.1.1 -> 80 }\naccept\n", 0o644)
	code, out, errOut := runCheckCLI(t, []string{"-c", path}, "")
	if code != 0 || out != "" {
		t.Fatalf("告警不应导致失败，实际 exit=%d stdout=%q", code, out)
	}
	if !strings.Contains(errOut, "W3") {
		t.Fatalf("stderr 应包含 W3 告警，实际: %s", errOut)
	}
	if _, _, quietErr := runCheckCLI(t, []string{"-c", "--quiet", path}, ""); quietErr != "" {
		t.Fatalf("--quiet 应抑制告警，实际 stderr=%q", quietErr)
	}
}

// TestCheckRejectsOutput -c 不产出产物，与 -o 互斥（用法错误 exit 2）。
func TestCheckRejectsOutput(t *testing.T) {
	path := writeACL(t, "rules.acl", "v6-bootstrap off\naccept { 1.1.1.1 }\ndrop\n", 0o644)
	code, _, errOut := runCheckCLI(t, []string{"-c", "-o", "out.nft", path}, "")
	if code != 2 {
		t.Fatalf("期望 exit 2，实际 %d（stderr: %s）", code, errOut)
	}
	if !strings.Contains(errOut, "不能与 -o") {
		t.Fatalf("stderr 应说明 -o 冲突，实际: %s", errOut)
	}
}

// TestCheckTooManyFiles -c 与 compile 一致：最多一个输入文件（用法错误 exit 2）。
func TestCheckTooManyFiles(t *testing.T) {
	a := writeACL(t, "a.acl", "drop\n", 0o644)
	b := writeACL(t, "b.acl", "drop\n", 0o644)
	code, _, errOut := runCheckCLI(t, []string{"-c", a, b}, "")
	if code != 2 || !strings.Contains(errOut, "最多接受一个输入文件") {
		t.Fatalf("期望 exit 2 与文件数错误，实际 exit=%d stderr=%q", code, errOut)
	}
}

// TestCheckInvalidDeployOptions -c 沿用 compile 的部署参数校验（E103，exit 2）。
func TestCheckInvalidDeployOptions(t *testing.T) {
	path := writeACL(t, "rules.acl", "drop\n", 0o644)
	code, _, errOut := runCheckCLI(t, []string{"-c", "--table", "table", path}, "")
	if code != 2 || !strings.Contains(errOut, "nft 关键字") {
		t.Fatalf("期望 exit 2 与 table 名错误，实际 exit=%d stderr=%q", code, errOut)
	}
}
