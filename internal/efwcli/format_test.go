package efwcli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lixiangzhong/efw/internal/efwcli"
)

// runCLI 以测试输入执行一次 CLI，返回退出码与 stdout/stderr。
func runCLI(t *testing.T, args []string, stdin string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	app := efwcli.App{Name: "efw", Usage: "test", Version: "test"}
	code := efwcli.Run(app, args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// writeACL 在临时目录写入文件并固定权限位（绕开 umask）。
func writeACL(t *testing.T, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("写入 %s 失败: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s 失败: %v", path, err)
	}
	return path
}

func readACL(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 %s 失败: %v", path, err)
	}
	return string(data)
}

// TestFormatStdin 无文件参数时从 stdin 读取，格式化结果写 stdout。
func TestFormatStdin(t *testing.T) {
	code, out, errOut := runCLI(t, []string{"format"}, "accept{1.1.1.1->80}\ndrop\n")
	if code != 0 {
		t.Fatalf("退出码 = %d，期望 0（stderr: %s）", code, errOut)
	}
	if want := "accept { 1.1.1.1 -> 80 }\ndrop\n"; out != want {
		t.Fatalf("stdout = %q，期望 %q", out, want)
	}
	if errOut != "" {
		t.Fatalf("stderr 应为空，实际 %q", errOut)
	}
}

// TestFormatFileToStdout 位置参数指定文件时只输出，不修改原文件。
func TestFormatFileToStdout(t *testing.T) {
	path := writeACL(t, "rules.acl", "accept{1.1.1.1}\ndrop\n", 0o644)
	code, out, errOut := runCLI(t, []string{"format", path}, "")
	if code != 0 {
		t.Fatalf("退出码 = %d，期望 0（stderr: %s）", code, errOut)
	}
	if want := "accept { 1.1.1.1 }\ndrop\n"; out != want {
		t.Fatalf("stdout = %q，期望 %q", out, want)
	}
	if got := readACL(t, path); got != "accept{1.1.1.1}\ndrop\n" {
		t.Fatalf("默认模式不应修改文件，实际 %q", got)
	}
}

// TestFormatFileFlag -f 与位置参数等价。
func TestFormatFileFlag(t *testing.T) {
	path := writeACL(t, "rules.acl", "accept{1.1.1.1}\ndrop\n", 0o644)
	code, out, errOut := runCLI(t, []string{"format", "-f", path}, "")
	if code != 0 {
		t.Fatalf("退出码 = %d，期望 0（stderr: %s）", code, errOut)
	}
	if want := "accept { 1.1.1.1 }\ndrop\n"; out != want {
		t.Fatalf("stdout = %q，期望 %q", out, want)
	}
}

// TestFormatWriteInPlace -w 原地写回，保留权限位，stdout 保持为空。
func TestFormatWriteInPlace(t *testing.T) {
	path := writeACL(t, "fw.sh", "accept{1.1.1.1->80}\ndrop\n", 0o750)
	code, out, errOut := runCLI(t, []string{"format", "-w", path}, "")
	if code != 0 {
		t.Fatalf("退出码 = %d，期望 0（stderr: %s）", code, errOut)
	}
	if out != "" {
		t.Fatalf("-w 不应写 stdout，实际 %q", out)
	}
	if errOut != "" {
		t.Fatalf("stderr 应为空，实际 %q", errOut)
	}
	if want := "accept { 1.1.1.1 -> 80 }\ndrop\n"; readACL(t, path) != want {
		t.Fatalf("文件内容未格式化: %q", readACL(t, path))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat 失败: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o750 {
		t.Fatalf("权限位 = %o，期望 750", got)
	}
}

// TestFormatWriteIdempotent 已格式化的文件再 -w 不产生内容变化。
func TestFormatWriteIdempotent(t *testing.T) {
	formatted := "accept {\n    1.1.1.1 -> 80\n}\ndrop\n"
	path := writeACL(t, "rules.acl", formatted, 0o644)
	code, _, errOut := runCLI(t, []string{"format", "-w", path}, "")
	if code != 0 {
		t.Fatalf("退出码 = %d，期望 0（stderr: %s）", code, errOut)
	}
	if got := readACL(t, path); got != formatted {
		t.Fatalf("内容被改动: %q", got)
	}
}

// TestFormatCheckDirty --check 发现未格式化：退出码 1，文件不变。
func TestFormatCheckDirty(t *testing.T) {
	const raw = "accept{1.1.1.1}\ndrop\n"
	path := writeACL(t, "rules.acl", raw, 0o644)
	code, out, errOut := runCLI(t, []string{"format", "--check", path}, "")
	if code != 1 {
		t.Fatalf("退出码 = %d，期望 1（stderr: %s）", code, errOut)
	}
	if out != "" {
		t.Fatalf("--check 不应写 stdout，实际 %q", out)
	}
	if !strings.Contains(errOut, "未格式化") {
		t.Fatalf("stderr = %q，期望包含「未格式化」", errOut)
	}
	if got := readACL(t, path); got != raw {
		t.Fatalf("--check 不应修改文件，实际 %q", got)
	}
}

// TestFormatCheckClean --check 通过：退出码 0 且无输出。
func TestFormatCheckClean(t *testing.T) {
	path := writeACL(t, "rules.acl", "accept { 1.1.1.1 }\ndrop\n", 0o644)
	code, out, errOut := runCLI(t, []string{"format", "--check", path}, "")
	if code != 0 || out != "" || errOut != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q，期望 0 且无输出", code, out, errOut)
	}
}

// TestFormatCheckStdinDirty stdin 也能做 --check；提示不引导写回 stdin。
func TestFormatCheckStdinDirty(t *testing.T) {
	code, out, errOut := runCLI(t, []string{"format", "--check"}, "accept{1.1.1.1}\ndrop\n")
	if code != 1 || out != "" {
		t.Fatalf("code=%d stdout=%q，期望退出码 1 且无 stdout", code, out)
	}
	if !strings.Contains(errOut, "未格式化") || strings.Contains(errOut, "format -w") {
		t.Fatalf("stderr = %q，期望提示未格式化且不引导 -w stdin", errOut)
	}
}

// TestFormatParseError 语法错误按编译错误输出（退出码 1），-w 不落盘。
func TestFormatParseError(t *testing.T) {
	const broken = "1.1.1.1 -> 80\n"
	path := writeACL(t, "broken.acl", broken, 0o644)
	code, out, errOut := runCLI(t, []string{"format", "-w", path}, "")
	if code != 1 {
		t.Fatalf("退出码 = %d，期望 1（stderr: %s）", code, errOut)
	}
	if !strings.Contains(errOut, "E101") {
		t.Fatalf("stderr = %q，期望包含 E101", errOut)
	}
	if out != "" {
		t.Fatalf("解析失败不应写 stdout，实际 %q", out)
	}
	if got := readACL(t, path); got != broken {
		t.Fatalf("解析失败不应修改文件，实际 %q", got)
	}
}

// TestFormatWriteRequiresFile -w 不能用于 stdin。
func TestFormatWriteRequiresFile(t *testing.T) {
	code, out, errOut := runCLI(t, []string{"format", "-w"}, "accept{1.1.1.1}\ndrop\n")
	if code != 2 {
		t.Fatalf("退出码 = %d，期望 2（stderr: %s）", code, errOut)
	}
	if out != "" || !strings.Contains(errOut, "E103") || !strings.Contains(errOut, "--write") {
		t.Fatalf("stdout=%q stderr=%q，期望 E103 且说明 --write 需要文件", out, errOut)
	}
}

// TestFormatWriteCheckConflict -w 与 --check 互斥。
func TestFormatWriteCheckConflict(t *testing.T) {
	code, _, errOut := runCLI(t, []string{"format", "-w", "--check"}, "accept{1.1.1.1}\ndrop\n")
	if code != 2 || !strings.Contains(errOut, "E103") {
		t.Fatalf("code=%d stderr=%q，期望退出码 2 与 E103", code, errOut)
	}
}

// TestFormatFileFlagConflict -f 与位置参数只能二选一。
func TestFormatFileFlagConflict(t *testing.T) {
	path := writeACL(t, "rules.acl", "accept{1.1.1.1}\ndrop\n", 0o644)
	code, _, errOut := runCLI(t, []string{"format", "-f", path, path}, "")
	if code != 2 || !strings.Contains(errOut, "E103") {
		t.Fatalf("code=%d stderr=%q，期望退出码 2 与 E103", code, errOut)
	}
}

// TestFormatWeirdFile 端到端：制表符、CRLF、注释与单行块混合的 fw.sh 原地格式化，
// shebang 与 0755 权限位保持不变。
func TestFormatWeirdFile(t *testing.T) {
	raw := "#!/usr/local/bin/efw apply\r\naccept{\r\n\tiface\teth0\tlog\r\n\t1.1.1.1\t->\t{80,443}\r\n}\r\ndrop{*}\r\n"
	path := writeACL(t, "fw.sh", raw, 0o755)
	code, out, errOut := runCLI(t, []string{"format", "-w", path}, "")
	if code != 0 || out != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q，期望 0 且无 stdout", code, out, errOut)
	}
	want := "#!/usr/local/bin/efw apply\naccept {\n    iface eth0 log\n    1.1.1.1 -> {80, 443}\n}\ndrop { * }\n"
	if got := readACL(t, path); got != want {
		t.Fatalf("内容不符\n--- got ---\n%q\n--- want ---\n%q", got, want)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("权限位未保留: %v %v", info, err)
	}
	if code, out, errOut := runCLI(t, []string{"format", "--check", path}, ""); code != 0 || out != "" || errOut != "" {
		t.Fatalf("格式化后 --check 应为 0: code=%d stdout=%q stderr=%q", code, out, errOut)
	}
}

// TestFormatWriteSymlink 目标是符号链接时写真实文件，链接本身保留。
func TestFormatWriteSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "fw.sh")
	if err := os.WriteFile(target, []byte("accept{1.1.1.1}\ndrop\n"), 0o640); err != nil {
		t.Fatalf("写入目标失败: %v", err)
	}
	if err := os.Chmod(target, 0o640); err != nil {
		t.Fatalf("chmod 失败: %v", err)
	}
	link := filepath.Join(dir, "link.acl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("创建符号链接失败: %v", err)
	}

	code, _, errOut := runCLI(t, []string{"format", "-w", link}, "")
	if code != 0 {
		t.Fatalf("退出码 = %d，期望 0（stderr: %s）", code, errOut)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("lstat 失败: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("符号链接被替换成了普通文件")
	}
	if want := "accept { 1.1.1.1 }\ndrop\n"; readACL(t, target) != want {
		t.Fatalf("目标文件未格式化: %q", readACL(t, target))
	}
	if info, err := os.Stat(target); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("目标文件权限位未保留: %v %v", info, err)
	}
}
