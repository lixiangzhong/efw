package efwcli_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lixiangzhong/efw/internal/efwcli"
)

// runApplyCLI 执行一次 apply；Applier 用 mock（不碰内核），返回实际收到的 ruleset。
func runApplyCLI(t *testing.T, args []string, stdin string, applyErr error) (code int, stderrOut string, applied []byte) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	app := efwcli.App{
		Name: "efw", Usage: "test", Version: "test",
		Compiler: compileForTest,
		Applier: func(ruleset []byte, table string) error {
			applied = ruleset
			return applyErr
		},
	}
	code = efwcli.Run(app, args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stderr.String(), applied
}

// aclWithOutput 生成带 output 指令的合法 ACL。
func aclWithOutput(path string) string {
	return fmt.Sprintf("output %s\nv6-bootstrap off\naccept { 1.1.1.1 }\ndrop\n", path)
}

// TestApplyWritesOutput apply 成功后把同一份产物写到 output 路径（0644）。
func TestApplyWritesOutput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "efw.nft")
	code, errOut, applied := runApplyCLI(t, []string{"apply"}, aclWithOutput(path), nil)
	if code != 0 {
		t.Fatalf("期望 exit 0，实际 %d（stderr: %s）", code, errOut)
	}
	if errOut != "" {
		t.Fatalf("apply 成功时不应输出状态信息，实际 stderr: %s", errOut)
	}
	if len(applied) == 0 {
		t.Fatal("Applier 未收到 ruleset")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 output 文件失败: %v", err)
	}
	if !bytes.Equal(got, applied) {
		t.Fatalf("output 文件与应用的 ruleset 不一致")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Fatalf("期望权限 0644，实际 %o", perm)
	}
}

// TestApplyCreatesParentDirs output 的父级目录不存在时自动创建。
func TestApplyCreatesParentDirs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a", "b", "c", "efw.nft")
	code, errOut, _ := runApplyCLI(t, []string{"apply"}, aclWithOutput(path), nil)
	if code != 0 {
		t.Fatalf("期望 exit 0，实际 %d（stderr: %s）", code, errOut)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("output 文件未创建: %v", err)
	}
}

// TestApplyOutputNotWrittenOnApplyError 内核应用失败时不写文件。
func TestApplyOutputNotWrittenOnApplyError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "efw.nft")
	code, errOut, _ := runApplyCLI(t, []string{"apply"}, aclWithOutput(path), fmt.Errorf("mock apply failure"))
	if code != 2 || !strings.Contains(errOut, "mock apply failure") {
		t.Fatalf("期望 exit 2 与 apply 错误，实际 exit=%d stderr=%q", code, errOut)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("apply 失败时不应写 output 文件")
	}
}

// TestApplyOutputSymlinkRejected 目标是符号链接时拒绝写入，且不改动链接指向的文件。
func TestApplyOutputSymlinkRejected(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.nft")
	if err := os.WriteFile(target, []byte("untouched"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.nft")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	code, errOut, _ := runApplyCLI(t, []string{"apply"}, aclWithOutput(link), nil)
	if code != 2 {
		t.Fatalf("期望 exit 2，实际 %d", code)
	}
	if !strings.Contains(errOut, "符号链接") || !strings.Contains(errOut, "规则已生效") {
		t.Fatalf("stderr 应说明符号链接与规则已生效，实际: %s", errOut)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "untouched" {
		t.Fatalf("链接目标不应被改写，实际: %q err=%v", got, err)
	}
}

// TestApplyOutputUnwritable 父目录不可写时返回 E104 且说明规则已生效。
func TestApplyOutputUnwritable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root 会绕过目录权限，跳过")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	code, errOut, applied := runApplyCLI(t, []string{"apply"}, aclWithOutput(filepath.Join(locked, "efw.nft")), nil)
	if code != 2 {
		t.Fatalf("期望 exit 2，实际 %d（stderr: %s）", code, errOut)
	}
	if !strings.Contains(errOut, "E104") || !strings.Contains(errOut, "规则已生效") {
		t.Fatalf("stderr 应为 E104 且说明规则已生效，实际: %s", errOut)
	}
	if len(applied) == 0 {
		t.Fatal("规则应当已经应用成功")
	}
}

// TestOutputIgnoredByCompileAndCheck output 只在 apply 生效：compile 与 -c 都不写文件。
func TestOutputIgnoredByCompileAndCheck(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "efw.nft")
	src := aclWithOutput(path)

	var stdout, stderr bytes.Buffer
	if code := efwcli.Run(efwcli.App{Name: "efw", Version: "test", Compiler: compileForTest},
		[]string{"compile"}, strings.NewReader(src), &stdout, &stderr); code != 0 {
		t.Fatalf("compile 失败: %s", stderr.String())
	}
	if !strings.Contains(stdout.String(), "table inet efw {") {
		t.Fatalf("compile 应输出产物到 stdout")
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("compile 不应写 output 文件")
	}

	stdout.Reset()
	stderr.Reset()
	if code := efwcli.Run(efwcli.App{Name: "efw", Version: "test", Compiler: compileForTest},
		[]string{"-c"}, strings.NewReader(src), &stdout, &stderr); code != 0 {
		t.Fatalf("-c 失败: %s", stderr.String())
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("-c 不应写 output 文件")
	}
}

// TestOutputPathValidation 非法路径与重复指令在编译期报错。
func TestOutputPathValidation(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"相对路径", "output efw.nft\nv6-bootstrap off\naccept { 1.1.1.1 }\ndrop\n", "绝对路径"},
		{"后缀不是 .nft", "output /etc/efw.conf\nv6-bootstrap off\naccept { 1.1.1.1 }\ndrop\n", ".nft"},
		{"重复", "output /a.nft\noutput /b.nft\nv6-bootstrap off\naccept { 1.1.1.1 }\ndrop\n", "output 指令重复"},
		{"块内出现", "v6-bootstrap off\naccept {\noutput /a.nft\n}\ndrop\n", "指令不能出现在块内"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := efwcli.Run(efwcli.App{Name: "efw", Version: "test", Compiler: compileForTest},
				[]string{"compile"}, strings.NewReader(tc.src), &stdout, &stderr)
			if code != 1 || !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("期望 exit 1 且包含 %q，实际 exit=%d stderr=%s", tc.want, code, stderr.String())
			}
		})
	}
}
