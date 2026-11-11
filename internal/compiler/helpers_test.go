package compiler_test

import (
	"strings"
	"testing"

	"github.com/lixiangzhong/efw/internal/compiler"
)

// compileOK 编译要求成功；若仅缺少兜底规则，自动补一行 drop 后重试（测试便利）。
func compileOK(t *testing.T, src string) []byte {
	t.Helper()
	out, _, err := compiler.Compile([]byte(src), testOptions("<test>"))
	if err == nil {
		return out
	}
	if strings.Contains(err.Error(), "缺少兜底规则") {
		out, _, err = compiler.Compile([]byte(src+"\ndrop\n"), testOptions("<test>"))
		if err == nil {
			return out
		}
	}
	t.Fatalf("编译失败: %v", err)
	return nil
}

// warningCodes 编译成功并返回告警码集合（缺兜底时自动补 drop）。
func warningCodes(t *testing.T, src string) map[string]bool {
	t.Helper()
	_, warns, err := compiler.Compile([]byte(src), testOptions("<test>"))
	if err != nil && strings.Contains(err.Error(), "缺少兜底规则") {
		_, warns, err = compiler.Compile([]byte(src+"\ndrop\n"), testOptions("<test>"))
	}
	if err != nil {
		t.Fatalf("期望编译成功，实际失败: %v", err)
	}
	codes := make(map[string]bool, len(warns))
	for _, w := range warns {
		codes[w.Code] = true
	}
	return codes
}

// compileRaw 不做任何补全，用于测试兜底/语法相关错误。
func compileRaw(src string) ([]byte, error) {
	out, _, err := compiler.Compile([]byte(src), testOptions("<test>"))
	return out, err
}

// stripComments 去掉注释行与空行，便于比较两种语法糖的产物语义。
func stripComments(out []byte) string {
	var lines []string
	for _, line := range strings.Split(string(out), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		lines = append(lines, trimmed)
	}
	return strings.Join(lines, "\n")
}
