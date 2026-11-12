package compiler_test

import (
	"strings"
	"testing"

	"github.com/lixiangzhong/efw/internal/compiler"
)

// compileOK 编译要求成功；若仅缺少兜底规则，自动补一行 drop 后重试（测试便利）。
func compileOK(t *testing.T, src string) []byte {
	t.Helper()
	src = blockifyLegacy(src)
	out, _, err := compiler.Compile([]byte(src), testOptions("<test>"))
	if err == nil {
		return out
	}
	if strings.Contains(err.Error(), "缺少兜底规则") {
		out, _, err = compiler.Compile([]byte(src+"\ndrop { * }\n"), testOptions("<test>"))
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
	src = blockifyLegacy(src)
	_, warns, err := compiler.Compile([]byte(src), testOptions("<test>"))
	if err != nil && strings.Contains(err.Error(), "缺少兜底规则") {
		_, warns, err = compiler.Compile([]byte(src+"\ndrop { * }\n"), testOptions("<test>"))
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

// blockifyLegacy 把块外规则的测试样例转换为块内语法（迁移期辅助）。
// 新用例应直接书写块内语法；该函数只用于复用历史用例，避免一次性重写数百条断言。
func blockifyLegacy(src string) string {
	depth := 0
	lines := strings.Split(src, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		code, comment := splitLineComment(line)
		trimmed := strings.TrimSpace(code)
		if depth == 0 && trimmed != "" && !strings.HasPrefix(trimmed, "}") {
			if converted, ok := blockifyTopLine(trimmed); ok {
				if comment != "" {
					converted += " " + comment
				}
				out = append(out, converted)
				continue
			}
		}
		out = append(out, line)
		depth += braceDelta(code)
		if depth < 0 {
			depth = 0
		}
	}
	return strings.Join(out, "\n")
}

// blockifyTopLine 把一条块外规则/动作行转换成单行块；无法安全转换时返回 false。
func blockifyTopLine(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", false
	}
	first := strings.ToLower(fields[0])
	if first == "default" || first == "established" || first == "v6-bootstrap" || first == "forward" {
		return "", false
	}
	// 单独动作行：drop / log drop / accept ...
	n := 0
	logOnlyAction := false
	if first == "log" {
		logOnlyAction = true
		n = 1
	}
	if n < len(fields) && len(fields) == n+1 && isActionWord(fields[n]) {
		action := strings.ToLower(fields[n])
		suffix := ""
		if logOnlyAction {
			suffix = " log"
		}
		return action + " { *" + suffix + " }", true
	}
	// 规则行尾部动作：<match> [log] accept|drop|reject
	last := strings.ToLower(fields[len(fields)-1])
	if !isActionWord(last) {
		return "", false
	}
	rest := fields[:len(fields)-1]
	log := false
	if len(rest) > 0 && strings.EqualFold(rest[len(rest)-1], "log") {
		log = true
		rest = rest[:len(rest)-1]
	}
	if len(rest) == 0 {
		return "", false
	}
	suffix := ""
	if log {
		suffix = " log"
	}
	return last + " { " + strings.Join(rest, " ") + suffix + " }", true
}

func isActionWord(s string) bool {
	switch strings.ToLower(s) {
	case "accept", "drop", "reject":
		return true
	}
	return false
}

func splitLineComment(line string) (code, comment string) {
	if idx := strings.IndexByte(line, '#'); idx >= 0 {
		return line[:idx], line[idx:]
	}
	return line, ""
}

func braceDelta(line string) int {
	return strings.Count(line, "{") - strings.Count(line, "}")
}
