package compiler_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// readmeGoldenCases 是 README 里与 golden 用例绑定的示例（标记名 = 用例名）。
var readmeGoldenCases = []string{"37_readme_quickstart", "38_readme_shebang"}

// TestReadmeGoldenInputs 校验 README 标记的示例代码块与 golden 输入逐字节一致，
// 防止文档改动后示例与测试悄悄脱节。
func TestReadmeGoldenInputs(t *testing.T) {
	readme, err := os.ReadFile(filepath.Join("..", "..", "README.md"))
	if err != nil {
		t.Fatalf("读取 README 失败: %v", err)
	}
	blocks := readmeGoldenBlocks(t, string(readme))

	for _, name := range readmeGoldenCases {
		want, ok := blocks[name]
		if !ok {
			t.Fatalf("README 缺少 <!-- golden: %s --> 标记的代码块", name)
		}
		path := filepath.Join(goldenDir, name+".acl")
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", path, err)
		}
		if string(got) != want {
			t.Fatalf("%s: README 示例与 %s 不一致（改示例后需同步用例并重生成黄金产物）\n--- README ---\n%s\n--- golden ---\n%s",
				name, path, want, got)
		}
	}
}

// readmeGoldenBlocks 从 README 提取 <!-- golden: NAME（说明） --> 标记后紧跟的代码块。
func readmeGoldenBlocks(t *testing.T, readme string) map[string]string {
	t.Helper()
	const (
		marker   = "<!-- golden: "
		fence    = "```"
		nameStop = " \t（(）)"
	)
	lines := strings.Split(readme, "\n")
	blocks := make(map[string]string, len(readmeGoldenCases))
	for i := 0; i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(trimmed, marker) {
			continue
		}
		rest := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, marker), "-->"))
		name := rest
		if idx := strings.IndexAny(name, nameStop); idx >= 0 {
			name = name[:idx]
		}
		if name == "" {
			t.Fatalf("README 第 %d 行的 golden 标记缺少用例名", i+1)
		}

		start := i + 1
		for start < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[start]), fence) {
			start++
		}
		if start >= len(lines) {
			t.Fatalf("%s: 标记后缺少代码块", name)
		}
		var body []string
		end := start + 1
		for ; end < len(lines); end++ {
			if strings.HasPrefix(strings.TrimSpace(lines[end]), fence) {
				break
			}
			body = append(body, lines[end])
		}
		if end >= len(lines) {
			t.Fatalf("%s: 代码块未闭合", name)
		}
		blocks[name] = strings.Join(body, "\n") + "\n"
		i = end
	}
	return blocks
}
