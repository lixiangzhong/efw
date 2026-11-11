package compiler_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lixiangzhong/efw/internal/compiler"
)

// goldenDir 是黄金文件目录（相对本包路径）。
const goldenDir = "../../testdata/golden"

func testOptions(source string) compiler.Options {
	return compiler.Options{
		Table:     "efw",
		Chain:     "input",
		Hook:      "input",
		Priority:  "filter",
		LogPrefix: "efw: ",
		Version:   compiler.Version,
		Source:    source,
	}
}

// TestGolden 逐字节比对 DSL 编译产物与冻结的期望输出，并验证确定性。
func TestGolden(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join(goldenDir, "*.acl"))
	if err != nil {
		t.Fatalf("glob 失败: %v", err)
	}
	if len(inputs) == 0 {
		t.Fatal("没有找到黄金用例")
	}

	for _, aclPath := range inputs {
		name := strings.TrimSuffix(filepath.Base(aclPath), ".acl")
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(aclPath)
			if err != nil {
				t.Fatalf("读取输入失败: %v", err)
			}
			want, err := os.ReadFile(strings.TrimSuffix(aclPath, ".acl") + ".nft")
			if err != nil {
				t.Fatalf("读取期望产物失败: %v", err)
			}

			opts := testOptions("testdata/golden/" + name + ".acl")
			got, _, err := compiler.Compile(src, opts)
			if err != nil {
				t.Fatalf("编译失败: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("产物与黄金文件不一致\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}

			again, _, err := compiler.Compile(src, opts)
			if err != nil {
				t.Fatalf("二次编译失败: %v", err)
			}
			if !bytes.Equal(got, again) {
				t.Fatal("同一输入两次编译结果不一致（产物不确定）")
			}
		})
	}
}
