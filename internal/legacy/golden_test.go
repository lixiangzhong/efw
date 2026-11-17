package legacy_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lixiangzhong/efw/internal/compiler"
	"github.com/lixiangzhong/efw/internal/legacy"
)

const (
	goldenDir       = "../../testdata/golden"
	legacyGoldenDir = "../../testdata/golden-nft08"
)

func testOptions(source string) legacy.Options {
	return legacy.Options{
		Table:     "efw",
		Chain:     "input",
		Hook:      "input",
		Priority:  "filter",
		LogPrefix: "efw: ",
		Version:   compiler.Version,
		Source:    source,
	}
}

// TestGoldenNft08 逐字节比对 nft 0.8 产物，并验证确定性；REGEN_GOLDEN=1 时重写期望文件。
func TestGoldenNft08(t *testing.T) {
	inputs, err := filepath.Glob(filepath.Join(goldenDir, "*.acl"))
	if err != nil {
		t.Fatalf("glob 失败: %v", err)
	}
	if len(inputs) == 0 {
		t.Fatal("没有找到黄金用例")
	}

	for _, aclPath := range inputs {
		name := strings.TrimSuffix(filepath.Base(aclPath), ".acl")
		if name == "35_masquerade" {
			continue // nft 0.8 不支持 masquerade，由 TestMasqueradeRejected 覆盖
		}
		t.Run(name, func(t *testing.T) {
			src, err := os.ReadFile(aclPath)
			if err != nil {
				t.Fatalf("读取输入失败: %v", err)
			}
			wantPath := filepath.Join(legacyGoldenDir, name+".nft")
			got, _, err := legacy.Compile(src, testOptions("testdata/golden/"+name+".acl"))
			if err != nil {
				t.Fatalf("编译失败: %v", err)
			}

			if os.Getenv("REGEN_GOLDEN") != "" {
				if err := os.MkdirAll(legacyGoldenDir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(wantPath, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}

			want, err := os.ReadFile(wantPath)
			if err != nil {
				t.Fatalf("读取期望产物失败: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("产物与 nft08 黄金文件不一致\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}

			again, _, err := legacy.Compile(src, testOptions("testdata/golden/"+name+".acl"))
			if err != nil {
				t.Fatalf("二次编译失败: %v", err)
			}
			if !bytes.Equal(got, again) {
				t.Fatal("同一输入两次编译结果不一致（产物不确定）")
			}
		})
	}
}
