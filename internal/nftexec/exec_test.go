package nftexec

import (
	"os"
	"path/filepath"
	"testing"
)

// TestInputPath 验证 /dev/stdin 优先与临时文件回退。
func TestInputPath(t *testing.T) {
	ruleset := []byte("table inet x {\n}\n")

	preferred := filepath.Join(t.TempDir(), "stdin")
	if err := os.WriteFile(preferred, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path, cleanup, err := inputPath(ruleset, preferred)
	if err != nil {
		t.Fatalf("优先路径失败: %v", err)
	}
	defer cleanup()
	if path != preferred {
		t.Fatalf("应优先使用 %s，得到 %s", preferred, path)
	}

	missing := filepath.Join(t.TempDir(), "missing")
	path, cleanup, err = inputPath(ruleset, missing)
	if err != nil {
		t.Fatalf("回退临时文件失败: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取临时文件失败: %v", err)
	}
	if string(data) != string(ruleset) {
		t.Fatalf("临时文件内容不符: %q", data)
	}
	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("cleanup 应删除临时文件 %s", path)
	}
}
