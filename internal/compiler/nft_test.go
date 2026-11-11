package compiler_test

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestGoldenNftCheck 用真实 nft 校验黄金产物语法。
// 本机没有 nft 或没有 NET_ADMIN 权限时跳过（集成环境见 SPEC §7.2）。
func TestGoldenNftCheck(t *testing.T) {
	nftPath, err := exec.LookPath("nft")
	if err != nil {
		t.Skip("未找到 nft 命令，跳过集成校验")
	}
	files, err := filepath.Glob(filepath.Join(goldenDir, "*.nft"))
	if err != nil {
		t.Fatalf("glob 失败: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("没有找到黄金产物")
	}

	for _, file := range files {
		out, err := exec.Command(nftPath, "-c", "-f", file).CombinedOutput()
		if err == nil {
			continue
		}
		msg := string(out)
		if strings.Contains(msg, "Operation not permitted") || strings.Contains(msg, "Permission denied") {
			t.Skipf("nft 校验需要 NET_ADMIN 权限，跳过: %s", msg)
		}
		t.Fatalf("%s 未通过 nft -c: %v\n%s", file, err, msg)
	}
}
