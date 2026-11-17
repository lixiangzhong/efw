// Package nftexec 负责把 ruleset 交给系统 nft，并以原子批次替换 table。
package nftexec

import (
	"bytes"
	"os"
	"os/exec"
	"strings"

	"github.com/lixiangzhong/efw/internal/errs"
)

const (
	// nftBinary 是调用的 nft 命令。
	nftBinary = "nft"
	// nftPreferredInput 是 ruleset 传给 nft -f 的路径。nft 0.8 不接受 "-"（stdin），
	// 但接受 /dev/stdin；该路径不可用时回退临时文件。
	nftPreferredInput = "/dev/stdin"
)

// Error 是 apply 环境/执行失败（E104），文本已按统一格式渲染。
type Error struct{ line string }

func (e *Error) Error() string { return e.line }

func errorf(format string, args ...any) error {
	return &Error{errs.NewError("", 0, 0, errs.CategoryApply, errs.CodeApply, format, args...).Format()}
}

// Apply 校验后原子替换 table：
//   - 表存在：同一 nft 批次内 delete + create（失败时旧表保持不变）；
//   - 表不存在：直接 create。
//
// 校验必须针对最终批次（含 delete）：nft 0.8 的 `-c` 会按真实内核状态评估，
// 只校验不含 delete 的原始规则时，二次 apply 会报 "File exists"。
func Apply(ruleset []byte, table string) error {
	nft, err := exec.LookPath(nftBinary)
	if err != nil {
		return errorf("找不到 %s 命令（应用规则需要 nftables）", nftBinary)
	}
	exists, err := tableExists(nft, table)
	if err != nil {
		return err
	}

	batch := ruleset
	if exists {
		batch = append([]byte("delete table inet "+table+"\n"), ruleset...)
	}
	inputPath, cleanup, err := inputPath(batch, nftPreferredInput)
	if err != nil {
		return errorf("无法准备 nft 输入：%v", err)
	}
	defer cleanup()
	if out, checkErr := runNft(nft, []string{"-c", "-f", inputPath}, batch); checkErr != nil {
		return errorf("nft 校验失败：%s", nftOutput(out, checkErr))
	}
	if out, applyErr := runNft(nft, []string{"-f", inputPath}, batch); applyErr != nil {
		return errorf("nft 应用失败（旧表保持不变）：%s", nftOutput(out, applyErr))
	}
	return nil
}

// inputPath 返回把 ruleset 交给 nft -f 的路径。
// nft 0.8 不接受 "-"（stdin），但接受 /dev/stdin；preferred 不可用时退回 0600 临时文件。
func inputPath(ruleset []byte, preferred string) (string, func(), error) {
	if preferred != "" {
		if _, err := os.Stat(preferred); err == nil {
			return preferred, func() {}, nil
		}
	}
	file, err := os.CreateTemp("", "efw-*.nft")
	if err != nil {
		return "", nil, err
	}
	path := file.Name()
	if _, err := file.Write(ruleset); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", nil, err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return "", nil, err
	}
	return path, func() { _ = os.Remove(path) }, nil
}

// tableExists 通过 nft list tables 判断 table 是否已存在。
// 不依赖缺表错误文案：nft 0.8 是 "Table 'x' does not exist"，nft 1.x 是 "No such file or directory"。
func tableExists(nft, table string) (bool, error) {
	out, err := runNft(nft, []string{"list", "tables"}, nil)
	if err != nil {
		return false, errorf("探测 table inet %s 失败：%s", table, nftOutput(out, err))
	}
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "table" && fields[1] == "inet" && fields[2] == table {
			return true, nil
		}
	}
	return false, nil
}

func runNft(nft string, args []string, stdin []byte) (string, error) {
	cmd := exec.Command(nft, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// nftOutput 汇总 nft 的错误输出，并对权限问题给出提示。
func nftOutput(out string, err error) string {
	text := strings.TrimSpace(out)
	if text == "" {
		if err != nil {
			return err.Error()
		}
		return "未知错误"
	}
	if strings.Contains(text, "Operation not permitted") || strings.Contains(text, "cache initialization failed") {
		return text + "（需要 root 或 CAP_NET_ADMIN）"
	}
	return text
}
