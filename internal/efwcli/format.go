package efwcli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/lixiangzhong/efw/internal/format"
	"github.com/lixiangzhong/efw/internal/parser"
	"github.com/urfave/cli/v3"
)

// stdinSource 是 readSource 对标准输入的标记。
const stdinSource = "<stdin>"

// formatCommand 构建 format 子命令：只改缩进与 token 间距，不改语义。
func formatCommand(app App, stdin io.Reader, stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name:      "format",
		Usage:     "格式化 DSL 源文件（缩进与 token 间距，不改语义）",
		UsageText: app.Name + " format [--write|--check] [file]",
		ArgsUsage: "[file]",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "file", Aliases: []string{"f"}, Usage: "从文件读取 DSL（默认位置参数或 stdin）"},
			&cli.BoolFlag{Name: "write", Aliases: []string{"w"}, Usage: "原地写回（同目录临时文件 + rename，保留权限位）"},
			&cli.BoolFlag{Name: "check", Usage: "只检查是否已格式化，未格式化时退出码 1"},
		},
		OnUsageError: func(ctx context.Context, cmd *cli.Command, err error, isSubcommand bool) error {
			return usageErrorf("%v", err)
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return formatAction(app, cmd, stdin, stdout)
		},
	}
}

// formatAction 读取输入、校验可解析性后输出或回写格式化结果。
func formatAction(app App, cmd *cli.Command, stdin io.Reader, stdout io.Writer) error {
	write := cmd.Bool("write")
	check := cmd.Bool("check")
	if write && check {
		return usageErrorf("--write 与 --check 不能同时使用")
	}

	source, src, err := readSource(compileOptions{file: cmd.String("file")}, cmd.Args().Slice(), stdin)
	if err != nil {
		return err
	}
	// 只格式化可解析的文件：语法错误按编译错误输出，避免把坏文件"排整齐"。
	if _, parseErrs := parser.Parse(source, src); len(parseErrs) > 0 {
		return compileError(parseErrs)
	}

	formatted := format.Source(src)
	switch {
	case check:
		if bytes.Equal(formatted, src) {
			return nil
		}
		if source == stdinSource {
			return &commandError{code: 1, lines: []string{"<stdin>: 未格式化"}}
		}
		return &commandError{code: 1, lines: []string{
			fmt.Sprintf("%s: 未格式化（运行 %s format -w %s 修正）", source, app.Name, source),
		}}
	case write:
		if source == stdinSource {
			return usageErrorf("--write 需要文件路径（不支持 stdin）")
		}
		if bytes.Equal(formatted, src) {
			return nil
		}
		if err := writeFileAtomic(source, formatted); err != nil {
			return usageErrorf("无法写入文件：%v", err)
		}
		return nil
	default:
		if _, err := stdout.Write(formatted); err != nil {
			return usageErrorf("写入 stdout 失败：%v", err)
		}
		return nil
	}
}

// writeFileAtomic 用同目录临时文件 + rename 原子替换目标，保留原权限位。
// 目标是符号链接时写入链接指向的真实文件，链接本身保持不变。
func writeFileAtomic(path string, data []byte) error {
	target := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		target = resolved
	}
	info, err := os.Stat(target)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), "."+filepath.Base(target)+".efw-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// rename 成功后临时路径已不存在，Remove 为 no-op；失败路径负责清理。
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, info.Mode().Perm()); err != nil {
		return err
	}
	return os.Rename(tmpName, target)
}
