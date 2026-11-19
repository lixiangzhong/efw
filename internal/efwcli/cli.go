// Package efwcli 提供 efw / efw-nft08 共用的命令行层：参数、输入输出与退出码。
// 方言差异只体现在注入的 Compiler；apply 传输层由 Applier 注入。
package efwcli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lixiangzhong/efw/internal/errs"
	"github.com/urfave/cli/v3"
)

var (
	// identifierRe 校验 table/chain 名：nft 标识符规则。
	identifierRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

	// priorityKeywords 是可用的 nft priority 关键字（产物中统一小写输出）。
	priorityKeywords = map[string]struct{}{
		"raw":      {},
		"mangle":   {},
		"filter":   {},
		"security": {},
		"dstnat":   {},
		"srcnat":   {},
	}

	// reservedNftWords 是 nft 语法关键字，不能用作 table/chain 名。
	reservedNftWords = map[string]struct{}{
		"table": {}, "chain": {}, "set": {}, "map": {}, "flowtable": {},
		"element": {}, "elements": {}, "type": {}, "hook": {}, "priority": {},
		"policy": {}, "flags": {}, "rule": {}, "rules": {},
	}
)

// Options 是一次编译所需的参数。
type Options struct {
	Table     string
	Chain     string
	Hook      string
	Priority  string
	LogPrefix string
	Version   string
	Source    string
	Stamp     bool
	Now       time.Time
}

// Compiler 把 DSL 源码编译为 ruleset。
type Compiler func(src []byte, opts Options) ([]byte, []errs.Warning, error)

// Applier 把 ruleset 原子应用到内核。
type Applier func(ruleset []byte, table string) error

// App 描述一个 CLI 实例；Name/Usage 用于帮助文本，Compiler/Applier 决定方言与落地方式。
type App struct {
	Name     string
	Usage    string
	Version  string
	Compiler Compiler
	Applier  Applier
}

// commandError 是带退出码的命令错误，由 Run 统一打印后返回退出码。
type commandError struct {
	code  int
	lines []string
}

func (e *commandError) Error() string { return strings.Join(e.lines, "\n") }

// usageErrorf 构造用法错误（退出码 2，E103）。
func usageErrorf(format string, args ...any) error {
	return &commandError{
		code:  2,
		lines: []string{errs.NewError("", 0, 0, errs.CategoryUsage, errs.CodeUsage, format, args...).Format()},
	}
}

// Run 是 CLI 入口，返回进程退出码：0 成功 / 1 编译错误 / 2 用法错误或 apply 失败。
func Run(app App, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cmd := newCommand(app, stdin, stdout, stderr)
	err := cmd.Run(context.Background(), append([]string{app.Name}, args...))
	if err == nil {
		return 0
	}

	var cmdErr *commandError
	if errors.As(err, &cmdErr) {
		for _, line := range cmdErr.lines {
			fmt.Fprintln(stderr, line)
		}
		return cmdErr.code
	}
	var exitErr cli.ExitCoder
	if errors.As(err, &exitErr) {
		if msg := exitErr.Error(); msg != "" {
			fmt.Fprintln(stderr, msg)
		}
		return exitErr.ExitCode()
	}
	fmt.Fprintln(stderr, err)
	return 1
}

func newCommand(app App, stdin io.Reader, stdout, stderr io.Writer) *cli.Command {
	return &cli.Command{
		Name:        app.Name,
		Usage:       app.Usage,
		UsageText:   fmt.Sprintf("%s <file> [flags]\n   %s compile [flags] [file]\n   %s apply [flags] [file]\n   %s format [--write|--check] [file]", app.Name, app.Name, app.Name, app.Name),
		Description: "DSL → nftables ruleset 文本（compile）、编译后原子应用到内核（apply，需 root/CAP_NET_ADMIN），或格式化源文件（format）。不给文件时从 stdin 读取。",
		Version:     app.Version,
		Reader:      stdin,
		Writer:      stdout,
		ErrWriter:   stderr,
		// 退出码与错误输出由 Run 统一处理，禁止 cli 自行 os.Exit。
		ExitErrHandler: func(context.Context, *cli.Command, error) {},
		OnUsageError: func(ctx context.Context, cmd *cli.Command, err error, isSubcommand bool) error {
			return usageErrorf("%v", err)
		},
		// 根命令直接接受编译参数，用于 shebang：#!/usr/local/bin/efw -f
		Flags: compileFlags(),
		Commands: []*cli.Command{
			compileCommand(app, stdin, stdout, stderr),
			applyCommand(app, stdin, stderr),
			formatCommand(app, stdin, stdout),
			versionCommand(app, stdout),
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return rootAction(app, cmd, stdin, stdout, stderr)
		},
	}
}

func rootAction(app App, cmd *cli.Command, stdin io.Reader, stdout, stderr io.Writer) error {
	// 两种文件形态：
	//   efw <file> [flags]        —— 根命令位置参数；也是无 -f shebang 的调用形态
	//   efw -f <file> [flags]     —— 显式 -f（等价，兼容旧写法）
	if cmd.IsSet("file") || cmd.Args().Len() > 0 {
		return compileAction(app, cmd, cmd.Args().Slice(), stdin, stdout, stderr)
	}
	// 无参数：帮助打印到 stderr（与旧行为一致），并以用法错误退出。
	writer := cmd.Writer
	cmd.Writer = cmd.ErrWriter
	_ = cli.DefaultShowRootCommandHelp(cmd)
	cmd.Writer = writer
	return usageErrorf("缺少子命令（仅支持 compile/apply/format）")
}

func compileFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "file", Aliases: []string{"f"}, Usage: "从文件读取 DSL（用于 shebang：#!/usr/local/bin/efw -f）"},
		&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "输出文件（默认 stdout）"},
		&cli.StringFlag{Name: "table", Value: "efw", Usage: "table 名"},
		&cli.StringFlag{Name: "chain", Value: "input", Usage: "chain 名（不能是 forward/postrouting）"},
		&cli.StringFlag{Name: "hook", Value: "input", Usage: "hook（v1 仅支持 input）"},
		&cli.StringFlag{Name: "priority", Value: "filter", Usage: "priority（nft 关键字或 32 位整数）"},
		&cli.StringFlag{Name: "log-prefix", Value: "efw: ", Usage: "log 前缀（原样输出）"},
		&cli.BoolFlag{Name: "stamp", Usage: "产物头追加生成时间"},
		&cli.BoolFlag{Name: "quiet", Usage: "抑制 warning"},
	}
}

func compileCommand(app App, stdin io.Reader, stdout, stderr io.Writer) *cli.Command {
	return &cli.Command{
		Name:      "compile",
		Usage:     "把 DSL 文件或标准输入编译为 nftables ruleset",
		UsageText: app.Name + " compile [flags] [file]",
		ArgsUsage: "[file]",
		Flags:     compileFlags(),
		OnUsageError: func(ctx context.Context, cmd *cli.Command, err error, isSubcommand bool) error {
			return usageErrorf("%v", err)
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return compileAction(app, cmd, cmd.Args().Slice(), stdin, stdout, stderr)
		},
	}
}

// compileOptions 是从 Flag 中解析出的编译参数。
type compileOptions struct {
	file      string
	output    string
	table     string
	chain     string
	hook      string
	priority  string
	logPrefix string
	stamp     bool
	quiet     bool
}

func collectOptions(cmd *cli.Command) (compileOptions, error) {
	opts := compileOptions{
		file:      cmd.String("file"),
		output:    cmd.String("output"),
		table:     cmd.String("table"),
		chain:     cmd.String("chain"),
		hook:      cmd.String("hook"),
		priority:  cmd.String("priority"),
		logPrefix: cmd.String("log-prefix"),
		stamp:     cmd.Bool("stamp"),
		quiet:     cmd.Bool("quiet"),
	}
	if cmd.IsSet("output") && opts.output == "" {
		return opts, usageErrorf("输出路径不能为空")
	}
	return opts, nil
}

// applyCommand 把编译结果原子应用到内核；重复执行即覆盖自己的 table。
func applyCommand(app App, stdin io.Reader, stderr io.Writer) *cli.Command {
	return &cli.Command{
		Name:      "apply",
		Usage:     "编译并原子应用到内核（覆盖同名 table，需 root/CAP_NET_ADMIN）",
		UsageText: app.Name + " apply [flags] [file]",
		ArgsUsage: "[file]",
		Flags:     compileFlags(),
		OnUsageError: func(ctx context.Context, cmd *cli.Command, err error, isSubcommand bool) error {
			return usageErrorf("%v", err)
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return applyAction(app, cmd, cmd.Args().Slice(), stdin, stderr)
		},
	}
}

// compileResult 是编译产物与告警。
type compileResult struct {
	ruleset []byte
	warns   []errs.Warning
}

// readSource 解析输入来源：-f/--file、唯一位置参数，否则 stdin。
func readSource(opts compileOptions, positional []string, stdin io.Reader) (string, []byte, error) {
	if len(positional) > 1 {
		return "", nil, usageErrorf("最多接受一个输入文件")
	}
	if opts.file != "" && len(positional) == 1 {
		return "", nil, usageErrorf("-f/--file 与位置参数只能二选一")
	}
	source := stdinSource
	switch {
	case opts.file != "":
		source = opts.file
	case len(positional) == 1:
		source = positional[0]
	}
	if source == stdinSource {
		data, err := io.ReadAll(stdin)
		if err != nil {
			return "", nil, usageErrorf("无法读取 stdin：%v", err)
		}
		return source, data, nil
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return "", nil, usageErrorf("无法读取文件：%v", err)
	}
	return source, data, nil
}

// buildCompiled 读取 DSL 并完成编译，告警写到 stderr。
func buildCompiled(app App, opts compileOptions, priority string, positional []string, stdin io.Reader, stderr io.Writer) (compileResult, error) {
	source, src, err := readSource(opts, positional, stdin)
	if err != nil {
		return compileResult{}, err
	}
	ruleset, warns, compileErr := app.Compiler(src, Options{
		Table:     opts.table,
		Chain:     opts.chain,
		Hook:      strings.ToLower(opts.hook),
		Priority:  priority,
		LogPrefix: opts.logPrefix,
		Version:   app.Version,
		Source:    source,
		Stamp:     opts.stamp,
		Now:       time.Now(),
	})
	if !opts.quiet {
		for _, warn := range warns {
			fmt.Fprintln(stderr, warn.Format())
		}
	}
	if compileErr != nil {
		return compileResult{}, compileError(compileErr)
	}
	return compileResult{ruleset: ruleset, warns: warns}, nil
}

// compileError 把编译错误转换为退出码 1 的命令错误。
func compileError(err error) error {
	var list errs.Errors
	if errors.As(err, &list) {
		lines := make([]string, 0, len(list))
		for _, item := range list {
			lines = append(lines, item.Format())
		}
		return &commandError{code: 1, lines: lines}
	}
	return &commandError{code: 1, lines: []string{err.Error()}}
}

func compileAction(app App, cmd *cli.Command, positional []string, stdin io.Reader, stdout, stderr io.Writer) error {
	opts, err := collectOptions(cmd)
	if err != nil {
		return err
	}
	priority, optErr := checkOptions(opts.table, opts.chain, opts.hook, opts.priority, opts.logPrefix)
	if optErr != nil {
		return &commandError{code: 2, lines: []string{optErr.Format()}}
	}
	result, err := buildCompiled(app, opts, priority, positional, stdin, stderr)
	if err != nil {
		return err
	}
	if opts.output == "" {
		if _, writeErr := stdout.Write(result.ruleset); writeErr != nil {
			return usageErrorf("写入 stdout 失败：%v", writeErr)
		}
		return nil
	}
	if writeErr := os.WriteFile(opts.output, result.ruleset, 0o644); writeErr != nil {
		return usageErrorf("无法写入文件：%v", writeErr)
	}
	return nil
}

func applyAction(app App, cmd *cli.Command, positional []string, stdin io.Reader, stderr io.Writer) error {
	opts, err := collectOptions(cmd)
	if err != nil {
		return err
	}
	if cmd.IsSet("output") {
		return usageErrorf("apply 不支持 -o/--output（需要产物文件请用 compile）")
	}
	priority, optErr := checkOptions(opts.table, opts.chain, opts.hook, opts.priority, opts.logPrefix)
	if optErr != nil {
		return &commandError{code: 2, lines: []string{optErr.Format()}}
	}
	result, err := buildCompiled(app, opts, priority, positional, stdin, stderr)
	if err != nil {
		return err
	}
	if applyErr := app.Applier(result.ruleset, opts.table); applyErr != nil {
		return &commandError{code: 2, lines: []string{applyErr.Error()}}
	}
	return nil
}

func versionCommand(app App, stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name:  "version",
		Usage: "打印版本",
		Action: func(context.Context, *cli.Command) error {
			fmt.Fprintf(stdout, "%s version %s\n", app.Name, app.Version)
			return nil
		},
	}
}

// checkOptions 校验部署参数，返回规范化后的 priority 与用法错误（E103）。
func checkOptions(table, chain, hook, priority, logPrefix string) (string, *errs.Error) {
	if !identifierRe.MatchString(table) {
		return "", errs.NewError("", 0, 0, errs.CategoryUsage, errs.CodeUsage,
			"table 名 %q 不合法（须匹配 [A-Za-z_][A-Za-z0-9_]*）", table)
	}
	if _, reserved := reservedNftWords[strings.ToLower(table)]; reserved {
		return "", errs.NewError("", 0, 0, errs.CategoryUsage, errs.CodeUsage,
			"table 名 %q 是 nft 关键字，不能使用", table)
	}
	if !identifierRe.MatchString(chain) {
		return "", errs.NewError("", 0, 0, errs.CategoryUsage, errs.CodeUsage,
			"chain 名 %q 不合法（须匹配 [A-Za-z_][A-Za-z0-9_]*）", chain)
	}
	if _, reserved := reservedNftWords[strings.ToLower(chain)]; reserved {
		return "", errs.NewError("", 0, 0, errs.CategoryUsage, errs.CodeUsage,
			"chain 名 %q 是 nft 关键字，不能使用", chain)
	}
	if strings.EqualFold(chain, "forward") {
		return "", errs.NewError("", 0, 0, errs.CategoryUsage, errs.CodeUsage,
			"chain 名不能是 forward（与内置转发链冲突）")
	}
	if strings.EqualFold(chain, "postrouting") {
		return "", errs.NewError("", 0, 0, errs.CategoryUsage, errs.CodeUsage,
			"chain 名不能是 postrouting（与内置 NAT 链冲突）")
	}
	if !strings.EqualFold(hook, "input") {
		return "", errs.NewError("", 0, 0, errs.CategoryUsage, errs.CodeUsage,
			"v1 仅支持 --hook input，得到 %q", hook)
	}

	normalized := priority
	lower := strings.ToLower(priority)
	if _, ok := priorityKeywords[lower]; ok {
		normalized = lower
	} else {
		if _, err := strconv.ParseInt(priority, 10, 32); err != nil {
			return "", errs.NewError("", 0, 0, errs.CategoryUsage, errs.CodeUsage,
				"priority %q 不合法（raw|mangle|filter|security|dstnat|srcnat 或 32 位整数）", priority)
		}
	}

	if logPrefix == "" {
		return "", errs.NewError("", 0, 0, errs.CategoryUsage, errs.CodeUsage, "log 前缀不能为空")
	}
	for _, r := range logPrefix {
		if r == '"' || r == '\\' || r < 0x20 || r == 0x7f {
			return "", errs.NewError("", 0, 0, errs.CategoryUsage, errs.CodeUsage,
				"log 前缀不能包含引号、反斜杠或控制字符")
		}
	}
	return normalized, nil
}
