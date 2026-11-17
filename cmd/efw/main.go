// efw 把面向 ACL 的 DSL 编译为完整、可直接 nft -f 加载的 nftables ruleset。
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/lixiangzhong/efw/internal/compiler"
	"github.com/lixiangzhong/efw/internal/errs"
	"github.com/urfave/cli/v3"
)

// version 是 --version 与产物头使用的版本号。
var version = compiler.Version

const (
	// nftBinary 是 apply 模式调用的 nft 命令。
	nftBinary = "nft"
	// nftPreferredInput 是 ruleset 传给 nft -f 的路径。nft 0.8 不接受 "-"（stdin），
	// 但接受 /dev/stdin；该路径不可用时回退临时文件。
	nftPreferredInput = "/dev/stdin"
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

	// nftVersionRe 从 `nft --version`（如 "nftables v0.8 (Joe Btfsplk)"）提取主次版本。
	nftVersionRe = regexp.MustCompile(`v(\d+)\.(\d+)`)
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// commandError 是带退出码的命令错误，由 run 统一打印后返回退出码。
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

// run 是 CLI 入口，返回进程退出码：0 成功 / 1 编译错误 / 2 用法错误。
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cmd := newCommand(stdin, stdout, stderr)
	err := cmd.Run(context.Background(), append([]string{"efw"}, args...))
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

func newCommand(stdin io.Reader, stdout, stderr io.Writer) *cli.Command {
	return &cli.Command{
		Name:        "efw",
		Usage:       "把 ACL DSL 编译为 nftables ruleset，或直接应用到内核",
		UsageText:   "efw <file> [flags]\n   efw compile [flags] [file]\n   efw apply [flags] [file]",
		Description: "DSL → nftables ruleset 文本（compile）或编译后原子应用到内核（apply，需 root/CAP_NET_ADMIN）。不给文件时从 stdin 读取。",
		Version:     version,
		Reader:      stdin,
		Writer:      stdout,
		ErrWriter:   stderr,
		// 退出码与错误输出由 run 统一处理，禁止 cli 自行 os.Exit。
		ExitErrHandler: func(context.Context, *cli.Command, error) {},
		OnUsageError: func(ctx context.Context, cmd *cli.Command, err error, isSubcommand bool) error {
			return usageErrorf("%v", err)
		},
		// 根命令直接接受编译参数，用于 shebang：#!/usr/local/bin/efw -f
		Flags: compileFlags(),
		Commands: []*cli.Command{
			compileCommand(stdin, stdout, stderr),
			applyCommand(stdin, stderr),
			versionCommand(stdout),
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return rootAction(cmd, stdin, stdout, stderr)
		},
	}
}

func rootAction(cmd *cli.Command, stdin io.Reader, stdout, stderr io.Writer) error {
	// 两种文件形态：
	//   efw <file> [flags]        —— 根命令位置参数；也是无 -f shebang 的调用形态
	//   efw -f <file> [flags]     —— 显式 -f（等价，兼容旧写法）
	if cmd.IsSet("file") || cmd.Args().Len() > 0 {
		return compileAction(cmd, cmd.Args().Slice(), stdin, stdout, stderr)
	}
	// 无参数：帮助打印到 stderr（与旧行为一致），并以用法错误退出。
	writer := cmd.Writer
	cmd.Writer = cmd.ErrWriter
	_ = cli.DefaultShowRootCommandHelp(cmd)
	cmd.Writer = writer
	return usageErrorf("缺少子命令（仅支持 compile/apply）")
}

func compileFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{Name: "file", Aliases: []string{"f"}, Usage: "从文件读取 DSL（用于 shebang：#!/usr/local/bin/efw -f）"},
		&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "输出文件（默认 stdout）"},
		&cli.StringFlag{Name: "table", Value: "efw", Usage: "table 名"},
		&cli.StringFlag{Name: "chain", Value: "input", Usage: "chain 名（不能是 forward/postrouting）"},
		&cli.StringFlag{Name: "hook", Value: "input", Usage: "hook（v1 仅支持 input）"},
		&cli.StringFlag{Name: "priority", Value: "filter", Usage: "priority（nft 关键字或 32 位整数）"},
		&cli.BoolFlag{Name: "compat", Usage: "兼容 nft <1.0（如 CentOS 7 的 0.8）：数字 priority、拆分 th dport、禁用 masquerade；apply 未显式指定时按本机 nft 版本自动判定"},
		&cli.StringFlag{Name: "log-prefix", Value: "efw: ", Usage: "log 前缀（原样输出）"},
		&cli.BoolFlag{Name: "stamp", Usage: "产物头追加生成时间"},
		&cli.BoolFlag{Name: "quiet", Usage: "抑制 warning"},
	}
}

func compileCommand(stdin io.Reader, stdout, stderr io.Writer) *cli.Command {
	return &cli.Command{
		Name:      "compile",
		Usage:     "把 DSL 文件或标准输入编译为 nftables ruleset",
		UsageText: "efw compile [flags] [file]",
		ArgsUsage: "[file]",
		Flags:     compileFlags(),
		OnUsageError: func(ctx context.Context, cmd *cli.Command, err error, isSubcommand bool) error {
			return usageErrorf("%v", err)
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return compileAction(cmd, cmd.Args().Slice(), stdin, stdout, stderr)
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
	compat    bool
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
		compat:    cmd.Bool("compat"),
	}
	if cmd.IsSet("output") && opts.output == "" {
		return opts, usageErrorf("输出路径不能为空")
	}
	return opts, nil
}

// applyCommand 把编译结果原子应用到内核；重复执行即覆盖自己的 table。
func applyCommand(stdin io.Reader, stderr io.Writer) *cli.Command {
	return &cli.Command{
		Name:      "apply",
		Usage:     "编译并原子应用到内核（覆盖同名 table，需 root/CAP_NET_ADMIN）",
		UsageText: "efw apply [flags] [file]",
		ArgsUsage: "[file]",
		Flags:     compileFlags(),
		OnUsageError: func(ctx context.Context, cmd *cli.Command, err error, isSubcommand bool) error {
			return usageErrorf("%v", err)
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return applyAction(cmd, cmd.Args().Slice(), stdin, stderr)
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
	source := "<stdin>"
	switch {
	case opts.file != "":
		source = opts.file
	case len(positional) == 1:
		source = positional[0]
	}
	if source == "<stdin>" {
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
func buildCompiled(opts compileOptions, priority string, positional []string, stdin io.Reader, stderr io.Writer) (compileResult, error) {
	source, src, err := readSource(opts, positional, stdin)
	if err != nil {
		return compileResult{}, err
	}
	ruleset, warns, compileErr := compiler.Compile(src, compiler.Options{
		Table:     opts.table,
		Chain:     opts.chain,
		Hook:      strings.ToLower(opts.hook),
		Priority:  priority,
		LogPrefix: opts.logPrefix,
		Version:   version,
		Source:    source,
		Stamp:     opts.stamp,
		Now:       time.Now(),
		Compat:    opts.compat,
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

func compileAction(cmd *cli.Command, positional []string, stdin io.Reader, stdout, stderr io.Writer) error {
	opts, err := collectOptions(cmd)
	if err != nil {
		return err
	}
	priority, optErr := checkOptions(opts.table, opts.chain, opts.hook, opts.priority, opts.logPrefix)
	if optErr != nil {
		return &commandError{code: 2, lines: []string{optErr.Format()}}
	}
	result, err := buildCompiled(opts, priority, positional, stdin, stderr)
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

func applyAction(cmd *cli.Command, positional []string, stdin io.Reader, stderr io.Writer) error {
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
	// 用户没显式指定 --compat 时，按本机 nft 版本自动判定（0.x 需要兼容产物）。
	if !cmd.IsSet("compat") {
		if nft, lookErr := exec.LookPath(nftBinary); lookErr == nil {
			opts.compat = nftNeedsCompat(nft)
		}
	}
	result, err := buildCompiled(opts, priority, positional, stdin, stderr)
	if err != nil {
		return err
	}
	return applyRuleset(result.ruleset, opts.table)
}

// applyRuleset 校验后原子替换 table：
//   - 表存在：同一 nft 批次内 delete + create（失败时旧表保持不变）；
//   - 表不存在：直接 create。
//
// 校验必须针对最终批次（含 delete）：nft 0.8 的 `-c` 会按真实内核状态评估，
// 只校验不含 delete 的原始规则时，二次 apply 会报 "File exists"。
func applyRuleset(ruleset []byte, table string) error {
	nft, err := exec.LookPath(nftBinary)
	if err != nil {
		return applyErrorf("找不到 %s 命令（应用规则需要 nftables）", nftBinary)
	}
	exists, err := nftTableExists(nft, table)
	if err != nil {
		return err
	}

	batch := ruleset
	if exists {
		batch = append([]byte("delete table inet "+table+"\n"), ruleset...)
	}
	inputPath, cleanup, err := nftInputPath(batch, nftPreferredInput)
	if err != nil {
		return applyErrorf("无法准备 nft 输入：%v", err)
	}
	defer cleanup()
	if out, checkErr := runNft(nft, []string{"-c", "-f", inputPath}, batch); checkErr != nil {
		return applyErrorf("nft 校验失败：%s", nftOutput(out, checkErr))
	}
	if out, applyErr := runNft(nft, []string{"-f", inputPath}, batch); applyErr != nil {
		return applyErrorf("nft 应用失败（旧表保持不变）：%s", nftOutput(out, applyErr))
	}
	return nil
}

// nftInputPath 返回把 ruleset 交给 nft -f 的路径。
// nft 0.8 不接受 "-"（stdin），但接受 /dev/stdin；preferred 不可用时退回 0600 临时文件。
func nftInputPath(ruleset []byte, preferred string) (string, func(), error) {
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

// nftNeedsCompat 报告 nft 是否属于 <1.0 的老版本（如 CentOS 7 的 0.8）：
// 这类版本只接受数字 priority，且不支持 th dport。
func nftNeedsCompat(nft string) bool {
	out, err := exec.Command(nft, "--version").Output()
	if err != nil {
		return false
	}
	match := nftVersionRe.FindStringSubmatch(string(out))
	if len(match) != 3 {
		return false
	}
	major, err := strconv.Atoi(match[1])
	if err != nil {
		return false
	}
	return major < 1
}

// nftTableExists 通过 nft list tables 判断 table 是否已存在。
// 不依赖缺表错误文案：nft 0.8 是 "Table 'x' does not exist"，nft 1.x 是 "No such file or directory"。
func nftTableExists(nft, table string) (bool, error) {
	out, err := runNft(nft, []string{"list", "tables"}, nil)
	if err != nil {
		return false, applyErrorf("探测 table inet %s 失败：%s", table, nftOutput(out, err))
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

func applyErrorf(format string, args ...any) error {
	return &commandError{
		code:  2,
		lines: []string{errs.NewError("", 0, 0, errs.CategoryApply, errs.CodeApply, format, args...).Format()},
	}
}

func versionCommand(stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name:  "version",
		Usage: "打印版本",
		Action: func(context.Context, *cli.Command) error {
			fmt.Fprintf(stdout, "efw version %s\n", version)
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
