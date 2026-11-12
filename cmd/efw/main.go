// efw 把面向 ACL 的 DSL 编译为完整、可直接 nft -f 加载的 nftables ruleset。
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lixiangzhong/efw/internal/compiler"
	"github.com/lixiangzhong/efw/internal/errs"
	"github.com/urfave/cli/v3"
)

// version 是 --version 与产物头使用的版本号。
var version = compiler.Version

// nftBinary 是 apply 模式调用的 nft 命令。
const nftBinary = "nft"

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
		&cli.StringFlag{Name: "chain", Value: "input", Usage: "chain 名"},
		&cli.StringFlag{Name: "hook", Value: "input", Usage: "hook（v1 仅支持 input）"},
		&cli.StringFlag{Name: "priority", Value: "filter", Usage: "priority（nft 关键字或 32 位整数）"},
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
func buildCompiled(opts compileOptions, priority string, positional []string, stdin io.Reader, stderr io.Writer, dockerNets []string) (compileResult, error) {
	source, src, err := readSource(opts, positional, stdin)
	if err != nil {
		return compileResult{}, err
	}
	ruleset, warns, compileErr := compiler.Compile(src, compiler.Options{
		Table:      opts.table,
		Chain:      opts.chain,
		Hook:       strings.ToLower(opts.hook),
		Priority:   priority,
		LogPrefix:  opts.logPrefix,
		Version:    version,
		Source:     source,
		Stamp:      opts.stamp,
		Now:        time.Now(),
		DockerNets: dockerNets,
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
	result, err := buildCompiled(opts, priority, positional, stdin, stderr, nil)
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
	dockerNets := detectDockerNets(stderr, opts.quiet)
	result, err := buildCompiled(opts, priority, positional, stdin, stderr, dockerNets)
	if err != nil {
		return err
	}
	return applyRuleset(result.ruleset, opts.table)
}

// detectDockerNets 在 apply 时探测本机 Docker 网络子网，追加到内网来源放行集合。
// 没有 docker 命令时返回 nil；docker 存在但探测失败时告警并返回 nil（不阻断 apply）。
func detectDockerNets(stderr io.Writer, quiet bool) []string {
	docker, err := exec.LookPath("docker")
	if err != nil {
		return nil
	}
	out, err := exec.Command(docker, "network", "ls", "--format", "{{.ID}}").Output()
	if err != nil {
		if !quiet {
			fmt.Fprintf(stderr, "efw: 警告: 检测到 docker 但无法列出网络，跳过 Docker 网段：%v\n", err)
		}
		return nil
	}
	ids := strings.Fields(string(out))
	if len(ids) == 0 {
		return nil
	}
	args := append([]string{
		"network", "inspect", "--format",
		`{{range .IPAM.Config}}{{.Subnet}}{{"\n"}}{{end}}`,
	}, ids...)
	out, err = exec.Command(docker, args...).Output()
	if err != nil {
		if !quiet {
			fmt.Fprintf(stderr, "efw: 警告: 无法读取 docker 网络子网，跳过 Docker 网段：%v\n", err)
		}
		return nil
	}
	seen := make(map[string]struct{})
	var nets []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if _, parseErr := netip.ParsePrefix(line); parseErr != nil {
			if !quiet {
				fmt.Fprintf(stderr, "efw: 警告: 忽略无法解析的 Docker 网段 %q\n", line)
			}
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		nets = append(nets, line)
	}
	sort.Strings(nets)
	return nets
}

// applyRuleset 校验后原子替换 table：
//   - 表存在：同一 nft 批次内 delete + create（失败时旧表保持不变）；
//   - 表不存在：直接 create。
func applyRuleset(ruleset []byte, table string) error {
	nft, err := exec.LookPath(nftBinary)
	if err != nil {
		return applyErrorf("找不到 %s 命令（应用规则需要 nftables）", nftBinary)
	}
	if out, checkErr := runNft(nft, []string{"-c", "-f", "-"}, ruleset); checkErr != nil {
		return applyErrorf("nft 校验失败：%s", nftOutput(out, checkErr))
	}
	exists, err := nftTableExists(nft, table)
	if err != nil {
		return err
	}

	batch := ruleset
	if exists {
		batch = append([]byte("delete table inet "+table+"\n"), ruleset...)
	}
	if out, applyErr := runNft(nft, []string{"-f", "-"}, batch); applyErr != nil {
		return applyErrorf("nft 应用失败（旧表保持不变）：%s", nftOutput(out, applyErr))
	}
	return nil
}

// nftTableExists 通过 nft list 判断 table 是否已存在。
func nftTableExists(nft, table string) (bool, error) {
	out, err := runNft(nft, []string{"list", "table", "inet", table}, nil)
	if err == nil {
		return true, nil
	}
	if strings.Contains(out, "No such file or directory") {
		return false, nil
	}
	return false, applyErrorf("探测 table inet %s 失败：%s", table, nftOutput(out, err))
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
