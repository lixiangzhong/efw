// efw 把面向 ACL 的 DSL 编译为完整、可直接 nft -f 加载的 nftables ruleset。
package main

import (
	"io"
	"os"

	"github.com/lixiangzhong/efw/internal/compiler"
	"github.com/lixiangzhong/efw/internal/efwcli"
	"github.com/lixiangzhong/efw/internal/errs"
	"github.com/lixiangzhong/efw/internal/nftexec"
)

// version 是 --version 与产物头使用的版本号。
var version = compiler.Version

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run 是 CLI 入口，返回进程退出码：0 成功 / 1 编译错误 / 2 用法错误或 apply 失败。
func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return efwcli.Run(efwcli.App{
		Name:     "efw",
		Usage:    "把 ACL DSL 编译为 nftables ruleset，或直接应用到内核",
		Version:  version,
		Compiler: compile,
		Applier:  nftexec.Apply,
	}, args, stdin, stdout, stderr)
}

// compile 使用现代 nft（≥1.0）方言编译。
func compile(src []byte, opts efwcli.Options) ([]byte, []errs.Warning, error) {
	return compiler.Compile(src, compiler.Options{
		Table:     opts.Table,
		Chain:     opts.Chain,
		Hook:      opts.Hook,
		Priority:  opts.Priority,
		LogPrefix: opts.LogPrefix,
		Version:   opts.Version,
		Source:    opts.Source,
		Stamp:     opts.Stamp,
		Now:       opts.Now,
	})
}
