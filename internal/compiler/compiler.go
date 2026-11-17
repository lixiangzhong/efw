// Package compiler 编排解析、校验、优化与生成四个阶段。
package compiler

import (
	"time"

	"github.com/lixiangzhong/efw/internal/emit"
	"github.com/lixiangzhong/efw/internal/errs"
	"github.com/lixiangzhong/efw/internal/optimize"
	"github.com/lixiangzhong/efw/internal/parser"
	"github.com/lixiangzhong/efw/internal/validate"
)

// Version 是产物头与 --version 使用的版本号。
var Version = "1.4.0"

// Options 是编译与产物头所需的全部参数。
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
	// Compat 生成 nft <1.0（如 CentOS 7 的 0.8）兼容产物。
	Compat bool
}

// Compile 把 DSL 文本编译为完整 nftables ruleset。
// 成功时返回产物与告警；失败时返回 errs.Errors（含逐条定位）。
func Compile(src []byte, opts Options) ([]byte, []errs.Warning, error) {
	file, parseErrs := parser.Parse(opts.Source, src)
	if len(parseErrs) > 0 {
		return nil, nil, parseErrs
	}

	problems, warns := validate.Check(file, opts.Source)
	if len(problems) > 0 {
		return nil, nil, problems
	}

	// nft <1.0 / 内核 <5.2 没有 inet 族 NAT，masquerade 无法加载，直接拒绝而不是生成坏产物。
	if opts.Compat && len(file.Masquerades) > 0 {
		first := file.Masquerades[0]
		return nil, nil, errs.Errors{errs.NewError(opts.Source, first.Line, 0, errs.CategorySemantic, errs.CodeSemantic,
			"compat 模式不支持 masquerade：nft <1.0 与内核 <5.2 没有 inet 族 NAT")}
	}

	unreachable := make(map[int]bool)
	for _, warn := range warns {
		if warn.Code == errs.CodeUnreachableRule {
			unreachable[warn.Line] = true
		}
	}

	plan := optimize.Run(file)
	out := emit.Render(file, plan, emit.Options{
		Table:            opts.Table,
		Chain:            opts.Chain,
		Hook:             opts.Hook,
		Priority:         opts.Priority,
		LogPrefix:        opts.LogPrefix,
		Version:          opts.Version,
		Source:           opts.Source,
		Stamp:            opts.Stamp,
		Now:              opts.Now,
		UnreachableLines: unreachable,
		Compat:           opts.Compat,
	})
	return out, warns, nil
}
