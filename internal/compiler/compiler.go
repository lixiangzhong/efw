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
var Version = "1.1.0"

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
	// DockerNets 是 apply 时探测到的 Docker 网络子网（compile 不填）。
	DockerNets []string
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
		DockerNets:       opts.DockerNets,
		UnreachableLines: unreachable,
	})
	return out, warns, nil
}
