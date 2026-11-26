package legacy

import (
	"github.com/lixiangzhong/efw/internal/errs"
	"github.com/lixiangzhong/efw/internal/optimize"
	"github.com/lixiangzhong/efw/internal/parser"
	"github.com/lixiangzhong/efw/internal/validate"
)

// Compile 把 DSL 文本编译为 nft 0.8（CentOS 7）可直接加载的 ruleset。
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

	// nft 0.8 / 内核 <5.2 没有 inet 族 NAT，masquerade 无法加载，直接拒绝而不是生成坏产物。
	if len(file.Masquerades) > 0 {
		first := file.Masquerades[0]
		return nil, nil, errs.Errors{errs.NewError(opts.Source, first.Line, 0, errs.CategorySemantic, errs.CodeSemantic,
			"nft 0.8 不支持 masquerade：inet 族 NAT 需要 nft ≥1.0 与内核 ≥5.2")}
	}
	// dnat/redirect 同样需要 inet 族 NAT，0.8 直接拒绝。
	if len(file.Dnats) > 0 {
		first := file.Dnats[0]
		return nil, nil, errs.Errors{errs.NewError(opts.Source, first.Line, 0, errs.CategorySemantic, errs.CodeSemantic,
			"nft 0.8 不支持 dnat/redirect：inet 族 NAT 需要 nft ≥1.0 与内核 ≥5.2")}
	}

	unreachable := make(map[int]bool)
	for _, warn := range warns {
		if warn.Code == errs.CodeUnreachableRule {
			unreachable[warn.Line] = true
		}
	}

	plan := optimize.Run(file)
	out := Render(file, plan, Options{
		Table:            opts.Table,
		Chain:            opts.Chain,
		Hook:             opts.Hook,
		Priority:         file.ResolvePriority(opts.Priority, opts.PrioritySet),
		PrioritySet:      opts.PrioritySet,
		LogPrefix:        opts.LogPrefix,
		Version:          opts.Version,
		Source:           opts.Source,
		Stamp:            opts.Stamp,
		Now:              opts.Now,
		UnreachableLines: unreachable,
	})
	return out, warns, nil
}
