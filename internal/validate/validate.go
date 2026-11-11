// Package validate 负责跨规则、跨指令的语义检查与告警。
package validate

import (
	"github.com/lixiangzhong/efw/internal/errs"
	"github.com/lixiangzhong/efw/internal/ir"
)

// Check 返回编译错误与告警。错误非空时文件不可编译；告警不影响退出码。
func Check(f *ir.File, fileName string) (errs.Errors, []errs.Warning) {
	var problems errs.Errors
	var warns []errs.Warning

	for _, r := range f.Rules {
		if r.Proto.IsICMP() && !r.Ports.IsAny() {
			problems = append(problems, errs.NewError(fileName, r.Line, 0, errs.CategorySemantic,
				errs.CodeSemantic, "icmp 规则不能指定端口"))
		}
		if r.Src.HasFamily() && r.Dst.HasFamily() && r.Src.Family != r.Dst.Family {
			problems = append(problems, errs.NewError(fileName, r.Line, 0, errs.CategorySemantic,
				errs.CodeSemantic, "源地址与目的地址的地址族不一致（v4 与 v6 不能混写）"))
		}
		// 单地址族协议（tcp4/tcp6/...）必须与显式地址族一致。
		if pf := r.Proto.Family(); pf != ir.FamilyAny {
			if r.Src.HasFamily() && r.Src.Family != pf {
				problems = append(problems, errs.NewError(fileName, r.Line, 0, errs.CategorySemantic,
					errs.CodeSemantic, "协议 %s 与源地址族不一致（%s 只能用于 %s 地址）", r.Proto, r.Proto, pf))
			}
			if r.Dst.HasFamily() && r.Dst.Family != pf {
				problems = append(problems, errs.NewError(fileName, r.Line, 0, errs.CategorySemantic,
					errs.CodeSemantic, "协议 %s 与目的地址族不一致（%s 只能用于 %s 地址）", r.Proto, r.Proto, pf))
			}
		}
	}

	// W1：相同匹配、不同动作 → 后者不可达。
	seen := make(map[string]ir.Rule, len(f.Rules))
	for _, r := range f.Rules {
		key := r.MatchKey()
		prev, ok := seen[key]
		if !ok {
			seen[key] = r
			continue
		}
		if prev.LogOnly {
			// 单独 log 不裁决、继续后续规则（SPEC §3.4），因此本规则仍可达。
			seen[key] = r
			continue
		}
		if prev.ActionKey() != r.ActionKey() {
			warns = append(warns, errs.NewWarning(fileName, r.Line, 0, errs.CodeUnreachableRule,
				"与第 %d 行匹配条件相同、动作不同，本规则不会被命中", prev.Line))
		}
	}

	// 兜底规则（匹配一切的规则）必须存在，且必须是展开后的最后一条。
	lastIndex := len(f.Rules) - 1
	var hasMatchAll bool
	for i, r := range f.Rules {
		if !r.MatchesAll() || r.LogOnly {
			continue
		}
		hasMatchAll = true
		if i != lastIndex {
			problems = append(problems, errs.NewError(fileName, r.Line, 0, errs.CategorySemantic,
				errs.CodeSemantic, "匹配一切的规则必须是展开后的最后一条（兜底）"))
		}
	}
	if !hasMatchAll {
		problems = append(problems, errs.NewError(fileName, 0, 0, errs.CategorySemantic,
			errs.CodeDirective,
			"缺少兜底规则：展开后的最后一条规则必须匹配一切（如 drop { * } 或单独的 drop）"))
		return problems, warns
	}

	fallback, ok := f.Fallback()
	if !ok {
		return problems, warns
	}

	if fallback == ir.VerdictAccept {
		if f.V6Bootstrap {
			warns = append(warns, errs.NewWarning(fileName, 0, 0, errs.CodeV6BootstrapIdle,
				"兜底为 accept 时 v6-bootstrap auto 无实际作用"))
		}
		warns = append(warns, errs.NewWarning(fileName, 0, 0, errs.CodeFallbackAccept,
			"兜底为 accept：未命中流量一律放行"))
	}

	return problems, warns
}
