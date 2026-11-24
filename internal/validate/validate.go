// Package validate 负责跨规则、跨指令的语义检查与告警。
package validate

import (
	"strings"

	"github.com/lixiangzhong/efw/internal/errs"
	"github.com/lixiangzhong/efw/internal/ir"
)

// reservedSetNames 是不能用作命名集合名的保留字（小写比较）：DSL 关键字、
// nft 结构关键字，以及产物里的内置链名/集合名。
var reservedSetNames = map[string]struct{}{
	"accept": {}, "allow": {}, "drop": {}, "reject": {}, "log": {}, "iface": {},
	"private": {}, "masquerade": {}, "established": {}, "v6-bootstrap": {},
	"forward": {}, "auto": {}, "off": {}, "default": {}, "set": {},
	"table": {}, "chain": {}, "type": {}, "hook": {}, "priority": {},
	"policy": {}, "elements": {}, "flags": {}, "interval": {},
	"input": {}, "postrouting": {}, "private4": {}, "private6": {},
}

// resolveSets 校验命名集合定义、解析引用并把地址族回填到规则上；
// 同时给出未使用集合告警（W4）。引用必须在使用前完成解析，否则生成阶段无法选 ip/ip6。
func resolveSets(f *ir.File, fileName string) (errs.Errors, []errs.Warning) {
	var problems errs.Errors
	var warns []errs.Warning

	declared := make(map[string]*ir.NamedSet, len(f.Sets))
	broken := make(map[string]bool, len(f.Sets))
	for i := range f.Sets {
		set := &f.Sets[i]
		if _, reserved := reservedSetNames[strings.ToLower(set.Name)]; reserved {
			problems = append(problems, errs.NewError(fileName, set.Line, 0, errs.CategorySemantic,
				errs.CodeSemantic, "命名集合名 %q 是保留字", set.Name))
			broken[set.Name] = true
			continue
		}
		if prev, ok := declared[set.Name]; ok {
			problems = append(problems, errs.NewError(fileName, set.Line, 0, errs.CategorySemantic,
				errs.CodeSemantic, "命名集合 %q 与第 %d 行重复定义", set.Name, prev.Line))
			broken[set.Name] = true
			continue
		}
		set.V4, set.V6 = ir.MergePrefixes(set.Elements)
		if !set.HasIPv4() && !set.HasIPv6() {
			problems = append(problems, errs.NewError(fileName, set.Line, 0, errs.CategorySemantic,
				errs.CodeSemantic, "命名集合 %q 没有可用地址", set.Name))
			broken[set.Name] = true
			continue
		}
		declared[set.Name] = set
	}

	used := make(map[string]bool, len(declared))
	for i := range f.Rules {
		r := &f.Rules[i]
		if r.Src.Named == "" || r.Src.Named == ir.PrivateName {
			continue
		}
		set, ok := declared[r.Src.Named]
		if !ok {
			if !broken[r.Src.Named] {
				problems = append(problems, errs.NewError(fileName, r.Line, 0, errs.CategorySemantic,
					errs.CodeSemantic, "未定义的命名集合 @%s", r.Src.Named))
			}
			continue
		}
		used[set.Name] = true
		// 单族集合回填具体族：后续的源/目一致性与协议族检查复用现有逻辑；
		// 混合集合保持 FamilyAny，由生成阶段按族展开两条规则。
		r.Src.Family = set.Family()
	}

	for i := range f.Sets {
		set := f.Sets[i]
		if broken[set.Name] || used[set.Name] {
			continue
		}
		warns = append(warns, errs.NewWarning(fileName, set.Line, 0, errs.CodeUnusedSet,
			"命名集合 %q 未被任何规则引用", set.Name))
	}
	return problems, warns
}

// Check 返回编译错误与告警。错误非空时文件不可编译；告警不影响退出码。
func Check(f *ir.File, fileName string) (errs.Errors, []errs.Warning) {
	var problems errs.Errors
	var warns []errs.Warning

	setProblems, setWarns := resolveSets(f, fileName)
	problems = append(problems, setProblems...)
	warns = append(warns, setWarns...)

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
