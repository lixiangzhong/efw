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
	"dnat": {}, "prerouting": {},
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

	// 目的 NAT：端口映射、地址族与 ICMP 约束。
	problems = append(problems, validateDnats(f, fileName)...)

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

	// W5：本机重定向的目标端口没有 input 放行（需要兜底状态，放在最后）。
	warns = append(warns, dnatInputAllowWarnings(f, fileName)...)

	return problems, warns
}

// validateDnats 校验目的 NAT 条目：端口映射必须可表示，跨机目标的地址族必须与
// 协议/匹配地址一致，ICMP 不能带端口。
func validateDnats(f *ir.File, fileName string) errs.Errors {
	var problems errs.Errors
	for _, entry := range f.Dnats {
		if msg := dnatMappingProblem(entry); msg != "" {
			problems = append(problems, errs.NewError(fileName, entry.Line, 0,
				errs.CategorySemantic, errs.CodeSemantic, "%s", msg))
		}
		if msg := dnatFamilyProblem(entry); msg != "" {
			problems = append(problems, errs.NewError(fileName, entry.Line, 0,
				errs.CategorySemantic, errs.CodeSemantic, "%s", msg))
		}
	}
	return problems
}

// dnatMappingProblem 校验端口映射：目标单端口允许多对一；目标范围必须与匹配范围等长。
// 返回空字符串表示合法。
func dnatMappingProblem(entry ir.Dnat) string {
	if entry.Proto.IsICMP() {
		if !entry.Ports.IsAny() {
			return "icmp 规则不能指定端口"
		}
		if entry.Target.Local {
			return "icmp 不能重定向到本机端口"
		}
		return ""
	}
	targets := entry.Target.Ports.Ranges
	if len(targets) == 0 {
		return "" // 跨机只改地址、不改端口
	}
	if len(targets) > 1 {
		return "dnat 目标端口只能是一个端口或一个范围"
	}
	portRange := targets[0]
	if portRange.Lo == portRange.Hi {
		return "" // 多对一：匹配侧可以是范围/列表/不限端口
	}
	sources := entry.Ports.Ranges
	switch {
	case len(sources) == 0:
		return "目标端口是范围时，匹配侧必须写明等长的端口范围（不能用 *）"
	case len(sources) > 1:
		return "目标端口是范围时，匹配端口只能写一个等长范围（不能用端口列表）"
	case int(sources[0].Hi)-int(sources[0].Lo) != int(portRange.Hi)-int(portRange.Lo):
		return "目标端口范围 " + portRange.String() + " 与匹配端口范围 " + sources[0].String() +
			" 长度不一致（端口映射必须一一对应；多对一请写单个目标端口）"
	}
	return ""
}

// dnatFamilyProblem 校验跨机目标的地址族：目标钉死单族，协议与匹配地址不能跨族。
func dnatFamilyProblem(entry ir.Dnat) string {
	if entry.Target.Local {
		return ""
	}
	family := entry.Target.Addr.Family
	if pf := entry.Proto.Family(); pf != ir.FamilyAny && pf != family {
		return "协议 " + entry.Proto.String() + " 与 dnat 目标地址族不一致"
	}
	if entry.Src.HasFamily() && entry.Src.Family != family {
		return "源地址与 dnat 目标地址的地址族不一致（v4 与 v6 不能混写）"
	}
	return ""
}

// dnatInputAllowWarnings 提示本机重定向的目标端口在 input 链没有对应放行。
//
// redirect 之后数据包变成「到本机」，会进入 input 链；默认零信任下若没有显式
// accept 目标端口，流量会被兜底丢弃（黑洞）。判定故意放宽——只看 accept、协议
// 大类与端口覆盖，不分析源地址/入口网卡，避免对已放行的配置误报。
func dnatInputAllowWarnings(f *ir.File, fileName string) []errs.Warning {
	if verdict, ok := f.Fallback(); ok && verdict == ir.VerdictAccept {
		return nil // 兜底 accept 已放行一切，W3 会单独提示
	}
	var warns []errs.Warning
	for _, entry := range f.Dnats {
		if !entry.Target.Local || entry.Target.Ports.IsAny() {
			continue
		}
		portRange := entry.Target.Ports.Ranges[0]
		if dnatInputAllowed(f.Rules, entry.Proto, portRange) {
			continue
		}
		warns = append(warns, errs.NewWarning(fileName, entry.Line, 0, errs.CodeDnatInputUnopened,
			"重定向到本机端口 %s 后流量进入 input 链，ACL 里没有对应的 accept 放行，会被兜底规则丢弃", portRange))
	}
	return warns
}

// dnatInputAllowed 判断 input 规则里是否存在覆盖目标端口的 accept。
func dnatInputAllowed(rules []ir.Rule, proto ir.Proto, portRange ir.PortRange) bool {
	for _, rule := range rules {
		if rule.LogOnly || rule.Verdict != ir.VerdictAccept {
			continue
		}
		if !protoCovers(rule.Proto, proto) {
			continue
		}
		if portsCover(rule.Ports, portRange) {
			return true
		}
	}
	return false
}

// protoCovers 报告放行规则的协议是否覆盖 NAT 匹配的协议（双栈变体按大类比较）。
func protoCovers(ruleProto, dnatProto ir.Proto) bool {
	if ruleProto == ir.ProtoAny || dnatProto == ir.ProtoAny {
		return true
	}
	return baseProto(ruleProto) == baseProto(dnatProto)
}

// baseProto 把单地址族协议（tcp4/tcp6 等）归并到双栈大类。
func baseProto(p ir.Proto) ir.Proto {
	switch p {
	case ir.ProtoTCP4, ir.ProtoTCP6:
		return ir.ProtoTCP
	case ir.ProtoUDP4, ir.ProtoUDP6:
		return ir.ProtoUDP
	case ir.ProtoICMP4, ir.ProtoICMP6:
		return ir.ProtoICMP
	}
	return p
}

// portsCover 报告放行规则的端口集合是否覆盖目标端口范围。
func portsCover(ports ir.PortSet, portRange ir.PortRange) bool {
	if ports.IsAny() {
		return true
	}
	for _, r := range ports.Ranges {
		if r.Lo <= portRange.Lo && portRange.Hi <= r.Hi {
			return true
		}
	}
	return false
}
