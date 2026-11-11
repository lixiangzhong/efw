// Package optimize 把 ir.Rule 列表转换为 nft 生成计划。
//
// 只做语义保留的变换（SPEC §3.5）：相邻规则归集成命名 set、单条规则端口区间合并、
// 相邻完全重复规则去重。绝不重排、跨规则移动或跨动作合并。
package optimize

import (
	"fmt"
	"hash/fnv"
	"sort"

	"github.com/lixiangzhong/efw/internal/ir"
)

const (
	kindIPv4    = "ipv4"
	kindIPv6    = "ipv6"
	kindService = "svc"

	// hashMask 保证 set 名中的哈希固定为 8 位十六进制。
	hashMask uint64 = 0xffffffff
)

// Address 是生成阶段的地址选择器：具体值、任意或命名 set。
type Address struct {
	Any     bool
	Family  ir.Family
	Value   string
	SetName string
}

// Ports 是生成阶段的端口选择器：不限、内联区间或命名 set。
type Ports struct {
	SetName string
	Ranges  []ir.PortRange
}

// IsAny 报告是否未限定端口。
func (p Ports) IsAny() bool { return p.SetName == "" && len(p.Ranges) == 0 }

// Rule 是一条待生成的 nft 规则（可能由多条 DSL 规则归集而来）。
type Rule struct {
	Lines   []int
	Raws    []string
	Src     Address
	Dst     Address
	Proto   ir.Proto
	Ports   Ports
	Log     bool
	LogOnly bool
	Verdict ir.Verdict
}

// Set 是一个命名 set 定义。
type Set struct {
	Name     string
	Kind     string
	Elements []string
}

// Plan 是生成阶段的完整输入。
type Plan struct {
	Rules []Rule
	Sets  []Set
}

type dimension uint8

const (
	dimNone dimension = iota
	dimSrc
	dimDst
	dimPorts
)

// Run 生成编译计划。输入规则顺序被严格保留。
func Run(f *ir.File) Plan {
	rules := dedupeConsecutive(f.Rules)

	var out []Rule
	sets := make(map[string]Set)

	for i := 0; i < len(rules); {
		j := i + 1
		dim := dimNone
		if j < len(rules) {
			dim = mergeableDim(rules[i], rules[j])
		}
		if dim != dimNone {
			for j < len(rules) && canMerge(rules[i], rules[j], dim) {
				j++
			}
		}
		if j-i >= 2 {
			out = append(out, buildMerged(rules[i:j], dim, sets))
		} else {
			out = append(out, buildSingle(rules[i]))
		}
		i = j
	}

	return Plan{Rules: out, Sets: sortedSets(sets)}
}

func dedupeConsecutive(in []ir.Rule) []ir.Rule {
	out := make([]ir.Rule, 0, len(in))
	for _, r := range in {
		if n := len(out); n > 0 {
			prev := out[n-1]
			// 单独 log 的日志条数是可观测语义，不参与去重（SPEC §3.5）。
			if !prev.LogOnly && !r.LogOnly && prev.MatchKey() == r.MatchKey() && prev.ActionKey() == r.ActionKey() {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

func actionEqual(a, b ir.Rule) bool {
	return a.Proto == b.Proto && a.Log == b.Log && a.LogOnly == b.LogOnly && a.Verdict == b.Verdict
}

// mergeableDim 判断相邻两条规则是否只在单一维度上不同，且该维度可归集为 set。
func mergeableDim(a, b ir.Rule) dimension {
	// 单独 log 的日志条数是可观测语义，不参与归集（SPEC §3.5）。
	if a.LogOnly || b.LogOnly {
		return dimNone
	}
	if !actionEqual(a, b) {
		return dimNone
	}
	diffSrc := !addrEqual(a.Src, b.Src)
	diffDst := !addrEqual(a.Dst, b.Dst)
	diffPorts := a.Ports.Key() != b.Ports.Key()

	dim := dimNone
	count := 0
	if diffSrc {
		count++
		dim = dimSrc
	}
	if diffDst {
		count++
		dim = dimDst
	}
	if diffPorts {
		count++
		dim = dimPorts
	}
	if count != 1 {
		return dimNone
	}

	switch dim {
	case dimSrc:
		if !a.Src.HasFamily() || !b.Src.HasFamily() || a.Src.Family != b.Src.Family {
			return dimNone
		}
	case dimDst:
		if !a.Dst.HasFamily() || !b.Dst.HasFamily() || a.Dst.Family != b.Dst.Family {
			return dimNone
		}
	case dimPorts:
		if a.Ports.IsAny() || b.Ports.IsAny() {
			return dimNone
		}
	}
	return dim
}

// canMerge 判断 cand 能否追加到以 base 为基准的同一归集组。
func canMerge(base, cand ir.Rule, dim dimension) bool {
	if !actionEqual(base, cand) {
		return false
	}
	switch dim {
	case dimSrc:
		return addrEqual(base.Dst, cand.Dst) &&
			base.Ports.Key() == cand.Ports.Key() &&
			cand.Src.HasFamily() && cand.Src.Family == base.Src.Family
	case dimDst:
		return addrEqual(base.Src, cand.Src) &&
			base.Ports.Key() == cand.Ports.Key() &&
			cand.Dst.HasFamily() && cand.Dst.Family == base.Dst.Family
	case dimPorts:
		return addrEqual(base.Src, cand.Src) && addrEqual(base.Dst, cand.Dst) && !cand.Ports.IsAny()
	default:
		return false
	}
}

func buildSingle(r ir.Rule) Rule {
	out := Rule{
		Lines:   []int{r.Line},
		Raws:    []string{r.Raw},
		Proto:   r.Proto,
		Log:     r.Log,
		LogOnly: r.LogOnly,
		Verdict: r.Verdict,
	}
	if r.Src.Any {
		out.Src = Address{Any: true}
	} else {
		out.Src = Address{Family: r.Src.Family, Value: r.Src.Value}
	}
	if r.Dst.Any {
		out.Dst = Address{Any: true}
	} else {
		out.Dst = Address{Family: r.Dst.Family, Value: r.Dst.Value}
	}
	if !r.Ports.IsAny() {
		out.Ports = Ports{Ranges: r.Ports.Ranges}
	}
	return out
}

func buildMerged(group []ir.Rule, dim dimension, sets map[string]Set) Rule {
	out := buildSingle(group[0])
	out.Lines = nil
	out.Raws = nil
	for _, r := range group {
		out.Lines = append(out.Lines, r.Line)
		out.Raws = append(out.Raws, r.Raw)
	}

	switch dim {
	case dimSrc:
		kind := kindOfFamily(group[0].Src.Family)
		elements := addrElements(group, func(r ir.Rule) ir.Addr { return r.Src })
		name := MakeSetName(kind, elements)
		sets[name] = Set{Name: name, Kind: kind, Elements: elements}
		out.Src = Address{Family: group[0].Src.Family, SetName: name}
	case dimDst:
		kind := kindOfFamily(group[0].Dst.Family)
		elements := addrElements(group, func(r ir.Rule) ir.Addr { return r.Dst })
		name := MakeSetName(kind, elements)
		sets[name] = Set{Name: name, Kind: kind, Elements: elements}
		out.Dst = Address{Family: group[0].Dst.Family, SetName: name}
	case dimPorts:
		var ranges []ir.PortRange
		for _, r := range group {
			ranges = append(ranges, r.Ports.Ranges...)
		}
		ranges = ir.MergePortRanges(ranges)
		elements := make([]string, len(ranges))
		for i, rr := range ranges {
			elements[i] = rr.String()
		}
		name := MakeSetName(kindService, elements)
		sets[name] = Set{Name: name, Kind: kindService, Elements: elements}
		out.Ports = Ports{SetName: name}
	}
	return out
}

func addrElements(group []ir.Rule, pick func(ir.Rule) ir.Addr) []string {
	seen := make(map[string]struct{}, len(group))
	elements := make([]string, 0, len(group))
	for _, r := range group {
		value := pick(r).Value
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		elements = append(elements, value)
	}
	sort.Strings(elements)
	return elements
}

func addrEqual(a, b ir.Addr) bool {
	if a.Any != b.Any {
		return false
	}
	if a.Any {
		return true
	}
	return a.Family == b.Family && a.Value == b.Value
}

func kindOfFamily(f ir.Family) string {
	if f == ir.FamilyIPv6 {
		return kindIPv6
	}
	return kindIPv4
}

// MakeSetName 按元素内容生成确定性 set 名：s_<kind>_<hash8>。
func MakeSetName(kind string, elements []string) string {
	sorted := make([]string, len(elements))
	copy(sorted, elements)
	sort.Strings(sorted)

	h := fnv.New64a()
	for _, e := range sorted {
		_, _ = h.Write([]byte(e))
		_, _ = h.Write([]byte{0})
	}
	return fmt.Sprintf("s_%s_%08x", kind, h.Sum64()&hashMask)
}

func sortedSets(m map[string]Set) []Set {
	names := make([]string, 0, len(m))
	for name := range m {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Set, 0, len(names))
	for _, name := range names {
		out = append(out, m[name])
	}
	return out
}
