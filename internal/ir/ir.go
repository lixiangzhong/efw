// Package ir 定义 efw DSL 的中间表示。
//
// 解析器负责把文本转换成这里的结构；校验器只看结构与语义；
// 优化器与生成器不得再回头关心原始文本（除溯源注释外）。
package ir

import (
	"fmt"
	"sort"
	"strings"
)

// Family 标识地址族。
type Family uint8

const (
	// FamilyAny 表示地址未限定（字段为 *）。
	FamilyAny Family = iota
	FamilyIPv4
	FamilyIPv6
)

func (f Family) String() string {
	switch f {
	case FamilyIPv4:
		return "ipv4"
	case FamilyIPv6:
		return "ipv6"
	default:
		return "any"
	}
}

// Verdict 是规则的最终动作。
type Verdict uint8

const (
	VerdictAccept Verdict = iota
	VerdictDrop
	VerdictReject
)

func (v Verdict) String() string {
	switch v {
	case VerdictDrop:
		return "drop"
	case VerdictReject:
		return "reject"
	default:
		return "accept"
	}
}

// Proto 是 L4 协议；ProtoAny 表示规则不限定协议。
type Proto uint8

const (
	ProtoAny Proto = iota
	ProtoTCP
	ProtoUDP
	ProtoICMP
	// 单地址族协议变体：tcp4/tcp6/udp4/udp6/icmp4/icmp6
	ProtoTCP4
	ProtoTCP6
	ProtoUDP4
	ProtoUDP6
	ProtoICMP4
	ProtoICMP6
)

func (p Proto) String() string {
	switch p {
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMP:
		return "icmp"
	case ProtoTCP4:
		return "tcp4"
	case ProtoTCP6:
		return "tcp6"
	case ProtoUDP4:
		return "udp4"
	case ProtoUDP6:
		return "udp6"
	case ProtoICMP4:
		return "icmp4"
	case ProtoICMP6:
		return "icmp6"
	default:
		return "any"
	}
}

// Family 返回协议限定的地址族；双栈协议（tcp/udp/icmp）与 * 返回 FamilyAny。
func (p Proto) Family() Family {
	switch p {
	case ProtoTCP4, ProtoUDP4, ProtoICMP4:
		return FamilyIPv4
	case ProtoTCP6, ProtoUDP6, ProtoICMP6:
		return FamilyIPv6
	default:
		return FamilyAny
	}
}

// IsICMP 报告是否为任意 ICMP 变体（icmp/icmp4/icmp6）。
func (p Proto) IsICMP() bool {
	return p == ProtoICMP || p == ProtoICMP4 || p == ProtoICMP6
}

// Addr 是地址选择器：Any 为 *，否则 Family + 规范化后的 IP/CIDR 文本。
type Addr struct {
	Any    bool
	Family Family
	Value  string
}

// Key 返回用于比较的规范文本。
func (a Addr) Key() string {
	if a.Any {
		return "*"
	}
	return a.Value
}

// HasFamily 表示地址是否限定了具体地址族。
func (a Addr) HasFamily() bool { return !a.Any }

// PortRange 是闭区间端口。
type PortRange struct{ Lo, Hi uint16 }

func (p PortRange) String() string {
	if p.Lo == p.Hi {
		return fmt.Sprintf("%d", p.Lo)
	}
	return fmt.Sprintf("%d-%d", p.Lo, p.Hi)
}

// PortSet 是有序、已合并的端口集合；空集合表示不限端口。
type PortSet struct{ Ranges []PortRange }

// IsAny 表示未指定端口。
func (p PortSet) IsAny() bool { return len(p.Ranges) == 0 }

// Key 返回用于比较的规范文本；空集合为 *。
func (p PortSet) Key() string {
	if p.IsAny() {
		return "*"
	}
	parts := make([]string, len(p.Ranges))
	for i := range p.Ranges {
		parts[i] = p.Ranges[i].String()
	}
	return strings.Join(parts, ",")
}

// Rule 是一条匹配规则。
type Rule struct {
	Line    int
	Raw     string
	Src     Addr
	Dst     Addr
	Proto   Proto
	Ports   PortSet
	Log     bool
	LogOnly bool // action 仅为 log：记录但不裁决
	Verdict Verdict
}

// MatchKey 只覆盖匹配条件，用于判断两条规则是否匹配同一流量。
func (r Rule) MatchKey() string {
	return strings.Join([]string{r.Src.Key(), r.Dst.Key(), r.Proto.String(), r.Ports.Key()}, "|")
}

// ActionKey 覆盖动作语义（含 log 状态），用于判断两条规则动作是否等价。
func (r Rule) ActionKey() string {
	if r.LogOnly {
		return "log-only"
	}
	return fmt.Sprintf("%t|%s", r.Log, r.Verdict)
}

// File 是解析后的完整 DSL 文件。
type File struct {
	Established bool // true = auto
	V6Bootstrap bool // true = auto
	Forward     bool // true = auto（同时生成 forward 链，仅匹配 DNAT 流量）
	Rules       []Rule
}

// MatchesAll 报告规则是否匹配一切（用于识别兜底规则）。
func (r Rule) MatchesAll() bool {
	return r.Src.Any && r.Dst.Any && r.Proto == ProtoAny && r.Ports.IsAny()
}

// Fallback 返回兜底规则的动作与是否存在。
//
// 兜底 = 展开后的最后一条规则，必须匹配一切且不是「单独 log」
// （log-only 不裁决，不能作为兜底）。
func (f *File) Fallback() (Verdict, bool) {
	if n := len(f.Rules); n > 0 {
		r := f.Rules[n-1]
		if r.MatchesAll() && !r.LogOnly {
			return r.Verdict, true
		}
	}
	return VerdictAccept, false
}

// FallbackDeny 报告兜底是否为拒绝类动作（drop/reject）。
func (f *File) FallbackDeny() bool {
	verdict, ok := f.Fallback()
	return ok && (verdict == VerdictDrop || verdict == VerdictReject)
}

// MergePortRanges 排序并合并重叠/相邻区间，保证输出确定性。
func MergePortRanges(ranges []PortRange) []PortRange {
	if len(ranges) == 0 {
		return nil
	}
	sorted := make([]PortRange, len(ranges))
	copy(sorted, ranges)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Lo != sorted[j].Lo {
			return sorted[i].Lo < sorted[j].Lo
		}
		return sorted[i].Hi < sorted[j].Hi
	})
	out := make([]PortRange, 0, len(sorted))
	for _, r := range sorted {
		last := len(out) - 1
		if last >= 0 && int(r.Lo) <= int(out[last].Hi)+1 {
			if r.Hi > out[last].Hi {
				out[last].Hi = r.Hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}
