// Package ir 定义 efw DSL 的中间表示。
//
// 解析器负责把文本转换成这里的结构；校验器只看结构与语义；
// 优化器与生成器不得再回头关心原始文本（除溯源注释外）。
package ir

import (
	"fmt"
	"sort"
	"strconv"
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

// PrivateName 是「局域网私有地址」集合的保留 token：RFC1918（IPv4）与 RFC4193（IPv6 ULA）。
const (
	PrivateName     = "private"
	Private4SetName = "private4"
	Private6SetName = "private6"
)

var (
	// Private4Prefixes 是 RFC1918 定义的三段 IPv4 私有地址。
	Private4Prefixes = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
	// Private6Prefixes 是 RFC4193 定义的 IPv6 唯一本地地址（ULA）。
	Private6Prefixes = []string{"fc00::/7"}
)

// Addr 是地址选择器：Any 为 *，Named 为命名集合引用，否则 Family + 规范化后的 IP/CIDR 文本。
type Addr struct {
	Any    bool
	Family Family
	Value  string
	Named  string // 命名集合引用（如 private）；非空时 Value 为空
}

// Key 返回用于比较的规范文本。
func (a Addr) Key() string {
	if a.Named != "" {
		return "@" + a.Named
	}
	if a.Any {
		return "*"
	}
	return a.Value
}

// HasFamily 表示地址是否限定了具体地址族。private 与混合族命名集合同时覆盖
// v4/v6（FamilyAny）不算限定；单族命名集合在解析后由 validate 回填具体族。
func (a Addr) HasFamily() bool { return !a.Any && a.Family != FamilyAny }

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
	Iface   string // 入口网卡名（iifname）；空 = 任意网卡
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
	return strings.Join([]string{r.Iface, r.Src.Key(), r.Dst.Key(), r.Proto.String(), r.Ports.Key()}, "|")
}

// ActionKey 覆盖动作语义（含 log 状态），用于判断两条规则动作是否等价。
func (r Rule) ActionKey() string {
	if r.LogOnly {
		return "log-only"
	}
	return fmt.Sprintf("%t|%s", r.Log, r.Verdict)
}

// Masquerade 是一条出站源 NAT 规则：匹配源地址后从指定接口 masquerade。
// 与 Rule 不同，它不参与 verdict/兜底/优化，按书写顺序生成（NAT 首条匹配生效）。
type Masquerade struct {
	Line  int
	Raw   string
	Src   Addr   // 源地址；Any 表示不限制来源（只按出接口）
	Iface string // 出接口名（必填）
}

// DnatTarget 是一条目的 NAT 规则的目标。
//
// Local 为 true 时只改写目的端口并把流量重定向到本机（nft `redirect to :port`，
// 等价 iptables 的 REDIRECT）；否则把目的地址（可选端口）改写为 Addr
// （nft `dnat ip|ip6 to`，等价 iptables 的 DNAT）。
type DnatTarget struct {
	Local bool
	Addr  Addr    // Local=false 时有效；必须是具体地址，不支持 Any/CIDR
	Ports PortSet // 空表示不改端口（仅 Local=false 允许）
}

// Dnat 是一条入站目的 NAT 规则（prerouting/dstnat 链）。
// 与 Masquerade 一样按书写顺序生成（NAT 首条匹配生效），不参与 verdict/兜底/优化。
type Dnat struct {
	Line   int
	Raw    string
	Iface  string // 入口网卡（iifname）；空表示任意入口
	Src    Addr   // 源地址匹配；Any 表示不限制来源
	Proto  Proto
	Ports  PortSet // 匹配的目的端口
	Target DnatTarget
}

// NamedSet 是用户定义的命名集合。DSL 层一个块可混写 IPv4/IPv6；因为 nft set
// 是单地址族的，产物按族拆成 <Name>_v4 / <Name>_v6（哪个族有元素才生成哪个）。
type NamedSet struct {
	Line     int
	Name     string
	Elements []string // 规范化后的 IP/CIDR（可混族，按书写顺序）
	V4       []string // 归并后的 IPv4 产物元素（升序、无重叠）
	V6       []string // 归并后的 IPv6 产物元素（升序、无重叠）
}

// HasIPv4 报告集合归并后是否含 IPv4 元素。
func (s NamedSet) HasIPv4() bool { return len(s.V4) > 0 }

// HasIPv6 报告集合归并后是否含 IPv6 元素。
func (s NamedSet) HasIPv6() bool { return len(s.V6) > 0 }

// Family 返回集合覆盖的地址族：单族返回对应族，两族都有返回 FamilyAny。
func (s NamedSet) Family() Family {
	switch {
	case s.HasIPv4() && s.HasIPv6():
		return FamilyAny
	case s.HasIPv6():
		return FamilyIPv6
	default:
		return FamilyIPv4
	}
}

// File 是解析后的完整 DSL 文件。
type File struct {
	Established bool // true = auto
	V6Bootstrap bool // true = auto
	Forward     bool // true = auto（同时生成 forward 链，仅匹配 DNAT 流量）
	// Priority 是 ACL 文件头 `priority` 指令的值（已归一）；空字符串表示文件未指定。
	Priority string
	// Output 是 ACL 文件头 `output` 指令的落盘路径（已 Clean）；仅 apply 成功后写入，空字符串表示未指定。
	Output      string
	Rules       []Rule
	Masquerades []Masquerade
	Dnats       []Dnat
	Sets        []NamedSet
}

// PriorityDefault 是 input 与 forward 链的默认 priority（可由 --priority 或 ACL 指令覆盖）。
const PriorityDefault = "-99"

// ResolvePriority 返回 input 与 forward 链实际使用的 priority。
//
// explicit 为 true 表示命令行显式给了 given（--priority），它优先于文件里的 priority 指令；
// 否则文件指令优先，未写指令时回落到 given（命令行默认值）。
func (f *File) ResolvePriority(given string, explicit bool) string {
	if !explicit && f.Priority != "" {
		return f.Priority
	}
	return given
}

// priorityKeywords 是 nft priority 关键字；产物统一小写输出。
var priorityKeywords = map[string]struct{}{
	"raw":      {},
	"mangle":   {},
	"filter":   {},
	"security": {},
	"dstnat":   {},
	"srcnat":   {},
}

// NormalizePriority 校验并归一 priority 取值：nft 关键字统一小写，整数规范化为十进制。
// ok=false 表示既不是关键字也不是 32 位整数。parser 与 CLI 共用这一份规则。
func NormalizePriority(raw string) (string, bool) {
	if _, ok := priorityKeywords[strings.ToLower(raw)]; ok {
		return strings.ToLower(raw), true
	}
	value, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return "", false
	}
	return strconv.FormatInt(value, 10), true
}

// MatchesAll 报告规则是否匹配一切（用于识别兜底规则）。
func (r Rule) MatchesAll() bool {
	return r.Iface == "" && r.Src.Any && r.Dst.Any && r.Proto == ProtoAny && r.Ports.IsAny()
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
