package optimize_test

import (
	"testing"

	"github.com/lixiangzhong/efw/internal/ir"
	"github.com/lixiangzhong/efw/internal/optimize"
)

func rule(line int, src, dst string, proto ir.Proto, ports []ir.PortRange, verdict ir.Verdict) ir.Rule {
	r := ir.Rule{Line: line, Raw: "line", Proto: proto, Verdict: verdict, Ports: ir.PortSet{Ranges: ports}}
	if src != "*" {
		r.Src = ir.Addr{Family: familyOf(src), Value: src}
	} else {
		r.Src = ir.Addr{Any: true}
	}
	if dst != "*" {
		r.Dst = ir.Addr{Family: familyOf(dst), Value: dst}
	} else {
		r.Dst = ir.Addr{Any: true}
	}
	return r
}

func familyOf(addr string) ir.Family {
	for _, c := range addr {
		if c == ':' {
			return ir.FamilyIPv6
		}
	}
	return ir.FamilyIPv4
}

func ports(ranges ...ir.PortRange) []ir.PortRange { return ranges }

func port(n uint16) ir.PortRange { return ir.PortRange{Lo: n, Hi: n} }

// TestNoMergeAcrossAction 动作不同、即使相邻也不得合并。
func TestNoMergeAcrossAction(t *testing.T) {
	f := &ir.File{Rules: []ir.Rule{
		rule(1, "1.1.1.1", "*", ir.ProtoTCP, ports(port(80)), ir.VerdictAccept),
		rule(2, "2.2.2.2", "*", ir.ProtoTCP, ports(port(80)), ir.VerdictDrop),
		rule(3, "3.3.3.3", "*", ir.ProtoTCP, ports(port(80)), ir.VerdictAccept),
	}}
	plan := optimize.Run(f)
	if len(plan.Rules) != 3 {
		t.Fatalf("动作不同不应合并，期望 3 条规则，实际 %d", len(plan.Rules))
	}
	if len(plan.Sets) != 0 {
		t.Fatalf("不应生成 set，实际 %d", len(plan.Sets))
	}
}

// TestNoMergeTwoDimensions 两个维度同时变化时不合并（v1 保守策略）。
func TestNoMergeTwoDimensions(t *testing.T) {
	f := &ir.File{Rules: []ir.Rule{
		rule(1, "1.1.1.1", "*", ir.ProtoTCP, ports(port(80)), ir.VerdictAccept),
		rule(2, "2.2.2.2", "10.0.0.1", ir.ProtoTCP, ports(port(80)), ir.VerdictAccept),
	}}
	plan := optimize.Run(f)
	if len(plan.Rules) != 2 {
		t.Fatalf("两个维度同时变化不应合并，实际 %d 条", len(plan.Rules))
	}
}

// TestNoMergeWhenAny 变化维度本身是「任意」时不参与归集。
func TestNoMergeWhenAny(t *testing.T) {
	f := &ir.File{Rules: []ir.Rule{
		rule(1, "1.1.1.1", "*", ir.ProtoTCP, nil, ir.VerdictAccept),
		rule(2, "1.1.1.1", "*", ir.ProtoTCP, ports(port(80)), ir.VerdictAccept),
	}}
	plan := optimize.Run(f)
	if len(plan.Rules) != 2 {
		t.Fatalf("端口从「不限」变为具体值不应归集，实际 %d 条", len(plan.Rules))
	}
}

// TestMergeSrcWithAnyPorts 变化维度是 src、端口恒为「不限」时可以归集。
func TestMergeSrcWithAnyPorts(t *testing.T) {
	f := &ir.File{Rules: []ir.Rule{
		rule(1, "1.1.1.1", "*", ir.ProtoTCP, nil, ir.VerdictAccept),
		rule(2, "2.2.2.2", "*", ir.ProtoTCP, nil, ir.VerdictAccept),
	}}
	plan := optimize.Run(f)
	if len(plan.Rules) != 1 {
		t.Fatalf("src 维度归集应当发生，实际 %d 条", len(plan.Rules))
	}
	if len(plan.Sets) != 1 {
		t.Fatalf("期望 1 个 set，实际 %d", len(plan.Sets))
	}
}

// TestMergeSrcStable 归集 src 维度时 set 内容与命名确定、顺序保留。
func TestMergeSrcStable(t *testing.T) {
	f := &ir.File{Rules: []ir.Rule{
		rule(1, "1.1.1.1", "*", ir.ProtoTCP, ports(port(80)), ir.VerdictAccept),
		rule(2, "2.2.2.2", "*", ir.ProtoTCP, ports(port(80)), ir.VerdictAccept),
	}}
	plan := optimize.Run(f)
	if len(plan.Rules) != 1 {
		t.Fatalf("期望合并为 1 条规则，实际 %d", len(plan.Rules))
	}
	if len(plan.Sets) != 1 || plan.Sets[0].Kind != "ipv4" {
		t.Fatalf("期望 1 个 ipv4 set，实际 %+v", plan.Sets)
	}
	if got, want := plan.Sets[0].Name, optimize.MakeSetName("ipv4", []string{"1.1.1.1", "2.2.2.2"}); got != want {
		t.Fatalf("set 名不稳定: got %s want %s", got, want)
	}
	if plan.Rules[0].Src.SetName != plan.Sets[0].Name {
		t.Fatal("规则未引用生成的 set")
	}
	if len(plan.Rules[0].Lines) != 2 || plan.Rules[0].Lines[0] != 1 || plan.Rules[0].Lines[1] != 2 {
		t.Fatalf("溯源行号错误: %v", plan.Rules[0].Lines)
	}
}

// TestDedupeConsecutive 相邻完全重复的规则去重。
func TestDedupeConsecutive(t *testing.T) {
	f := &ir.File{Rules: []ir.Rule{
		rule(1, "1.1.1.1", "*", ir.ProtoTCP, ports(port(80)), ir.VerdictAccept),
		rule(2, "1.1.1.1", "*", ir.ProtoTCP, ports(port(80)), ir.VerdictAccept),
	}}
	plan := optimize.Run(f)
	if len(plan.Rules) != 1 {
		t.Fatalf("期望去重为 1 条，实际 %d", len(plan.Rules))
	}
}

// TestMatchAllRuleLast 匹配一切的规则（兜底）保持在最后，且不参与归集。
func TestMatchAllRuleLast(t *testing.T) {
	all := ir.Rule{Line: 3, Raw: "log drop", Src: ir.Addr{Any: true}, Dst: ir.Addr{Any: true},
		Log: true, Verdict: ir.VerdictDrop}
	f := &ir.File{
		Rules: []ir.Rule{
			rule(1, "1.1.1.1", "*", ir.ProtoTCP, ports(port(80)), ir.VerdictAccept),
			rule(2, "2.2.2.2", "*", ir.ProtoTCP, ports(port(80)), ir.VerdictAccept),
			all,
		},
	}
	plan := optimize.Run(f)
	if len(plan.Rules) != 2 {
		t.Fatalf("期望 2 条（合并后的规则 + 兜底），实际 %d", len(plan.Rules))
	}
	last := plan.Rules[len(plan.Rules)-1]
	if !last.Src.Any || !last.Dst.Any || !last.Log || last.Verdict != ir.VerdictDrop {
		t.Fatalf("兜底规则位置或内容错误: %+v", last)
	}
}

// TestSetNameDeterministic 同样内容不同顺序应生成相同 set 名。
func TestSetNameDeterministic(t *testing.T) {
	a := optimize.MakeSetName("ipv4", []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"})
	b := optimize.MakeSetName("ipv4", []string{"3.3.3.3", "1.1.1.1", "2.2.2.2"})
	if a != b {
		t.Fatalf("set 名不确定: %s vs %s", a, b)
	}
	c := optimize.MakeSetName("ipv4", []string{"1.1.1.1", "2.2.2.2"})
	if a == c {
		t.Fatal("不同内容不应生成相同 set 名")
	}
}

// TestLogOnlyNotMergedOrDeduped 单独 log 的日志条数是可观测语义，不得归集或去重。
func TestLogOnlyNotMergedOrDeduped(t *testing.T) {
	logOnly := func(line int, src string) ir.Rule {
		r := rule(line, src, "*", ir.ProtoTCP, ports(port(80)), ir.VerdictAccept)
		r.Log = true
		r.LogOnly = true
		return r
	}
	f := &ir.File{Rules: []ir.Rule{
		logOnly(1, "1.1.1.1"),
		logOnly(2, "1.1.1.1"),
		logOnly(3, "2.2.2.2"),
	}}
	plan := optimize.Run(f)
	if len(plan.Rules) != 3 {
		t.Fatalf("log-only 规则不应去重/归集，期望 3 条，实际 %d", len(plan.Rules))
	}
	if len(plan.Sets) != 0 {
		t.Fatalf("log-only 规则不应生成 set，实际 %d", len(plan.Sets))
	}
}
