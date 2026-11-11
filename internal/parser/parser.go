// Package parser 把 DSL 文本解析为 ir.File。
//
// 解析器负责：文件头指令、动作块（accept/drop/reject { ... }）、匹配规则、
// 单独动作行（等价 action { * }）、地址/端口取值规范化，以及所有可在单行/单块内判定的语法与取值错误。
// 跨规则、跨指令的语义检查由 validate 包负责。
package parser

import (
	"bytes"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/lixiangzhong/efw/internal/errs"
	"github.com/lixiangzhong/efw/internal/ir"
)

// utf8BOM 是可能出现在文件头部的字节序标记。
const utf8BOM = "\xef\xbb\xbf"

// portItemRe 匹配单个端口项（80 或 80-90）。
var portItemRe = regexp.MustCompile(`^[0-9]+(-[0-9]+)?$`)

// directiveNames 是文件头指令名。
var directiveNames = map[string]struct{}{
	"established":  {},
	"v6-bootstrap": {},
}

// blockCtx 是当前动作块的上下文。
type blockCtx struct {
	verdict ir.Verdict
	line    int
	rules   int
}

// Parse 解析 DSL 文本。返回错误非空时文件不可编译。
func Parse(fileName string, src []byte) (*ir.File, errs.Errors) {
	p := &parser{fileName: fileName}
	p.run(src)
	if len(p.errs) > 0 {
		return nil, p.errs
	}
	return p.file, nil
}

type parser struct {
	fileName string
	file     *ir.File
	errs     errs.Errors

	estSet       bool
	v6Set        bool
	rulesStarted bool
	block        *blockCtx
}

func (p *parser) run(src []byte) {
	p.file = &ir.File{Established: true, V6Bootstrap: true}

	body := bytes.TrimPrefix(src, []byte(utf8BOM))
	for i, rawLine := range strings.Split(string(body), "\n") {
		p.parseLine(i+1, rawLine)
	}

	if p.block != nil {
		p.syntaxErr(p.block.line, "块未闭合（缺少 }）")
	}
}

func (p *parser) parseLine(lineNo int, rawLine string) {
	line := strings.TrimSuffix(rawLine, "\r")
	if idx := strings.IndexByte(line, '#'); idx >= 0 {
		line = line[:idx]
	}
	text := strings.TrimSpace(line)
	if text == "" {
		return
	}

	if text == "}" {
		p.closeBlock(lineNo)
		return
	}
	if verdict, content, ok := inlineBlock(text); ok {
		p.parseInlineBlock(lineNo, rawLine, verdict, content)
		return
	}
	if verdict, ok := blockHeaderVerdict(text); ok {
		p.openBlock(lineNo, verdict)
		return
	}
	if strings.HasSuffix(text, "{") {
		p.syntaxErr(lineNo, "块头格式错误（应为 accept|drop|reject {）或花括号未闭合")
		return
	}
	if p.block != nil {
		p.parseBlockRule(lineNo, rawLine, text)
		return
	}
	p.parseTopLine(lineNo, rawLine, text)
}

// inlineBlock 识别单行块：`accept { <一条规则> }`。
func inlineBlock(text string) (ir.Verdict, string, bool) {
	idx := strings.IndexByte(text, '{')
	if idx < 0 || !strings.HasSuffix(text, "}") {
		return 0, "", false
	}
	verdict, ok := parseVerdict(strings.TrimSpace(text[:idx]))
	if !ok {
		return 0, "", false
	}
	return verdict, strings.TrimSpace(text[idx+1 : len(text)-1]), true
}

// parseInlineBlock 解析单行块；内容按块内一条规则处理。
func (p *parser) parseInlineBlock(lineNo int, rawLine string, verdict ir.Verdict, content string) {
	if p.block != nil {
		p.syntaxErr(lineNo, "不支持嵌套块")
		return
	}
	if content == "" {
		p.syntaxErr(lineNo, "块内至少需要一条规则")
		return
	}
	if strings.Count(content, "{") != strings.Count(content, "}") {
		p.syntaxErr(lineNo, "端口列表的花括号不匹配")
		return
	}
	p.rulesStarted = true
	p.block = &blockCtx{verdict: verdict, line: lineNo}
	p.parseBlockRule(lineNo, rawLine, content)
	p.block = nil
}

// blockHeaderVerdict 判断一行是否是块头（accept|drop|reject {），返回块动作。
func blockHeaderVerdict(text string) (ir.Verdict, bool) {
	if !strings.HasSuffix(text, "{") {
		return 0, false
	}
	name := strings.TrimSpace(strings.TrimSuffix(text, "{"))
	fields := strings.Fields(name)
	if len(fields) != 1 {
		return 0, false
	}
	return parseVerdict(fields[0])
}

func (p *parser) openBlock(lineNo int, verdict ir.Verdict) {
	if p.block != nil {
		p.syntaxErr(lineNo, "不支持嵌套块")
		return
	}
	p.rulesStarted = true
	p.block = &blockCtx{verdict: verdict, line: lineNo}
}

func (p *parser) closeBlock(lineNo int) {
	if p.block == nil {
		p.syntaxErr(lineNo, "多余的 }（没有打开的块）")
		return
	}
	if p.block.rules == 0 {
		p.syntaxErr(p.block.line, "块内至少需要一条规则")
	}
	p.block = nil
}

func (p *parser) parseTopLine(lineNo int, rawLine, text string) {
	fields := strings.Fields(text)
	first := strings.ToLower(fields[0])
	switch {
	case first == "default":
		p.directiveErr(lineNo, "default 指令已移除：未命中策略改由文件末尾的兜底规则表达（如 drop { * } 或收尾 drop）")
	case isDirective(first):
		p.parseDirective(lineNo, fields)
	case isVerdictWord(first) || first == "log":
		p.parseActionOnlyRule(lineNo, rawLine, fields)
	default:
		if looksLikeUnknownDirective(fields) {
			p.directiveErr(lineNo, "未知指令 %q", fields[0])
			return
		}
		p.parseRule(lineNo, rawLine, text)
	}
}

func (p *parser) parseDirective(lineNo int, fields []string) {
	name := strings.ToLower(fields[0])
	if p.rulesStarted {
		p.directiveErr(lineNo, "指令 %s 必须位于所有规则之前", name)
		return
	}
	if len(fields) != 2 {
		p.syntaxErr(lineNo, "指令 %s 需要一个参数", name)
		return
	}
	value := strings.ToLower(fields[1])

	switch name {
	case "established":
		if p.estSet {
			p.directiveErr(lineNo, "established 指令重复")
			return
		}
		v, ok := parseAutoOff(value)
		if !ok {
			p.semanticErr(lineNo, "established 只接受 auto 或 off，得到 %q", fields[1])
			return
		}
		p.file.Established = v
		p.estSet = true
	case "v6-bootstrap":
		if p.v6Set {
			p.directiveErr(lineNo, "v6-bootstrap 指令重复")
			return
		}
		v, ok := parseAutoOff(value)
		if !ok {
			p.semanticErr(lineNo, "v6-bootstrap 只接受 auto 或 off，得到 %q", fields[1])
			return
		}
		p.file.V6Bootstrap = v
		p.v6Set = true
	}
}

// parseActionOnlyRule 解析单独一行的动作：等价于 `verdict { * }`（匹配一切的兜底规则）。
// 它是一条普通规则，是否位于最后由 validate 检查。
func (p *parser) parseActionOnlyRule(lineNo int, rawLine string, fields []string) {
	p.rulesStarted = true
	log := false
	idx := 0
	if strings.ToLower(fields[0]) == "log" {
		log = true
		idx = 1
	}
	if idx >= len(fields) {
		p.syntaxErr(lineNo, "动作行缺少动作（accept|drop|reject）")
		return
	}
	if len(fields) != idx+1 {
		p.syntaxErr(lineNo, "动作行格式应为 [log] accept|drop|reject（等价于 drop { * }）")
		return
	}
	verdict, ok := parseVerdict(fields[idx])
	if !ok {
		p.syntaxErr(lineNo, "%q 不是合法动作（accept|drop|reject）", fields[idx])
		return
	}
	p.appendRule(lineNo, rawLine, ir.Addr{Any: true}, ir.Addr{Any: true},
		ir.ProtoAny, ir.PortSet{}, log, false, verdict)
}

func (p *parser) parseRule(lineNo int, rawLine, text string) {
	p.rulesStarted = true

	arrow := strings.Index(text, "->")
	if arrow < 0 {
		p.parseShortRule(lineNo, rawLine, text)
		return
	}
	parts, ok := p.parseRuleWithArrow(lineNo, text, true, ir.VerdictAccept)
	if !ok {
		return
	}
	if !p.checkFamilies(lineNo, parts.src, parts.dst) {
		return
	}
	p.appendRule(lineNo, rawLine, parts.src, parts.dst, parts.proto, parts.ports, parts.log, parts.logOnly, parts.verdict)
}

// ruleParts 是一条规则解析完成的中间结果。
type ruleParts struct {
	src     ir.Addr
	dst     ir.Addr
	proto   ir.Proto
	ports   ir.PortSet
	log     bool
	logOnly bool
	verdict ir.Verdict
}

// parseRuleWithArrow 解析带 -> 的规则主体。
//
// actionRequired=true 时必须显式写动作（顶层规则）；
// actionRequired=false 时动作可省略并继承 blockVerdict（动作块内规则），
// 显式动作必须与 blockVerdict 一致。协议 token 可出现在匹配部分的任意位置且最多一次。
func (p *parser) parseRuleWithArrow(lineNo int, text string, actionRequired bool, blockVerdict ir.Verdict) (ruleParts, bool) {
	var parts ruleParts

	arrow := strings.Index(text, "->")
	if arrow < 0 {
		p.syntaxErr(lineNo, "规则缺少 ->")
		return parts, false
	}
	if strings.Contains(text[arrow+2:], "->") {
		p.syntaxErr(lineNo, "规则中出现多个 ->")
		return parts, false
	}
	lhsText := strings.TrimSpace(text[:arrow])
	rhsText := strings.TrimSpace(text[arrow+2:])
	if lhsText == "" || rhsText == "" {
		p.syntaxErr(lineNo, "-> 两侧都不能为空")
		return parts, false
	}
	if strings.Count(rhsText, "{") != strings.Count(rhsText, "}") {
		p.syntaxErr(lineNo, "端口列表的花括号不匹配")
		return parts, false
	}

	fields := splitRuleFields(rhsText)
	if len(fields) == 0 {
		p.syntaxErr(lineNo, "规则缺少动作与匹配部分")
		return parts, false
	}

	var matchTokens []string
	if actionRequired {
		verdict, log, logOnly, matchCount, ok := p.parseActionTokens(lineNo, fields)
		if !ok {
			return parts, false
		}
		parts.verdict, parts.log, parts.logOnly = verdict, log, logOnly
		matchTokens = fields[:matchCount]
	} else {
		log := false
		n := len(fields)
		if n > 0 {
			last := strings.ToLower(fields[n-1])
			if last == "log" {
				log = true
				n--
			} else if v, ok := parseVerdict(fields[n-1]); ok {
				if v != blockVerdict {
					p.semanticErr(lineNo, "块内规则动作必须与块头一致（块为 %s）", blockVerdict)
					return parts, false
				}
				n--
				if n > 0 && strings.EqualFold(fields[n-1], "log") {
					log = true
					n--
				}
			}
		}
		parts.verdict, parts.log = blockVerdict, log
		matchTokens = fields[:n]
	}
	if len(matchTokens) == 0 {
		p.syntaxErr(lineNo, "规则缺少匹配部分")
		return parts, false
	}
	matchTokens = mergePortListFragments(matchTokens)

	lhsTokens := splitRuleFields(lhsText)
	if len(lhsTokens) == 0 {
		p.syntaxErr(lineNo, "缺少源地址")
		return parts, false
	}
	proto, lhsTokens, found, ok := p.extractProtoTokens(lineNo, lhsTokens, ir.ProtoAny, false)
	if !ok {
		return parts, false
	}
	proto, matchTokens, _, ok = p.extractProtoTokens(lineNo, matchTokens, proto, found)
	if !ok {
		return parts, false
	}
	parts.proto = proto

	if len(lhsTokens) != 1 {
		p.syntaxErr(lineNo, "源地址只能有一个 token（协议请单独写）")
		return parts, false
	}
	src, ok := p.parseSrcToken(lineNo, lhsTokens[0])
	if !ok {
		return parts, false
	}
	parts.src = src

	dst, ports, ok := p.parseRhsMatchTokens(lineNo, matchTokens)
	if !ok {
		return parts, false
	}
	parts.dst, parts.ports = dst, ports
	return parts, true
}

// parseShortRule 解析省略 -> 的简写：src [proto] [log] action，等价 src -> *://*:*。
func (p *parser) parseShortRule(lineNo int, rawLine, text string) {
	fields := splitRuleFields(text)
	if len(fields) == 0 {
		p.syntaxErr(lineNo, "规则缺少 ->")
		return
	}
	if allPortTokens(fields) {
		p.syntaxErr(lineNo, "无箭头简写需要动作（如 `80 443 accept`；块内可省略）")
		return
	}
	verdict, log, logOnly, matchCount, ok := p.parseActionTokens(lineNo, fields)
	if !ok {
		return
	}
	matchTokens := mergePortListFragments(fields[:matchCount])
	proto, rest, _, ok := p.extractProtoTokens(lineNo, matchTokens, ir.ProtoAny, false)
	if !ok {
		return
	}
	if len(rest) > 0 && hasPortSemantics(rest) {
		// 含端口的 token 不可能是源地址（本语法无源端口）：
		// 视为隐式 * 源的目的地址/端口，如 `10.0.0.1:80 accept` ≡ `* -> 10.0.0.1:80 accept`。
		dst, ports, ok := p.parseRhsMatchTokens(lineNo, rest)
		if !ok {
			return
		}
		p.appendRule(lineNo, rawLine, ir.Addr{Any: true}, dst, proto, ports, log, logOnly, verdict)
		return
	}
	if len(rest) == 0 {
		// 只有协议 token（如 `tcp4 accept`）：隐式 * 源，等价 `* -> tcp4`。
		if proto == ir.ProtoAny {
			p.syntaxErr(lineNo, "无箭头简写缺少匹配部分")
			return
		}
		p.appendRule(lineNo, rawLine, ir.Addr{Any: true}, ir.Addr{Any: true}, proto, ir.PortSet{}, log, logOnly, verdict)
		return
	}
	if len(rest) != 1 {
		p.syntaxErr(lineNo, "无箭头写法只能写「协议? 源地址」或「协议? 端口」")
		return
	}
	src, ok := p.parseSrcToken(lineNo, rest[0])
	if !ok {
		return
	}
	p.appendRule(lineNo, rawLine, src, ir.Addr{Any: true}, proto, ir.PortSet{}, log, logOnly, verdict)
}

// parseBlockRule 解析动作块内的规则：action 可省略（继承块动作），显式动作必须与块一致。
func (p *parser) parseBlockRule(lineNo int, rawLine, text string) {
	verdict := p.block.verdict
	fields := strings.Fields(text)
	first := strings.ToLower(fields[0])
	if isDirective(first) || first == "default" {
		p.directiveErr(lineNo, "指令不能出现在块内")
		return
	}
	if isVerdictWord(first) || first == "log" {
		p.semanticErr(lineNo, "动作行不能出现在块内（块内规则只写匹配条件；兜底写 `*`）")
		return
	}

	arrow := strings.Index(text, "->")
	if arrow < 0 {
		p.parseBlockShortRule(lineNo, rawLine, text, verdict)
		return
	}
	parts, ok := p.parseRuleWithArrow(lineNo, text, false, verdict)
	if !ok {
		return
	}
	if !p.checkFamilies(lineNo, parts.src, parts.dst) {
		return
	}
	p.appendRule(lineNo, rawLine, parts.src, parts.dst, parts.proto, parts.ports, parts.log, parts.logOnly, parts.verdict)
	p.block.rules++
}

// parseBlockShortRule 解析块内无箭头规则：src [proto] [log] [动作]，等价 src -> *://*:*。
func (p *parser) parseBlockShortRule(lineNo int, rawLine, text string, verdict ir.Verdict) {
	fields := splitRuleFields(text)
	log := false
	n := len(fields)
	if n > 0 {
		last := strings.ToLower(fields[n-1])
		if last == "log" {
			log = true
			n--
		} else if v, ok := parseVerdict(fields[n-1]); ok {
			if v != verdict {
				p.semanticErr(lineNo, "块内规则动作必须与块头一致（块为 %s）", verdict)
				return
			}
			n--
			if n > 0 && strings.EqualFold(fields[n-1], "log") {
				log = true
				n--
			}
		}
	}
	matchTokens := mergePortListFragments(fields[:n])
	proto, rest, _, ok := p.extractProtoTokens(lineNo, matchTokens, ir.ProtoAny, false)
	if !ok {
		return
	}
	if len(rest) > 0 && hasPortSemantics(rest) {
		// 含端口的 token 不可能是源地址：视为隐式 * 源的目的地址/端口。
		dst, ports, ok := p.parseRhsMatchTokens(lineNo, rest)
		if !ok {
			return
		}
		p.appendRule(lineNo, rawLine, ir.Addr{Any: true}, dst, proto, ports, log, false, verdict)
		p.block.rules++
		return
	}
	if len(rest) == 0 {
		// 只有协议 token（如 `accept{ tcp4 }`）：隐式 * 源，等价 `* -> tcp4`。
		if proto == ir.ProtoAny {
			p.syntaxErr(lineNo, "块内无箭头写法缺少匹配部分")
			return
		}
		p.appendRule(lineNo, rawLine, ir.Addr{Any: true}, ir.Addr{Any: true}, proto, ir.PortSet{}, log, false, verdict)
		p.block.rules++
		return
	}
	if len(rest) != 1 {
		p.syntaxErr(lineNo, "块内无箭头写法只能写「协议? 源地址」或「协议? 端口」")
		return
	}
	src, ok := p.parseSrcToken(lineNo, rest[0])
	if !ok {
		return
	}
	p.appendRule(lineNo, rawLine, src, ir.Addr{Any: true}, proto, ir.PortSet{}, log, false, verdict)
	p.block.rules++
}

// parseActionTokens 从右侧解析 [log] verdict 或单独的 log，返回匹配字段个数。
func (p *parser) parseActionTokens(lineNo int, fields []string) (verdict ir.Verdict, log, logOnly bool, matchCount int, ok bool) {
	n := len(fields)
	switch strings.ToLower(fields[n-1]) {
	case "accept", "drop", "reject":
		verdict, _ = parseVerdict(fields[n-1])
		n--
	case "log":
		logOnly = true
		n--
	default:
		p.syntaxErr(lineNo, "%q 不是合法动作（accept|drop|reject|log）", fields[n-1])
		return 0, false, false, 0, false
	}
	if !logOnly && n >= 1 && strings.EqualFold(fields[n-1], "log") {
		log = true
		n--
		if n >= 1 && strings.EqualFold(fields[n-1], "log") {
			p.syntaxErr(lineNo, "log 重复出现")
			return 0, false, false, 0, false
		}
	}
	return verdict, log, logOnly, n, true
}

// allPortTokens 判断 tokens 是否全部是端口/范围/列表（裸端口行的隐式 * 源简写）。
func allPortTokens(tokens []string) bool {
	if len(tokens) == 0 {
		return false
	}
	for _, tok := range tokens {
		if !looksLikePortSet(tok) {
			return false
		}
	}
	return true
}

// hasPortSemantics 判断无箭头写法的匹配 token 中是否包含端口语义
// （纯端口、addr:port、[v6]:port）。由于本语法不存在源端口，
// 含端口的 token 不可能是源地址，可安全地按「隐式 * 源的目的地址」解析。
func hasPortSemantics(tokens []string) bool {
	for _, tok := range tokens {
		if looksLikePortSet(tok) {
			return true
		}
		if strings.HasPrefix(tok, "[") {
			end := strings.IndexByte(tok, ']')
			if end < 0 || end+1 >= len(tok) || tok[end+1] != ':' {
				continue
			}
			if looksLikePortSet(tok[end+2:]) {
				return true
			}
			continue
		}
		if strings.Count(tok, ":") == 1 {
			idx := strings.IndexByte(tok, ':')
			if looksLikePortSet(tok[idx+1:]) {
				return true
			}
		}
	}
	return false
}

// protoWord 识别协议 token。
func protoWord(raw string) (ir.Proto, bool) {
	switch strings.ToLower(raw) {
	case "tcp":
		return ir.ProtoTCP, true
	case "udp":
		return ir.ProtoUDP, true
	case "icmp":
		return ir.ProtoICMP, true
	case "tcp4":
		return ir.ProtoTCP4, true
	case "tcp6":
		return ir.ProtoTCP6, true
	case "udp4":
		return ir.ProtoUDP4, true
	case "udp6":
		return ir.ProtoUDP6, true
	case "icmp4":
		return ir.ProtoICMP4, true
	case "icmp6":
		return ir.ProtoICMP6, true
	default:
		return ir.ProtoAny, false
	}
}

// extractProtoTokens 从 tokens 中移除协议 token；found 记录此前是否已出现过协议。
func (p *parser) extractProtoTokens(lineNo int, tokens []string, proto ir.Proto, found bool) (ir.Proto, []string, bool, bool) {
	out := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		if pw, ok := protoWord(tok); ok {
			if found {
				p.semanticErr(lineNo, "协议 token 只能出现一次")
				return proto, nil, found, false
			}
			proto, found = pw, true
			continue
		}
		out = append(out, tok)
	}
	return proto, out, found, true
}

// mergePortListFragments 把被空白拆开的裸端口列表片段拼回去（80, 443 → 80,443）。
func mergePortListFragments(tokens []string) []string {
	out := make([]string, 0, len(tokens))
	for i := 0; i < len(tokens); i++ {
		cur := tokens[i]
		for strings.HasSuffix(cur, ",") && i+1 < len(tokens) {
			i++
			cur += tokens[i]
		}
		out = append(out, cur)
	}
	return out
}

// parseSrcToken 解析源地址（不允许带端口）。
func (p *parser) parseSrcToken(lineNo int, raw string) (ir.Addr, bool) {
	if strings.Contains(raw, "://") {
		p.syntaxErr(lineNo, "`://` 语法已移除：协议请写成独立 token（如 `tcp 1.1.1.1 -> 80`）")
		return ir.Addr{}, false
	}
	src, msg := parseAddr(raw)
	if msg != "" {
		if strings.Contains(raw, ":") {
			p.semanticErr(lineNo, "源地址不能带端口：%s", msg)
		} else {
			p.semanticErr(lineNo, "%s", msg)
		}
		return ir.Addr{}, false
	}
	return src, true
}

// tokenKind 是右侧匹配 token 的类别。
type tokenKind uint8

const (
	tokenAddr tokenKind = iota
	tokenPort
	tokenAddrPort
)

// parseRhsMatchTokens 把右侧匹配 token 归类为目的地与端口。
// 目的地地址最多一个；端口 token 可以多个（自动取并集）。
func (p *parser) parseRhsMatchTokens(lineNo int, tokens []string) (ir.Addr, ir.PortSet, bool) {
	dst := ir.Addr{Any: true}
	var ranges []ir.PortRange
	haveAddr := false

	for _, tok := range tokens {
		kind, addrVal, portVal, ok := p.classifyToken(lineNo, tok)
		if !ok {
			return ir.Addr{}, ir.PortSet{}, false
		}
		switch kind {
		case tokenAddr:
			if haveAddr {
				p.semanticErr(lineNo, "目的地址只能出现一次")
				return ir.Addr{}, ir.PortSet{}, false
			}
			dst, haveAddr = addrVal, true
		case tokenPort:
			ranges = append(ranges, portVal.Ranges...)
		case tokenAddrPort:
			if haveAddr {
				p.semanticErr(lineNo, "目的地址只能出现一次")
				return ir.Addr{}, ir.PortSet{}, false
			}
			dst, haveAddr = addrVal, true
			ranges = append(ranges, portVal.Ranges...)
		}
	}
	var ports ir.PortSet
	if len(ranges) > 0 {
		ports = ir.PortSet{Ranges: ir.MergePortRanges(ranges)}
	}
	return dst, ports, true
}

// classifyToken 判断单个右侧 token 是地址、端口，还是「地址:端口」。
func (p *parser) classifyToken(lineNo int, raw string) (tokenKind, ir.Addr, ir.PortSet, bool) {
	if strings.Contains(raw, "://") {
		p.syntaxErr(lineNo, "`://` 语法已移除：协议请写成独立 token，目的地址直接写（如 `tcp 10.0.0.1:80`）")
		return tokenAddr, ir.Addr{}, ir.PortSet{}, false
	}
	if strings.HasPrefix(raw, "[") {
		end := strings.IndexByte(raw, ']')
		if end < 0 {
			p.syntaxErr(lineNo, "IPv6 方括号未闭合")
			return tokenAddr, ir.Addr{}, ir.PortSet{}, false
		}
		addrText := raw[1:end]
		if addrText == "" || addrText == "*" {
			p.semanticErr(lineNo, "方括号内必须是 IPv6 地址或 CIDR")
			return tokenAddr, ir.Addr{}, ir.PortSet{}, false
		}
		dst, msg := parseAddr(addrText)
		if msg != "" {
			p.semanticErr(lineNo, "%s", msg)
			return tokenAddr, ir.Addr{}, ir.PortSet{}, false
		}
		if dst.Family != ir.FamilyIPv6 {
			p.semanticErr(lineNo, "方括号只能用于 IPv6 地址")
			return tokenAddr, ir.Addr{}, ir.PortSet{}, false
		}
		after := raw[end+1:]
		if after == "" {
			return tokenAddr, dst, ir.PortSet{}, true
		}
		if !strings.HasPrefix(after, ":") {
			p.syntaxErr(lineNo, "方括号地址后只能跟 :端口")
			return tokenAddr, ir.Addr{}, ir.PortSet{}, false
		}
		ports, ok := p.parsePorts(lineNo, after[1:])
		if !ok {
			return tokenAddr, ir.Addr{}, ir.PortSet{}, false
		}
		return tokenAddrPort, dst, ports, true
	}
	if looksLikePortSet(raw) {
		ports, ok := p.parsePorts(lineNo, raw)
		if !ok {
			return tokenAddr, ir.Addr{}, ir.PortSet{}, false
		}
		return tokenPort, ir.Addr{}, ports, true
	}
	if strings.Count(raw, ":") == 1 {
		idx := strings.IndexByte(raw, ':')
		host, portText := raw[:idx], raw[idx+1:]
		if host == "*" || isIPv4(host) {
			dst := ir.Addr{Any: true}
			if host != "*" {
				dst, _ = parseAddr(host)
			}
			ports, ok := p.parsePorts(lineNo, portText)
			if !ok {
				return tokenAddr, ir.Addr{}, ir.PortSet{}, false
			}
			return tokenAddrPort, dst, ports, true
		}
		if strings.Contains(host, ".") {
			p.semanticErr(lineNo, "地址 %q 不是合法的 IPv4/CIDR", host)
			return tokenAddr, ir.Addr{}, ir.PortSet{}, false
		}
	}
	if dst, msg := parseAddr(raw); msg == "" {
		return tokenAddr, dst, ir.PortSet{}, true
	}
	if isIdentifierWord(raw) {
		p.semanticErr(lineNo, "未知协议 token %q（tcp|udp|icmp）", raw)
		return tokenAddr, ir.Addr{}, ir.PortSet{}, false
	}
	p.syntaxErr(lineNo, "目的地址/端口写法无法识别：%q", raw)
	return tokenAddr, ir.Addr{}, ir.PortSet{}, false
}

func (p *parser) parsePorts(lineNo int, raw string) (ir.PortSet, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		p.syntaxErr(lineNo, "端口为空")
		return ir.PortSet{}, false
	}
	if raw == "*" {
		return ir.PortSet{}, true
	}

	items, msg := splitPortItems(raw)
	if msg != "" {
		p.syntaxErr(lineNo, "%s", msg)
		return ir.PortSet{}, false
	}

	ranges := make([]ir.PortRange, 0, len(items))
	for _, item := range items {
		lo, hi, msg := parsePortItem(item)
		if msg != "" {
			p.semanticErr(lineNo, "%s", msg)
			return ir.PortSet{}, false
		}
		ranges = append(ranges, ir.PortRange{Lo: lo, Hi: hi})
	}
	return ir.PortSet{Ranges: ir.MergePortRanges(ranges)}, true
}

func (p *parser) appendRule(lineNo int, rawLine string, src, dst ir.Addr, proto ir.Proto, ports ir.PortSet, log, logOnly bool, verdict ir.Verdict) {
	p.file.Rules = append(p.file.Rules, ir.Rule{
		Line:    lineNo,
		Raw:     rawLine,
		Src:     src,
		Dst:     dst,
		Proto:   proto,
		Ports:   ports,
		Log:     log,
		LogOnly: logOnly,
		Verdict: verdict,
	})
}

func (p *parser) checkFamilies(lineNo int, src, dst ir.Addr) bool {
	if src.HasFamily() && dst.HasFamily() && src.Family != dst.Family {
		hint := ""
		if src.Family == ir.FamilyIPv6 || dst.Family == ir.FamilyIPv6 {
			hint = "（如需给 IPv6 地址指定端口，请用方括号写成 [地址]:端口）"
		}
		p.semanticErr(lineNo, "源地址与目的地址的地址族不一致（v4 与 v6 不能混写）%s", hint)
		return false
	}
	return true
}

func (p *parser) syntaxErr(lineNo int, format string, args ...any) {
	p.errs = append(p.errs, errs.NewError(p.fileName, lineNo, 0, errs.CategorySyntax, errs.CodeSyntax, format, args...))
}

func (p *parser) semanticErr(lineNo int, format string, args ...any) {
	p.errs = append(p.errs, errs.NewError(p.fileName, lineNo, 0, errs.CategorySemantic, errs.CodeSemantic, format, args...))
}

func (p *parser) directiveErr(lineNo int, format string, args ...any) {
	p.errs = append(p.errs, errs.NewError(p.fileName, lineNo, 0, errs.CategorySemantic, errs.CodeDirective, format, args...))
}

// splitRuleFields 按空白切分规则右侧，但保留 {} 端口列表内部的空白。
func splitRuleFields(s string) []string {
	var fields []string
	var cur strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '{':
			depth++
			cur.WriteRune(r)
		case r == '}':
			if depth > 0 {
				depth--
			}
			cur.WriteRune(r)
		case unicode.IsSpace(r) && depth == 0:
			if cur.Len() > 0 {
				fields = append(fields, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		fields = append(fields, cur.String())
	}
	return fields
}

// splitPortItems 拆分端口列表：支持 {80,443} 与裸写的 80,443，元素内部允许空格。
func splitPortItems(raw string) ([]string, string) {
	inner := raw
	if strings.HasPrefix(inner, "{") {
		if !strings.HasSuffix(inner, "}") {
			return nil, "端口列表缺少右花括号"
		}
		inner = strings.TrimSpace(inner[1 : len(inner)-1])
	}
	if inner == "" {
		return nil, "端口列表为空"
	}
	parts := strings.Split(inner, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, "端口列表含空元素"
		}
		items = append(items, part)
	}
	return items, ""
}

// looksLikePortSet 判断一段文本是否是端口/范围/列表，用于「只写端口」简写。
func looksLikePortSet(raw string) bool {
	s := strings.TrimSpace(raw)
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, "{") {
		if !strings.HasSuffix(s, "}") {
			return false
		}
		s = strings.TrimSpace(s[1 : len(s)-1])
		if s == "" {
			return true // 交由 parsePorts 报「端口列表为空」
		}
	}
	parts := strings.Split(s, ",")
	for _, item := range parts {
		item = strings.TrimSpace(item)
		if item == "" {
			// 空端口项（如 "80," / "80,,443"）仍视为端口列表，
			// 交由 parsePorts 报出精确的「含空元素」错误。
			return len(parts) > 1
		}
		if !portItemRe.MatchString(item) {
			return false
		}
	}
	return true
}

// parseAddr 解析 * / IPv4 / IPv6 / CIDR，返回规范化文本。
// 族判定按书写形式保留（IPv4-mapped IPv6 仍视为 IPv6，不会被折叠成 IPv4）。
func parseAddr(raw string) (ir.Addr, string) {
	if raw == "*" {
		return ir.Addr{Any: true}, ""
	}
	if strings.Contains(raw, "/") {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return ir.Addr{}, fmt.Sprintf("地址 %q 不是合法的 CIDR", raw)
		}
		prefix = prefix.Masked()
		family := ir.FamilyIPv6
		if prefix.Addr().Is4() {
			family = ir.FamilyIPv4
		}
		return ir.Addr{Family: family, Value: prefix.String()}, ""
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return ir.Addr{}, fmt.Sprintf("地址 %q 不合法", raw)
	}
	family := ir.FamilyIPv6
	if addr.Is4() {
		family = ir.FamilyIPv4
	}
	return ir.Addr{Family: family, Value: addr.String()}, ""
}

func isIPv4(raw string) bool {
	addr, msg := parseAddr(raw)
	return msg == "" && addr.Family == ir.FamilyIPv4
}

func parsePortItem(item string) (uint16, uint16, string) {
	if strings.Contains(item, "-") {
		parts := strings.Split(item, "-")
		if len(parts) != 2 {
			return 0, 0, fmt.Sprintf("端口范围 %q 不合法", item)
		}
		lo, msg := parsePortNumber(parts[0])
		if msg != "" {
			return 0, 0, msg
		}
		hi, msg := parsePortNumber(parts[1])
		if msg != "" {
			return 0, 0, msg
		}
		if lo > hi {
			return 0, 0, fmt.Sprintf("端口范围 %q 起点大于终点", item)
		}
		return lo, hi, ""
	}
	n, msg := parsePortNumber(item)
	if msg != "" {
		return 0, 0, msg
	}
	return n, n, ""
}

func parsePortNumber(raw string) (uint16, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, "端口为空"
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Sprintf("端口 %q 不是数字", raw)
	}
	if n < 1 || n > 65535 {
		return 0, fmt.Sprintf("端口 %q 越界（1-65535）", raw)
	}
	return uint16(n), ""
}

func parseVerdict(raw string) (ir.Verdict, bool) {
	switch strings.ToLower(raw) {
	case "accept":
		return ir.VerdictAccept, true
	case "drop":
		return ir.VerdictDrop, true
	case "reject":
		return ir.VerdictReject, true
	default:
		return ir.VerdictAccept, false
	}
}

func parseAutoOff(raw string) (bool, bool) {
	switch strings.ToLower(raw) {
	case "auto":
		return true, true
	case "off":
		return false, true
	default:
		return false, false
	}
}

func isDirective(name string) bool {
	_, ok := directiveNames[name]
	return ok
}

func isVerdictWord(word string) bool {
	_, ok := parseVerdict(word)
	return ok
}

func looksLikeUnknownDirective(fields []string) bool {
	if len(fields) < 2 {
		return false
	}
	if !isIdentifierWord(fields[0]) {
		return false
	}
	switch strings.ToLower(fields[1]) {
	case "deny", "allow", "auto", "off":
		return true
	default:
		return false
	}
}

func isIdentifierWord(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 {
			if !unicode.IsLetter(r) {
				return false
			}
			continue
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			return false
		}
	}
	return true
}
