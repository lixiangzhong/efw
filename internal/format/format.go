// Package format 把 efw DSL 源文本归一为统一的缩进与 token 间距。
//
// 只做空白层面的改写：不重排 token、不删除注释、不改写等价语法；块体缩进
// 4 空格，单行块保持单行。输入应当是 parser 能解析的文本（由调用方先行校验）。
package format

import "strings"

const (
	// indentUnit 是块体每级缩进。
	indentUnit = "    "
	// inlineCommentGap 是代码与行内注释之间的固定间距。
	inlineCommentGap = "  "
	// setNameMaxLen 是命名集合名的最大长度（与 parser 的 `NAME {` 规则一致）。
	setNameMaxLen = 32
)

// blockKeywords 是可作块头的关键字（大小写不敏感）。
var blockKeywords = map[string]struct{}{
	"accept":     {},
	"drop":       {},
	"reject":     {},
	"masquerade": {},
}

// Source 返回格式化后的 DSL 文本，输出以单个换行结束。
//
// 处理规则：块体缩进 4 空格、`}` 回退一级；token 之间单空格（`->` 两侧各一）；
// 端口列表统一为 `{80, 443}`；行内注释前固定两个空格；连续空行折叠为一行；
// 末尾空行删除并保证以单个换行结束。单行块保持单行。
func Source(src []byte) []byte {
	text := strings.TrimPrefix(string(src), "\ufeff")
	text = strings.ReplaceAll(text, "\r\n", "\n")

	lines := make([]string, 0, 64)
	depth := 0
	prevBlank := false
	for _, raw := range strings.Split(text, "\n") {
		code, comment := splitComment(raw)
		code = strings.TrimSpace(code)
		if code == "" {
			if comment == "" {
				if !prevBlank {
					lines = append(lines, "")
					prevBlank = true
				}
				continue
			}
			lines = append(lines, pad(depth)+comment)
			prevBlank = false
			continue
		}

		switch {
		case code == "}":
			if depth > 0 {
				depth--
			}
			lines = append(lines, addComment(pad(depth)+"}", comment))
		case strings.HasSuffix(code, "{"):
			// 块头必须单独收尾在 `{`；端口列表的花括号不会出现在行尾。
			header := joinTokens(tokenize(strings.TrimSuffix(code, "{")))
			lines = append(lines, addComment(pad(depth)+header+" {", comment))
			depth++
		default:
			if header, content, ok := inlineBlock(code); ok {
				lines = append(lines, addComment(inlineBlockLine(depth, header, content), comment))
			} else {
				lines = append(lines, addComment(pad(depth)+joinTokens(tokenize(code)), comment))
			}
		}
		prevBlank = false
	}

	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) == 0 {
		return nil
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// splitComment 把一行拆成代码与行内注释（`#` 到行尾）；DSL 没有字符串，
// 第一个 `#` 即注释起点。
func splitComment(line string) (code, comment string) {
	if idx := strings.IndexByte(line, '#'); idx >= 0 {
		return line[:idx], strings.TrimRight(line[idx:], " \t\r")
	}
	return line, ""
}

// pad 返回指定缩进层级的空格。
func pad(depth int) string {
	return strings.Repeat(indentUnit, depth)
}

// addComment 在代码行尾追加行内注释。
func addComment(code, comment string) string {
	if comment == "" {
		return code
	}
	return code + inlineCommentGap + comment
}

// inlineBlock 识别单行块：`accept { ... }`、`masquerade { ... }`、`NAME { ... }`。
// 规则行里的端口列表（如 `1.1.1.1 -> {80, 443}`）块头不是关键字/集合名，不会误判。
func inlineBlock(code string) (header, content string, ok bool) {
	if !strings.HasSuffix(code, "}") {
		return "", "", false
	}
	open := strings.IndexByte(code, '{')
	if open < 0 {
		return "", "", false
	}
	header = strings.TrimSpace(code[:open])
	if !isBlockHeader(header) {
		return "", "", false
	}
	return header, joinTokens(tokenize(code[open+1 : len(code)-1])), true
}

// isBlockHeader 判断单行块头：块关键字，或命名集合的裸名字。
func isBlockHeader(text string) bool {
	if text == "" || strings.ContainsAny(text, " \t") {
		return false
	}
	if _, ok := blockKeywords[strings.ToLower(text)]; ok {
		return true
	}
	return isSetName(text)
}

// isSetName 与 parser 的命名集合名规则一致：字母/下划线开头，后接字母/数字/
// 下划线，长度 1-32。
func isSetName(text string) bool {
	if len(text) == 0 || len(text) > setNameMaxLen {
		return false
	}
	for i, r := range text {
		switch {
		case r == '_' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z'):
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

// inlineBlockLine 渲染单行块；空内容保持 `{}`，避免产生悬空空格。
func inlineBlockLine(depth int, header, content string) string {
	line := pad(depth) + header + " {"
	if content == "" {
		return line + "}"
	}
	return line + " " + content + " }"
}

// tokenize 把一行代码拆成 token：花括号与逗号作为独立符号，`->` 视为一个 token。
// DSL 没有字符串与转义，按字节扫描即可。
func tokenize(code string) []string {
	tokens := make([]string, 0, 8)
	for i := 0; i < len(code); {
		c := code[i]
		switch {
		case c == ' ' || c == '\t':
			i++
		case c == '{' || c == '}' || c == ',':
			tokens = append(tokens, string(c))
			i++
		case c == '-' && i+1 < len(code) && code[i+1] == '>':
			tokens = append(tokens, "->")
			i += 2
		default:
			start := i
			for i < len(code) {
				if c := code[i]; c == ' ' || c == '\t' || c == '{' || c == '}' || c == ',' {
					break
				}
				if code[i] == '-' && i+1 < len(code) && code[i+1] == '>' {
					break
				}
				i++
			}
			tokens = append(tokens, code[start:i])
		}
	}
	return tokens
}

// joinTokens 以单空格拼接 token；`{` 后与 `,`、`}` 前不留空格。
// `地址:端口列表`（如 `*:{80, 443}`）的 `{` 必须与冒号结尾的 token 连写，
// 否则 parser 会把 `*:` 当成缺少端口的地址:端口 token 而报错。
func joinTokens(tokens []string) string {
	var b strings.Builder
	for i, tok := range tokens {
		if i > 0 {
			prev := tokens[i-1]
			if tok != "," && tok != "}" && prev != "{" && !(tok == "{" && strings.HasSuffix(prev, ":")) {
				b.WriteByte(' ')
			}
		}
		b.WriteString(tok)
	}
	return b.String()
}
