// Package errs 定义编译问题的统一表示：文件、行列、分类与错误码。
//
// 输出格式（见 SPEC §5）：
//
//	<file>:<line>:<col>: <category>: <code>: <message>
//	<file>: <category>: <code>: <message>      // 文件级问题，无行列
package errs

import (
	"fmt"
	"strconv"
	"strings"
)

// Category 是问题分类。
type Category string

const (
	CategorySyntax   Category = "syntax"
	CategorySemantic Category = "semantic"
	CategoryUsage    Category = "usage"
	CategoryWarning  Category = "warning"
)

// 错误码（SPEC §6）。
const (
	CodeDirective = "E100" // 文件头指令问题
	CodeSyntax    = "E101" // 词法/语法问题
	CodeSemantic  = "E102" // 字段组合等语义问题
	CodeUsage     = "E103" // CLI 用法问题
)

// 告警码（SPEC §6）。
const (
	CodeUnreachableRule = "W1" // 相同匹配、不同动作，后者不可达
	CodeV6BootstrapIdle = "W2" // 兜底 accept 时 v6-bootstrap 无作用
	CodeFallbackAccept  = "W3" // 兜底为 accept：未命中流量一律放行
)

// Problem 是错误与告警共有的定位信息。
type Problem struct {
	File string
	Line int
	Col  int
	Cat  Category
	Code string
	Msg  string
}

// Format 按 SPEC §5 的格式渲染一行。
func (p Problem) Format() string {
	var b strings.Builder
	if p.File != "" {
		b.WriteString(p.File)
		if p.Line > 0 {
			b.WriteString(":")
			b.WriteString(strconv.Itoa(p.Line))
			if p.Col > 0 {
				b.WriteString(":")
				b.WriteString(strconv.Itoa(p.Col))
			}
		}
		b.WriteString(": ")
	}
	b.WriteString(string(p.Cat))
	b.WriteString(": ")
	b.WriteString(p.Code)
	b.WriteString(": ")
	b.WriteString(p.Msg)
	return b.String()
}

// Error 是一条编译错误。
type Error struct{ Problem }

func (e *Error) Error() string { return e.Format() }

// Warning 是一条编译告警；它不影响退出码。
type Warning struct{ Problem }

// Errors 是多条错误的聚合，可同时用于 errors 接口与逐条打印。
type Errors []*Error

func (e Errors) Error() string {
	lines := make([]string, len(e))
	for i, item := range e {
		lines[i] = item.Error()
	}
	return strings.Join(lines, "\n")
}

// NewError 构造一条错误。
func NewError(file string, line, col int, cat Category, code, format string, args ...any) *Error {
	return &Error{Problem{
		File: file,
		Line: line,
		Col:  col,
		Cat:  cat,
		Code: code,
		Msg:  fmt.Sprintf(format, args...),
	}}
}

// NewWarning 构造一条告警。
func NewWarning(file string, line, col int, code, format string, args ...any) Warning {
	return Warning{Problem{
		File: file,
		Line: line,
		Col:  col,
		Cat:  CategoryWarning,
		Code: code,
		Msg:  fmt.Sprintf(format, args...),
	}}
}
