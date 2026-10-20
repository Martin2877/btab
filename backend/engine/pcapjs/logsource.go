package pcapjs

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Martin2877/blue-team-box/engine/local/weblog"
)

// LogSource 日志数据源：把解析后的 web 访问日志包装成 Source 供行为脚本查询。
// 与 TsharkSource 的显示过滤器不同，这里使用轻量合取语法：
//
//	条件 ::= field op value（空格或 && 连接多个条件，取交集）
//	op   ::= = | != | ~ | !~ | > | >= | < | <=
//	field: no ip time method url path status bytes referer ua raw
//
// 说明：~ / !~ 按正则匹配（非法正则退化为子串包含）；
// status / bytes / no 为数值字段，= != > >= < <= 按数值比较；
// 其余字段 = / != 按精确比较（不区分大小写），> < 不适用会被忽略。
//
//	例：ip=1.2.3.4 && status>=400
//	    method=GET url~admin|login
type LogSource struct {
	Lines []weblog.Line
}

// logFields 字段名到取值函数；ua / useragent / agent 等价
var logFields = map[string]func(l *weblog.Line) string{
	"no":        func(l *weblog.Line) string { return strconv.Itoa(l.No) },
	"ip":        func(l *weblog.Line) string { return l.IP },
	"time":      func(l *weblog.Line) string { return l.Time },
	"method":    func(l *weblog.Line) string { return l.Method },
	"url":       func(l *weblog.Line) string { return l.URL },
	"path":      func(l *weblog.Line) string { return l.Path },
	"status":    func(l *weblog.Line) string { return strconv.Itoa(l.Status) },
	"bytes":     func(l *weblog.Line) string { return strconv.Itoa(l.Bytes) },
	"referer":   func(l *weblog.Line) string { return l.Referer },
	"ua":        func(l *weblog.Line) string { return l.UserAgent },
	"useragent": func(l *weblog.Line) string { return l.UserAgent },
	"agent":     func(l *weblog.Line) string { return l.UserAgent },
	"raw":       func(l *weblog.Line) string { return l.Raw },
}

var numericFields = map[string]bool{"no": true, "status": true, "bytes": true}

type logCond struct {
	field string
	op    string
	val   string
	num   int
	isNum bool
	re    *regexp.Regexp
	sub   string
}

// parseLogFilter 解析轻量过滤表达式；非法条件返回 error
func parseLogFilter(filter string) ([]logCond, error) {
	filter = strings.TrimSpace(strings.ReplaceAll(filter, "&&", " "))
	if filter == "" {
		return nil, nil
	}
	var conds []logCond
	for _, tok := range strings.Fields(filter) {
		c, err := parseLogCond(tok)
		if err != nil {
			return nil, err
		}
		conds = append(conds, c)
	}
	return conds, nil
}

var logOps = []string{"!=", "!~", ">=", "<=", "=", "~", ">", "<"}

func parseLogCond(tok string) (logCond, error) {
	var c logCond
	for _, op := range logOps {
		i := strings.Index(tok, op)
		if i <= 0 {
			continue
		}
		c.field, c.op, c.val = strings.ToLower(tok[:i]), op, tok[i+len(op):]
		break
	}
	if c.op == "" {
		return c, fmt.Errorf("日志过滤条件缺少操作符: %s", tok)
	}
	if _, ok := logFields[c.field]; !ok {
		return c, fmt.Errorf("未知日志字段: %s（可用: no ip time method url path status bytes referer ua raw）", c.field)
	}
	if numericFields[c.field] {
		c.num, _ = strconv.Atoi(c.val)
		c.isNum = true
	}
	if c.op == "~" || c.op == "!~" {
		if re, err := regexp.Compile("(?i)" + c.val); err == nil {
			c.re = re
		} else {
			c.sub = strings.ToLower(c.val)
		}
	}
	return c, nil
}

func (c *logCond) match(l *weblog.Line) bool {
	getter := logFields[c.field]
	v := getter(l)
	if c.isNum && (c.op == "=" || c.op == "!=" || c.op == ">" || c.op == ">=" || c.op == "<" || c.op == "<=") {
		n, err := strconv.Atoi(v)
		if err != nil {
			return c.op == "!=" // 字段缺失视为"不等于"
		}
		switch c.op {
		case "=":
			return n == c.num
		case "!=":
			return n != c.num
		case ">":
			return n > c.num
		case ">=":
			return n >= c.num
		case "<":
			return n < c.num
		case "<=":
			return n <= c.num
		}
	}
	switch c.op {
	case "=", "==":
		return strings.EqualFold(v, c.val)
	case "!=":
		return !strings.EqualFold(v, c.val)
	case "~":
		if c.re != nil {
			return c.re.MatchString(v)
		}
		return strings.Contains(strings.ToLower(v), c.sub)
	case "!~":
		if c.re != nil {
			return !c.re.MatchString(v)
		}
		return !strings.Contains(strings.ToLower(v), c.sub)
	}
	return true
}

// Query 实现 Source：按过滤条件返回行，fields 为空返回全部字段
func (s *LogSource) Query(filter string, fields []string) ([]map[string][]string, error) {
	conds, err := parseLogFilter(filter)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, f := range fields {
		f = strings.ToLower(strings.TrimSpace(f))
		if _, ok := logFields[f]; !ok {
			return nil, fmt.Errorf("未知日志字段: %s（可用: no ip time method url path status bytes referer ua raw）", f)
		}
		want[f] = true
	}
	var rows []map[string][]string
	for i := range s.Lines {
		l := &s.Lines[i]
		ok := true
		for _, c := range conds {
			if !c.match(l) {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		row := map[string][]string{}
		for name, getter := range logFields {
			if len(want) > 0 && !want[name] {
				continue
			}
			if v := getter(l); v != "" {
				row[name] = []string{v}
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}
