// Package urldetect URL 检测引擎：对日志/请求中的 URI 与 UA 等位置做
// 正则规则匹配，并叠加 libinjection 对解码后的参数值做 SQLi/XSS 检测。
package urldetect

import (
	"net/url"
	"regexp"

	"github.com/Martin2877/blue-team-box/engine/local/sqli"
	"github.com/Martin2877/blue-team-box/engine/local/weblog"
	"github.com/corazawaf/libinjection-go"
)

// Rule 编译前的规则描述（与 db.UrlRule 字段对齐，引擎本身不依赖 db 层）
type Rule struct {
	RuleId     string
	Name       string
	Regex      string
	Place      string // url | useragent | referer
	Level      string
	TypeName   string
	ActionDesc string
}

// Hit 一次规则/内建检测命中
type Hit struct {
	RuleId     string `json:"rule_id"`
	Name       string `json:"name"`
	Place      string `json:"place"`
	Level      string `json:"level"`
	TypeName   string `json:"type_name"`
	ActionDesc string `json:"action_desc"`
	Value      string `json:"value"`   // 被检测的原始值（url/ua/referer）
	Matched    string `json:"matched"` // 命中的子串/指纹
	Engine     string `json:"engine"`  // url规则 | libinjection
	Line       int    `json:"line"`
	IP         string `json:"ip"`
	Method     string `json:"method"`
	Status     int    `json:"status"`
}

type compiledRule struct {
	Rule
	re *regexp.Regexp
}

// Scanner 已编译规则集
type Scanner struct {
	rules []compiledRule
	// Libinjection 是否叠加 SQLi/XSS 词法检测（解码后参数值）
	Libinjection bool
}

// New 编译规则；无效正则被跳过
func New(rules []Rule) *Scanner {
	s := &Scanner{Libinjection: true}
	for _, r := range rules {
		re, err := regexp.Compile(r.Regex)
		if err != nil {
			continue
		}
		s.rules = append(s.rules, compiledRule{Rule: r, re: re})
	}
	return s
}

func (s *Scanner) Len() int { return len(s.rules) }

// decodeOnce URL 解码一次（失败/无变化返回原值），减少规则对编码形态的重复
func decodeOnce(v string) string {
	if d, err := url.QueryUnescape(v); err == nil && d != v {
		return d
	}
	return v
}

// ScanValue 对单个值按位置匹配规则，返回命中（每条规则至多一条命中）
func (s *Scanner) ScanValue(place, value string) []Hit {
	if value == "" {
		return nil
	}
	decoded := decodeOnce(value)
	var hits []Hit
	for _, r := range s.rules {
		if r.Place != place {
			continue
		}
		m := r.re.FindString(value)
		if m == "" && decoded != value {
			m = r.re.FindString(decoded)
		}
		if m == "" {
			continue
		}
		hits = append(hits, Hit{
			RuleId: r.RuleId, Name: r.Name, Place: place,
			Level: r.Level, TypeName: r.TypeName, ActionDesc: r.ActionDesc,
			Value: value, Matched: m, Engine: "url规则",
		})
	}
	return hits
}

// libinjectionScan 对解码后的 URI 与 query 参数值做 SQLi/XSS 词法检测
func (s *Scanner) libinjectionScan(rawURL string) []Hit {
	decoded := decodeOnce(rawURL)
	var hits []Hit
	if ok, fp := sqli.Check(decoded); ok {
		hits = append(hits, Hit{
			RuleId: "lib-sqli", Name: "SQL注入特征（词法检测）", Place: "url",
			Level: "high", TypeName: "SQL注入攻击", ActionDesc: "URI 含 SQL 注入词法特征：" + fp,
			Value: rawURL, Matched: fp, Engine: "libinjection",
		})
	}
	// XSS：原始 URI、解码 URI 与每个参数值各测一次
	values := map[string]struct{}{rawURL: {}, decoded: {}}
	if u, err := url.Parse(rawURL); err == nil {
		for _, vs := range u.Query() {
			for _, v := range vs {
				values[v] = struct{}{}
			}
		}
	}
	for v := range values {
		if libinjection.IsXSS(v) {
			hits = append(hits, Hit{
				RuleId: "lib-xss", Name: "XSS特征（词法检测）", Place: "url",
				Level: "medium", TypeName: "XSS跨站脚本攻击", ActionDesc: "URI 参数含 XSS 特征",
				Value: rawURL, Matched: v, Engine: "libinjection",
			})
			break
		}
	}
	return hits
}

// ScanLine 对一条解析后的日志行做全位置检测
func (s *Scanner) ScanLine(l weblog.Line) []Hit {
	var hits []Hit
	hits = append(hits, s.ScanValue("url", l.URL)...)
	hits = append(hits, s.ScanValue("useragent", l.UserAgent)...)
	hits = append(hits, s.ScanValue("referer", l.Referer)...)
	if s.Libinjection {
		hits = append(hits, s.libinjectionScan(l.URL)...)
	}
	for i := range hits {
		hits[i].Line = l.No
		hits[i].IP = l.IP
		hits[i].Method = l.Method
		hits[i].Status = l.Status
	}
	return hits
}

// ScanLog 对整份日志逐行检测，onProgress(done,total) 可选节流上报
func (s *Scanner) ScanLog(lines []weblog.Line, onProgress func(done, total int)) []Hit {
	var hits []Hit
	for i, l := range lines {
		hits = append(hits, s.ScanLine(l)...)
		if onProgress != nil && (i%200 == 0 || i == len(lines)-1) {
			onProgress(i+1, len(lines))
		}
	}
	return hits
}
