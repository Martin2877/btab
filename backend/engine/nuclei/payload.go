package nuclei

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ResourceReader 按模板中引用的路径读取字典文件内容
type ResourceReader func(p string) ([]byte, bool)

// ParseOptions 模板解析选项
type ParseOptions struct {
	// Resources 读取 payloads 中引用的字典文件，为空则不解析外部字典
	Resources ResourceReader
	// ExpandPayloads 为 true 时把 payloads/variables 的取值展开为具体请求特征，否则 {{var}} 一律视为通配
	ExpandPayloads bool
	// ExpandLimit 单个变量取值数上限，超过则该变量退化为通配，默认 100
	ExpandLimit int
}

const (
	maxCombos   = 500
	maxValueLen = 200
)

var simpleVarRe = regexp.MustCompile(`\{\{\s*([A-Za-z_][\w-]*)\s*\}\}`)

func substVars(s string, vars map[string]string) string {
	if len(vars) == 0 || !strings.Contains(s, "{{") {
		return s
	}
	return simpleVarRe.ReplaceAllStringFunc(s, func(m string) string {
		name := simpleVarRe.FindStringSubmatch(m)[1]
		if v, ok := vars[name]; ok {
			return v
		}
		return m
	})
}

func scalarString(v interface{}) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case int, int64, float64, bool:
		return fmt.Sprint(x), true
	}
	return "", false
}

func splitLines(raw []byte) []string {
	var out []string
	for _, l := range strings.Split(string(raw), "\n") {
		if l = strings.TrimRight(l, "\r"); strings.TrimSpace(l) != "" {
			out = append(out, l)
		}
	}
	return out
}

// payloadLists 解析 payloads 取值，同时登记模板引用的外部字典
func (r *HTTPRequest) payloadLists(t *Template, o *ParseOptions) map[string][]string {
	lists := map[string][]string{}
	for name, v := range r.Payloads {
		switch x := v.(type) {
		case []interface{}:
			seen := map[string]bool{}
			for _, e := range x {
				if s, ok := scalarString(e); ok && !seen[s] {
					seen[s] = true
					lists[name] = append(lists[name], s)
				}
			}
		case string:
			t.Refs = appendUnique(t.Refs, x)
			if o.Resources == nil {
				t.MissingRefs = appendUnique(t.MissingRefs, x)
				continue
			}
			raw, ok := o.Resources(x)
			if !ok {
				t.MissingRefs = appendUnique(t.MissingRefs, x)
				continue
			}
			lists[name] = splitLines(raw)
		}
	}
	return lists
}

func appendUnique(list []string, s string) []string {
	for _, e := range list {
		if e == s {
			return list
		}
	}
	return append(list, s)
}

// combos 生成请求定义中变量的取值组合；无可展开变量时返回单个（可能为空的）组合
func (r *HTTPRequest) combos(t *Template, o *ParseOptions) []map[string]string {
	base := map[string]string{}
	if o.ExpandPayloads {
		for k, v := range t.Variables {
			if s, ok := scalarString(v); ok && !strings.Contains(s, "{{") && !strings.Contains(s, "(") {
				base[k] = s
			}
		}
	}
	lists := r.payloadLists(t, o)
	if !o.ExpandPayloads || len(lists) == 0 {
		return []map[string]string{base}
	}
	limit := o.ExpandLimit
	if limit <= 0 {
		limit = 100
	}
	var names []string
	for n, l := range lists {
		var vals []string
		for _, s := range l {
			if len(s) <= maxValueLen {
				vals = append(vals, s)
			}
		}
		if len(vals) == 0 || len(vals) > limit {
			continue
		}
		lists[n] = vals
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return []map[string]string{base}
	}
	merge := func(extra map[string]string) map[string]string {
		m := make(map[string]string, len(base)+len(extra))
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	var out []map[string]string
	switch strings.ToLower(r.Attack) {
	case "batteringram":
		for _, v := range lists[names[0]] {
			e := map[string]string{}
			for _, n := range names {
				e[n] = v
			}
			out = append(out, merge(e))
		}
	case "pitchfork":
		n := len(lists[names[0]])
		for _, nm := range names {
			if len(lists[nm]) < n {
				n = len(lists[nm])
			}
		}
		for i := 0; i < n; i++ {
			e := map[string]string{}
			for _, nm := range names {
				e[nm] = lists[nm][i]
			}
			out = append(out, merge(e))
		}
	default:
		for {
			total := 1
			for _, nm := range names {
				total *= len(lists[nm])
			}
			if total <= maxCombos || len(names) <= 1 {
				break
			}
			big := 0
			for i, nm := range names {
				if len(lists[nm]) > len(lists[names[big]]) {
					big = i
				}
			}
			names = append(names[:big], names[big+1:]...)
		}
		out = []map[string]string{{}}
		for _, nm := range names {
			var next []map[string]string
			for _, c := range out {
				for _, v := range lists[nm] {
					e := map[string]string{nm: v}
					for k, cv := range c {
						e[k] = cv
					}
					next = append(next, e)
				}
			}
			out = next
		}
		for i := range out {
			out[i] = merge(out[i])
		}
	}
	if len(out) > maxCombos {
		out = out[:maxCombos]
	}
	if len(out) == 0 {
		return []map[string]string{base}
	}
	return out
}

// Meta 模板的轻量元信息，不要求模板可被本引擎完整解析
type Meta struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Author      string   `json:"author"`
	Description string   `json:"description"`
	CVE         string   `json:"cve"`
	Tags        []string `json:"tags"`
	Protocols   []string `json:"protocols"`
}

var protocolKeys = []string{"http", "requests", "dns", "tcp", "network", "file", "ssl", "websocket", "whois", "code", "javascript", "headless", "workflows", "workflow", "flow"}

// Inspect 宽松解析模板元信息（id/info/协议块）
func Inspect(data []byte) (Meta, error) {
	var t struct {
		ID   string `yaml:"id"`
		Info Info   `yaml:"info"`
	}
	if err := yaml.Unmarshal(data, &t); err != nil {
		return Meta{}, err
	}
	var top map[string]interface{}
	_ = yaml.Unmarshal(data, &top)
	m := Meta{ID: t.ID, Name: t.Info.Name, Severity: strings.ToLower(t.Info.Severity), Description: t.Info.Description}
	m.Author = strings.Join(t.Info.Author, ",")
	for _, tg := range t.Info.Tags {
		for _, p := range strings.Split(tg, ",") {
			if p = strings.TrimSpace(p); p != "" {
				m.Tags = append(m.Tags, p)
			}
		}
	}
	if cve, ok := t.Info.Classification["cve-id"]; ok {
		switch c := cve.(type) {
		case string:
			m.CVE = c
		case []interface{}:
			var ss []string
			for _, e := range c {
				ss = append(ss, fmt.Sprint(e))
			}
			m.CVE = strings.Join(ss, ",")
		}
	}
	for _, k := range protocolKeys {
		if _, ok := top[k]; ok {
			if k == "requests" {
				k = "http"
			}
			m.Protocols = appendUnique(m.Protocols, k)
		}
	}
	if m.Severity == "" {
		m.Severity = "info"
	}
	if m.Name == "" {
		m.Name = m.ID
	}
	return m, nil
}

// Diag 单个模板请求块对某次交互的诊断结果
type Diag struct {
	TemplateID     string   `json:"template_id"`
	Template       string   `json:"template"`
	Block          int      `json:"block"`
	RequestMatched bool     `json:"request_matched"`
	MatchersOK     bool     `json:"matchers_ok"`
	Evidence       []string `json:"evidence,omitempty"`
	Note           string   `json:"note,omitempty"`
}

// Diagnose 逐模板、逐请求块说明请求特征与响应 matcher 是否命中，用于规则调试
func (e *Engine) Diagnose(exs []*Exchange) []Diag {
	var out []Diag
	for _, t := range e.Templates {
		for i := range t.HTTP {
			r := &t.HTTP[i]
			for _, ex := range exs {
				d := Diag{TemplateID: t.ID, Template: path.Base(t.File), Block: i}
				switch {
				case !r.hasResultMatchers():
					d.Note = "该请求块没有 matcher，不参与检测"
				case !r.hasRespMatchers():
					d.Note = "该请求块仅有请求侧 matcher，无法确认响应，不参与检出"
				case len(r.specs) == 0:
					d.Note = "请求定义全为变量，无法约束请求，已跳过"
				case !requestMatches(r, ex):
					d.Note = "请求特征未命中（method/path/query/headers/body）"
				default:
					d.RequestMatched = true
					mo := evalMatchers(r, ex)
					d.MatchersOK, d.Evidence = mo.ok && mo.respHit, truncate(mo.ev)
					switch {
					case !mo.ok:
						d.Note = "请求命中，但响应 matcher 未满足"
					case !mo.respHit && !ex.HasResp:
						d.Note = "无响应可校验，不判检出"
					case !mo.respHit:
						d.Note = "仅请求侧 matcher 命中，响应未命中，不判检出"
					}
				}
				out = append(out, d)
			}
		}
	}
	return out
}
