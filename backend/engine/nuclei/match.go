package nuclei

import (
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/antchfx/htmlquery"
	"github.com/antchfx/xmlquery"
	"github.com/antchfx/xpath"
	"github.com/projectdiscovery/dsl"
)

type compiledMatcher struct {
	words    []string
	regexes  []*regexp.Regexp
	binaries []string
	xpaths   []*xpath.Expr
	and      bool
}

type compiledExtractor struct {
	regexes []*regexp.Regexp
	xpaths  []*xpath.Expr
}

func compileMatcher(m *Matcher) (*compiledMatcher, error) {
	m.Type = strings.ToLower(m.Type)
	c := &compiledMatcher{and: strings.EqualFold(m.Condition, "and")}
	switch m.Type {
	case "word":
		for _, w := range m.Words {
			if m.CaseInsensitive {
				w = strings.ToLower(w)
			}
			c.words = append(c.words, w)
		}
	case "regex":
		for _, r := range m.Regex {
			if m.CaseInsensitive {
				r = "(?i)" + r
			}
			re, err := regexp.Compile(toUTF8(r))
			if err != nil {
				return nil, fmt.Errorf("matcher regex %q: %w", r, err)
			}
			c.regexes = append(c.regexes, re)
		}
	case "xpath":
		for _, x := range m.Xpath {
			e, err := xpath.Compile(x)
			if err != nil {
				return nil, fmt.Errorf("matcher xpath %q: %w", x, err)
			}
			c.xpaths = append(c.xpaths, e)
		}
	case "binary":
		for _, b := range m.Binary {
			d, err := hex.DecodeString(strings.ReplaceAll(b, " ", ""))
			if err != nil {
				return nil, fmt.Errorf("matcher binary %q: %w", b, err)
			}
			c.binaries = append(c.binaries, string(d))
		}
	case "status", "size", "dsl":
	default:
		return nil, fmt.Errorf("不支持的 matcher 类型: %q", m.Type)
	}
	return c, nil
}

func compileExtractor(e *Extractor) (*compiledExtractor, error) {
	e.Type = strings.ToLower(e.Type)
	c := &compiledExtractor{}
	switch e.Type {
	case "regex":
		for _, r := range e.Regex {
			re, err := regexp.Compile(toUTF8(r))
			if err != nil {
				return nil, fmt.Errorf("extractor regex %q: %w", r, err)
			}
			c.regexes = append(c.regexes, re)
		}
	case "xpath":
		for _, x := range e.Xpath {
			xp, err := xpath.Compile(x)
			if err != nil {
				return nil, fmt.Errorf("extractor xpath %q: %w", x, err)
			}
			c.xpaths = append(c.xpaths, xp)
		}
	}
	return c, nil
}

// xpathCount 返回 XPath 在响应内容上命中的节点数；XML 文档走 xmlquery，其余按 HTML 解析
func xpathCount(corpus string, expr *xpath.Expr) int {
	if strings.HasPrefix(strings.TrimSpace(corpus), "<?xml") {
		doc, err := xmlquery.Parse(strings.NewReader(corpus))
		if err != nil {
			return 0
		}
		return len(xmlquery.QuerySelectorAll(doc, expr))
	}
	doc, err := htmlquery.Parse(strings.NewReader(corpus))
	if err != nil {
		return 0
	}
	return len(htmlquery.QuerySelectorAll(doc, expr))
}

// xpathExtract 用 XPath 提取响应内容：attribute 非空取属性值，否则取节点文本
func xpathExtract(corpus string, expr *xpath.Expr, attr string) []string {
	var out []string
	if strings.HasPrefix(strings.TrimSpace(corpus), "<?xml") {
		doc, err := xmlquery.Parse(strings.NewReader(corpus))
		if err != nil {
			return nil
		}
		for _, n := range xmlquery.QuerySelectorAll(doc, expr) {
			v := n.InnerText()
			if attr != "" {
				v = n.SelectAttr(attr)
			}
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
		return out
	}
	doc, err := htmlquery.Parse(strings.NewReader(corpus))
	if err != nil {
		return nil
	}
	for _, n := range htmlquery.QuerySelectorAll(doc, expr) {
		v := htmlquery.InnerText(n)
		if attr != "" {
			v = htmlquery.SelectAttr(n, attr)
		}
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// partValue 取出匹配所需的报文片段。request 为 true 表示取请求侧
func partValue(ex *Exchange, part string) string {
	switch p := strings.ToLower(part); p {
	case "", "body", "resp_body", "response_body":
		return ex.RespBody
	case "header", "all_headers", "response_headers", "resp_headers":
		return ex.ResponseHeaderText()
	case "all", "raw", "response", "full_response":
		return ex.ResponseRaw()
	case "request", "req":
		return ex.RequestRaw()
	case "status_code":
		return strconv.Itoa(ex.Status)
	case "content_length":
		return strconv.Itoa(len(ex.RespBody))
	default:
		return headerValue(ex.RespHeaders, strings.ReplaceAll(p, "_", "-"))
	}
}

func dslVars(ex *Exchange) map[string]interface{} {
	vars := map[string]interface{}{
		"body":           ex.RespBody,
		"header":         ex.ResponseHeaderText(),
		"all_headers":    ex.ResponseHeaderText(),
		"response":       ex.ResponseRaw(),
		"raw":            ex.ResponseRaw(),
		"request":        ex.RequestRaw(),
		"status_code":    ex.Status,
		"content_length": len(ex.RespBody),
		"host":           ex.Host,
		"duration":       0.0,
	}
	for _, h := range ex.RespHeaders {
		k := strings.ReplaceAll(strings.ToLower(h.Name), "-", "_")
		if _, exists := vars[k]; !exists {
			vars[k] = h.Value
		}
	}
	return vars
}

// matchOne 计算单个 matcher（含 negative 取反），返回是否命中及命中证据
func matchOne(m *Matcher, ex *Exchange) (bool, []string) {
	if !ex.HasResp && m.Type != "dsl" && !strings.EqualFold(m.Part, "request") {
		return false, nil
	}
	c := m.compiled
	var ok bool
	var ev []string
	if c == nil {
		return false, nil
	}
	val := partValue(ex, m.Part)
	switch m.Type {
	case "word":
		hay := val
		if m.CaseInsensitive {
			hay = strings.ToLower(hay)
		}
		ok, ev = matchList(len(c.words), c.and, func(i int) (bool, string) {
			w := c.words[i]
			if hasVar(w) {
				re, err := regexp.Compile("(?s)" + wildRegex(w, `.*?`))
				if err != nil {
					return false, ""
				}
				loc := re.FindString(hay)
				return loc != "", loc
			}
			return strings.Contains(hay, w), w
		})
	case "regex":
		ok, ev = matchList(len(c.regexes), c.and, func(i int) (bool, string) {
			loc := c.regexes[i].FindString(val)
			return c.regexes[i].MatchString(val), loc
		})
	case "xpath":
		ok, ev = matchList(len(c.xpaths), c.and, func(i int) (bool, string) {
			if xpathCount(val, c.xpaths[i]) == 0 {
				return false, ""
			}
			if vs := xpathExtract(val, c.xpaths[i], m.Attribute); len(vs) > 0 {
				return true, vs[0]
			}
			return true, c.xpaths[i].String()
		})
	case "binary":
		ok, ev = matchList(len(c.binaries), c.and, func(i int) (bool, string) {
			return strings.Contains(val, c.binaries[i]), hex.EncodeToString([]byte(c.binaries[i]))
		})
	case "status":
		for _, s := range m.Status {
			if ex.HasResp && s == ex.Status {
				ok = true
				ev = append(ev, strconv.Itoa(s))
				break
			}
		}
	case "size":
		for _, s := range m.Size {
			if s == len(val) {
				ok = true
				ev = append(ev, strconv.Itoa(s))
				break
			}
		}
	case "dsl":
		vars := dslVars(ex)
		ok, ev = matchList(len(m.DSL), strings.EqualFold(m.Condition, "and"), func(i int) (bool, string) {
			res, err := dsl.EvalExpr(m.DSL[i], vars)
			b, isBool := res.(bool)
			return err == nil && isBool && b, m.DSL[i]
		})
	}
	if m.Negative {
		return !ok, nil
	}
	return ok, ev
}

var (
	// dsl 中引用请求侧数据的变量（request=请求原文，host=请求 Host）
	dslReqVarRe = regexp.MustCompile(`\b(request|host)\b`)
	// dsl 中引用响应侧数据的变量；body_1/status_code_2 等多请求编号形式同算
	dslRespVarRe = regexp.MustCompile(`\b(body|header|all_headers|response|raw|status_code|content_length|duration|content_type)(_\d+)?\b`)
)

// matcherTag 命中证据的来源标注：优先 matcher 名，否则按 匹配位置/类型
func matcherTag(m *Matcher) string {
	if m.Name != "" {
		return m.Name
	}
	switch m.Type {
	case "status", "size", "dsl":
		return m.Type
	}
	part := strings.ToLower(m.Part)
	if part == "" {
		part = "body"
	}
	return part + " " + m.Type
}

func labelEvidence(m *Matcher, ev []string) []string {
	tag := matcherTag(m)
	out := make([]string, 0, len(ev))
	for _, e := range ev {
		out = append(out, tag+": "+e)
	}
	return out
}

// respSide 判断 matcher 是否校验响应侧内容。
// part: request 与仅引用请求侧变量的 dsl 属于请求侧 matcher，
// 可参与 matchers-condition 组合，但不能单独作为检出依据（检出必须有响应证据）。
func (m *Matcher) respSide() bool {
	switch strings.ToLower(m.Part) {
	case "request", "req":
		return false
	}
	if m.Type != "dsl" {
		return true
	}
	reqRef, respRef := false, false
	for _, e := range m.DSL {
		if dslReqVarRe.MatchString(e) {
			reqRef = true
		}
		if dslRespVarRe.MatchString(e) {
			respRef = true
		}
	}
	return respRef || !reqRef
}

func matchList(n int, and bool, f func(i int) (bool, string)) (bool, []string) {
	var ev []string
	for i := 0; i < n; i++ {
		ok, e := f(i)
		if ok {
			ev = append(ev, e)
			if !and {
				return true, ev
			}
		} else if and {
			return false, nil
		}
	}
	return n > 0 && and, ev
}

// matchOutcome matchers 评估结果
type matchOutcome struct {
	ok      bool     // matchers-condition 整体满足
	respHit bool     // 有响应侧 matcher 在真实响应上命中（检出依据）
	ev      []string // 全部命中证据（带来源标注）
	names   []string // 命中 matcher 名
	respEv  []string // 响应侧命中证据（请求侧命中不计入）
}

// evalMatchers 按 matchers-condition 合并多个 matcher。
// or 模式下不提前返回：需统计全部命中项以区分请求侧/响应侧命中。
func evalMatchers(r *HTTPRequest, ex *Exchange) matchOutcome {
	and := strings.EqualFold(r.MatchersCondition, "and")
	var res matchOutcome
	for _, m := range r.Matchers {
		if m.Internal {
			continue
		}
		mok, ev := matchOne(m, ex)
		if !mok {
			if and {
				return matchOutcome{}
			}
			continue
		}
		res.ok = true
		labelled := labelEvidence(m, ev)
		if ex.HasResp && m.respSide() {
			res.respHit = true
			res.respEv = append(res.respEv, labelled...)
		}
		res.ev = append(res.ev, labelled...)
		if m.Name != "" {
			res.names = append(res.names, m.Name)
		}
	}
	return res
}

func runExtractors(r *HTTPRequest, ex *Exchange) map[string][]string {
	if !ex.HasResp {
		return nil
	}
	out := map[string][]string{}
	for i, e := range r.Extractors {
		key := e.Name
		if key == "" {
			key = fmt.Sprintf("extractor_%d", i+1)
		}
		val := partValue(ex, e.Part)
		switch e.Type {
		case "regex":
			for _, re := range e.compiled.regexes {
				for _, m := range re.FindAllStringSubmatch(val, -1) {
					g := e.Group
					if g >= len(m) {
						g = 0
					}
					out[key] = append(out[key], m[g])
				}
			}
		case "xpath":
			for _, xp := range e.compiled.xpaths {
				out[key] = append(out[key], xpathExtract(val, xp, e.Attribute)...)
			}
		case "kval":
			for _, k := range e.KVal {
				if v := headerValue(ex.RespHeaders, strings.ReplaceAll(k, "_", "-")); v != "" {
					out[key] = append(out[key], v)
				}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
