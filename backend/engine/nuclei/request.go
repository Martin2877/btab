package nuclei

import (
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	varRe = regexp.MustCompile(`\{\{[^{}]*\}\}`)
	// 基础地址变量：匹配时视为空
	// 路径参数（如 ;jsessionid=xxx）
	pathParamRe = regexp.MustCompile(`;[^/?#]*`)
	baseVarRe   = regexp.MustCompile(`^\{\{(BaseURL|RootURL)\}\}/?`)
	// 通用头，不参与请求匹配
	skipHeaders = map[string]bool{
		"host": true, "user-agent": true, "accept": true, "accept-encoding": true, "accept-language": true,
		"connection": true, "content-length": true, "cache-control": true, "pragma": true,
		"upgrade-insecure-requests": true, "referer": true, "origin": true, "cookie": true,
	}
)

type qcond struct {
	key string
	val *regexp.Regexp // nil 表示仅要求 key 存在
	raw *regexp.Regexp // 无 key=value 形式的片段，要求出现在 query 中
}

type hcond struct {
	name string
	val  *regexp.Regexp
}

// toUTF8 把字符串中的无效 UTF-8 字节逐个替换为 U+FFFD。
// URL 解码（%E1%EE、%AD、%C0%AF 等）可能得到 Windows-1251/GBK 等编码的原始字节，
// 而 Go 的 regexp 要求 pattern 为合法 UTF-8。逐字节替换保证可编译，同时输入侧
// 同样的无效字节在正则引擎中也会逐字节解码为 RuneError，仍能按位置命中。
func toUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			b.WriteRune(utf8.RuneError)
			i++
			continue
		}
		b.WriteString(s[i : i+size])
		i += size
	}
	return b.String()
}

// litParts 提取模板变量之间的字面量片段
func litParts(s string) []string {
	s = toUTF8(s)
	var out []string
	last := 0
	for _, loc := range varRe.FindAllStringIndex(s, -1) {
		if t := strings.TrimSpace(s[last:loc[0]]); t != "" {
			out = append(out, t)
		}
		last = loc[1]
	}
	if t := strings.TrimSpace(s[last:]); t != "" {
		out = append(out, t)
	}
	return out
}

// reqSpec 模板中一条可被流量请求匹配的请求定义
type reqSpec struct {
	method  string
	pathRe  *regexp.Regexp
	query   []qcond
	headers []hcond
	bodyRe  *regexp.Regexp
	// literals 该请求定义中的纯字面量片段（path/query/headers/body），用于载荷特征识别
	literals []string
}

// wildRegex 把含 {{var}} 的文本转为正则：字面量转义，变量转通配
func wildRegex(s, wild string) string {
	s = toUTF8(s)
	var sb strings.Builder
	last := 0
	for _, loc := range varRe.FindAllStringIndex(s, -1) {
		sb.WriteString(regexp.QuoteMeta(s[last:loc[0]]))
		sb.WriteString(wild)
		last = loc[1]
	}
	sb.WriteString(regexp.QuoteMeta(s[last:]))
	return sb.String()
}

func hasVar(s string) bool { return varRe.MatchString(s) }

func buildPathSpec(method, p string) (*reqSpec, error) {
	p = strings.TrimSpace(p)
	p = baseVarRe.ReplaceAllString(p, "/")
	if hasVar(p) && strings.Trim(wildOnly(p), "/?&=") == "" {
		// 整个路径都是变量（如 {{BaseURL}}{{path}}），无法约束请求，跳过以免泛化误报
		return nil, nil
	}
	if p == "" || p[0] == '?' {
		p = "/" + p
	}
	if p[0] != '/' && !strings.HasPrefix(p, "{{") {
		p = "/" + p
	}
	pathPart, queryPart := p, ""
	if i := strings.Index(p, "?"); i >= 0 {
		pathPart, queryPart = p[:i], p[i+1:]
	}
	if u, err := url.PathUnescape(pathPart); err == nil && !hasVar(pathPart) {
		pathPart = toUTF8(u)
	}
	spec := &reqSpec{method: strings.ToUpper(method)}
	spec.literals = litParts(strings.TrimRight(pathPart, "/"))
	pr := "^" + wildRegex(strings.TrimRight(pathPart, "/"), `[^?#]*`) + `/*$`
	re, err := regexp.Compile(pr)
	if err != nil {
		return nil, err
	}
	spec.pathRe = re
	if queryPart != "" {
		for _, seg := range strings.Split(queryPart, "&") {
			if seg == "" {
				continue
			}
			k, v, ok := strings.Cut(seg, "=")
			if !ok {
				r, err := regexp.Compile("(?s)" + wildRegex(unescapeLoose(seg), `.*?`))
				if err != nil {
					return nil, err
				}
				spec.query = append(spec.query, qcond{raw: r})
				continue
			}
			c := qcond{key: unescapeLoose(k)}
			if v != "" {
				vv := unescapeLoose(v)
				spec.literals = append(spec.literals, litParts(vv)...)
				r, err := regexp.Compile("(?s)^" + wildRegex(vv, `.*?`) + "$")
				if err != nil {
					return nil, err
				}
				c.val = r
			}
			spec.query = append(spec.query, c)
		}
	}
	return spec, nil
}

func unescapeLoose(s string) string {
	if hasVar(s) {
		// 保护 {{var}} 不被 unescape 破坏
		return s
	}
	if u, err := url.QueryUnescape(s); err == nil {
		return toUTF8(u)
	}
	return s
}

func buildSpecs(r *HTTPRequest, combos []map[string]string) ([]*reqSpec, error) {
	var specs []*reqSpec
	for _, vars := range combos {
		ss, err := buildSpecsOnce(r, vars)
		if err != nil {
			return nil, err
		}
		specs = append(specs, ss...)
	}
	return specs, nil
}

func buildSpecsOnce(r *HTTPRequest, vars map[string]string) ([]*reqSpec, error) {
	var specs []*reqSpec
	addCommon := func(s *reqSpec, headers map[string]string, body string) error {
		for k, v := range headers {
			lk := strings.ToLower(k)
			if skipHeaders[lk] || strings.TrimSpace(wildOnly(v)) == "" {
				continue
			}
			re, err := regexp.Compile("(?is)" + wildRegex(v, `.*?`))
			if err != nil {
				return err
			}
			s.headers = append(s.headers, hcond{name: lk, val: re})
			s.literals = append(s.literals, litParts(v)...)
		}
		body = strings.TrimSpace(strings.ReplaceAll(body, "\r", ""))
		if body != "" && strings.TrimSpace(wildOnly(body)) != "" {
			re, err := regexp.Compile("(?s)" + wildRegex(body, `.*?`))
			if err != nil {
				return err
			}
			s.bodyRe = re
			s.literals = append(s.literals, litParts(body)...)
		}
		return nil
	}
	method := r.Method
	if method == "" {
		method = "GET"
	}
	if len(vars) > 0 {
		headers := make(map[string]string, len(r.Headers))
		for k, v := range r.Headers {
			headers[k] = substVars(v, vars)
		}
		rr := *r
		rr.Headers, rr.Body = headers, substVars(r.Body, vars)
		r = &rr
	}
	for _, p := range r.Path {
		p = substVars(p, vars)
		s, err := buildPathSpec(method, p)
		if err != nil {
			return nil, err
		}
		if s == nil {
			continue
		}
		if err := addCommon(s, r.Headers, r.Body); err != nil {
			return nil, err
		}
		specs = append(specs, s)
	}
	for _, raw := range r.Raw {
		s, err := buildRawSpec(substVars(raw, vars), addCommon)
		if err != nil {
			return nil, err
		}
		if s != nil {
			specs = append(specs, s)
		}
	}
	return specs, nil
}

// wildOnly 去掉变量后的剩余字面量
func wildOnly(s string) string { return varRe.ReplaceAllString(s, "") }

func buildRawSpec(raw string, addCommon func(*reqSpec, map[string]string, string) error) (*reqSpec, error) {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	var lines []string
	for _, l := range strings.Split(raw, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "@") && len(lines) == 0 {
			continue
		}
		lines = append(lines, l)
	}
	for len(lines) > 0 && strings.TrimSpace(lines[0]) == "" {
		lines = lines[1:]
	}
	if len(lines) == 0 {
		return nil, nil
	}
	parts := strings.Fields(lines[0])
	if len(parts) < 2 {
		return nil, nil
	}
	s, err := buildPathSpec(parts[0], parts[1])
	if err != nil || s == nil {
		return nil, err
	}
	headers := map[string]string{}
	i := 1
	for ; i < len(lines) && strings.TrimSpace(lines[i]) != ""; i++ {
		if k, v, ok := strings.Cut(lines[i], ":"); ok {
			headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	body := ""
	if i+1 < len(lines) {
		body = strings.Join(lines[i+1:], "\n")
	}
	if err := addCommon(s, headers, body); err != nil {
		return nil, err
	}
	return s, nil
}

func splitURI(uri string) (path, query string) {
	if i := strings.Index(uri, "://"); i >= 0 && !strings.ContainsAny(uri[:i], "/?") {
		// :// 仅出现在首个 / 或 ? 之前才是 scheme（query 参数值里常含 https:// 等字面量）
		rest := uri[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			uri = rest[j:]
		} else {
			uri = "/"
		}
	}
	if i := strings.Index(uri, "#"); i >= 0 {
		uri = uri[:i]
	}
	path, query, _ = strings.Cut(uri, "?")
	if path == "" {
		path = "/"
	}
	return
}

// match 判断流量中的请求是否符合该请求定义
func (s *reqSpec) match(ex *Exchange) bool {
	if s.method != "" && !strings.EqualFold(s.method, ex.Method) {
		return false
	}
	path, query := splitURI(ex.URI)
	pathOK := s.pathRe.MatchString(path)
	if !pathOK {
		if u, err := url.PathUnescape(path); err == nil {
			pathOK = s.pathRe.MatchString(u)
		}
	}
	if !pathOK {
		pathOK = s.pathRe.MatchString(pathParamRe.ReplaceAllString(path, ""))
	}
	if !pathOK {
		return false
	}
	if len(s.query) > 0 {
		params := map[string][]string{}
		for _, seg := range strings.Split(query, "&") {
			k, v, _ := strings.Cut(seg, "=")
			k, v = unescapeAny(k), unescapeAny(v)
			params[k] = append(params[k], v)
		}
		full := unescapeAny(query)
		for _, c := range s.query {
			if c.raw != nil {
				if !c.raw.MatchString(full) {
					return false
				}
				continue
			}
			vals, ok := params[c.key]
			if !ok {
				return false
			}
			if c.val == nil {
				continue
			}
			found := false
			for _, v := range vals {
				if c.val.MatchString(v) {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
	}
	for _, h := range s.headers {
		if !h.val.MatchString(headerValue(ex.ReqHeaders, h.name)) {
			return false
		}
	}
	if s.bodyRe != nil && !s.bodyRe.MatchString(strings.ReplaceAll(ex.ReqBody, "\r", "")) {
		return false
	}
	return true
}

func unescapeAny(s string) string {
	if u, err := url.QueryUnescape(s); err == nil {
		return toUTF8(u)
	}
	return s
}
