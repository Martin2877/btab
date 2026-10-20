// Package inject 从 HTTP 请求中提取可注入参数值（query/form/json/cookie/请求头等），
// 交由 libinjection 按值检测。避免把整段报文（尤其 HTML 页面、路径文本）喂给
// 词法引擎造成的大量误报。
package inject

import (
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"strconv"
	"strings"

	"github.com/Martin2877/blue-team-box/engine/local/sqli"
	"github.com/corazawaf/libinjection-go"
)

// Point 一个可注入参数值
type Point struct {
	Source string `json:"source"` // query / path / form / json / cookie / header / body
	Name   string `json:"name"`   // 参数名或头名，path/body 时为空
	Value  string `json:"value"`
}

// Hit 参数值命中结果
type Hit struct {
	Point  Point  `json:"point"`
	Engine string `json:"engine"` // sqli / xss
	Detail string `json:"detail"` // 词法指纹等命中详情
}

const (
	maxPoints   = 256
	maxValueLen = 8192
	jsonDepth   = 8
)

// headerPoints 参与注入检测的请求头（小写名 -> 展示名）；Cookie 单独按 k=v 拆分
var headerNames = map[string]string{
	"x-forwarded-for": "X-Forwarded-For",
	"x-real-ip":       "X-Real-IP",
	"x-client-ip":     "X-Client-IP",
	"referer":         "Referer",
	"user-agent":      "User-Agent",
}

// Points 从请求 URI/Body/头部提取可注入参数值。
// headers 为请求头小写名 -> 值，可为 nil。
func Points(uri, body string, headers map[string]string) []Point {
	var pts []Point
	seen := map[string]struct{}{}
	add := func(source, name, value string) {
		value = strings.TrimSpace(value)
		if len(value) < 2 || len(pts) >= maxPoints {
			return
		}
		if len(value) > maxValueLen {
			value = value[:maxValueLen]
		}
		key := source + "\x00" + name + "\x00" + value
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		pts = append(pts, Point{Source: source, Name: name, Value: value})
	}

	if u, err := url.Parse(uri); err == nil && u != nil {
		for name, vs := range u.Query() {
			for _, v := range vs {
				add("query", name, v)
			}
		}
		if p := u.EscapedPath(); p != "" && p != "/" {
			if dec, err := url.PathUnescape(p); err == nil {
				p = dec
			}
			add("path", "", p)
		}
	}

	if b := strings.TrimSpace(body); b != "" {
		ct := ""
		if headers != nil {
			ct = headers["content-type"]
		}
		switch {
		case strings.HasPrefix(ct, "multipart/form-data"):
			multipartPoints(b, ct, add)
		case looksJSON(b):
			before := len(pts)
			jsonPoints([]byte(b), add)
			if len(pts) == before {
				add("body", "", b) // JSON 无字符串值时按整体检测
			}
		case strings.Contains(b, "=") && !strings.Contains(b, "\n"):
			if m, err := url.ParseQuery(b); err == nil && len(m) > 0 {
				for name, vs := range m {
					for _, v := range vs {
						add("form", name, v)
					}
				}
			} else {
				add("body", "", b)
			}
		default:
			add("body", "", b)
		}
	}

	if headers != nil {
		if v := headers["cookie"]; v != "" {
			for _, pair := range strings.Split(v, ";") {
				pair = strings.TrimSpace(pair)
				if i := strings.Index(pair, "="); i > 0 {
					add("cookie", strings.TrimSpace(pair[:i]), pair[i+1:])
				} else if pair != "" {
					add("cookie", "", pair)
				}
			}
		}
		for key, disp := range headerNames {
			if v := headers[key]; v != "" {
				add("header", disp, v)
			}
		}
	}
	return pts
}

func looksJSON(b string) bool {
	return strings.HasPrefix(b, "{") || strings.HasPrefix(b, "[")
}

// multipartPoints 解析 multipart/form-data 中的文本字段值；文件字段内容跳过
func multipartPoints(b, contentType string, add func(source, name, value string)) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil || params["boundary"] == "" {
		return
	}
	r := multipart.NewReader(strings.NewReader(b), params["boundary"])
	for {
		part, err := r.NextPart()
		if err != nil {
			return
		}
		name := part.FormName()
		if name == "" || part.FileName() != "" {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(part, maxValueLen+1))
		if err != nil {
			continue
		}
		add("form", name, string(data))
	}
}

// jsonPoints 提取 JSON 中的字符串叶子值，参数名为键路径（如 a.b[0]）
func jsonPoints(data []byte, add func(source, name, value string)) {
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		return
	}
	var walk func(n interface{}, path string, depth int)
	walk = func(n interface{}, path string, depth int) {
		if depth > jsonDepth {
			return
		}
		switch t := n.(type) {
		case map[string]interface{}:
			for k, val := range t {
				p := k
				if path != "" {
					p = path + "." + k
				}
				walk(val, p, depth+1)
			}
		case []interface{}:
			for i, val := range t {
				walk(val, path+"["+strconv.Itoa(i)+"]", depth+1)
			}
		case string:
			add("json", path, t)
		}
	}
	walk(v, "", 0)
}

// Location 命中位置的可读描述（如 query[id]、cookie[session]、header[X-Forwarded-For]）
func (h Hit) Location() string {
	if h.Point.Name == "" {
		return h.Point.Source
	}
	return h.Point.Source + "[" + h.Point.Name + "]"
}

// Scan 对请求的各参数值分别做 sqli/xss 检测，返回全部命中。
// sqli 走 libinjection 词法 + 危险 SQL 结构签名（sqli.Check），xss 走 libinjection。
func Scan(uri, body string, headers map[string]string) []Hit {
	var hits []Hit
	for _, p := range Points(uri, body, headers) {
		if found, detail := sqli.Check(p.Value); found {
			hits = append(hits, Hit{Point: p, Engine: "sqli", Detail: detail})
		}
		if libinjection.IsXSS(p.Value) {
			hits = append(hits, Hit{Point: p, Engine: "xss", Detail: "libinjection XSS 指纹"})
		}
	}
	return hits
}
