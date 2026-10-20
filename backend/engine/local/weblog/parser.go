// Package weblog 解析 Web 访问日志（Nginx/Apache 的 NCSA combined/common 格式），
// 为 URL 规则检测与日志行为分析提供结构化条目。
package weblog

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Line 一条解析后的访问日志
type Line struct {
	No        int    `json:"no"`         // 行号（1 起）
	IP        string `json:"ip"`         // 客户端 IP
	Time      string `json:"time"`       // 原始时间串
	Method    string `json:"method"`     // 请求方法
	URL       string `json:"url"`        // 原始请求目标（path?query）
	Protocol  string `json:"protocol"`   // HTTP/1.1 等
	Path      string `json:"path"`       // 解码后的 path
	Status    int    `json:"status"`     // 状态码
	Bytes     int    `json:"bytes"`      // 响应字节数
	Referer   string `json:"referer"`    // Referer
	UserAgent string `json:"user_agent"` // User-Agent
	Raw       string `json:"raw"`        // 原始行
}

// combined/common 统一行格式：IP - - [time] "request" status bytes ["referer" "ua" [...]]
// 请求段整体捕获后在 Go 中拆分，兼容 "GET /a HTTP/1.1"、"-"、"GET /a b" 等形态
var lineRe = regexp.MustCompile(
	`^(\S+)\s+\S+\s+\S*\s*\[([^\]]+)\]\s+"((?:[^"\\]|\\.)*)"\s+(\d{3})\s+(\S+)(?:\s+"((?:[^"\\]|\\.)*)"\s+"((?:[^"\\]|\\.)*)")?.*$`)

// splitRequest 拆请求段 "METHOD URL PROTO"：URL 为中间部分（可含空格），
// 无协议段时整体视为 URL
func splitRequest(req string) (method, uri, proto string) {
	req = strings.TrimSpace(req)
	if req == "" || req == "-" {
		return "", "", ""
	}
	i := strings.Index(req, " ")
	if i < 0 {
		return req, "", ""
	}
	method, rest := req[:i], req[i+1:]
	if j := strings.LastIndex(rest, " HTTP/"); j >= 0 {
		return method, rest[:j], rest[j+1:]
	}
	return method, rest, ""
}

// timeLayouts 常见日志时间格式
var timeLayouts = []string{
	"02/Jan/2006:15:04:05 -0700",
	"02/Jan/2006:15:04:05",
	"2006-01-02T15:04:05-07:00",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02 15:04:05 -0700",
	"2006-01-02 15:04:05",
	"02/Jan/2006:15:04:05.000 -0700",
}

// ParseTime 解析日志时间串，失败返回零值
func ParseTime(s string) (t time.Time) {
	for _, l := range timeLayouts {
		if tt, err := time.Parse(l, s); err == nil {
			return tt
		}
	}
	return
}

// parseLine 单行解析；不匹配返回 nil
func parseLine(raw string) *Line {
	m := lineRe.FindStringSubmatch(raw)
	if m == nil {
		return nil
	}
	method, uri, proto := splitRequest(m[3])
	if uri == "" {
		return nil
	}
	l := &Line{Raw: raw, IP: m[1], Time: m[2], Method: method, URL: uri, Protocol: proto}
	l.Status, _ = strconv.Atoi(m[4])
	l.Bytes, _ = strconv.Atoi(strings.Trim(m[5], "-"))
	if len(m) > 6 && m[6] != "-" {
		l.Referer = m[6]
	}
	if len(m) > 7 && m[7] != "-" {
		l.UserAgent = m[7]
	}
	// 拆分 path（保留解码后形态供规则/行为脚本使用）
	if u, err := url.Parse(l.URL); err == nil {
		l.Path = u.Path
		if dec, err2 := url.PathUnescape(u.Path); err2 == nil {
			l.Path = dec
		}
	} else {
		l.Path = l.URL
	}
	return l
}

// ParseLines 按行解析全部内容，返回解析成功的条目
func ParseLines(content string) []Line {
	var out []Line
	for i, raw := range strings.Split(content, "\n") {
		raw = strings.TrimRight(raw, "\r")
		if l := parseLine(raw); l != nil {
			l.No = i + 1
			out = append(out, *l)
		}
	}
	return out
}

// LooksLikeLog 判断文本是否为 web 访问日志：
// 至少 3 个非空行且六成以上行能按 combined/common 格式解析
func LooksLikeLog(content string) bool {
	total, hit := 0, 0
	for _, raw := range strings.Split(content, "\n") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		total++
		if parseLine(raw) != nil {
			hit++
		}
	}
	return total >= 3 && hit*10 >= total*6
}

// Summary 日志概览统计
type Summary struct {
	Lines     int            `json:"lines"`
	StartTime string         `json:"start_time,omitempty"`
	EndTime   string         `json:"end_time,omitempty"`
	TopIP     [][2]any       `json:"top_ip"`
	TopPath   [][2]any       `json:"top_path"`
	Status    map[int]int    `json:"status"`
	Methods   map[string]int `json:"methods"`
}

// Summarize 统计日志分布（top 10 IP / path）
func Summarize(lines []Line) *Summary {
	s := &Summary{Lines: len(lines), Status: map[int]int{}, Methods: map[string]int{}}
	ipCnt, pathCnt := map[string]int{}, map[string]int{}
	var minT, maxT time.Time
	for _, l := range lines {
		ipCnt[l.IP]++
		pathCnt[l.Path]++
		s.Status[l.Status]++
		s.Methods[l.Method]++
		if t := ParseTime(l.Time); !t.IsZero() {
			if minT.IsZero() || t.Before(minT) {
				minT = t
			}
			if t.After(maxT) {
				maxT = t
			}
		}
	}
	if !minT.IsZero() {
		s.StartTime, s.EndTime = minT.Format(time.RFC3339), maxT.Format(time.RFC3339)
	}
	s.TopIP = topN(ipCnt, 10)
	s.TopPath = topN(pathCnt, 10)
	return s
}

func topN(m map[string]int, n int) [][2]any {
	type kv struct {
		k string
		v int
	}
	var arr []kv
	for k, v := range m {
		arr = append(arr, kv{k, v})
	}
	for i := 0; i < len(arr); i++ {
		for j := i + 1; j < len(arr); j++ {
			if arr[j].v > arr[i].v {
				arr[i], arr[j] = arr[j], arr[i]
			}
		}
	}
	if len(arr) > n {
		arr = arr[:n]
	}
	out := make([][2]any, len(arr))
	for i, e := range arr {
		out[i] = [2]any{e.k, e.v}
	}
	return out
}
