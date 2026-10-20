package httpparse

import (
	"regexp"
	"strings"
)

// RawExchange 一对原始 HTTP 报文（字节级文本）
type RawExchange struct {
	Request  string
	Response string
}

var (
	streamReqLine  = regexp.MustCompile(`(?m)^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+\S+\s+HTTP/\d`)
	streamRespLine = regexp.MustCompile(`(?m)^HTTP/\d\.\d\s+\d{3}`)
)

// ParseStream 解析 Wireshark "Follow HTTP/TCP Stream" 导出的文本：
// 内容为按时间序拼接的原始请求/响应，用请求行与状态行做边界切分后顺序配对。
func ParseStream(content string) []RawExchange {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	var marks []struct {
		pos   int
		isReq bool
	}
	for _, loc := range streamReqLine.FindAllStringIndex(content, -1) {
		marks = append(marks, struct {
			pos   int
			isReq bool
		}{loc[0], true})
	}
	for _, loc := range streamRespLine.FindAllStringIndex(content, -1) {
		marks = append(marks, struct {
			pos   int
			isReq bool
		}{loc[0], false})
	}
	if len(marks) == 0 {
		return nil
	}
	for i := 1; i < len(marks); i++ {
		for j := i; j > 0 && marks[j].pos < marks[j-1].pos; j-- {
			marks[j], marks[j-1] = marks[j-1], marks[j]
		}
	}
	var out []RawExchange
	cur := -1
	for i, m := range marks {
		end := len(content)
		if i+1 < len(marks) {
			end = marks[i+1].pos
		}
		block := strings.TrimSpace(content[m.pos:end])
		if m.isReq {
			out = append(out, RawExchange{Request: block})
			cur = len(out) - 1
		} else if cur >= 0 && out[cur].Response == "" {
			out[cur].Response = block
		} else {
			out = append(out, RawExchange{Response: block})
			cur = len(out) - 1
		}
	}
	return out
}

// LooksLikeStream 判断文本是否为 httpstream 导出（含请求行+状态行，或多条请求行）
func LooksLikeStream(content string) bool {
	c := strings.ReplaceAll(content, "\r\n", "\n")
	nReq := len(streamReqLine.FindAllStringIndex(c, -1))
	nResp := len(streamRespLine.FindAllStringIndex(c, -1))
	return nReq >= 2 || (nReq >= 1 && nResp >= 1)
}
