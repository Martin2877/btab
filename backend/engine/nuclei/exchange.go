package nuclei

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/Martin2877/blue-team-box/pkg/pcap"
	"github.com/tidwall/gjson"
)

type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Exchange 一次 HTTP 交互（请求 + 可选的响应），是检测引擎的输入单元
type Exchange struct {
	Stream    string `json:"stream"`
	ReqFrame  int    `json:"req_frame"`
	RespFrame int    `json:"resp_frame,omitempty"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`

	Host       string   `json:"host"`
	Method     string   `json:"method"`
	URI        string   `json:"uri"`
	Version    string   `json:"version,omitempty"`
	ReqHeaders []Header `json:"req_headers,omitempty"`
	ReqBody    string   `json:"req_body,omitempty"`
	// ReqBodyHex/RespBodyHex 调用方以 hex 传输二进制 body 时使用，Normalize 后填充 ReqBody/RespBody
	ReqBodyHex string `json:"req_body_hex,omitempty"`

	HasResp     bool     `json:"has_resp"`
	Status      int      `json:"status,omitempty"`
	Phrase      string   `json:"phrase,omitempty"`
	RespVersion string   `json:"resp_version,omitempty"`
	RespHeaders []Header `json:"resp_headers,omitempty"`
	RespBody    string   `json:"resp_body,omitempty"`
	RespBodyHex string   `json:"resp_body_hex,omitempty"`
}

// Normalize 解码 hex 形式的 body，补全 Host 等派生字段
func (e *Exchange) Normalize() {
	if e.ReqBody == "" && e.ReqBodyHex != "" {
		e.ReqBody = decodeBody([]string{e.ReqBodyHex})
	}
	if e.RespBody == "" && e.RespBodyHex != "" {
		e.RespBody = decodeBody([]string{e.RespBodyHex})
	}
	if e.Host == "" {
		e.Host = headerValue(e.ReqHeaders, "Host")
	}
	e.ReqBodyHex, e.RespBodyHex = "", ""
}

func headerValue(hs []Header, name string) string {
	for _, h := range hs {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}

func headersText(hs []Header) string {
	var sb strings.Builder
	for _, h := range hs {
		sb.WriteString(h.Name + ": " + h.Value + "\r\n")
	}
	return sb.String()
}

// RequestRaw 还原请求原文
func (e *Exchange) RequestRaw() string {
	v := e.Version
	if v == "" {
		v = "HTTP/1.1"
	}
	return fmt.Sprintf("%s %s %s\r\n%s\r\n%s", e.Method, e.URI, v, headersText(e.ReqHeaders), e.ReqBody)
}

// ResponseHeaderText 响应头（不含状态行）
func (e *Exchange) ResponseHeaderText() string { return headersText(e.RespHeaders) }

// ResponseRaw 还原响应原文
func (e *Exchange) ResponseRaw() string {
	if !e.HasResp {
		return ""
	}
	v := e.RespVersion
	if v == "" {
		v = "HTTP/1.1"
	}
	return fmt.Sprintf("%s %d %s\r\n%s\r\n%s", v, e.Status, e.Phrase, headersText(e.RespHeaders), e.RespBody)
}

func parseHeaderLines(lines []string) []Header {
	var hs []Header
	for _, l := range lines {
		l = strings.TrimRight(l, "\r\n")
		i := strings.Index(l, ":")
		if i <= 0 {
			continue
		}
		hs = append(hs, Header{Name: strings.TrimSpace(l[:i]), Value: strings.TrimSpace(l[i+1:])})
	}
	return hs
}

var exchangeFields = []string{
	"frame.number", "tcp.stream", "ip.src", "ip.dst", "ipv6.src", "ipv6.dst", "tcp.srcport", "tcp.dstport",
	"http.request.method", "http.request.uri", "http.request.version", "http.request.line", "http.host",
	"http.response.code", "http.response.phrase", "http.response.version", "http.response.line",
	"http.file_data", "http.request_in",
}

func decodeBody(parts []string) string {
	var sb strings.Builder
	for _, p := range parts {
		if b, err := hex.DecodeString(strings.ReplaceAll(p, ":", "")); err == nil {
			sb.Write(b)
		} else {
			sb.WriteString(p)
		}
	}
	return sb.String()
}

// LoadExchanges 通过 tshark 读取 pcap，并将 HTTP 请求与响应配对为 Exchange
func LoadExchanges(file string) ([]*Exchange, error) {
	p := pcap.CreatePcaper()
	if err := p.Load(file); err != nil {
		return nil, err
	}
	p.SetFields(exchangeFields)
	raw, _, err := p.Query("http")
	if err != nil {
		return nil, err
	}
	var rows []map[string][]string
	for _, layer := range gjson.GetBytes(raw, "#._source.layers").Array() {
		row := map[string][]string{}
		layer.ForEach(func(k, v gjson.Result) bool {
			if v.IsArray() {
				for _, e := range v.Array() {
					row[k.String()] = append(row[k.String()], e.String())
				}
			} else {
				row[k.String()] = []string{v.String()}
			}
			return true
		})
		rows = append(rows, row)
	}
	return PairExchanges(rows), nil
}

func first(row map[string][]string, keys ...string) string {
	for _, k := range keys {
		if v := row[k]; len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// PairExchanges 将 tshark 字段行（按帧序）配对为 HTTP 交互。
// 优先使用 http.request_in 精确配对，缺失时在同一 tcp.stream 内按先进先出配对。
func PairExchanges(rows []map[string][]string) []*Exchange {
	var all []*Exchange
	byFrame := map[int]*Exchange{}
	pending := map[string][]*Exchange{}
	for _, row := range rows {
		frame, _ := strconv.Atoi(first(row, "frame.number"))
		stream := first(row, "tcp.stream")
		if m := first(row, "http.request.method"); m != "" {
			ex := &Exchange{
				Stream: stream, ReqFrame: frame,
				SrcIP: first(row, "ip.src", "ipv6.src"), DstIP: first(row, "ip.dst", "ipv6.dst"),
				Host: first(row, "http.host"), Method: m, URI: first(row, "http.request.uri"),
				Version:    first(row, "http.request.version"),
				ReqHeaders: parseHeaderLines(row["http.request.line"]),
				ReqBody:    decodeBody(row["http.file_data"]),
			}
			ex.SrcPort, _ = strconv.Atoi(first(row, "tcp.srcport"))
			ex.DstPort, _ = strconv.Atoi(first(row, "tcp.dstport"))
			if ex.Host == "" {
				ex.Host = headerValue(ex.ReqHeaders, "Host")
			}
			all = append(all, ex)
			byFrame[frame] = ex
			pending[stream] = append(pending[stream], ex)
			continue
		}
		code := first(row, "http.response.code")
		if code == "" {
			continue
		}
		var ex *Exchange
		if in, err := strconv.Atoi(first(row, "http.request_in")); err == nil {
			ex = byFrame[in]
		}
		if ex == nil || ex.HasResp {
			if q := pending[stream]; len(q) > 0 {
				ex = q[0]
			} else {
				ex = nil
			}
		}
		if ex == nil {
			continue
		}
		q := pending[ex.Stream]
		for i, e := range q {
			if e == ex {
				pending[ex.Stream] = append(q[:i:i], q[i+1:]...)
				break
			}
		}
		ex.HasResp = true
		ex.RespFrame = frame
		ex.Status, _ = strconv.Atoi(code)
		ex.Phrase = first(row, "http.response.phrase")
		ex.RespVersion = first(row, "http.response.version")
		ex.RespHeaders = parseHeaderLines(row["http.response.line"])
		ex.RespBody = decodeBody(row["http.file_data"])
	}
	return all
}

// ExchangeFromRaw 将原始 HTTP 请求/响应文本构造为 Exchange（用于 httpstream/手工报文检测）
func ExchangeFromRaw(req, resp string) *Exchange {
	e := &Exchange{Method: "GET", URI: "/"}
	if req != "" {
		head, body := splitHTTP(req)
		lines := strings.Split(head, "\n")
		if len(lines) > 0 {
			f := strings.Fields(strings.TrimRight(lines[0], "\r"))
			if len(f) >= 1 {
				e.Method = strings.ToUpper(f[0])
			}
			if len(f) >= 2 {
				e.URI = f[1]
			}
			if len(f) >= 3 {
				e.Version = f[2]
			}
		}
		e.ReqHeaders = parseHeaderLines(lines[1:])
		e.ReqBody = body
	}
	if resp != "" {
		head, body := splitHTTP(resp)
		lines := strings.Split(head, "\n")
		if len(lines) > 0 {
			f := strings.Fields(strings.TrimRight(lines[0], "\r"))
			if len(f) >= 1 {
				e.RespVersion = f[0]
			}
			if len(f) >= 2 {
				if n, err := strconv.Atoi(f[1]); err == nil {
					e.Status = n
					e.HasResp = true
				}
			}
			if len(f) >= 3 {
				e.Phrase = strings.Join(f[2:], " ")
			}
		}
		e.RespHeaders = parseHeaderLines(lines[1:])
		e.RespBody = body
	}
	e.Normalize()
	return e
}

// splitHTTP 以空行分隔头部与 body
func splitHTTP(s string) (head, body string) {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	if i := strings.Index(s, "\n\n"); i >= 0 {
		return s[:i], s[i+2:]
	}
	return s, ""
}
