package http_parse

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Martin2877/blue-team-box/api/msg"
	localbash "github.com/Martin2877/blue-team-box/engine/local/bash"
	"github.com/Martin2877/blue-team-box/engine/local/btt"
	localhttp_parse "github.com/Martin2877/blue-team-box/engine/local/http_parse"
	"github.com/Martin2877/blue-team-box/engine/local/inject"
	"github.com/Martin2877/blue-team-box/engine/local/pcapgen"
	localwebshell "github.com/Martin2877/blue-team-box/engine/local/webshell"
	"github.com/Martin2877/blue-team-box/engine/nuclei"
	"github.com/Martin2877/blue-team-box/engine/session"
	"github.com/Martin2877/blue-team-box/engine/vuln"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/gin-gonic/gin"
)

type Http_Request_ struct {
	Req_data string `json:"req_data"`
	Res_data string `json:"res_data"`
}

func Get_Tips(c *gin.Context) {
	paJson := Http_Request_{}
	if err := c.ShouldBindJSON(&paJson); err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	http_parseInstance := localhttp_parse.HTTP_PARSE{}

	// 识别输入形态：httpstream 导出 / 请求+响应 / 仅请求。
	// 请求框或响应框粘贴完整的 httpstream 文本均可（多对请求/响应自动拆分）。
	var rawEx []localhttp_parse.RawExchange
	stream := false
	if localhttp_parse.LooksLikeStream(paJson.Req_data) {
		rawEx = localhttp_parse.ParseStream(paJson.Req_data)
		// 拆出单个请求且响应框另有内容时，按请求+响应处理
		if len(rawEx) == 1 && rawEx[0].Response == "" && paJson.Res_data != "" {
			rawEx[0].Response = paJson.Res_data
		}
		stream = len(rawEx) > 1
	}
	if len(rawEx) == 0 && localhttp_parse.LooksLikeStream(paJson.Res_data) && paJson.Req_data == "" {
		rawEx = localhttp_parse.ParseStream(paJson.Res_data)
		stream = len(rawEx) > 1
	}
	if len(rawEx) == 0 {
		req, res := paJson.Req_data, paJson.Res_data
		// 仅粘贴了响应报文到请求框时按响应处理
		if res == "" && strings.HasPrefix(strings.TrimSpace(req), "HTTP/") {
			req, res = "", req
		}
		rawEx = []localhttp_parse.RawExchange{{Request: req, Response: res}}
	}
	if len(rawEx) == 0 || (rawEx[0].Request == "" && rawEx[0].Response == "") {
		msg.ResultFailed(c, "无检测内容")
		return
	}

	// 逐段特征解析（保持旧版扁平 map 输出以兼容前端）
	var merged map[string]interface{}
	exs := make([]*nuclei.Exchange, 0, len(rawEx))
	var summaries []gin.H
	var details []gin.H
	var params []gin.H
	for i, re := range rawEx {
		m := map[string]interface{}{}
		req_map := make(map[string]string)
		res_map := make(map[string]string)
		req_url_args := make(map[string]map[string]string)
		req_client_args := make(map[string]map[string]string)
		var formdata localhttp_parse.Form_data
		if re.Request != "" {
			req_map, req_url_args, req_client_args, formdata = http_parseInstance.Req_parse(re.Request)
		}
		if re.Response != "" {
			res_map = http_parseInstance.Res_parse(re.Response)
		}
		for _, src := range []interface{}{req_map, res_map, req_url_args, req_client_args, formdata} {
			raw, _ := json.Marshal(src)
			json.Unmarshal(raw, &m)
		}
		if merged == nil {
			merged = m
		}

		// 结构化 exchange（hex 报文先解码再解析，供检测与详情展示复用）
		e := nuclei.ExchangeFromRaw(localhttp_parse.DecodeHex(re.Request), localhttp_parse.DecodeHex(re.Response))
		e.Stream = fmt.Sprint(i)
		e.ReqFrame = i + 1
		exs = append(exs, e)
		summaries = append(summaries, gin.H{
			"index": i + 1, "method": e.Method, "uri": e.URI,
			"host": e.Host, "status": e.Status, "has_resp": e.HasResp,
		})
		details = append(details, exchangeDetail(e, m, req_url_args, req_client_args, formdata))
		params = append(params, paramRows(i+1, req_url_args, req_client_args, formdata)...)
	}
	if merged == nil {
		merged = map[string]interface{}{}
	}
	merged["stream_exchanges"] = len(rawEx)
	if stream {
		merged["is_stream"] = true
	}
	merged["exchange_summaries"] = summaries
	merged["exchanges"] = details
	merged["params"] = params
	merged["risk"] = detectRisk(exs)

	jres := msg.JsonResponse{
		Code:    20000,
		Message: fmt.Sprintf("已成功解析 %d 个请求/响应", len(rawEx)),
		Result:  merged,
		Type:    "success",
	}
	msg.ResultSuccess(c, &jres)
}

// clipText 截断过长的 body 内容，避免详情数据过大
func clipText(s string, n int) string {
	if len(s) > n {
		return s[:n] + fmt.Sprintf("\n... [已截断，共 %d 字节]", len(s))
	}
	return s
}

// decodeParamValue 尝试对参数值做一次解码还原（URL 解码 / Base64），无可还原内容时返回空
func decodeParamValue(v string) string {
	if v == "" {
		return ""
	}
	if d, err := url.QueryUnescape(v); err == nil && d != v {
		return d
	}
	if len(v) >= 8 && len(v)%4 == 0 {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
			if b, err := enc.DecodeString(v); err == nil && len(b) > 0 && mostlyPrintable(b) {
				return string(b)
			}
		}
	}
	return ""
}

func mostlyPrintable(b []byte) bool {
	n := 0
	for _, c := range b {
		if c == '\r' || c == '\n' || c == '\t' || (c >= 0x20 && c < 0x7f) {
			n++
		}
	}
	return float64(n)/float64(len(b)) > 0.85
}

// argItems 将 url_arg_*/cba_* 形态的参数 map 转为有序列表（键去掉前缀）
func argItems(args map[string]map[string]string, prefix string) []gin.H {
	var out []gin.H
	for k, a := range args {
		out = append(out, gin.H{
			"name":    strings.TrimPrefix(k, prefix),
			"value":   a["value"],
			"decoded": decodeParamValue(a["value"]),
			"type":    a["type"],
		})
	}
	return out
}

// fileItems 将 multipart 上传文件 map 转为列表
func fileItems(fd localhttp_parse.Form_data) []gin.H {
	var out []gin.H
	for name, meta := range fd.Files {
		out = append(out, gin.H{
			"filename":     name,
			"file_type":    meta["file_type"],
			"suffix_match": meta["file_suffix_type"],
		})
	}
	return out
}

// exchangeDetail 单个请求/响应对的完整解析详情（供前端可视化展示）
func exchangeDetail(e *nuclei.Exchange, m map[string]interface{}, urlArgs, cbaArgs map[string]map[string]string, fd localhttp_parse.Form_data) gin.H {
	// 浅拷贝扁平解析结果，避免与 merged 引用同一 map 造成序列化循环引用
	parsed := make(map[string]interface{}, len(m))
	for k, v := range m {
		parsed[k] = v
	}
	return gin.H{
		"index":   e.ReqFrame,
		"method":  e.Method,
		"uri":     e.URI,
		"version": e.Version,
		"host":    e.Host,

		"req_headers":      e.ReqHeaders,
		"req_body":         clipText(e.ReqBody, 40000),
		"req_url_type":     m["req_url_type"],
		"req_content_type": m["req_content_type"],
		"req_body_type":    m["req_client_body_type"],
		"req_ua_type":      m["req_ua_type"],
		"url_args":         argItems(urlArgs, "url_arg_"),
		"body_args":        argItems(cbaArgs, "cba_"),
		"form_kv":          fd.Key_va,
		"files":            fileItems(fd),

		"has_resp":         e.HasResp,
		"status":           e.Status,
		"phrase":           e.Phrase,
		"resp_version":     e.RespVersion,
		"resp_headers":     e.RespHeaders,
		"resp_body":        clipText(e.RespBody, 40000),
		"res_content_type": m["res_content_type"],
		"res_body_type":    m["res_client_body_type"],

		"parsed": parsed, // 原始扁平解析结果，供前端「原始数据」查看
	}
}

// paramRows 将某个请求的参数打平为表格行（含位置、解码值、类型判断）
func paramRows(exIdx int, urlArgs, cbaArgs map[string]map[string]string, fd localhttp_parse.Form_data) []gin.H {
	var out []gin.H
	add := func(location, name, value string) {
		out = append(out, gin.H{
			"exchange": exIdx,
			"location": location,
			"name":     name,
			"value":    value,
			"decoded":  decodeParamValue(value),
			"type":     localhttp_parse.Judge_arg_value_type(value),
		})
	}
	for k, a := range urlArgs {
		add("query", strings.TrimPrefix(k, "url_arg_"), a["value"])
	}
	for k, a := range cbaArgs {
		add("body", strings.TrimPrefix(k, "cba_"), a["value"])
	}
	for k, v := range fd.Key_va {
		add("form", k, v)
	}
	for name, meta := range fd.Files {
		t := "文件上传"
		if meta["file_suffix_type"] == "True" {
			t = "文件上传（内容与后缀一致）"
		} else if meta["file_suffix_type"] == "None" {
			t = "文件上传（内容与后缀不匹配，可疑）"
		}
		out = append(out, gin.H{
			"exchange": exIdx,
			"location": "file",
			"name":     name,
			"value":    meta["file_type"],
			"decoded":  "",
			"type":     t,
		})
	}
	return out
}

// riskItem 本地引擎检出项，携带引擎名与命中规则，便于前端标注来源
type riskItem struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Engine   string `json:"engine"`   // 检出引擎显示名
	Rule     string `json:"rule"`     // 命中规则/特征描述
	Severity string `json:"severity"` // 严重级别
	Detail   string `json:"detail"`   // 详细说明
	Frame    int    `json:"frame,omitempty"`
	Method   string `json:"method,omitempty"`
	URI      string `json:"uri,omitempty"`
	Found    bool   `json:"found"`
	Result   string `json:"result"`
}

// detectRisk 对解析出的请求/响应做综合风险判定：本地引擎 + nuclei 模板 + 跨会话分析
func detectRisk(exs []*nuclei.Exchange) gin.H {

	var items []riskItem

	// 本地引擎：对请求 uri+body 做载荷识别
	for _, e := range exs {
		target := e.URI + "\n" + e.ReqBody
		if target == "\n" {
			continue
		}
		at := func(it riskItem) riskItem {
			it.Frame = e.ReqFrame
			it.Method = e.Method
			it.URI = e.URI
			return it
		}
		if w := localwebshell.Check([]byte(target)); w.Webshell {
			items = append(items, at(riskItem{
				Type: "webshell", Title: "Webshell", Engine: "本地引擎·Webshell",
				Severity: "high", Rule: strings.Join(w.Hits, ", "),
				Detail: fmt.Sprintf("%s（语言:%s 解码链:%s 评分:%d）", w.Result, w.Lang, w.Chain, w.Score),
				Found:  true, Result: w.Result,
			}))
		}
		if b := localbash.Check(target); b.Found {
			rule := strings.Join(b.Hits, ", ")
			detail := fmt.Sprintf("%s（评分:%d）", b.Result, b.Score)
			if b.Normalized != "" && b.Normalized != target {
				detail += " 还原后: " + b.Normalized
			}
			items = append(items, at(riskItem{
				Type: "bash", Title: "Bash命令", Engine: "本地引擎·Bash命令",
				Severity: "high", Rule: rule, Detail: detail,
				Found: true, Result: b.Result,
			}))
		}
		if lookups, danger := btt.ParseLog4j2(target); danger {
			var rules []string
			for _, l := range lookups {
				if l.Danger {
					rules = append(rules, l.Raw)
				}
			}
			items = append(items, at(riskItem{
				Type: "log4j2", Title: "Log4j2 JNDI", Engine: "本地引擎·Log4j2",
				Severity: "critical", Rule: "危险 JNDI lookup: " + strings.Join(rules, " , "),
				Detail: fmt.Sprintf("检测到 %d 个 ${...} lookup 表达式，其中 %d 个为可利用的 JNDI 注入", len(lookups), len(rules)),
				Found:  true, Result: fmt.Sprintf("检测到 JNDI 注入风险 (%d 个 lookup)", len(lookups)),
			}))
		}
		// sqli/xss：按解析出的参数值（query/form/json/cookie/请求头）检测，
		// 不再整段扫报文，避免 HTML/路径文本命中 libinjection 误报
		hdrs := make(map[string]string, len(e.ReqHeaders))
		for _, h := range e.ReqHeaders {
			hdrs[strings.ToLower(h.Name)] = h.Value
		}
		for _, hit := range inject.Scan(e.URI, e.ReqBody, hdrs) {
			detail := fmt.Sprintf("参数 %s，值【%s】，%s",
				hit.Location(), trunc(hit.Point.Value, 120), hit.Detail)
			if hit.Engine == "sqli" {
				items = append(items, at(riskItem{
					Type: "sqli", Title: "SQL注入", Engine: "本地引擎·SQLi(libinjection)",
					Severity: "high", Rule: "libinjection 词法指纹",
					Detail: detail, Found: true, Result: detail,
				}))
			} else {
				items = append(items, at(riskItem{
					Type: "xss", Title: "XSS", Engine: "本地引擎·XSS(libinjection)",
					Severity: "medium", Rule: "libinjection XSS 检测",
					Detail: detail, Found: true, Result: detail,
				}))
			}
		}
	}

	// nuclei：完整请求+响应匹配（命中即视为攻击成功）
	var nFindings []nuclei.Finding
	var sigHits []nuclei.SigHit
	if db.GlobalDB != nil {
		eng, _ := vuln.Load()
		if len(eng.Templates) > 0 {
			nFindings = eng.Detect(exs)
			for _, e := range exs {
				sigHits = append(sigHits, eng.SignatureMatch(e.RequestRaw(), 3)...)
			}
		}
	}

	// 跨会话（webshell 等）
	sessFindings := session.Analyze(exs)

	success := len(nFindings) > 0
	found := success || len(items) > 0 || len(sigHits) > 0 || len(sessFindings) > 0
	title := "未识别到攻击特征"
	switch {
	case success:
		title = nFindings[0].Name
	case len(items) > 0:
		title = items[0].Title
	case len(sigHits) > 0:
		title = "疑似 " + sigHits[0].Name
	case len(sessFindings) > 0:
		title = sessFindings[0].Title
	}
	var ver string
	switch {
	case success:
		ver = "攻击成功（请求与响应均命中 nuclei 规则特征）"
	case found:
		ver = "发现攻击特征，但响应未命中漏洞特征（无法确认成功）"
	default:
		ver = "未发现攻击特征"
	}
	return gin.H{
		"found": found, "success": success, "title": title, "verdict": ver,
		"items": items, "nuclei": nFindings, "signature": sigHits, "session": sessFindings,
	}
}

type GenPcapReq struct {
	SrcIP    string `json:"src_ip"`
	DstIP    string `json:"dst_ip"`
	SrcPort  int    `json:"src_port"`
	DstPort  int    `json:"dst_port"`
	ReqData  string `json:"req_data"`
	ResData  string `json:"res_data"`
	Filename string `json:"filename"`
}

// GenPcap 将请求/响应文本合成为含完整 TCP 会话的 pcap 文件下载
func GenPcap(c *gin.Context) {
	var r GenPcapReq
	if err := c.ShouldBindJSON(&r); err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	if r.ReqData == "" && r.ResData == "" {
		msg.ResultFailed(c, "无内容")
		return
	}
	// httpstream 粘贴时自动拆分全部会话，逐个会话串行写入同一连接序列不合适，
	// 取第一对生成单会话 pcap；多会话场景建议分别合成
	if localhttp_parse.LooksLikeStream(r.ReqData) {
		pairs := localhttp_parse.ParseStream(r.ReqData)
		if len(pairs) > 0 {
			if pairs[0].Response == "" && r.ResData != "" {
				pairs[0].Response = r.ResData
			}
			r.ReqData, r.ResData = pairs[0].Request, pairs[0].Response
		}
	} else if r.ReqData == "" && localhttp_parse.LooksLikeStream(r.ResData) {
		pairs := localhttp_parse.ParseStream(r.ResData)
		if len(pairs) > 0 {
			r.ReqData, r.ResData = pairs[0].Request, pairs[0].Response
		}
	}
	norm := func(s string) []byte {
		s = localhttp_parse.DecodeHex(s)
		s = strings.ReplaceAll(s, "\r\n", "\n")
		s = strings.ReplaceAll(s, "\n", "\r\n")
		return []byte(s)
	}
	data := pcapgen.HTTP(pcapgen.Options{
		SrcIP: r.SrcIP, DstIP: r.DstIP,
		SrcPort: uint16(r.SrcPort), DstPort: uint16(r.DstPort),
	}, norm(r.ReqData), norm(r.ResData))
	name := strings.TrimSpace(r.Filename)
	if name == "" {
		name = "btab_http_session"
	}
	if !strings.HasSuffix(name, ".pcap") {
		name += ".pcap"
	}
	c.Header("Content-Disposition", "attachment; filename=\""+name+"\"")
	c.Data(http.StatusOK, "application/vnd.tcpdump.pcap", data)
}

func trunc(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
