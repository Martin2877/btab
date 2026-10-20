// Package analyze 为程序化调用方（如 Wireshark 插件、脚本、CI）提供
// 面向单次分析的无状态 API：攻击检测、HTTP 深度解析、payload 解码、
// pcap 流量检测梳理、DSL 引擎查询。
//
// 与 /api/risk/* 不同，这些接口不依赖数据库存储检测结果，
// 输入输出均为纯 JSON，适合自动化流程串联。
package analyze

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Martin2877/blue-team-box/api/msg"
	localbash "github.com/Martin2877/blue-team-box/engine/local/bash"
	httpengine "github.com/Martin2877/blue-team-box/engine/local/http_parse"
	"github.com/Martin2877/blue-team-box/engine/local/inject"
	localsqli "github.com/Martin2877/blue-team-box/engine/local/sqli"
	localwebshell "github.com/Martin2877/blue-team-box/engine/local/webshell"
	localxss "github.com/Martin2877/blue-team-box/engine/local/xss"
	"github.com/Martin2877/blue-team-box/engine/plugin"
	"github.com/Martin2877/blue-team-box/pkg/conf"
	"github.com/Martin2877/blue-team-box/pkg/file"
	pkgpcap "github.com/Martin2877/blue-team-box/pkg/pcap"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

var startTime = time.Now()

// ===================== Health =====================

// GET /api/analyze/health
func Health(c *gin.Context) {
	resolved, tsharkErr := pkgpcap.ResolveTsharkPath()
	msg.ResultSuccess(c, gin.H{
		"version":         conf.Version,
		"uptime_sec":      int(time.Since(startTime).Seconds()),
		"tshark_path":     conf.GlobalConfig.PcapAnalyseConfig.TsharkPath,
		"tshark_resolved": resolved,
		"tshark_ok":       tsharkErr == nil,
		"engines":         []string{"sqli", "xss", "bash", "webshell"},
		"plugins":         pluginNames(),
	})
}

func pluginNames() []string {
	names := make([]string, 0, len(plugin.MapPluginGlb))
	for name := range plugin.MapPluginGlb {
		names = append(names, name)
	}
	return names
}

// ===================== Detect =====================

type DetectRequest struct {
	Content string `json:"content" binding:"required"`
	// url_decode: 先对 content 做一次 URL 解码再检测（处理双重编码/整个编码后的请求）
	URLDecode bool `json:"url_decode"`
	// input_format: raw（默认）| hex（content 为 hex 编码的字节，如 tcp.payload）
	InputFormat string `json:"input_format"`
	// engines: 指定检测引擎，默认 ["sqli","xss"]；可选 "bash"、"webshell"（均为本地检测）
	Engines []string `json:"engines"`
}

type DetectItem struct {
	Found     bool        `json:"found"`
	Code      int         `json:"code"`
	Message   string      `json:"message"`
	Result    interface{} `json:"result"`
	Available bool        `json:"available"` // 引擎是否可用
}

// POST /api/analyze/detect
func Detect(c *gin.Context) {
	var req DetectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	if req.Content == "" {
		msg.ResultFailed(c, "无检测内容")
		return
	}

	content := req.Content
	if strings.EqualFold(req.InputFormat, "hex") {
		clean := strings.Map(func(r rune) rune {
			switch {
			case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
				return r
			}
			return -1
		}, content)
		if b, err := hex.DecodeString(clean); err == nil {
			content = string(b)
		}
	}
	if req.URLDecode {
		if decoded, err := url.QueryUnescape(content); err == nil {
			content = decoded
		}
	}

	engines := req.Engines
	if len(engines) == 0 {
		engines = []string{"sqli", "xss"}
	}

	resp := gin.H{"risk": false}
	var summaryParts []string

	for _, eng := range engines {
		switch strings.ToLower(eng) {
		case "sqli":
			s := localsqli.Sqli{}
			jres, err := s.SubmitOnce(content)
			item := DetectItem{Available: true}
			if err != nil {
				item.Message = err.Error()
			} else {
				item.Code = jres.Code
				item.Message = jres.Message
				item.Result = jres.Result
				item.Found = jres.Code == 20000
			}
			resp["sqli"] = item
			if item.Found {
				summaryParts = append(summaryParts, "SQL注入")
			}
		case "xss":
			x := localxss.XSS{}
			jres, err := x.SubmitOnce(content)
			item := DetectItem{Available: true}
			if err != nil {
				item.Message = err.Error()
			} else {
				item.Code = jres.Code
				item.Message = jres.Message
				item.Result = jres.Result
				item.Found = jres.Code == 20000
			}
			resp["xss"] = item
			if item.Found {
				summaryParts = append(summaryParts, "XSS")
			}
		case "bash":
			item := DetectItem{Available: true}
			res := localbash.Check(content)
			item.Found = res.Found
			item.Message = res.Result
			item.Result = res
			resp["bash"] = item
			if item.Found {
				summaryParts = append(summaryParts, "Bash命令执行")
			}
		case "webshell":
			item := DetectItem{Available: true}
			res := localwebshell.Check([]byte(content))
			item.Code = 40400
			item.Found = res.Webshell
			item.Message = res.Result
			item.Result = res
			if res.Webshell {
				item.Code = 20000
			}
			resp["webshell"] = item
			if item.Found {
				summaryParts = append(summaryParts, "Webshell")
			}
		}
	}

	if len(summaryParts) > 0 {
		resp["risk"] = true
		resp["summary"] = "检测到攻击: " + strings.Join(summaryParts, "、")
	} else {
		resp["summary"] = "未检测到攻击特征"
	}
	msg.ResultSuccess(c, resp)
}

// ===================== HTTP Parse =====================

type HttpParseRequest struct {
	ReqData string `json:"req_data"`
	ResData string `json:"res_data"`
}

// POST /api/analyze/http_parse
// 与 /api/risk/http_parse/submit 相同能力，独立暴露便于程序化调用
func HttpParse(c *gin.Context) {
	var req HttpParseRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	if req.ReqData == "" && req.ResData == "" {
		msg.ResultFailed(c, "无检测内容")
		return
	}

	hp := httpengine.HTTP_PARSE{}
	out := gin.H{}
	if req.ReqData != "" {
		reqMap, urlArgs, clientArgs, formdata := hp.Req_parse(req.ReqData)
		out["request"] = gin.H{
			"summary":   reqMap,
			"url_args":  urlArgs,
			"body_args": clientArgs,
			"form_data": formdata,
		}
	}
	if req.ResData != "" {
		out["response"] = hp.Res_parse(req.ResData)
	}
	msg.ResultSuccess(c, out)
}

// ===================== Decode =====================

type DecodeRequest struct {
	Content string `json:"content" binding:"required"`
	// encoding: auto | base64 | base64url | url | hex | java
	// auto 时依次尝试全部解码器，返回所有成功项
	Encoding string `json:"encoding"`
	// input_format: raw（默认，content 即原始内容）| hex（content 为 hex 编码的字节）
	InputFormat string `json:"input_format"`
}

type DecodeResult struct {
	Encoding string `json:"encoding"`
	Success  bool   `json:"success"`
	Output   string `json:"output"`
	Note     string `json:"note,omitempty"`
}

// POST /api/analyze/decode
func Decode(c *gin.Context) {
	var req DecodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	if req.Content == "" {
		msg.ResultFailed(c, "无检测内容")
		return
	}

	content := req.Content
	if strings.EqualFold(req.InputFormat, "hex") {
		clean := strings.Map(func(r rune) rune {
			switch {
			case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
				return r
			}
			return -1
		}, content)
		if b, err := hex.DecodeString(clean); err == nil {
			content = string(b)
		}
	}

	enc := strings.ToLower(req.Encoding)
	if enc == "" {
		enc = "auto"
	}
	var results []DecodeResult

	tryB64 := func(name string, dec *base64.Encoding) {
		if out, err := dec.DecodeString(strings.TrimSpace(content)); err == nil {
			results = append(results, DecodeResult{Encoding: name, Success: true, Output: string(out)})
		}
	}

	if enc == "auto" || enc == "base64" {
		tryB64("base64", base64.StdEncoding)
	}
	if enc == "auto" || enc == "base64url" {
		tryB64("base64url", base64.URLEncoding)
	}
	if enc == "auto" || enc == "url" {
		if out, err := url.QueryUnescape(content); err == nil && out != content {
			results = append(results, DecodeResult{Encoding: "url", Success: true, Output: out})
		}
	}
	if enc == "auto" || enc == "hex" {
		clean := strings.Map(func(r rune) rune {
			switch {
			case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
				return r
			}
			return -1
		}, content)
		if len(clean) >= 2 && len(clean)%2 == 0 {
			if b, err := hex.DecodeString(clean); err == nil {
				results = append(results, DecodeResult{Encoding: "hex", Success: true, Output: string(b)})
			}
		}
	}

	// java 序列化解析（纯 Go 实现，无需 java 环境）
	if enc == "java" {
		pgs, err := plugin.NewPlugin("SerializationDumper")
		if err != nil {
			msg.ResultFailed(c, err.Error())
			return
		}
		pgs.Plugin.Init()
		pgs.Plugin.Set("content", content)
		if err := pgs.Plugin.Check(); err != nil {
			msg.ResultFailed(c, err.Error())
			return
		}
		if err := pgs.Plugin.Exec(); err != nil {
			results = append(results, DecodeResult{Encoding: "java", Success: false, Note: err.Error()})
		} else {
			results = append(results, DecodeResult{Encoding: "java", Success: true, Output: pgs.Plugin.GetResult()})
		}
	}

	msg.ResultSuccess(c, gin.H{"results": results})
}

// ===================== Pcap 分析 =====================

type PcapAnalyzeRequest struct {
	// file: 服务端本地 pcap 文件路径（上传优先）
	File string `json:"file"`
	// filter: tshark display filter，默认 "http"
	Filter string `json:"filter"`
	// fields: 额外提取的 tshark 字段
	Fields []string `json:"fields"`
	// detect: 是否对每个 HTTP 请求跑攻击检测，默认 true
	Detect *bool `json:"detect"`
}

type FlowDetection struct {
	Type   string `json:"type"`   // sqli / xss / bash
	Detail string `json:"detail"` // 命中详情
}

type FlowItem struct {
	Frame         int             `json:"frame"`
	Time          string          `json:"time"`
	SrcIP         string          `json:"src_ip"`
	SrcPort       string          `json:"src_port"`
	DstIP         string          `json:"dst_ip"`
	DstPort       string          `json:"dst_port"`
	Stream        string          `json:"stream"`
	Method        string          `json:"method"`
	Host          string          `json:"host"`
	URI           string          `json:"uri"`
	UserAgent     string          `json:"user_agent"`
	Cookie        string          `json:"cookie,omitempty"`
	XForwardedFor string          `json:"x_forwarded_for,omitempty"`
	Referer       string          `json:"referer,omitempty"`
	ContentType   string          `json:"content_type,omitempty"`
	Body          string          `json:"body"`
	Detections    []FlowDetection `json:"detections"`
}

// POST /api/analyze/pcap
// 两种用法：
//  1. multipart/form-data 上传: -F "file=@x.pcap" [-F "filter=http"]
//  2. application/json: {"file": "/path/to/x.pcap", "filter": "http"}
//
// 返回 HTTP 会话列表 + 每会话攻击检测结果（攻击过程梳理）
func Pcap(c *gin.Context) {
	var req PcapAnalyzeRequest
	var cleanup []string
	defer func() {
		for _, f := range cleanup {
			os.Remove(f)
		}
	}()

	ctype := c.ContentType()
	if strings.HasPrefix(ctype, "multipart/form-data") {
		header, err := c.FormFile("file")
		if err != nil {
			msg.ResultFailed(c, "缺少上传文件: "+err.Error())
			return
		}
		name := file.SafeFileName(header.Filename)
		if name == "" {
			msg.ResultFailed(c, "非法文件名")
			return
		}
		tmp := filepath.Join(os.TempDir(), fmt.Sprintf("btab_%d_%s", time.Now().UnixNano(), name))
		fh, err := header.Open()
		if err != nil {
			msg.ResultFailed(c, err.Error())
			return
		}
		data, err := io.ReadAll(fh)
		fh.Close()
		if err != nil {
			msg.ResultFailed(c, err.Error())
			return
		}
		if err := file.WriteFileBinary(data, tmp, false); err != nil {
			msg.ResultFailed(c, err.Error())
			return
		}
		cleanup = append(cleanup, tmp)
		req.File = tmp
		req.Filter = c.PostForm("filter")
	} else {
		if err := c.ShouldBindJSON(&req); err != nil {
			msg.ResultFailed(c, "参数不合法:"+err.Error())
			return
		}
		// 服务端本地路径：要求文件存在且为 pcap 后缀
		abs, err := filepath.Abs(req.File)
		if err != nil || !file.Exists(abs) {
			msg.ResultFailed(c, "文件不存在: "+req.File)
			return
		}
		req.File = abs
	}

	if req.File == "" {
		msg.ResultFailed(c, "缺少 pcap 文件")
		return
	}
	if req.Filter == "" {
		req.Filter = "http"
	}
	doDetect := req.Detect == nil || *req.Detect

	flows, err := analyzePcapFlows(req.File, req.Filter, req.Fields)
	if err != nil {
		msg.ResultFailed(c, err.Error())
		return
	}

	summary := gin.H{
		"total_flows": len(flows),
	}
	if doDetect {
		detectPcapFlows(flows, nil)
		hits := 0
		attackKinds := map[string]bool{}
		for _, f := range flows {
			if len(f.Detections) > 0 {
				hits++
				for _, d := range f.Detections {
					attackKinds[d.Type] = true
				}
			}
		}
		summary["detected_flows"] = hits
		kinds := make([]string, 0, len(attackKinds))
		for k := range attackKinds {
			kinds = append(kinds, k)
		}
		summary["attack_types"] = kinds
	}
	msg.ResultSuccess(c, gin.H{"summary": summary, "flows": flows})
}

var defaultPcapFields = []string{
	"frame.number", "frame.time",
	"ip.src", "tcp.srcport", "ip.dst", "tcp.dstport", "tcp.stream",
	"http.request.method", "http.request.uri", "http.host",
	"http.user_agent", "http.cookie", "http.x_forwarded_for",
	"http.referer", "http.content_type", "http.file_data",
}

// analyzePcapFlows 用 tshark 提取指定字段，组装为流列表
func analyzePcapFlows(filePath, filter string, extraFields []string) ([]*FlowItem, error) {
	pcaper := pkgpcap.CreatePcaper()
	if err := pcaper.Load(filePath); err != nil {
		return nil, err
	}
	fields := append([]string{}, defaultPcapFields...)
	fields = append(fields, extraFields...)
	pcaper.SetFields(fields)

	raw, _, err := pcaper.Query(filter)
	if err != nil {
		return nil, err
	}
	packets := gjson.GetBytes(raw, "#._source.layers")
	if !packets.Exists() || len(packets.Array()) == 0 {
		return nil, fmt.Errorf("pcap 无匹配数据（filter=%s）", filter)
	}

	flows := make([]*FlowItem, 0, len(packets.Array()))
	for _, p := range packets.Array() {
		get := func(k string) string { return p.Get(k + ".0").String() }
		var bodyBuilder strings.Builder
		for _, fd := range p.Get("http\\.file_data").Array() {
			if b, err := hex.DecodeString(fd.String()); err == nil {
				bodyBuilder.Write(b)
			} else {
				bodyBuilder.WriteString(fd.String())
			}
		}
		frame, _ := strconv.Atoi(get("frame\\.number"))
		flows = append(flows, &FlowItem{
			Frame:         frame,
			Time:          get("frame\\.time"),
			SrcIP:         get("ip\\.src"),
			SrcPort:       get("tcp\\.srcport"),
			DstIP:         get("ip\\.dst"),
			DstPort:       get("tcp\\.dstport"),
			Stream:        get("tcp\\.stream"),
			Method:        get("http\\.request\\.method"),
			Host:          get("http\\.host"),
			URI:           get("http\\.request\\.uri"),
			UserAgent:     get("http\\.user_agent"),
			Cookie:        get("http\\.cookie"),
			XForwardedFor: get("http\\.x_forwarded_for"),
			Referer:       get("http\\.referer"),
			ContentType:   get("http\\.content_type"),
			Body:          bodyBuilder.String(),
		})
	}
	return flows, nil
}

// detectPcapFlows 对每个 flow 的请求参数值（query/form/json/cookie/头部）做 sqli/xss 检测；
// report 非空时上报处理进度。
// 只对请求帧检测：响应帧的 http.file_data 为页面内容，整段喂给 libinjection 会产生大量误报。
func detectPcapFlows(flows []*FlowItem, report func(done, total int)) {
	for i, f := range flows {
		if report != nil && i%16 == 0 {
			report(i, len(flows))
		}
		if f.Method == "" {
			continue
		}
		headers := map[string]string{
			"cookie":          f.Cookie,
			"x-forwarded-for": f.XForwardedFor,
			"referer":         f.Referer,
			"user-agent":      f.UserAgent,
			"content-type":    f.ContentType,
		}
		for _, h := range inject.Scan(f.URI, f.Body, headers) {
			f.Detections = append(f.Detections, FlowDetection{
				Type:   h.Engine,
				Detail: fmt.Sprintf("%s=【%s】%s", h.Location(), clipStr(h.Point.Value, 120), h.Detail),
			})
		}
	}
	if report != nil {
		report(len(flows), len(flows))
	}
}

// ===================== 结构化流分析 =====================

type FlowInput struct {
	Frame     int    `json:"frame"`
	Time      string `json:"time"`
	SrcIP     string `json:"src_ip"`
	SrcPort   string `json:"src_port"`
	DstIP     string `json:"dst_ip"`
	DstPort   string `json:"dst_port"`
	Stream    string `json:"stream"`
	Method    string `json:"method"`
	Host      string `json:"host"`
	URI       string `json:"uri"`
	UserAgent string `json:"user_agent"`
	Body      string `json:"body"`
	BodyHex   string `json:"body_hex"`
}

type FlowsRequest struct {
	Flows  []FlowInput `json:"flows" binding:"required"`
	Detect *bool       `json:"detect"`
}

// POST /api/analyze/flows
// 接受调用方（如 Wireshark Lua tap）已提取的结构化 HTTP 流，
// 对每条流的 URI+Body 做 sqli/xss 检测，返回带 detections 的流列表。
// 与 /api/analyze/pcap 的区别：输入是结构化数据而非 pcap 文件，
// 不要求调用方与服务端同机，也不要求捕获文件落盘。
func Flows(c *gin.Context) {
	var req FlowsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	if len(req.Flows) == 0 {
		msg.ResultFailed(c, "flows 为空")
		return
	}
	if len(req.Flows) > 10000 {
		msg.ResultFailed(c, "单次最多 10000 条流，请分批提交")
		return
	}

	flows := make([]*FlowItem, 0, len(req.Flows))
	for _, fi := range req.Flows {
		item := &FlowItem{
			Frame: fi.Frame, Time: fi.Time,
			SrcIP: fi.SrcIP, SrcPort: fi.SrcPort,
			DstIP: fi.DstIP, DstPort: fi.DstPort,
			Stream: fi.Stream, Method: fi.Method,
			Host: fi.Host, URI: fi.URI,
			UserAgent: fi.UserAgent, Body: fi.Body,
		}
		if item.Body == "" && fi.BodyHex != "" {
			clean := strings.Map(func(r rune) rune {
				switch {
				case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
					return r
				}
				return -1
			}, fi.BodyHex)
			if len(clean) >= 2 && len(clean)%2 == 0 {
				if b, err := hex.DecodeString(clean); err == nil {
					item.Body = string(b)
				}
			}
		}
		flows = append(flows, item)
	}

	summary := gin.H{"total_flows": len(flows)}
	if req.Detect == nil || *req.Detect {
		detectPcapFlows(flows, nil)
		hits := 0
		attackKinds := map[string]bool{}
		hitFrames := []int{}
		for _, f := range flows {
			if len(f.Detections) > 0 {
				hits++
				hitFrames = append(hitFrames, f.Frame)
				for _, d := range f.Detections {
					attackKinds[d.Type] = true
				}
			}
		}
		summary["detected_flows"] = hits
		summary["hit_frames"] = hitFrames
		kinds := make([]string, 0, len(attackKinds))
		for k := range attackKinds {
			kinds = append(kinds, k)
		}
		summary["attack_types"] = kinds
	}
	msg.ResultSuccess(c, gin.H{"summary": summary, "flows": flows})
}

// ===================== DSL Engine =====================

type EngineRequest struct {
	// query: DSL 查询，如
	//   | jq
	//   |: filter .xxx
	//   |: content {...}
	Query string `json:"query" binding:"required"`
}

// POST /api/analyze/engine 执行 btab DSL 引擎查询（插件链）
func Engine(c *gin.Context) {
	var req EngineRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	result, err := engineRun(req.Query)
	if err != nil {
		msg.ResultFailed(c, err.Error())
		return
	}
	msg.ResultSuccess(c, gin.H{"result": result})
}
