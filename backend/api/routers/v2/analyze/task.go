package analyze

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/api/routers/v2/risk"
	"github.com/Martin2877/blue-team-box/api/routers/v2/risk/pcapanalyse"
	httpengine "github.com/Martin2877/blue-team-box/engine/local/http_parse"
	"github.com/Martin2877/blue-team-box/engine/local/urldetect"
	"github.com/Martin2877/blue-team-box/engine/local/weblog"
	"github.com/Martin2877/blue-team-box/engine/nuclei"
	"github.com/Martin2877/blue-team-box/engine/pcapjs"
	pluginpcap "github.com/Martin2877/blue-team-box/engine/plugin/pcap"
	"github.com/Martin2877/blue-team-box/engine/vuln"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/Martin2877/blue-team-box/pkg/file"
	utils "github.com/Martin2877/blue-team-box/pkg/util"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/unknwon/com"
)

// 一键分析支持的检测方式；为空时表示按输入类型自动选择全部适用项
const (
	MethodClassify = "classify" // 载荷自动识别（webshell/bash/log4j2/sqli/xss/nuclei特征）
	MethodHTTP     = "http"     // HTTP 请求响应深度解析
	MethodFlow     = "flow"     // 流量会话梳理 + 逐流载荷检测（pcap）
	MethodStrategy = "strategy" // 行为检测脚本（pcap / log 各自数据源的策略）
	MethodNuclei   = "nuclei"   // nuclei 规则检测（pcap / httpstream 文本）
	MethodSession  = "session"  // 跨会话关联分析（pcap）
	MethodURLRules = "urlrules" // URL 规则检测（web 日志）
)

var textMethods = map[string]bool{MethodClassify: true, MethodHTTP: true, MethodNuclei: true}
var pcapMethods = map[string]bool{MethodFlow: true, MethodStrategy: true, MethodNuclei: true, MethodSession: true}
var logMethods = map[string]bool{MethodURLRules: true, MethodStrategy: true}

// MethodOptions 返回前端可选的检测方式说明
func MethodOptions() []gin.H {
	return []gin.H{
		{"key": MethodClassify, "label": "载荷自动识别", "input": "text"},
		{"key": MethodHTTP, "label": "HTTP深度解析", "input": "text"},
		{"key": MethodFlow, "label": "流量会话梳理", "input": "pcap"},
		{"key": MethodStrategy, "label": "行为检测脚本", "input": "pcap/log"},
		{"key": MethodNuclei, "label": "nuclei规则检测", "input": "text/pcap"},
		{"key": MethodSession, "label": "跨会话关联分析", "input": "pcap"},
		{"key": MethodURLRules, "label": "URL规则检测", "input": "log"},
	}
}

// ===== 报告结构 =====

type Step struct {
	Name   string `json:"name"`   // 步骤名称
	Status string `json:"status"` // ok | hit | error | skip
	Detail string `json:"detail"` // 一句话说明
	Ms     int64  `json:"ms"`
}

type Report struct {
	Verdict string            `json:"verdict"` // 结论
	Risk    bool              `json:"risk"`
	Types   []string          `json:"types"`            // 判定风险类别
	Steps   []Step            `json:"steps"`            // 分析过程
	Items   []risk.DetectItem `json:"items,omitempty"`  // 载荷识别明细（text）
	HTTP    interface{}       `json:"http,omitempty"`   // HTTP 解析结果（text）
	Flows   int               `json:"flows,omitempty"`  // 提取的 HTTP 会话数（pcap）
	Events  []pcapjs.Event    `json:"events,omitempty"` // 检出事件（pcap/log）
	Log     interface{}       `json:"log,omitempty"`    // 日志梳理概览（log）
	Errors  []string          `json:"errors,omitempty"`
}

// ===== 进度 =====

type taskProgress struct {
	mu    sync.Mutex
	cur   string
	done  int
	total int
	steps []Step // 已完成步骤快照，供前端实时展示
}

var taskProgressMap sync.Map // task id -> *taskProgress

func (p *taskProgress) start(name string) {
	p.mu.Lock()
	p.cur = name
	p.mu.Unlock()
}
func (p *taskProgress) stepDone(s Step) {
	p.mu.Lock()
	p.done++
	p.steps = append(p.steps, s)
	p.mu.Unlock()
}
func (p *taskProgress) snapshot() (string, int, int, []Step) {
	p.mu.Lock()
	defer p.mu.Unlock()
	steps := make([]Step, len(p.steps))
	copy(steps, p.steps)
	return p.cur, p.done, p.total, steps
}

// ===== 输入判定 =====

var httpReqRe = regexp.MustCompile(`^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+\S+\s+HTTP/|^HTTP/`)

func isPcapData(name string, head []byte) bool {
	if len(head) >= 4 {
		magic := uint32(head[0])<<24 | uint32(head[1])<<16 | uint32(head[2])<<8 | uint32(head[3])
		if magic == 0xa1b2c3d4 || magic == 0xd4c3b2a1 || magic == 0x0a0d0d0a || magic == 0xa1b23c4d || magic == 0x4d3cb2a1 {
			return true
		}
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".pcap", ".pcapng", ".cap":
		return true
	}
	return false
}

// isTextData 粗略判断是否为文本（前 4KB 无 NUL 且大多可打印）
func isTextData(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if len(b) > 4096 {
		b = b[:4096]
	}
	printable := 0
	for _, c := range b {
		if c == 0 {
			return false
		}
		if c >= 0x20 || c == '\t' || c == '\r' || c == '\n' || c >= 0x80 {
			printable++
		}
	}
	return printable >= len(b)*9/10
}

const maxTextInput = 8 << 20 // 粘贴文本上限 8MB
const maxLogInput = 50 << 20 // 日志输入上限 50MB（与 web 日志仓库一致）

// TaskMethods GET /api/analyze/task/methods 返回可选检测方式
func TaskMethods(c *gin.Context) {
	msg.ResultSuccess(c, MethodOptions())
}

// ===== 接口 =====

// SubmitTask POST /api/analyze/task/submit
//  1. application/json: {"name":"可选", "content":"载荷文本", "methods":["classify","http"]}
//     或 {"pcap_id": N, "methods":[...]} 直接引用威胁仓库中已登记的流量包（stores/pcap 文件），免上传
//  2. multipart/form-data: -F "file=@x.pcap|x.txt" [-F "name="] [-F "methods=strategy,nuclei"]
func SubmitTask(c *gin.Context) {
	var (
		name, content, filePath, inputType, inputName string
		methods                                       []string
		tmpFile                                       string
	)
	if strings.HasPrefix(c.ContentType(), "multipart/form-data") {
		header, err := c.FormFile("file")
		if err != nil {
			msg.ResultFailed(c, "缺少上传文件: "+err.Error())
			return
		}
		fname := file.SafeFileName(header.Filename)
		if fname == "" {
			msg.ResultFailed(c, "非法文件名")
			return
		}
		tmpFile = filepath.Join(os.TempDir(), fmt.Sprintf("btab_task_%d_%s", time.Now().UnixNano(), fname))
		if err := c.SaveUploadedFile(header, tmpFile); err != nil {
			msg.ResultFailed(c, err.Error())
			return
		}
		head, _ := os.ReadFile(tmpFile)
		if isPcapData(fname, head) {
			inputType, filePath = "pcap", tmpFile
			content = ""
		} else if isTextData(head) {
			// 文本文件：自动识别 web 访问日志（nginx/apache combined/common）
			content = string(head)
			if weblog.LooksLikeLog(content) {
				inputType = "log"
			} else {
				inputType = "text"
			}
			os.Remove(tmpFile)
			tmpFile = ""
		} else {
			os.Remove(tmpFile)
			msg.ResultFailed(c, "无法识别文件类型：支持 pcap 流量包或文本载荷")
			return
		}
		inputName = fname
		name = c.PostForm("name")
		for _, m := range strings.Split(c.PostForm("methods"), ",") {
			if m = strings.TrimSpace(m); m != "" {
				methods = append(methods, m)
			}
		}
	} else {
		var req struct {
			Name    string   `json:"name"`
			Content string   `json:"content"`
			Methods []string `json:"methods"`
			// PcapID 引用威胁仓库中已登记的流量包，直接读 stores/pcap 文件参与分析
			PcapID int `json:"pcap_id"`
			// WeblogID 引用威胁仓库中已登记的 web 日志（weblog 表，gzip 内容）
			WeblogID int `json:"weblog_id"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			msg.ResultFailed(c, "参数不合法: "+err.Error())
			return
		}
		name, content, methods = req.Name, req.Content, req.Methods
		inputType, inputName = "text", "粘贴文本"
		if req.PcapID > 0 {
			p := db.GetPcap(req.PcapID)
			fname := file.SafeFileName(p.Name)
			storePath := filepath.Join(pluginpcap.Dir(), fname)
			if p.Id == 0 || fname == "" || !file.Exists(storePath) {
				msg.ResultFailed(c, "威胁仓库中找不到该流量包")
				return
			}
			inputType, inputName, filePath = "pcap", p.Name, storePath
		} else if req.WeblogID > 0 {
			w := db.GetWeblog(req.WeblogID)
			raw, err := w.GetContent()
			if w.Id == 0 || err != nil || len(raw) == 0 {
				msg.ResultFailed(c, "威胁仓库中找不到该日志")
				return
			}
			inputType, inputName, content = "log", w.Name, string(raw)
		} else if weblog.LooksLikeLog(content) {
			// 粘贴文本自动识别为 web 访问日志
			inputType = "log"
		}
	}

	content = strings.TrimSpace(content)
	if inputType == "text" || inputType == "log" {
		if content == "" {
			msg.ResultFailed(c, "无检测内容")
			return
		}
		limit := maxTextInput
		if inputType == "log" {
			limit = maxLogInput
		}
		if len(content) > limit {
			msg.ResultFailed(c, fmt.Sprintf("内容过大（上限 %dMB）", limit>>20))
			return
		}
	}

	// 校验检测方式
	valid := pcapMethods
	switch inputType {
	case "text":
		valid = textMethods
	case "log":
		valid = logMethods
	}
	var sel []string
	for _, m := range methods {
		if valid[m] {
			sel = append(sel, m)
		}
	}

	preview := content
	if inputType == "pcap" {
		preview = fmt.Sprintf("[pcap] %s", inputName)
	}
	if len([]rune(preview)) > 300 {
		preview = string([]rune(preview)[:300])
	}
	if name == "" {
		name = preview
		if inputType == "pcap" {
			name = inputName
		}
		if len([]rune(name)) > 40 {
			name = string([]rune(name)[:40]) + "…"
		}
	}

	size := len(content)
	if inputType == "pcap" {
		if fi, err := os.Stat(filePath); err == nil {
			size = int(fi.Size())
		}
	}

	t := db.AnalyzeTask{
		Uuid:      uuid.NewString(),
		Name:      name,
		InputType: inputType,
		InputName: inputName,
		InputSize: size,
		Preview:   preview,
		Methods:   strings.Join(sel, ","),
		State:     db.PAStateRunning,
	}
	db.CreateAnalyzeTask(&t)
	// 进度条目先于 goroutine 创建，保证"运行中但无进度"可判定为残留任务
	// text：归档+识别+载荷检测+nuclei；pcap：归档+流量梳理+行为脚本+漏洞规则
	prog := &taskProgress{total: 4}
	taskProgressMap.Store(t.Id, prog)
	go runTask(t.Id, prog, inputType, inputName, content, filePath, tmpFile, sel)
	msg.ResultSuccess(c, gin.H{"id": t.Id, "uuid": t.Uuid})
}

func splitMethods(sel []string) map[string]bool {
	if len(sel) == 0 {
		return nil // 自动：全部适用项
	}
	m := map[string]bool{}
	for _, s := range sel {
		m[s] = true
	}
	return m
}

// runTask 异步执行分析并生成报告
func runTask(id int, prog *taskProgress, inputType, inputName, content, filePath, tmpFile string, sel []string) {
	if tmpFile != "" {
		defer os.Remove(tmpFile)
	}
	defer taskProgressMap.Delete(id)
	methods := splitMethods(sel)
	rep := &Report{Steps: []Step{}, Types: []string{}}

	// 兜底：goroutine panic 时也要把任务落为失败，避免永远卡在"分析中"
	defer func() {
		if r := recover(); r != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("内部异常: %v", r))
			raw, _ := json.Marshal(rep)
			db.EditAnalyzeTask(id, db.AnalyzeTask{State: db.PAStateFailed, Verdict: "分析异常中断", Report: string(raw)})
		}
	}()

	step := func(name string, fn func() (status, detail string)) {
		prog.start(name)
		begin := time.Now()
		status, detail := "ok", ""
		func() {
			defer func() {
				if r := recover(); r != nil {
					status, detail = "error", fmt.Sprint(r)
				}
			}()
			status, detail = fn()
		}()
		s := Step{Name: name, Status: status, Detail: detail, Ms: time.Since(begin).Milliseconds()}
		rep.Steps = append(rep.Steps, s)
		prog.stepDone(s)
	}
	want := func(m string) bool { return methods == nil || methods[m] }

	// 输入样本先入威胁仓库，保证后续分析 panic 时样本不丢
	step("样本归档", func() (string, string) {
		return archiveInput(id, inputType, inputName, content, filePath)
	})

	switch inputType {
	case "text":
		runText(rep, step, want, prog, content)
	case "log":
		runLog(rep, step, want, prog, content)
	default:
		runPcap(rep, step, want, prog, filePath)
	}

	update := db.AnalyzeTask{State: db.PAStateFinish, Risk: rep.Risk, Verdict: rep.Verdict}
	raw, _ := json.Marshal(rep)
	update.Report = string(raw)
	db.EditAnalyzeTask(id, update)
}

func uniqAdd(dst *[]string, s string) {
	for _, v := range *dst {
		if v == s {
			return
		}
	}
	*dst = append(*dst, s)
}

// ===== 样本归档 =====

// archiveStorePcapMax 归档 pcap 上限，与威胁仓库存储上传上限一致
const archiveStorePcapMax = 200 << 20

// archiveInput 将统一分析入口的输入自动归档到威胁仓库：
// pcap → stores/pcap 目录 + Pcap 元数据；web 日志 → Weblog 库（gzip 入库）；
// 文本载荷 → Payload 库（gzip 入库）。
// 按 sha1 去重；同名不同内容时追加短哈希后缀。失败不阻断分析任务。
func archiveInput(taskId int, inputType, inputName, content, filePath string) (status, detail string) {
	defer func() {
		if r := recover(); r != nil {
			status, detail = "error", fmt.Sprint("归档异常: ", r)
		}
	}()
	desc := fmt.Sprintf("分析任务 #%d 自动归档", taskId)
	if inputType == "log" {
		raw := []byte(content)
		sha1 := utils.Sha1Bytes(raw)
		if db.ExistWeblogBySha1(sha1) {
			return "skip", "威胁仓库已存在相同日志"
		}
		name := storeName(inputName, sha1, ".log", db.ExistWeblogByName)
		if name == "" {
			return "skip", "文件名冲突，未归档"
		}
		w := db.Weblog{
			Name: name, Sha1: sha1, Format: "combined",
			Lines: len(file.SplitLines(raw)), Size: len(raw),
			Description: desc,
		}
		w.SetContent(raw)
		db.AddWeblog(&w)
		return "ok", fmt.Sprintf("已归档到威胁仓库：weblog/%s (id=%d)", name, w.Id)
	}
	if inputType == "pcap" {
		raw, err := os.ReadFile(filePath)
		if err != nil || len(raw) == 0 {
			return "error", "读取上传文件失败: " + fmt.Sprint(err)
		}
		if len(raw) > archiveStorePcapMax {
			return "skip", "超过威胁仓库单文件上限，未归档"
		}
		sha1 := utils.Sha1Bytes(raw)
		if db.ExistPcapBySha1(sha1) {
			return "skip", "威胁仓库已存在相同流量包"
		}
		name := storeName(inputName, sha1, ".pcap", db.ExistPcapByName)
		if name == "" {
			return "skip", "文件名冲突，未归档"
		}
		if err := file.WriteFileBinary(raw, filepath.Join(pluginpcap.Dir(), name), false); err != nil {
			return "error", "流量包落盘失败: " + err.Error()
		}
		db.AddPcap(db.Pcap{Name: name, Sha1: sha1, Size: len(raw), Description: desc})
		return "ok", fmt.Sprintf("已归档到威胁仓库：pcap/%s", name)
	}

	raw := []byte(content)
	sha1 := utils.Sha1Bytes(raw)
	if db.ExistPayloadBySha1(sha1) {
		return "skip", "威胁仓库已存在相同载荷"
	}
	name := storeName(inputName, sha1, ".txt", db.ExistPayloadByName)
	if name == "" {
		return "skip", "文件名冲突，未归档"
	}
	p := db.Payload{
		Name:        name,
		Sha1:        sha1,
		Lines:       len(file.SplitLines(raw)),
		Size:        len(raw),
		Description: desc,
	}
	p.SetContent(raw)
	db.AddPayload(p)
	return "ok", fmt.Sprintf("已归档到威胁仓库：payload/%s", name)
}

// storeName 生成入库文件名：保留合法原始文件名，粘贴文本按时间戳+短哈希命名；
// 同名但内容不同（sha1 去重已在调用方完成）时追加短哈希后缀。仍冲突返回空串。
func storeName(inputName, sha1, defExt string, exists func(string) bool) string {
	name := file.SafeFileName(inputName)
	if name == "" || inputName == "粘贴文本" {
		name = fmt.Sprintf("paste_%s_%s%s",
			time.Now().Format("20060102_150405"), sha1[:8], defExt)
	}
	if exists(name) {
		ext := filepath.Ext(name)
		name = strings.TrimSuffix(name, ext) + "_" + sha1[:8] + ext
	}
	if exists(name) {
		return ""
	}
	return name
}

// runText 文本载荷：HTTP 解析 + 载荷自动识别 + （httpstream 时）nuclei 规则检测
func runText(rep *Report, step func(string, func() (string, string)), want func(string) bool, prog *taskProgress, content string) {
	isHTTP := httpReqRe.MatchString(content)

	step("输入识别", func() (string, string) {
		kind := "载荷文本"
		if isHTTP {
			kind = "HTTP 报文"
		}
		return "ok", fmt.Sprintf("输入为%s，共 %d 字符", kind, len([]rune(content)))
	})

	step("载荷检测", func() (string, string) {
		var parts []string
		if want(MethodHTTP) && isHTTP {
			hp := httpengine.HTTP_PARSE{}
			reqMap, urlArgs, clientArgs, formdata := hp.Req_parse(content)
			rep.HTTP = gin.H{
				"summary":   reqMap,
				"url_args":  urlArgs,
				"body_args": clientArgs,
				"form_data": formdata,
			}
			parts = append(parts, fmt.Sprintf("HTTP 解析出 %d 项特征", len(reqMap)))
		}
		if want(MethodClassify) {
			prog.start("载荷检测（特征识别与模板特征匹配…）")
			res := risk.DetectContent(content)
			rep.Items = res.Items
			rep.Risk = res.Found
			for _, it := range res.Items {
				if it.Found {
					uniqAdd(&rep.Types, it.Title)
				}
			}
			if res.Found {
				parts = append(parts, "识别为 "+res.Title)
			} else {
				parts = append(parts, "未识别出攻击类别")
			}
		}
		if len(parts) == 0 {
			return "skip", "未选择适用于文本的检测方式"
		}
		if rep.Risk {
			return "hit", strings.Join(parts, "；")
		}
		return "ok", strings.Join(parts, "；")
	})

	step("nuclei 规则检测", func() (string, string) {
		if !want(MethodNuclei) {
			return "skip", "未选择该检测方式"
		}
		// nuclei 检出要求请求+响应，只对可识别为 httpstream 的文本做检测；
		// 普通载荷文本或单纯 HTTP 请求报文不适用
		if !httpengine.LooksLikeStream(content) {
			return "skip", "输入非 HTTP 请求响应报文（httpstream），nuclei 不适用"
		}
		var exs []*nuclei.Exchange
		for _, re := range httpengine.ParseStream(content) {
			ex := nuclei.ExchangeFromRaw(httpengine.DecodeHex(re.Request), httpengine.DecodeHex(re.Response))
			if ex.HasResp {
				exs = append(exs, ex)
			}
		}
		if len(exs) == 0 {
			return "skip", "仅解析到请求、无响应报文，nuclei 不检测"
		}
		prog.start("nuclei 规则检测（加载模板缓存…）")
		eng, loadErrs := vuln.Load()
		for _, e := range loadErrs {
			rep.Errors = append(rep.Errors, "模板加载: "+e.Error())
		}
		if len(eng.Templates) == 0 {
			return "skip", "无启用的 nuclei 模板"
		}
		eng.Progress = func(stage string) {
			prog.start("nuclei 规则检测 " + stage)
		}
		findings := eng.Detect(exs)
		for _, f := range findings {
			rep.Events = append(rep.Events, pcapjs.Event{
				Strategy: "nuclei", Name: fmt.Sprintf("[%s] %s", f.Severity, f.Name),
				Severity: f.Severity,
				Desc: fmt.Sprintf("模板 %s，%s %s，帧 %d%s",
					f.TemplateID, f.Method, f.URI, f.ReqFrame, respEvDesc(f.RespEvidence)),
				Engine: "nuclei", Rule: f.TemplateID,
				Src: []string{f.Src}, Dst: []string{f.Dst},
			})
			uniqAdd(&rep.Types, "nuclei:"+f.Name)
		}
		if len(findings) > 0 {
			rep.Risk = true
			return "hit", fmt.Sprintf("解析 HTTP 交互 %d 条，nuclei 检出 %d 条", len(exs), len(findings))
		}
		return "ok", fmt.Sprintf("解析 HTTP 交互 %d 条，nuclei 未检出", len(exs))
	})
	if rep.Events == nil {
		rep.Events = []pcapjs.Event{}
	}
	finishVerdict(rep)
}

// flowSeverity 流量载荷命中的等级映射（sqli 高危、xss 中危，其余默认 high）
func flowSeverity(t string) string {
	switch t {
	case "xss":
		return "medium"
	default:
		return "high"
	}
}

// respEvDesc 响应命中特征片段；无证据返回空串
func respEvDesc(ev []string) string {
	if len(ev) == 0 {
		return ""
	}
	var parts []string
	for i, e := range ev {
		if i >= 3 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(ev)))
			break
		}
		parts = append(parts, clipStr(e, 120))
	}
	return "，响应命中 " + strings.Join(parts, "；")
}

// runPcap 流量包：报文提取（流量梳理）→ 行为检测脚本 → nuclei + 会话分析
func runPcap(rep *Report, step func(string, func() (string, string)), want func(string) bool, prog *taskProgress, filePath string) {
	var events []pcapjs.Event
	flowsHit := 0

	step("流量会话梳理", func() (string, string) {
		if !want(MethodFlow) {
			return "skip", "未选择该检测方式"
		}
		prog.start("流量会话梳理（tshark 提取 HTTP 会话…）")
		flows, err := analyzePcapFlows(filePath, "http", nil)
		if err != nil {
			return "error", "HTTP 会话提取失败: " + err.Error()
		}
		rep.Flows = len(flows)
		detectPcapFlows(flows, func(done, total int) {
			prog.start(fmt.Sprintf("流量载荷检测（%d/%d）", done, total))
		})
		for _, f := range flows {
			if len(f.Detections) > 0 {
				flowsHit++
				for _, d := range f.Detections {
					events = append(events, pcapjs.Event{
						Strategy: "flow", Name: "流量载荷命中 " + d.Type,
						Severity: flowSeverity(d.Type),
						Desc:     fmt.Sprintf("帧 %d %s:%s → %s:%s %s %s：%s", f.Frame, f.SrcIP, f.SrcPort, f.DstIP, f.DstPort, f.Method, f.URI, d.Detail),
						Engine:   "流量梳理", Rule: d.Type,
						Src: []string{f.SrcIP}, Dst: []string{f.DstIP},
					})
					uniqAdd(&rep.Types, d.Type)
				}
			}
		}
		if flowsHit > 0 {
			return "hit", fmt.Sprintf("提取 HTTP 会话 %d 条，其中 %d 条载荷检出攻击特征", len(flows), flowsHit)
		}
		return "ok", fmt.Sprintf("提取 HTTP 会话 %d 条，未检出载荷攻击", len(flows))
	})

	step("行为检测脚本", func() (string, string) {
		if !want(MethodStrategy) {
			return "skip", "未选择该检测方式"
		}
		// 脚本数多、每个查询都要调 tshark，逐步上报子进度避免长时间无反馈
		scriptTotal := len(pcapjs.Default().List())
		scriptDone := 0
		results, err := pcapjs.Default().RunProgress(
			&pcapjs.TsharkSource{File: filePath}, nil,
			func(r pcapjs.StrategyResult) {
				scriptDone++
				prog.start(fmt.Sprintf("行为检测脚本（%d/%d）", scriptDone, scriptTotal))
			})
		if err != nil {
			return "error", err.Error()
		}
		hit, failed := 0, 0
		for _, r := range results {
			if r.Error != "" {
				failed++
				rep.Errors = append(rep.Errors, r.Strategy+": "+r.Error)
				continue
			}
			if r.Hit {
				hit++
				uniqAdd(&rep.Types, "策略命中:"+r.Strategy)
			}
			events = append(events, r.Events...)
		}
		d := fmt.Sprintf("执行 %d 个脚本", len(results))
		if failed > 0 {
			d += fmt.Sprintf("，%d 个执行失败", failed)
		}
		if hit > 0 {
			return "hit", d + fmt.Sprintf("，命中 %d 个", hit)
		}
		return "ok", d + "，均未命中"
	})

	step("漏洞规则与跨会话分析", func() (string, string) {
		useNuclei, useSession := want(MethodNuclei), want(MethodSession)
		if !useNuclei && !useSession {
			return "skip", "未选择该检测方式"
		}
		var nEvents, sEvents int
		for _, ev := range pcapanalyse.ExtraEvents(filePath, useNuclei, useSession, prog.start) {
			switch ev.Strategy {
			case "nuclei":
				nEvents++
				uniqAdd(&rep.Types, "nuclei:"+ev.Name)
			case "session":
				sEvents++
				uniqAdd(&rep.Types, "会话:"+ev.Name)
			}
			events = append(events, ev)
		}
		d := fmt.Sprintf("nuclei 检出 %d 条，跨会话检出 %d 条", nEvents, sEvents)
		if nEvents+sEvents > 0 {
			return "hit", d
		}
		return "ok", d
	})

	if len(events) == 0 {
		events = []pcapjs.Event{}
	}
	rep.Events = events
	finishVerdict(rep)
}

// runLog web 日志：解析梳理 → URL 规则检测 → 日志行为脚本分析
func runLog(rep *Report, step func(string, func() (string, string)), want func(string) bool, prog *taskProgress, content string) {
	var lines []weblog.Line
	var events []pcapjs.Event

	step("日志解析梳理", func() (string, string) {
		lines = weblog.ParseLines(content)
		if len(lines) == 0 {
			return "error", "未能解析出日志行（支持 nginx/apache combined/common 格式）"
		}
		sum := weblog.Summarize(lines)
		rep.Log = sum
		d := fmt.Sprintf("解析 %d 行，来源 IP %d 个", sum.Lines, len(sum.TopIP))
		if sum.StartTime != "" {
			d += fmt.Sprintf("，时段 %s ~ %s", sum.StartTime, sum.EndTime)
		}
		return "ok", d
	})

	step("URL 规则检测", func() (string, string) {
		if !want(MethodURLRules) {
			return "skip", "未选择该检测方式"
		}
		if len(lines) == 0 {
			return "skip", "无解析后的日志行"
		}
		dbRules := db.GetEnabledUrlRules()
		in := make([]urldetect.Rule, 0, len(dbRules))
		for _, r := range dbRules {
			in = append(in, urldetect.Rule{
				RuleId: r.RuleId, Name: r.Name, Regex: r.Regex, Place: r.Place,
				Level: r.Level, TypeName: r.TypeName, ActionDesc: r.ActionDesc,
			})
		}
		sc := urldetect.New(in)
		if sc.Len() == 0 {
			return "skip", "无启用的 URL 规则"
		}
		hits := sc.ScanLog(lines, func(done, total int) {
			prog.start(fmt.Sprintf("URL 规则检测（%d/%d 行）", done, total))
		})
		// 命中过多时按 规则+IP 收敛事件，明细仍保留在事件描述里
		seen := map[string]int{}
		for _, h := range hits {
			key := h.RuleId + "|" + h.IP
			seen[key]++
			if seen[key] > 3 {
				continue
			}
			ev := pcapjs.Event{
				Strategy: "urlrule",
				Name:     h.Name,
				Severity: h.Level,
				Engine:   "URL检测",
				Rule:     h.RuleId,
				Src:      []string{h.IP},
			}
			ev.Desc = fmt.Sprintf("行 %d：%s %s（状态 %d）命中 %s·%s",
				h.Line, h.Method, clipStr(h.Value, 160), h.Status, h.TypeName, clipStr(h.Matched, 80))
			if h.ActionDesc != "" && h.ActionDesc != h.Name {
				ev.Desc = h.ActionDesc + "；" + ev.Desc
			}
			events = append(events, ev)
			uniqAdd(&rep.Types, "URL:"+h.TypeName)
		}
		d := fmt.Sprintf("%d 条规则扫描 %d 行，命中 %d 处", sc.Len(), len(lines), len(hits))
		if len(hits) > 0 {
			return "hit", d
		}
		return "ok", d
	})

	step("日志行为分析", func() (string, string) {
		if !want(MethodStrategy) {
			return "skip", "未选择该检测方式"
		}
		if len(lines) == 0 {
			return "skip", "无解析后的日志行"
		}
		var logStrategies []*pcapjs.Strategy
		for _, s := range pcapjs.Default().List() {
			if s.Input == "log" && !s.Disabled {
				logStrategies = append(logStrategies, s)
			}
		}
		scriptTotal := len(logStrategies)
		scriptDone := 0
		results, err := pcapjs.Default().RunLog(
			&pcapjs.LogSource{Lines: lines}, nil,
			func(r pcapjs.StrategyResult) {
				scriptDone++
				prog.start(fmt.Sprintf("日志行为分析（%d/%d）", scriptDone, scriptTotal))
			})
		if err != nil {
			return "error", err.Error()
		}
		hit, failed := 0, 0
		for _, r := range results {
			if r.Error != "" {
				failed++
				rep.Errors = append(rep.Errors, r.Strategy+": "+r.Error)
				continue
			}
			if r.Hit {
				hit++
				uniqAdd(&rep.Types, "日志行为:"+r.Strategy)
			}
			events = append(events, r.Events...)
		}
		d := fmt.Sprintf("执行 %d 个日志行为脚本", len(results))
		if failed > 0 {
			d += fmt.Sprintf("，%d 个失败", failed)
		}
		if hit > 0 {
			return "hit", d + fmt.Sprintf("，命中 %d 个", hit)
		}
		return "ok", d + "，均未命中"
	})

	if events == nil {
		events = []pcapjs.Event{}
	}
	rep.Events = events
	finishVerdict(rep)
}

// finishVerdict 汇总结论
func finishVerdict(rep *Report) {
	for _, s := range rep.Steps {
		if s.Status == "hit" {
			rep.Risk = true
			break
		}
	}
	if rep.Risk {
		if len(rep.Types) == 0 {
			rep.Verdict = "检出风险"
		} else {
			rep.Verdict = "检出风险：" + strings.Join(rep.Types, "、")
		}
	} else {
		rep.Verdict = "未发现明显风险"
	}
}

type taskPageResult struct {
	Page      int              `json:"page"`
	PageCount int              `json:"pageCount"`
	PageSize  int              `json:"pageSize"`
	Total     int64            `json:"total"`
	List      []db.AnalyzeTask `json:"list"`
}

// TaskList GET /api/analyze/tasks?page=&pageSize=&search=
func TaskList(c *gin.Context) {
	field := db.AnalyzeTaskSearchField{Search: c.Query("search")}
	page, _ := com.StrTo(c.Query("page")).Int()
	pageSize, _ := com.StrTo(c.Query("pageSize")).Int()
	page, pageSize = msg.NormalizePageParams(page, pageSize)
	list := db.GetAnalyzeTasks(page, pageSize, &field)
	total := db.GetAnalyzeTaskTotal(&field)
	for i := range list {
		list[i].Report = "" // 列表不返回报告全文
		if list[i].State == db.PAStateRunning {
			if v, ok := taskProgressMap.Load(list[i].Id); ok {
				cur, done, total, _ := v.(*taskProgress).snapshot()
				list[i].Progress = gin.H{"current": cur, "done": done, "total": total}
			} else if interruptStaleTask(&list[i]) {
				// 残留任务已就地标记中断
			}
		}
	}
	msg.ResultSuccess(c, taskPageResult{page, msg.PageCount(total, pageSize), pageSize, total, list})
}

// interruptStaleTask 运行中但无进度记录且已存活超过 30s：进程已重启或 goroutine 异常退出，
// 落库为失败避免永远"分析中"。返回是否发生了中断标记。
func interruptStaleTask(t *db.AnalyzeTask) bool {
	if t.State != db.PAStateRunning || time.Since(t.CreatedAt) <= 30*time.Second {
		return false
	}
	db.EditAnalyzeTask(t.Id, db.AnalyzeTask{State: db.PAStateFailed, Verdict: "任务中断（服务重启）"})
	t.State, t.Verdict = db.PAStateFailed, "任务中断（服务重启）"
	return true
}

// TaskDetail GET /api/analyze/task?id= 返回任务与报告；运行中附带实时进度
func TaskDetail(c *gin.Context) {
	id := com.StrTo(c.Query("id")).MustInt()
	t := db.GetAnalyzeTask(id)
	if t.Id == 0 {
		msg.ResultFailed(c, "任务不存在")
		return
	}
	out := gin.H{"task": t}
	var rep Report
	if json.Unmarshal([]byte(t.Report), &rep) == nil {
		out["report"] = rep
	}
	if t.State == db.PAStateRunning {
		if v, ok := taskProgressMap.Load(id); ok {
			cur, done, total, steps := v.(*taskProgress).snapshot()
			out["progress"] = gin.H{"running": true, "current": cur, "done": done, "total": total, "steps": steps}
		} else if interruptStaleTask(&t) {
			out["task"] = t
		}
	}
	msg.ResultSuccess(c, out)
}

// TaskDelete POST /api/analyze/task/del {id}
func TaskDelete(c *gin.Context) {
	var req struct {
		Id int `json:"id"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		msg.ResultFailed(c, "参数不合法: "+err.Error())
		return
	}
	if db.ExistAnalyzeTaskById(req.Id) {
		db.DeleteAnalyzeTask(req.Id)
		msg.ResultSuccess(c, "删除成功")
		return
	}
	msg.ResultFailed(c, "删除失败")
}
