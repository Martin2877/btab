package pcapanalyse

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/engine/nuclei"
	"github.com/Martin2877/blue-team-box/engine/pcapjs"
	pluginpcap "github.com/Martin2877/blue-team-box/engine/plugin/pcap"
	"github.com/Martin2877/blue-team-box/engine/session"
	"github.com/Martin2877/blue-team-box/engine/vuln"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/Martin2877/blue-team-box/pkg/file"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/unknwon/com"
)

type TableResult struct {
	Page      int              `json:"page"`
	PageCount int              `json:"pageCount"`
	PageSize  int              `json:"pageSize"`
	List      []db.PcapAnalyse `json:"list"`
}

func Get(c *gin.Context) {
	// 获取整个表
	// 先进行更新
	//fmt.Println("get")
	//go UpdateTable()
	field := db.PcapAnalyseSearchField{Search: ""}

	// 分页
	page, _ := com.StrTo(c.Query("page")).Int()
	pageSize, _ := com.StrTo(c.Query("pageSize")).Int()

	// 查询条件
	if arg := c.Query("search"); arg != "" {
		field.Search = arg
	}

	page, pageSize = msg.NormalizePageParams(page, pageSize)
	infos := db.GetPcapAnalyses(page, pageSize, &field)
	total := db.GetPcapAnalyseTotal(&field)
	tableResult := TableResult{Page: page, PageSize: pageSize, List: infos}
	tableResult.PageCount = msg.PageCount(total, pageSize)

	msg.ResultSuccess(c, tableResult)
	return
}

type PATask struct {
	Name     string `json:"name"`
	Pcap     int    `json:"pcap"`
	Strategy []int  `json:"strategy"`
	Nuclei   bool   `json:"-"` // 检测项含 engine_nuclei 或未选择任何检测项
	Session  bool   `json:"-"` // 检测项含 engine_session 或未选择任何检测项

	allSelected bool // 未选择任何检测项：跑全部策略+内置引擎
}

// parseTask 兼容 JSON body 与 query/form：
// 前端 axios 把 strategy 数组提交为 JSON（元素可为数字或 "engine_xxx" 等字符串），
// 旧版表单则以 strategy[]=1&strategy[]=2 重复键传值
func parseTask(c *gin.Context) (PATask, error) {
	var t PATask
	if strings.HasPrefix(c.ContentType(), "application/json") {
		var raw struct {
			Name     string            `json:"name"`
			Pcap     int               `json:"pcap"`
			Strategy []json.RawMessage `json:"strategy"`
		}
		if err := c.ShouldBindJSON(&raw); err != nil {
			return t, err
		}
		t.Name, t.Pcap = raw.Name, raw.Pcap
		var vals []string
		for _, r := range raw.Strategy {
			var s string
			if json.Unmarshal(r, &s) == nil {
				vals = append(vals, s)
				continue
			}
			var n float64
			if json.Unmarshal(r, &n) == nil {
				vals = append(vals, strconv.Itoa(int(n)))
			}
		}
		t.applyStrategy(vals)
		return t, nil
	}
	t.Name = c.PostForm("name")
	if t.Name == "" {
		t.Name = c.Query("name")
	}
	t.Pcap, _ = strconv.Atoi(firstNonEmpty(c.PostForm("pcap"), c.Query("pcap")))
	vals := append(c.QueryArray("strategy[]"), c.QueryArray("strategy")...)
	vals = append(vals, c.PostFormArray("strategy[]")...)
	vals = append(vals, c.PostFormArray("strategy")...)
	t.applyStrategy(vals)
	return t, nil
}

// applyStrategy 解析检测项取值：策略 id（数字或 "strategy_<id>"）、内置引擎标记 engine_nuclei/engine_session
func (t *PATask) applyStrategy(vals []string) {
	for _, v := range vals {
		switch v {
		case "engine_nuclei":
			t.Nuclei = true
		case "engine_session":
			t.Session = true
		default:
			if id, err := strconv.Atoi(strings.TrimPrefix(v, "strategy_")); err == nil {
				t.Strategy = append(t.Strategy, id)
			}
		}
	}
	t.allSelected = len(t.Strategy) == 0 && !t.Nuclei && !t.Session
	if t.allSelected {
		t.Nuclei, t.Session = true, true // 未选择检测项时默认启用内置引擎
	}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// Submit 提交流量包检测任务：使用内置 JS 策略引擎异步检测，结果写入任务记录
func Submit(c *gin.Context) {
	t, err := parseTask(c)
	if err != nil {
		msg.ResultFailed(c, "参数不合法: "+err.Error())
		return
	}
	if t.Name == "" {
		msg.ResultFailed(c, "参数不合法: 缺少任务名称")
		return
	}
	pcapInfo := db.GetPcap(t.Pcap)
	if pcapInfo.Id <= 0 {
		msg.ResultFailed(c, "流量包不存在")
		return
	}
	filePath := filepath.Join(pluginpcap.Dir(), filepath.Base(pcapInfo.Name))
	if !file.Exists(filePath) {
		msg.ResultFailed(c, "流量包文件未保存在服务端 stores/pcap 目录，请改用 /api/analyze/pcap_detect 上传检测")
		return
	}

	var ids []string
	var names []string
	for _, sid := range t.Strategy {
		s := db.GetStrategy(sid)
		if s.Id <= 0 {
			msg.ResultFailed(c, "检测策略不存在")
			return
		}
		ids = append(ids, s.Name)
		names = append(names, s.Name)
	}

	desc := strings.Join(names, ",")
	if desc == "" {
		desc = "全部策略"
	}
	if t.Nuclei {
		desc += ",nuclei规则检测"
	}
	if t.Session {
		desc += ",跨会话分析"
	}
	pa := db.PcapAnalyse{
		Uuid:        uuid.NewString(),
		Name:        t.Name,
		State:       db.PAStateRunning,
		Pcap:        t.Pcap,
		Result:      "[]",
		Description: desc,
	}
	if len(t.Strategy) == 1 {
		pa.Strategy = t.Strategy[0]
	}
	db.CreatePcapAnalyse(&pa)
	go run(pa.Id, filePath, ids, t.Nuclei, t.Session, t.allSelected)
	msg.ResultSuccess(c, gin.H{"id": pa.Id, "uuid": pa.Uuid})
}

// paProgress 任务运行进度（内存态；任务结束后由 Progress 回退到 DB 结果）
type paProgress struct {
	total  int
	mu     sync.Mutex
	done   int
	events []pcapjs.Event
	errs   []string
}

func (p *paProgress) add(r pcapjs.StrategyResult) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done++
	p.events = append(p.events, r.Events...)
	if r.Error != "" {
		p.errs = append(p.errs, r.Strategy+": "+r.Error)
	}
}

func (p *paProgress) snapshot() (done, total int, events []pcapjs.Event, errs []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	events = append(events, p.events...)
	errs = append(errs, p.errs...)
	return p.done, p.total, events, errs
}

var paProgressMap sync.Map // 任务 id -> *paProgress

func run(id int, filePath string, ids []string, useNuclei, useSession, allSelected bool) {
	total := len(ids)
	if total == 0 {
		if allSelected {
			total = len(pcapjs.Default().List())
		} else {
			total = 1 // 仅内置引擎时进度条不空转
		}
	}
	prog := &paProgress{total: total}
	paProgressMap.Store(id, prog)
	defer paProgressMap.Delete(id)

	var res []pcapjs.StrategyResult
	var err error
	if len(ids) > 0 || allSelected {
		res, err = pcapjs.Default().RunProgress(&pcapjs.TsharkSource{File: filePath}, ids, prog.add)
	}
	extraEvents := nucleiDetectEvents(filePath, useNuclei, useSession, nil)
	prog.done = prog.total
	update := db.PcapAnalyse{State: db.PAStateFinish}
	if err != nil {
		update.State = db.PAStateFailed
		update.Result = fmt.Sprintf(`[{"name":"检测失败","desc":%q}]`, err.Error())
	} else {
		events := []pcapjs.Event{}
		errMap := map[string][]string{} // 相同错误聚合，避免刷屏
		for _, r := range res {
			events = append(events, r.Events...)
			if r.Error != "" {
				errMap[r.Error] = append(errMap[r.Error], r.Strategy)
			}
		}
		var errMsgs []string
		for e := range errMap {
			errMsgs = append(errMsgs, e)
		}
		sort.Strings(errMsgs)
		for _, e := range errMsgs {
			ss := errMap[e]
			events = append(events, pcapjs.Event{
				Name:   "策略执行失败",
				Desc:   fmt.Sprintf("%d 个策略执行失败（%s）: %s", len(ss), strings.Join(ss, ", "), e),
				Engine: "行为脚本",
			})
		}
		events = append(events, extraEvents...)
		raw, _ := json.Marshal(events)
		update.Result = string(raw)
	}
	db.EditPcapAnalyse(id, update)
}

// Progress GET /api/risk/pa/progress?id=xx 查询检测进度与实时结果：
// 运行中返回 done/total 与已检出事件；已结束回退到 DB 中的最终状态与结果
func Progress(c *gin.Context) {
	id, _ := strconv.Atoi(c.Query("id"))
	if id <= 0 {
		msg.ResultFailed(c, "参数不合法: 缺少 id")
		return
	}
	if v, ok := paProgressMap.Load(id); ok {
		done, total, events, errs := v.(*paProgress).snapshot()
		msg.ResultSuccess(c, gin.H{
			"running": true,
			"state":   db.PAStateRunning,
			"total":   total,
			"done":    done,
			"events":  events,
			"errors":  errs,
		})
		return
	}
	pa := db.GetPcapAnalyse(id)
	var events []pcapjs.Event
	_ = json.Unmarshal([]byte(pa.Result), &events)
	if events == nil {
		events = []pcapjs.Event{}
	}
	msg.ResultSuccess(c, gin.H{
		"running": false,
		"state":   pa.State,
		"events":  events,
	})
}

func Delete(c *gin.Context) {
	paJson := db.PcapAnalyse{}
	//fmt.Println(paJson)
	err := c.ShouldBindJSON(&paJson)
	if err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	if db.ExistPcapAnalyseById(paJson.Id) {
		// 删除数据库
		db.DeletePcapAnalyse(paJson.Id)
		msg.ResultSuccess(c, "删除成功")
		return
	} else {
		msg.ResultFailed(c, "删除失败")
		return
	}
}

// ExtraEvents 用数据库中启用的 nuclei 模板 + 跨会话关联引擎检测流量，转换为通用事件。
// 供流量包检测任务与统一分析任务共用。report 非空时上报当前阶段文本（供任务进度展示）。
func ExtraEvents(filePath string, useNuclei, useSession bool, report func(stage string)) []pcapjs.Event {
	return nucleiDetectEvents(filePath, useNuclei, useSession, report)
}

// evSuffix 生成事件描述中的响应命中特征片段；无证据返回空串
func evSuffix(ev []string) string {
	if len(ev) == 0 {
		return ""
	}
	var parts []string
	for i, e := range ev {
		if i >= 3 {
			parts = append(parts, fmt.Sprintf("等 %d 项", len(ev)))
			break
		}
		if len(e) > 120 {
			e = e[:120] + "..."
		}
		parts = append(parts, e)
	}
	return "，响应命中 " + strings.Join(parts, "；")
}

// nucleiDetectEvents 用数据库中启用的 nuclei 模板 + 跨会话关联引擎检测流量，转换为通用事件
func nucleiDetectEvents(filePath string, useNuclei, useSession bool, report func(stage string)) []pcapjs.Event {
	var out []pcapjs.Event
	if !useNuclei && !useSession {
		return out
	}
	tell := func(stage string) {
		if report != nil {
			report(stage)
		}
	}
	tell("加载 nuclei 模板缓存…")
	eng, loadErrs := vuln.Load()
	for _, err := range loadErrs {
		out = append(out, pcapjs.Event{Strategy: "nuclei", Name: "模板加载失败", Desc: err.Error(), Engine: "nuclei"})
	}
	tell("提取 HTTP 交互…")
	exs, err := nuclei.LoadExchanges(filePath)
	if err != nil {
		if useNuclei && len(eng.Templates) > 0 {
			out = append(out, pcapjs.Event{Strategy: "nuclei", Name: "HTTP 流量提取失败", Desc: err.Error(), Engine: "nuclei"})
		}
		return out
	}
	if !useNuclei {
		eng = nuclei.New()
	} else if len(eng.Templates) == 0 {
		out = append(out, pcapjs.Event{Strategy: "nuclei", Name: "nuclei 规则检测", Desc: "未启用模板，在「检测引擎-漏洞检测引擎」上传并启用后生效", Engine: "nuclei"})
	}
	if len(eng.Templates) > 0 {
		// With() 返回的是引擎副本，挂载进度回调不影响共享缓存
		eng.Progress = func(stage string) {
			tell("nuclei 规则检测 " + stage)
		}
	}
	for _, f := range eng.Detect(exs) {
		out = append(out, pcapjs.Event{
			Strategy: "nuclei", Name: fmt.Sprintf("[%s] %s", f.Severity, f.Name),
			Severity: f.Severity,
			Desc:     fmt.Sprintf("模板 %s，%s %s，帧 %d%s", f.TemplateID, f.Method, f.URI, f.ReqFrame, evSuffix(f.RespEvidence)),
			Engine:   "nuclei", Rule: f.TemplateID,
			Src: []string{f.Src}, Dst: []string{f.Dst},
		})
	}
	if !useSession {
		return out
	}
	tell("跨会话关联分析")
	for _, f := range session.Analyze(exs) {
		desc := f.Detail
		for _, d := range f.Decoded {
			if len(desc) < 500 {
				desc += fmt.Sprintf(" | 帧%d %s[%s]: %.200s", d.Frame, d.Direction, d.Chain, d.Plain)
			}
		}
		out = append(out, pcapjs.Event{
			Strategy: "session", Name: fmt.Sprintf("[%s] %s", f.Severity, f.Title),
			Severity: f.Severity,
			Desc:     desc,
			Engine:   "会话关联", Rule: f.Type,
			Src: []string{f.Src}, Dst: []string{f.Host},
		})
	}
	return out
}
