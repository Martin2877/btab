package nuclei

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Finding 一条命中结果
type Finding struct {
	Engine      string   `json:"engine"` // 检出引擎，固定为 nuclei
	TemplateID  string   `json:"template_id"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Tags        []string `json:"tags,omitempty"`
	Description string   `json:"description,omitempty"`
	Reference   []string `json:"reference,omitempty"`
	Template    string   `json:"template,omitempty"`
	Stream      string   `json:"stream"`
	ReqFrame    int      `json:"req_frame"`
	RespFrame   int      `json:"resp_frame,omitempty"`
	Src         string   `json:"src"`
	Dst         string   `json:"dst"`
	Host        string   `json:"host,omitempty"`
	Method      string   `json:"method"`
	URI         string   `json:"uri"`
	Status      int      `json:"status,omitempty"`
	Matchers    []string `json:"matchers,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	// RespEvidence 仅响应侧 matcher 的命中证据（检出依据，供告警事件呈现）
	RespEvidence []string            `json:"resp_evidence,omitempty"`
	Extracted    map[string][]string `json:"extracted,omitempty"`
}

// Options 引擎选项
type Options struct {
	// MinSeverity 仅输出不低于该级别的结果：info < low < medium < high < critical
	MinSeverity string
	// Tags 非空时仅使用包含任一标签的模板
	Tags []string
	// ExcludeTags 含任一标签的模板被排除
	ExcludeTags []string
	// ExcludeIDs 被排除的模板 id
	ExcludeIDs []string
}

type Engine struct {
	Templates []*Template
	Opts      Options
	// Parse 模板解析选项（字典读取、payload 展开），须在 AddTemplate 之前设置
	Parse ParseOptions
	// Progress 检测进度回调：约每 300ms 回调一次当前阶段文本
	// （模板序号/名称与交互进度），慢模板逐个交互求值时也会持续上报；nil 不上报
	Progress func(stage string)
}

func New() *Engine { return &Engine{} }

// With 返回共享已编译模板、但使用独立 Options 的副本（模板加载后只读，可并发使用）
func (e *Engine) With(o Options) *Engine {
	c := *e
	c.Opts = o
	return &c
}

// AddTemplate 解析并加入一个模板
func (e *Engine) AddTemplate(name string, data []byte) error {
	t, err := ParseTemplateOpts(name, data, &e.Parse)
	if err != nil {
		return err
	}
	e.Templates = append(e.Templates, t)
	return nil
}

// LoadDir 递归加载目录（或单个文件）下的 yaml/yml 模板，返回成功数与失败原因
func (e *Engine) LoadDir(dir string) (int, []error) {
	var errs []error
	n := 0
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, rerr := os.ReadFile(p)
		if rerr != nil {
			errs = append(errs, rerr)
			return nil
		}
		if aerr := e.AddTemplate(p, data); aerr != nil {
			errs = append(errs, aerr)
			return nil
		}
		n++
		return nil
	})
	return n, errs
}

var severityRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func (e *Engine) usable(t *Template) bool {
	if e.Opts.MinSeverity != "" && severityRank[t.Info.Severity] < severityRank[strings.ToLower(e.Opts.MinSeverity)] {
		return false
	}
	for _, id := range e.Opts.ExcludeIDs {
		if strings.EqualFold(id, t.ID) {
			return false
		}
	}
	for _, ex := range e.Opts.ExcludeTags {
		for _, have := range t.Info.Tags {
			if strings.EqualFold(ex, have) {
				return false
			}
		}
	}
	if len(e.Opts.Tags) == 0 {
		return true
	}
	for _, want := range e.Opts.Tags {
		for _, have := range t.Info.Tags {
			if strings.EqualFold(want, have) {
				return true
			}
		}
	}
	return false
}

// hasResultMatchers 是否存在可产出结果的（非 internal）matcher
func (r *HTTPRequest) hasResultMatchers() bool {
	for _, m := range r.Matchers {
		if !m.Internal {
			return true
		}
	}
	return false
}

// hasRespMatchers 是否存在可校验响应的（非 internal）matcher；
// 仅有请求侧 matcher 的请求块无法确认响应，不参与检出
func (r *HTTPRequest) hasRespMatchers() bool {
	for _, m := range r.Matchers {
		if !m.Internal && m.respSide() {
			return true
		}
	}
	return false
}

func requestMatches(r *HTTPRequest, ex *Exchange) bool {
	for _, s := range r.specs {
		if s.match(ex) {
			return true
		}
	}
	return false
}

// Detect 用已加载的模板检测一组 HTTP 交互。
// 检出要求请求特征命中、且至少一个响应侧 matcher 在真实响应上命中；
// 无响应或仅请求侧命中（part: request、仅引用请求侧变量的 dsl）不产生检出，避免弱特征误报。
func (e *Engine) Detect(exchanges []*Exchange) []Finding {
	var out []Finding
	total, nx := len(e.Templates), len(exchanges)
	lastRep := time.Now()
	report := func(ti, ei int, name string) {
		if e.Progress == nil {
			return
		}
		lastRep = time.Now()
		if ei >= 0 {
			e.Progress(fmt.Sprintf("%d/%d 模板 %s · 交互 %d/%d", ti+1, total, name, ei+1, nx))
			return
		}
		e.Progress(fmt.Sprintf("%d/%d 模板 %s", ti+1, total, name))
	}
	for ti, t := range e.Templates {
		if ti == 0 || ti == total-1 || time.Since(lastRep) > 300*time.Millisecond {
			report(ti, -1, tplName(t))
		}
		if !e.usable(t) {
			continue
		}
		for ei, ex := range exchanges {
			if time.Since(lastRep) > 300*time.Millisecond {
				report(ti, ei, tplName(t))
			}
			for i := range t.HTTP {
				r := &t.HTTP[i]
				if !r.hasRespMatchers() || !requestMatches(r, ex) {
					continue
				}
				mo := evalMatchers(r, ex)
				if !mo.ok || !mo.respHit {
					continue
				}
				out = append(out, Finding{
					Engine: "nuclei", TemplateID: t.ID, Name: t.Info.Name, Severity: t.Info.Severity,
					Tags: t.Info.Tags, Description: t.Info.Description, Reference: t.Info.Reference,
					Template: t.File, Stream: ex.Stream, ReqFrame: ex.ReqFrame, RespFrame: ex.RespFrame,
					Src: fmt.Sprintf("%s:%d", ex.SrcIP, ex.SrcPort), Dst: fmt.Sprintf("%s:%d", ex.DstIP, ex.DstPort),
					Host: ex.Host, Method: ex.Method, URI: ex.URI, Status: ex.Status,
					Matchers: mo.names, Evidence: truncate(mo.ev), RespEvidence: truncate(mo.respEv),
					Extracted: runExtractors(r, ex),
				})
				break
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ReqFrame < out[j].ReqFrame })
	return out
}

// tplName 进度展示用的模板名：优先 id，其次名称，最后文件名
func tplName(t *Template) string {
	if t.ID != "" {
		return t.ID
	}
	if t.Info.Name != "" {
		return t.Info.Name
	}
	return t.File
}

func truncate(ev []string) []string {
	for i, s := range ev {
		if len(s) > 200 {
			ev[i] = s[:200] + "..."
		}
	}
	return ev
}

// DetectPcap 解析 pcap 中的 HTTP 流量并用模板检测
func (e *Engine) DetectPcap(file string) ([]Finding, error) {
	exs, err := LoadExchanges(file)
	if err != nil {
		return nil, err
	}
	return e.Detect(exs), nil
}

// SigHit 载荷与模板请求特征的匹配
type SigHit struct {
	Engine     string   `json:"engine"` // 检出引擎，固定为 nuclei
	TemplateID string   `json:"template_id"`
	Name       string   `json:"name"`
	Severity   string   `json:"severity"`
	Template   string   `json:"template"`
	Literal    string   `json:"literal"`            // 最具区分度的命中特征（最长强特征片段）
	Literals   []string `json:"literals,omitempty"` // 命中的全部强特征片段（去重，按长度排序）
	Score      int      `json:"score"`
}

// weakSigExact 弱特征字面量：常见通用值，单独命中无法区分攻击与正常请求
var weakSigExact = map[string]bool{
	"application/x-www-form-urlencoded": true,
	"application/json":                  true,
	"application/xml":                   true,
	"application/javascript":            true,
	"application/octet-stream":          true,
	"text/xml":                          true,
	"text/html":                         true,
	"text/plain":                        true,
	"text/css":                          true,
	"text/javascript":                   true,
	"multipart/form-data":               true,
	"xmlhttprequest":                    true,
	"keep-alive":                        true,
	"close":                             true,
	"no-cache":                          true,
	"no-store":                          true,
	"must-revalidate":                   true,
	"utf-8":                             true,
	"gzip":                              true,
	"deflate":                           true,
	"gzip, deflate":                     true,
	"gzip, deflate, br":                 true,
	"http/1.0":                          true,
	"http/1.1":                          true,
	"*/*":                               true,
}

// weakSigPrefix 带参数形式的通用值（如 "application/json; charset=utf-8"）
var weakSigPrefix = []string{
	"application/x-www-form-urlencoded",
	"application/json",
	"multipart/form-data",
	"text/html",
	"text/plain",
	"image/",
	"charset=",
}

// weakSigLiteral 判断字面量是否为弱特征（通用片段，不能单独作为模板命中依据）
func weakSigLiteral(lit string) bool {
	l := strings.ToLower(strings.TrimSpace(lit))
	if weakSigExact[l] {
		return true
	}
	for _, p := range weakSigPrefix {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// sigLitKey 归一化模板字面量：过短（<4）的片段无区分度直接丢弃，过长的截断
func sigLitKey(lit string) string {
	if len(lit) < 4 {
		return ""
	}
	if len(lit) > 200 {
		lit = lit[:200]
	}
	return lit
}

// SignatureMatch 用模板请求定义中的字面量片段识别一段攻击载荷疑似对应的 nuclei 模板。
// 适用于无响应可校验的单载荷场景（攻击载荷检测）。
//
// 模板请求特征分强弱：Content-Type 等通用头部值、以及在大量模板中重复出现的片段属于弱特征，
// 仅命中弱特征不算疑似命中（如普通表单请求里的 application/x-www-form-urlencoded 不代表存在
// Struts2 攻击）；至少命中一个该模板特有的强特征片段才会输出。
func (e *Engine) SignatureMatch(content string, limit int) []SigHit {
	var usable []*Template
	for _, t := range e.Templates {
		if e.usable(t) {
			usable = append(usable, t)
		}
	}
	// 字面量文档频率：同一字面量出现在越多模板中，区分度越低
	df := map[string]int{}
	for _, t := range usable {
		seen := map[string]bool{}
		for i := range t.HTTP {
			for _, sp := range t.HTTP[i].specs {
				for _, lit := range sp.literals {
					if k := sigLitKey(lit); k != "" {
						seen[k] = true
					}
				}
			}
		}
		for k := range seen {
			df[k]++
		}
	}
	maxDF := len(usable) / 5
	if maxDF < 4 {
		maxDF = 4
	}
	strong := func(lit string) bool {
		return !weakSigLiteral(lit) && df[lit] <= maxDF
	}
	var out []SigHit
	for _, t := range usable {
		var hits []string
		seen := map[string]bool{}
		for i := range t.HTTP {
			for _, sp := range t.HTTP[i].specs {
				for _, lit := range sp.literals {
					lit = sigLitKey(lit)
					if lit == "" || seen[lit] || !strings.Contains(content, lit) || !strong(lit) {
						continue
					}
					seen[lit] = true
					hits = append(hits, lit)
				}
			}
		}
		if len(hits) == 0 {
			continue
		}
		// 最长片段区分度最高，作为代表特征展示
		sort.SliceStable(hits, func(i, j int) bool { return len(hits[i]) > len(hits[j]) })
		lits := hits
		if len(lits) > 5 {
			lits = lits[:5]
		}
		out = append(out, SigHit{
			Engine: "nuclei", TemplateID: t.ID, Name: t.Info.Name, Severity: t.Info.Severity,
			Template: t.File, Literal: hits[0], Literals: lits,
			// 命中的强特征越多、片段越长，置信度越高
			Score: len(hits[0]) + 8*(len(hits)-1),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		return a.Score > b.Score
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}
