// Package vulnapi 漏洞检测引擎（nuclei 规则、字典、配置）的管理接口
package vulnapi

import (
	"io"
	"path"
	"strings"

	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/engine/nuclei"
	"github.com/Martin2877/blue-team-box/engine/vuln"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/gin-gonic/gin"
	"github.com/unknwon/com"
)

type pageResult struct {
	Page      int         `json:"page"`
	PageCount int         `json:"pageCount"`
	PageSize  int         `json:"pageSize"`
	Total     int64       `json:"total"`
	List      interface{} `json:"list"`
}

func queryField(get func(string) string) db.NucleiTemplateSearchField {
	return db.NucleiTemplateSearchField{
		Search: get("search"), Severity: strings.ToLower(get("severity")), Tag: get("tag"),
		Protocol: get("protocol"), Status: get("status"), Enabled: get("enabled"),
	}
}

func readUpload(c *gin.Context, limit int64) (name string, raw []byte, ok bool) {
	f, header, err := c.Request.FormFile("file")
	if err != nil {
		msg.ResultSelfDefined(c, err.Error())
		return
	}
	defer f.Close()
	if header.Size > limit {
		msg.ResultSelfDefined(c, "文件过大")
		return
	}
	raw, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > limit {
		msg.ResultSelfDefined(c, "文件为空或过大")
		return
	}
	return header.Filename, raw, true
}

// Overview GET /api/engine/vuln/overview
// 引擎未编译时不阻塞等待（全量模板编译需数秒），返回 loading 由前端轮询；
// 后台 Warmup 构建缓存，元信息补全在构建内完成（EnsureMeta）
func Overview(c *gin.Context) {
	out := gin.H{
		"stats": db.GetNucleiStats(), "resources": db.CountNucleiResources(),
		"settings": vuln.GetSettings(),
	}
	if eng, errs := vuln.Cached(); eng != nil {
		out["loaded"], out["load_errors"] = len(eng.Templates), len(errs)
	} else {
		vuln.Warmup()
		out["loading"] = true
	}
	msg.ResultSuccess(c, out)
}

// List GET /api/engine/vuln/templates
func List(c *gin.Context) {
	vuln.EnsureMeta()
	field := queryField(c.Query)
	page, _ := com.StrTo(c.Query("page")).Int()
	pageSize, _ := com.StrTo(c.Query("pageSize")).Int()
	page, pageSize = msg.NormalizePageParams(page, pageSize)
	list := db.GetNucleiTemplates(page, pageSize, &field)
	total := db.GetNucleiTemplateTotal(&field)
	msg.ResultSuccess(c, pageResult{page, msg.PageCount(total, pageSize), pageSize, total, list})
}

// Detail GET /api/engine/vuln/templates/content?id=&path=（兼容旧接口 ?search=<sha1>）返回模板原文
// path 为模板相对路径（检测结果中携带的 template 字段），查不到时按模板 id 兜底
func Detail(c *gin.Context) {
	var tpl db.NucleiTemplate
	if id := com.StrTo(c.Query("id")).MustInt(); id > 0 {
		tpl = db.GetNucleiTemplate(id)
	} else if p := c.Query("path"); p != "" {
		tpl = db.GetNucleiTemplateByPath(p)
		if tpl.Id == 0 {
			tpl = db.GetNucleiTemplateByTID(p)
		}
	} else if s := c.Query("search"); s != "" {
		tpl = db.GetNucleiTemplateBySha1(s)
	}
	if tpl.Id == 0 {
		msg.ResultFailed(c, "数据库找不到模板")
		return
	}
	content, err := tpl.GetContent()
	if err != nil {
		msg.ResultFailed(c, "内容解析失败")
		return
	}
	msg.ResultSuccess(c, string(content))
}

// Upload POST /api/engine/vuln/templates/upload
// 支持 .yaml/.yml 模板、.zip 模板包（保留目录结构，同时导入字典等资源）以及 .txt 等字典文件
func Upload(c *gin.Context) {
	name, raw, ok := readUpload(c, vuln.MaxZipSize)
	if !ok {
		return
	}
	lower := strings.ToLower(name)
	source := c.PostForm("source")
	if strings.HasSuffix(lower, ".zip") {
		if source == "" {
			source = name
		}
		msg.ResultSuccess(c, vuln.ImportZip(raw, source))
		return
	}
	if len(raw) > vuln.MaxFileSize {
		msg.ResultSelfDefined(c, "文件过大")
		return
	}
	p := vuln.CleanPath(c.DefaultPostForm("path", name))
	if p == "" || path.Ext(p) == "" {
		msg.ResultSelfDefined(c, "非法文件名")
		return
	}
	kind, isTpl := vuln.Classify(p)
	if kind == "skip" {
		if k := c.PostForm("kind"); k != "" {
			kind = k
		} else {
			kind = "wordlist"
		}
	}
	if isTpl {
		added, changed := vuln.SaveTemplate(p, source, raw, vuln.GetSettings(), vuln.ResourceReader())
		vuln.Invalidate()
		res := vuln.ImportResult{}
		switch {
		case added:
			res.Added, res.Message = 1, "已新增模板"
		case changed:
			res.Updated, res.Message = 1, "已更新模板"
		default:
			res.Skipped, res.Message = 1, "模板内容未变化"
		}
		msg.ResultSuccess(c, res)
		return
	}
	res := vuln.ImportResult{Message: "已更新资源"}
	if vuln.SaveResource(p, kind, raw) {
		res.Resources, res.Message = 1, "已新增资源"
	}
	vuln.Invalidate()
	msg.ResultSuccess(c, res)
}

type batchReq struct {
	IDs    []int  `json:"ids"`
	Action string `json:"action"` // enable | disable | delete
	All    bool   `json:"all"`
	Filter struct {
		Search   string `json:"search"`
		Severity string `json:"severity"`
		Tag      string `json:"tag"`
		Protocol string `json:"protocol"`
		Status   string `json:"status"`
		Enabled  string `json:"enabled"`
	} `json:"filter"`
}

func applyBatch(ids []int, action string) int64 {
	if len(ids) == 0 {
		return 0
	}
	q := db.GlobalDB.Model(&db.NucleiTemplate{}).Where("id in ?", ids)
	switch action {
	case "enable":
		return q.Where("parse_error = '' and (',' || protocols || ',') like ?", "%,http,%").Update("enabled", true).RowsAffected
	case "disable":
		return q.Update("enabled", false).RowsAffected
	case "delete":
		return db.GlobalDB.Unscoped().Where("id in ?", ids).Delete(&db.NucleiTemplate{}).RowsAffected
	}
	return 0
}

// Batch POST /api/engine/vuln/templates/batch 按 id 列表或筛选条件批量启用/停用/删除
func Batch(c *gin.Context) {
	var req batchReq
	if err := c.ShouldBindJSON(&req); err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	if req.Action != "enable" && req.Action != "disable" && req.Action != "delete" {
		msg.ResultFailed(c, "不支持的操作")
		return
	}
	ids := req.IDs
	if req.All {
		f := req.Filter
		ids = db.GetNucleiTemplateIds(&db.NucleiTemplateSearchField{
			Search: f.Search, Severity: strings.ToLower(f.Severity), Tag: f.Tag,
			Protocol: f.Protocol, Status: f.Status, Enabled: f.Enabled,
		})
	}
	n := int64(0)
	for i := 0; i < len(ids); i += 500 {
		end := i + 500
		if end > len(ids) {
			end = len(ids)
		}
		n += applyBatch(ids[i:end], req.Action)
	}
	vuln.Invalidate()
	msg.ResultSuccess(c, gin.H{"affected": n})
}

// Delete GET /api/engine/vuln/templates/del?id=
func Delete(c *gin.Context) {
	id := com.StrTo(c.Query("id")).MustInt()
	if !db.ExistNucleiTemplateById(id) {
		msg.ResultFailed(c, "删除失败")
		return
	}
	applyBatch([]int{id}, "delete")
	vuln.Invalidate()
	msg.ResultSuccess(c, "删除成功")
}

// Enable GET /api/engine/vuln/templates/enable?id=&enabled=true|false
func Enable(c *gin.Context) {
	id := com.StrTo(c.Query("id")).MustInt()
	if !db.ExistNucleiTemplateById(id) {
		msg.ResultFailed(c, "模板不存在")
		return
	}
	action := "disable"
	if strings.ToLower(c.Query("enabled")) == "true" {
		action = "enable"
	}
	applyBatch([]int{id}, action)
	vuln.Invalidate()
	msg.ResultSuccess(c, "已更新")
}

type saveReq struct {
	ID      int    `json:"id"`
	Path    string `json:"path"`
	Content string `json:"content"`
}

func describe(content string) gin.H {
	meta, merr := nuclei.Inspect([]byte(content))
	res := gin.H{"ok": false, "meta": meta}
	if merr != nil {
		res["error"] = merr.Error()
		return res
	}
	eng := vuln.NewEngine()
	if err := eng.AddTemplate("template.yaml", []byte(content)); err != nil {
		res["error"] = err.Error()
		return res
	}
	t := eng.Templates[0]
	res["ok"], res["refs"], res["missing_refs"], res["unsupported"] = true, t.Refs, t.MissingRefs, t.Unsupported
	return res
}

// Validate POST /api/engine/vuln/templates/validate {content} 校验模板并返回元信息、字典引用情况
func Validate(c *gin.Context) {
	var req saveReq
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Content) == "" {
		msg.ResultFailed(c, "参数不合法：缺少 content")
		return
	}
	msg.ResultSuccess(c, describe(req.Content))
}

// Save POST /api/engine/vuln/templates/save {id?, path, content} 新增或编辑模板（模板有解析错误时也会保存，但不会生效）
func Save(c *gin.Context) {
	var req saveReq
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Content) == "" {
		msg.ResultFailed(c, "参数不合法：缺少 content")
		return
	}
	if len(req.Content) > vuln.MaxFileSize {
		msg.ResultFailed(c, "内容过大")
		return
	}
	raw := []byte(req.Content)
	rr := vuln.ResourceReader()
	if req.ID > 0 {
		t := db.GetNucleiTemplate(req.ID)
		if t.Id == 0 {
			msg.ResultFailed(c, "模板不存在")
			return
		}
		vuln.FillMeta(&t, raw, rr)
		t.SetContent(raw)
		db.GlobalDB.Save(&t)
	} else {
		p := vuln.CleanPath(req.Path)
		if p == "" || path.Ext(p) == "" {
			msg.ResultFailed(c, "非法路径")
			return
		}
		if db.GetNucleiTemplateByPath(p).Id > 0 {
			msg.ResultFailed(c, "路径已存在")
			return
		}
		vuln.SaveTemplate(p, "manual", raw, vuln.GetSettings(), rr)
	}
	vuln.Invalidate()
	msg.ResultSuccess(c, describe(req.Content))
}

// ResourceList GET /api/engine/vuln/resources
func ResourceList(c *gin.Context) {
	field := db.NucleiResourceSearchField{Search: c.Query("search"), Kind: c.Query("kind")}
	page, _ := com.StrTo(c.Query("page")).Int()
	pageSize, _ := com.StrTo(c.Query("pageSize")).Int()
	page, pageSize = msg.NormalizePageParams(page, pageSize)
	list := db.GetNucleiResources(page, pageSize, &field)
	total := db.GetNucleiResourceTotal(&field)
	msg.ResultSuccess(c, pageResult{page, msg.PageCount(total, pageSize), pageSize, total, list})
}

// ResourceContent GET /api/engine/vuln/resources/content?id=&limit=（默认预览前 200 行）
func ResourceContent(c *gin.Context) {
	r := db.GetNucleiResource(com.StrTo(c.Query("id")).MustInt())
	if r.Id == 0 {
		msg.ResultFailed(c, "资源不存在")
		return
	}
	raw, err := r.GetContent()
	if err != nil {
		msg.ResultFailed(c, "内容解析失败")
		return
	}
	limit := com.StrTo(c.Query("limit")).MustInt()
	if limit <= 0 || limit > 5000 {
		limit = 200
	}
	lines := strings.Split(string(raw), "\n")
	truncated := len(lines) > limit
	if truncated {
		lines = lines[:limit]
	}
	msg.ResultSuccess(c, gin.H{"path": r.Path, "kind": r.Kind, "lines": r.Lines, "truncated": truncated, "content": strings.Join(lines, "\n")})
}

// ResourceDelete GET /api/engine/vuln/resources/del?id=
func ResourceDelete(c *gin.Context) {
	db.DeleteNucleiResource(com.StrTo(c.Query("id")).MustInt())
	vuln.Invalidate()
	msg.ResultSuccess(c, "删除成功")
}

// GetSettings GET /api/engine/vuln/settings
func GetSettings(c *gin.Context) { msg.ResultSuccess(c, vuln.GetSettings()) }

// SetSettings POST /api/engine/vuln/settings
func SetSettings(c *gin.Context) {
	var st vuln.Settings
	if err := c.ShouldBindJSON(&st); err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	if err := vuln.SaveSettings(st); err != nil {
		msg.ResultFailed(c, err.Error())
		return
	}
	msg.ResultSuccess(c, vuln.GetSettings())
}

type debugReq struct {
	TemplateID int    `json:"template_id"`
	Content    string `json:"content"`
	Request    string `json:"request"`
	Response   string `json:"response"`
}

// Debug POST /api/engine/vuln/debug 用一条 HTTP 请求/响应验证模板（指定模板 id 或内联 content；都不给则使用全部启用模板）
func Debug(c *gin.Context) {
	var req debugReq
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Request) == "" {
		msg.ResultFailed(c, "参数不合法：需要 request（response 可选）")
		return
	}
	var eng *nuclei.Engine
	var loadErrs []string
	switch {
	case strings.TrimSpace(req.Content) != "" || req.TemplateID > 0:
		content := req.Content
		if strings.TrimSpace(content) == "" {
			t := db.GetNucleiTemplate(req.TemplateID)
			raw, err := t.GetContent()
			if t.Id == 0 || err != nil {
				msg.ResultFailed(c, "模板不存在")
				return
			}
			content = string(raw)
		}
		eng = vuln.NewEngine()
		if err := eng.AddTemplate("debug.yaml", []byte(content)); err != nil {
			msg.ResultFailed(c, "模板解析失败: "+err.Error())
			return
		}
	default:
		var errs []error
		eng, errs = vuln.Load()
		for _, e := range errs {
			loadErrs = append(loadErrs, e.Error())
		}
	}
	ex := nuclei.ExchangeFromRaw(req.Request, req.Response)
	ex.Normalize()
	diags := eng.Diagnose([]*nuclei.Exchange{ex})
	// 全量模式下只保留请求特征命中的诊断，避免列出成千上万条未命中项
	if req.TemplateID == 0 && strings.TrimSpace(req.Content) == "" {
		kept := diags[:0]
		for _, d := range diags {
			if d.RequestMatched {
				kept = append(kept, d)
			}
		}
		diags = kept
	}
	msg.ResultSuccess(c, gin.H{
		"templates": len(eng.Templates), "diagnose": diags,
		"findings": eng.Detect([]*nuclei.Exchange{ex}), "errors": loadErrs,
	})
}
