// Package logicapi 行为检测引擎（goja JS 检测脚本）的管理接口：
// 脚本列表/查看/编辑/校验/删除/上传，以及对流量包的脚本调试
package logicapi

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/api/routers/v2/risk"
	"github.com/Martin2877/blue-team-box/engine/pcapjs"
	pluginpcap "github.com/Martin2877/blue-team-box/engine/plugin/pcap"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/Martin2877/blue-team-box/pkg/file"
	"github.com/gin-gonic/gin"
	"github.com/unknwon/com"
)

// maxScriptSize 单个脚本大小上限
const maxScriptSize = 512 << 10

// 脚本 ID 即文件名（stores/strategy/<id>.js），只允许安全字符
var idRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

type pageResult struct {
	Page      int         `json:"page"`
	PageCount int         `json:"pageCount"`
	PageSize  int         `json:"pageSize"`
	Total     int64       `json:"total"`
	List      interface{} `json:"list"`
}

// scriptItem 列表/概览使用的脚本视图模型
type scriptItem struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Desc       string `json:"desc"`
	Type       string `json:"type"`
	Phase      string `json:"phase"`
	Author     string `json:"author"`
	Builtin    bool   `json:"builtin"`    // 存在内置版本
	Custom     bool   `json:"custom"`     // 存在自定义脚本文件
	Overridden bool   `json:"overridden"` // 自定义脚本覆盖了同名内置脚本
	Disabled   bool   `json:"disabled"`   // 已停用
	Error      string `json:"error,omitempty"`
}

// collect 汇总注册表中已加载的策略与用户目录中的脚本文件（含编译失败未加载的）
func collect() []*scriptItem {
	builtinIDs := pcapjs.BuiltinIDs()
	disabled := pcapjs.DisabledIDs()
	byID := map[string]*scriptItem{}
	for _, s := range pcapjs.Default().List() {
		byID[s.ID] = &scriptItem{
			ID: s.ID, Name: s.Name, Desc: s.Desc, Type: s.Type,
			Phase: s.Phase, Author: s.Author, Builtin: builtinIDs[s.ID], Disabled: s.Disabled,
		}
	}
	files, _ := filepath.Glob(filepath.Join(pcapjs.UserDir, "*.js"))
	for _, f := range files {
		id := strings.TrimSuffix(filepath.Base(f), ".js")
		it := byID[id]
		if it == nil {
			it = &scriptItem{ID: id, Name: id, Builtin: builtinIDs[id], Disabled: disabled[id]}
			if raw, err := os.ReadFile(f); err == nil {
				if s, err := pcapjs.Compile(id+".js", string(raw), false); err != nil {
					it.Error = err.Error()
				} else {
					it.Name, it.Desc, it.Type, it.Phase, it.Author = s.Name, s.Desc, s.Type, s.Phase, s.Author
				}
			}
			byID[id] = it
		}
		it.Custom = true
		it.Overridden = it.Builtin && it.Custom
	}
	list := make([]*scriptItem, 0, len(byID))
	for _, it := range byID {
		list = append(list, it)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	return list
}

func userFile(id string) (string, error) {
	if !idRe.MatchString(id) {
		return "", fmt.Errorf("脚本 ID 不合法（仅允许字母数字、_、-）")
	}
	return filepath.Join(pcapjs.UserDir, id+".js"), nil
}

// describe 校验脚本并返回元信息，与 vuln 模板的 describe 语义一致
func describe(content string) gin.H {
	res := gin.H{"ok": false}
	s, err := pcapjs.Check(content)
	if err != nil {
		res["error"] = err.Error()
		return res
	}
	res["ok"] = true
	res["meta"] = s
	return res
}

// reload 脚本变更后重建注册表并同步策略到数据库（检测任务按名称选择策略）
func reload() {
	pcapjs.Default().Reload()
	risk.SyncStrategies()
}

// Overview GET /api/engine/logic/overview
func Overview(c *gin.Context) {
	items := collect()
	var total, builtin, custom, errs, disabled int
	types := map[string]int{}
	phases := map[string]int{}
	for _, it := range items {
		total++
		if it.Disabled {
			disabled++
		}
		if it.Custom {
			custom++
		} else if it.Builtin {
			builtin++
		}
		if it.Error != "" {
			errs++
		}
		if it.Type != "" {
			types[it.Type]++
		}
		if it.Phase != "" {
			phases[it.Phase]++
		}
	}
	msg.ResultSuccess(c, gin.H{
		"total": total, "builtin": builtin, "custom": custom, "errors": errs, "disabled": disabled,
		"types": types, "phases": phases, "user_dir": pcapjs.UserDir,
	})
}

// List GET /api/engine/logic/scripts?search=&type=&origin=builtin|custom&page=&pageSize=
func List(c *gin.Context) {
	search := strings.ToLower(strings.TrimSpace(c.Query("search")))
	typ := c.Query("type")
	origin := c.Query("origin")
	var filtered []*scriptItem
	for _, it := range collect() {
		if search != "" &&
			!strings.Contains(strings.ToLower(it.ID+" "+it.Name+" "+it.Desc+" "+it.Author), search) {
			continue
		}
		if typ != "" && it.Type != typ {
			continue
		}
		switch origin {
		case "builtin":
			if it.Custom {
				continue
			}
		case "custom":
			if !it.Custom {
				continue
			}
		}
		switch c.Query("disabled") {
		case "1":
			if !it.Disabled {
				continue
			}
		case "0":
			if it.Disabled {
				continue
			}
		}
		filtered = append(filtered, it)
	}
	page, _ := com.StrTo(c.Query("page")).Int()
	pageSize, _ := com.StrTo(c.Query("pageSize")).Int()
	page, pageSize = msg.NormalizePageParams(page, pageSize)
	total := int64(len(filtered))
	start := (page - 1) * pageSize
	end := start + pageSize
	if start > len(filtered) {
		start = len(filtered)
	}
	if end > len(filtered) {
		end = len(filtered)
	}
	msg.ResultSuccess(c, pageResult{page, msg.PageCount(total, pageSize), pageSize, total, filtered[start:end]})
}

// Detail GET /api/engine/logic/scripts/content?id= 返回脚本原文与元信息
func Detail(c *gin.Context) {
	id := c.Query("id")
	if !idRe.MatchString(id) {
		msg.ResultFailed(c, "脚本 ID 不合法")
		return
	}
	it := &scriptItem{ID: id, Name: id, Builtin: pcapjs.BuiltinIDs()[id]}
	var content string
	if f, err := userFile(id); err == nil && file.Exists(f) {
		raw, err := os.ReadFile(f)
		if err != nil {
			msg.ResultFailed(c, "读取失败: "+err.Error())
			return
		}
		content = string(raw)
		it.Custom = true
		it.Overridden = it.Builtin
	} else if s := pcapjs.Default().Get(id); s != nil {
		content = s.Source()
		it.Name, it.Desc, it.Type, it.Phase, it.Author = s.Name, s.Desc, s.Type, s.Phase, s.Author
	} else {
		msg.ResultFailed(c, "脚本不存在")
		return
	}
	msg.ResultSuccess(c, gin.H{"meta": it, "content": content})
}

type saveReq struct {
	ID      string `json:"id"`
	Content string `json:"content"`
}

// Save POST /api/engine/logic/scripts/save {id, content}
// 保存到用户脚本目录 stores/strategy/<id>.js；与内置同名时覆盖内置脚本；
// 有语法错误时也会保存（不生效，校验结果在返回值中体现）
func Save(c *gin.Context) {
	var req saveReq
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Content) == "" {
		msg.ResultFailed(c, "参数不合法：缺少 content")
		return
	}
	if len(req.Content) > maxScriptSize {
		msg.ResultFailed(c, "脚本过大")
		return
	}
	f, err := userFile(req.ID)
	if err != nil {
		msg.ResultFailed(c, err.Error())
		return
	}
	if err := os.MkdirAll(pcapjs.UserDir, 0o755); err != nil {
		msg.ResultFailed(c, err.Error())
		return
	}
	if err := os.WriteFile(f, []byte(req.Content), 0o644); err != nil {
		msg.ResultFailed(c, "保存失败: "+err.Error())
		return
	}
	reload()
	msg.ResultSuccess(c, describe(req.Content))
}

// Validate POST /api/engine/logic/scripts/validate {content} 校验脚本并返回 INFO 元信息
func Validate(c *gin.Context) {
	var req saveReq
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Content) == "" {
		msg.ResultFailed(c, "参数不合法：缺少 content")
		return
	}
	msg.ResultSuccess(c, describe(req.Content))
}

// Enable POST /api/engine/logic/scripts/enable {id, enable}
// 停用后不参与全量检测（流量包检测、一键分析、脚本调试的"全部脚本"），也不出现在策略选项中；
// 调试时单独选择该脚本仍可执行
func Enable(c *gin.Context) {
	var req struct {
		ID     string `json:"id"`
		Enable *bool  `json:"enable"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Enable == nil || req.ID == "" {
		msg.ResultFailed(c, "参数不合法：需要 id 与 enable")
		return
	}
	if !idRe.MatchString(req.ID) {
		msg.ResultFailed(c, "脚本 ID 不合法")
		return
	}
	if err := pcapjs.Default().SetDisabled(req.ID, !*req.Enable); err != nil {
		msg.ResultFailed(c, "设置失败: "+err.Error())
		return
	}
	risk.SyncStrategies()
	if *req.Enable {
		msg.ResultSuccess(c, "已启用")
		return
	}
	msg.ResultSuccess(c, "已停用")
}

// Delete GET /api/engine/logic/scripts/del?id= 删除自定义脚本；覆盖内置的脚本删除后恢复内置版本
func Delete(c *gin.Context) {
	id := c.Query("id")
	f, err := userFile(id)
	if err != nil {
		msg.ResultFailed(c, err.Error())
		return
	}
	if !file.Exists(f) {
		if pcapjs.BuiltinIDs()[id] {
			msg.ResultFailed(c, "内置脚本不可删除（可在编辑后保存为同名自定义版本覆盖它）")
		} else {
			msg.ResultFailed(c, "脚本不存在")
		}
		return
	}
	if err := os.Remove(f); err != nil {
		msg.ResultFailed(c, "删除失败: "+err.Error())
		return
	}
	reload()
	if pcapjs.BuiltinIDs()[id] {
		msg.ResultSuccess(c, "已删除自定义版本，恢复为内置脚本")
		return
	}
	msg.ResultSuccess(c, "删除成功")
}

// Upload POST /api/engine/logic/scripts/upload 上传 .js 脚本文件到用户脚本目录
func Upload(c *gin.Context) {
	header, err := c.FormFile("file")
	if err != nil {
		msg.ResultFailed(c, "缺少上传文件: "+err.Error())
		return
	}
	name := file.SafeFileName(header.Filename)
	if name == "" || !strings.HasSuffix(strings.ToLower(name), ".js") {
		msg.ResultFailed(c, "仅支持 .js 脚本文件")
		return
	}
	if header.Size > maxScriptSize {
		msg.ResultFailed(c, "文件过大")
		return
	}
	id := strings.TrimSuffix(name, filepath.Ext(name))
	f, err := userFile(id)
	if err != nil {
		msg.ResultFailed(c, err.Error())
		return
	}
	if err := os.MkdirAll(pcapjs.UserDir, 0o755); err != nil {
		msg.ResultFailed(c, err.Error())
		return
	}
	if err := c.SaveUploadedFile(header, f); err != nil {
		msg.ResultFailed(c, "保存失败: "+err.Error())
		return
	}
	raw, _ := os.ReadFile(f)
	reload()
	res := describe(string(raw))
	res["message"] = "已导入 " + name
	msg.ResultSuccess(c, res)
}

// Debug POST /api/engine/logic/debug 对流量包运行脚本：
//  1. JSON: {id} 指定脚本、{content} 内联脚本、{pcap} 仓库流量包 id、{file} 服务端 pcap 路径；均空则运行全部脚本
//  2. multipart/form-data: -F "file=@x.pcap" [-F "id=" | -F "content="]
func Debug(c *gin.Context) {
	var id, content, filePath string
	if strings.HasPrefix(c.ContentType(), "multipart/form-data") {
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
		if err := c.SaveUploadedFile(header, tmp); err != nil {
			msg.ResultFailed(c, err.Error())
			return
		}
		defer os.Remove(tmp)
		filePath = tmp
		id, content = c.PostForm("id"), c.PostForm("content")
	} else {
		var req struct {
			ID      string `json:"id"`
			Content string `json:"content"`
			Pcap    int    `json:"pcap"`
			File    string `json:"file"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			msg.ResultFailed(c, "参数不合法: "+err.Error())
			return
		}
		id, content = req.ID, req.Content
		switch {
		case req.Pcap > 0:
			pi := db.GetPcap(req.Pcap)
			if pi.Id <= 0 {
				msg.ResultFailed(c, "流量包不存在")
				return
			}
			filePath = filepath.Join(pluginpcap.Dir(), filepath.Base(pi.Name))
			if !file.Exists(filePath) {
				msg.ResultFailed(c, "流量包文件不在服务端 stores/pcap 目录")
				return
			}
		case req.File != "":
			abs, err := filepath.Abs(req.File)
			if err != nil || !file.Exists(abs) {
				msg.ResultFailed(c, "文件不存在: "+req.File)
				return
			}
			filePath = abs
		}
	}
	if filePath == "" {
		msg.ResultFailed(c, "缺少流量包：上传文件、选择流量包或提供 file 路径")
		return
	}
	src := &pcapjs.TsharkSource{File: filePath}
	if strings.TrimSpace(content) != "" {
		finish(c, []pcapjs.StrategyResult{pcapjs.RunCode(src, content)})
		return
	}
	var ids []string
	if id != "" {
		ids = []string{id}
	}
	results, err := pcapjs.Default().Run(src, ids)
	if err != nil {
		msg.ResultFailed(c, err.Error())
		return
	}
	finish(c, results)
}

func finish(c *gin.Context, results []pcapjs.StrategyResult) {
	events := []pcapjs.Event{}
	hit := 0
	for _, r := range results {
		if r.Hit {
			hit++
		}
		events = append(events, r.Events...)
	}
	msg.ResultSuccess(c, gin.H{
		"summary": gin.H{"strategies": len(results), "hit": hit, "events": len(events)},
		"events":  events,
		"results": results,
	})
}
