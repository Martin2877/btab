// Package urlruleapi URL 检测引擎管理接口：规则列表/编辑/校验/启停/导入，以及对 URL 的在线检测调试
package urlruleapi

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/engine/local/urldetect"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/gin-gonic/gin"
	"github.com/unknwon/com"
	"gopkg.in/yaml.v3"
)

var urlPlaces = map[string]bool{"url": true, "useragent": true, "referer": true}
var urlLevels = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}

type pageResult struct {
	Page      int         `json:"page"`
	PageCount int         `json:"pageCount"`
	PageSize  int         `json:"pageSize"`
	Total     int64       `json:"total"`
	List      interface{} `json:"list"`
}

func searchField(c *gin.Context) *db.UrlRuleSearchField {
	return &db.UrlRuleSearchField{
		Search:  strings.TrimSpace(c.Query("search")),
		Place:   c.Query("place"),
		Level:   c.Query("level"),
		Enabled: c.Query("enabled"),
	}
}

// Overview GET /api/engine/urlrule/overview
func Overview(c *gin.Context) {
	field := &db.UrlRuleSearchField{}
	total := db.GetUrlRuleTotal(field)
	enabled := db.GetUrlRuleTotal(&db.UrlRuleSearchField{Enabled: "1"})
	byPlace := map[string]int64{}
	for _, p := range []string{"url", "useragent", "referer"} {
		byPlace[p] = db.GetUrlRuleTotal(&db.UrlRuleSearchField{Place: p})
	}
	msg.ResultSuccess(c, gin.H{
		"total": total, "enabled": enabled, "disabled": total - enabled,
		"places": byPlace, "levels": []string{"info", "low", "medium", "high", "critical"},
	})
}

// List GET /api/engine/urlrule/rules?search=&place=&level=&enabled=&page=&pageSize=
func List(c *gin.Context) {
	field := searchField(c)
	page, _ := com.StrTo(c.Query("page")).Int()
	pageSize, _ := com.StrTo(c.Query("pageSize")).Int()
	page, pageSize = msg.NormalizePageParams(page, pageSize)
	list := db.GetUrlRules(page, pageSize, field)
	total := db.GetUrlRuleTotal(field)
	msg.ResultSuccess(c, pageResult{page, msg.PageCount(total, pageSize), pageSize, total, list})
}

// Detail GET /api/engine/urlrule/rules/content?id=
func Detail(c *gin.Context) {
	id := com.StrTo(c.Query("id")).MustInt()
	r := db.GetUrlRule(id)
	if r.Id <= 0 {
		msg.ResultFailed(c, "规则不存在")
		return
	}
	msg.ResultSuccess(c, r)
}

func checkRule(r *db.UrlRule) error {
	if strings.TrimSpace(r.Regex) == "" {
		return fmt.Errorf("正则不能为空")
	}
	if _, err := regexp.Compile(r.Regex); err != nil {
		return fmt.Errorf("正则编译失败: %v", err)
	}
	if !urlPlaces[r.Place] {
		return fmt.Errorf("place 必须是 url / useragent / referer")
	}
	if r.Level == "" {
		r.Level = "info"
	}
	if !urlLevels[r.Level] {
		return fmt.Errorf("level 必须是 info/low/medium/high/critical")
	}
	if r.Name == "" {
		if r.ActionDesc != "" {
			r.Name = r.ActionDesc
		} else {
			r.Name = r.TypeName
		}
	}
	return nil
}

type saveReq struct {
	Id         int    `json:"id"`
	Name       string `json:"name"`
	Regex      string `json:"regex"`
	Place      string `json:"place"`
	Level      string `json:"level"`
	TypeName   string `json:"type_name"`
	ActionDesc string `json:"action_desc"`
	Enabled    bool   `json:"enabled"`
}

// Save POST /api/engine/urlrule/rules/save {id?, name, regex, place, level, type_name, action_desc, enabled}
// id 为空时新建自定义规则（rule_id 自动生成 custom-N），id 存在时更新（内置规则也可编辑）
func Save(c *gin.Context) {
	var req saveReq
	if err := c.ShouldBindJSON(&req); err != nil {
		msg.ResultFailed(c, "参数不合法: "+err.Error())
		return
	}
	r := db.UrlRule{
		Name: req.Name, Regex: req.Regex, Place: req.Place, Level: req.Level,
		TypeName: req.TypeName, ActionDesc: req.ActionDesc, Enabled: req.Enabled,
	}
	if err := checkRule(&r); err != nil {
		msg.ResultFailed(c, err.Error())
		return
	}
	if req.Id > 0 {
		old := db.GetUrlRule(req.Id)
		if old.Id <= 0 {
			msg.ResultFailed(c, "规则不存在")
			return
		}
		r.RuleId, r.Builtin, r.Source = old.RuleId, old.Builtin, old.Source
		db.EditUrlRule(req.Id, r)
		msg.ResultSuccess(c, gin.H{"id": req.Id, "rule_id": r.RuleId})
		return
	}
	r.RuleId = db.NextUrlRuleId()
	r.Source = "custom"
	db.AddUrlRule(r)
	msg.ResultSuccess(c, gin.H{"id": r.Id, "rule_id": r.RuleId})
}

// Validate POST /api/engine/urlrule/rules/validate {regex, place, value}
// 校验正则并可选地用 value 试配一次
func Validate(c *gin.Context) {
	var req struct {
		Regex string `json:"regex"`
		Place string `json:"place"`
		Value string `json:"value"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Regex) == "" {
		msg.ResultFailed(c, "参数不合法：缺少 regex")
		return
	}
	re, err := regexp.Compile(req.Regex)
	if err != nil {
		msg.ResultSuccess(c, gin.H{"ok": false, "error": "正则编译失败: " + err.Error()})
		return
	}
	res := gin.H{"ok": true}
	if req.Value != "" {
		res["matched"] = re.MatchString(req.Value)
		res["match"] = re.FindString(req.Value)
	}
	msg.ResultSuccess(c, res)
}

// Enable POST /api/engine/urlrule/rules/enable {id, enable}
func Enable(c *gin.Context) {
	var req struct {
		Id     int   `json:"id"`
		Enable *bool `json:"enable"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || req.Enable == nil || req.Id <= 0 {
		msg.ResultFailed(c, "参数不合法：需要 id 与 enable")
		return
	}
	r := db.GetUrlRule(req.Id)
	if r.Id <= 0 {
		msg.ResultFailed(c, "规则不存在")
		return
	}
	db.EditUrlRule(req.Id, db.UrlRule{Enabled: *req.Enable})
	if *req.Enable {
		msg.ResultSuccess(c, "已启用")
		return
	}
	msg.ResultSuccess(c, "已停用")
}

// Delete GET /api/engine/urlrule/rules/del?id=
func Delete(c *gin.Context) {
	id := com.StrTo(c.Query("id")).MustInt()
	r := db.GetUrlRule(id)
	if r.Id <= 0 {
		msg.ResultFailed(c, "规则不存在")
		return
	}
	db.DeleteUrlRule(id)
	msg.ResultSuccess(c, "删除成功")
}

// Batch POST /api/engine/urlrule/rules/batch {ids:[], action:"enable|disable|delete"}
func Batch(c *gin.Context) {
	var req struct {
		Ids    []int  `json:"ids"`
		Action string `json:"action"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Ids) == 0 {
		msg.ResultFailed(c, "参数不合法：需要 ids")
		return
	}
	done := 0
	for _, id := range req.Ids {
		switch req.Action {
		case "enable":
			db.EditUrlRule(id, db.UrlRule{Enabled: true})
			done++
		case "disable":
			db.EditUrlRule(id, db.UrlRule{Enabled: false})
			done++
		case "delete":
			db.DeleteUrlRule(id)
			done++
		default:
			msg.ResultFailed(c, "action 必须是 enable/disable/delete")
			return
		}
	}
	msg.ResultSuccess(c, gin.H{"done": done})
}

// importYaml webloghunter rules.yaml 导入格式
type importYaml struct {
	AttackRegex []struct {
		Regex      string `yaml:"regex"`
		Place      string `yaml:"place"`
		TypeName   string `yaml:"typename"`
		Level      int    `yaml:"level"`
		ActionDesc string `yaml:"actiondesc"`
	} `yaml:"attackregex"`
	ScannerRegex []struct {
		Regex    string `yaml:"regex"`
		TypeName string `yaml:"typename"`
	} `yaml:"scannerregex"`
	Other []struct {
		Regex    string `yaml:"regex"`
		Place    string `yaml:"place"`
		TypeName string `yaml:"typename"`
	} `yaml:"other"`
}

// Upload POST /api/engine/urlrule/rules/upload 导入 webloghunter 格式 rules.yaml
func Upload(c *gin.Context) {
	header, err := c.FormFile("file")
	if err != nil {
		msg.ResultFailed(c, "缺少上传文件: "+err.Error())
		return
	}
	f, err := header.Open()
	if err != nil {
		msg.ResultFailed(c, err.Error())
		return
	}
	defer f.Close()
	var y importYaml
	if err := yaml.NewDecoder(f).Decode(&y); err != nil {
		msg.ResultFailed(c, "YAML 解析失败: "+err.Error())
		return
	}
	imported, skipped, invalid := 0, 0, 0
	add := func(ruleId, regex, place, level, typeName, actionDesc string, enabled bool) {
		r := db.UrlRule{
			RuleId: ruleId, Name: actionDesc, Regex: regex, Place: place,
			Level: level, TypeName: typeName, ActionDesc: actionDesc,
			Enabled: enabled, Source: "import",
		}
		if r.Name == "" {
			r.Name = typeName
		}
		if checkRule(&r) != nil {
			invalid++
			return
		}
		if db.ExistUrlRuleByRuleId(ruleId) {
			skipped++
			return
		}
		db.AddUrlRule(r)
		imported++
	}
	for i, r := range y.AttackRegex {
		place := r.Place
		if place == "" {
			place = "url"
		}
		add(fmt.Sprintf("attack-%d", i+1), r.Regex, place, db.MapUrlRuleLevel(r.Level), r.TypeName, r.ActionDesc, true)
	}
	for i, r := range y.ScannerRegex {
		add(fmt.Sprintf("scanner-%d", i+1), r.Regex, "useragent", "info", "扫描器", "识别到扫描器/爬虫 UA："+r.TypeName, true)
	}
	for i, r := range y.Other {
		place := r.Place
		if place == "" {
			place = "url"
		}
		add(fmt.Sprintf("other-%d", i+1), r.Regex, place, "info", "其他特征", r.TypeName, false)
	}
	msg.ResultSuccess(c, gin.H{"imported": imported, "skipped": skipped, "invalid": invalid})
}

// Debug POST /api/engine/urlrule/debug {value, place?} 用启用规则检测单个 URL/UA 值
func Debug(c *gin.Context) {
	var req struct {
		Value string `json:"value"`
		Place string `json:"place"`
	}
	if err := c.ShouldBindJSON(&req); err != nil || strings.TrimSpace(req.Value) == "" {
		msg.ResultFailed(c, "参数不合法：缺少 value")
		return
	}
	rules := db.GetEnabledUrlRules()
	in := make([]urldetect.Rule, 0, len(rules))
	for _, r := range rules {
		in = append(in, urldetect.Rule{
			RuleId: r.RuleId, Name: r.Name, Regex: r.Regex, Place: r.Place,
			Level: r.Level, TypeName: r.TypeName, ActionDesc: r.ActionDesc,
		})
	}
	sc := urldetect.New(in)
	place := req.Place
	if place == "" {
		place = "url"
	}
	hits := sc.ScanValue(place, req.Value)
	msg.ResultSuccess(c, gin.H{"rules": sc.Len(), "hits": hits})
}
