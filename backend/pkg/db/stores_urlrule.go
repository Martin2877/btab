package db

import (
	"fmt"

	"gorm.io/gorm"
)

// UrlRule URL 检测引擎规则：按正则匹配日志/请求中的 url、useragent 等位置，
// 输出攻击类别（TypeName）与行为描述（ActionDesc）与严重级别（Level）
type UrlRule struct {
	gorm.Model
	Id         int    `gorm:"primary_key" json:"id"`
	RuleId     string `gorm:"column:rule_id" json:"rule_id"`
	Name       string `json:"name"`        // 展示名（默认同 ActionDesc/TypeName）
	Regex      string `json:"regex"`       // 匹配正则
	Place      string `json:"place"`       // url | useragent | referer
	Level      string `json:"level"`       // info | low | medium | high | critical
	TypeName   string `json:"type_name"`   // 攻击类别：SQL注入攻击 / XSS跨站脚本攻击 / 扫描器 等
	ActionDesc string `json:"action_desc"` // 行为描述：正在…
	Enabled    bool   `json:"enabled"`
	Builtin    bool   `json:"builtin"` // 内置规则（webloghunter 规则集）
	Source     string `json:"source"`  // builtin | custom | 导入来源名
}

// UrlRuleLevelRank 级别排序（详情页/列表用）
var UrlRuleLevelRank = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// MapUrlRuleLevel webloghunter level(1/2/3) 到引擎级别
func MapUrlRuleLevel(lv int) string {
	switch lv {
	case 3:
		return "high"
	case 2:
		return "medium"
	case 1:
		return "low"
	default:
		return "info"
	}
}

type UrlRuleSearchField struct {
	Search  string
	Place   string
	Level   string
	Enabled string // "" | "1" | "0"
}

func (f *UrlRuleSearchField) apply(db *gorm.DB) *gorm.DB {
	if f.Search != "" {
		db = db.Where(
			GlobalDB.Where("name like ?", "%"+f.Search+"%").
				Or("type_name like ?", "%"+f.Search+"%").
				Or("action_desc like ?", "%"+f.Search+"%").
				Or("regex like ?", "%"+f.Search+"%"))
	}
	if f.Place != "" {
		db = db.Where("place = ?", f.Place)
	}
	if f.Level != "" {
		db = db.Where("level = ?", f.Level)
	}
	switch f.Enabled {
	case "1":
		db = db.Where("enabled = ?", true)
	case "0":
		db = db.Where("enabled = ?", false)
	}
	return db
}

func GetUrlRule(id int) (r UrlRule) {
	GlobalDB.Model(&UrlRule{}).Where("id = ?", id).First(&r)
	return
}

func GetUrlRuleByRuleId(ruleId string) (r UrlRule) {
	GlobalDB.Model(&UrlRule{}).Where("rule_id = ?", ruleId).First(&r)
	return
}

func AddUrlRule(r UrlRule) bool {
	GlobalDB.Create(&r)
	return true
}

func EditUrlRule(id int, r UrlRule) bool {
	GlobalDB.Model(&UrlRule{}).Where("id = ?", id).Updates(r)
	return true
}

func DeleteUrlRule(id int) bool {
	GlobalDB.Model(&UrlRule{}).Where("id = ?", id).Delete(&UrlRule{})
	return true
}

func GetUrlRules(page, pageSize int, field *UrlRuleSearchField) (list []UrlRule) {
	db := field.apply(GlobalDB.Model(&UrlRule{}))
	if !(page > 0 && pageSize > 0) {
		page, pageSize = 1, 10
	}
	db.Offset((page - 1) * pageSize).Order("id").Limit(pageSize).Find(&list)
	return
}

func GetUrlRuleTotal(field *UrlRuleSearchField) (total int64) {
	field.apply(GlobalDB.Model(&UrlRule{})).Count(&total)
	return
}

// GetEnabledUrlRules 返回全部启用的规则
func GetEnabledUrlRules() (list []UrlRule) {
	GlobalDB.Model(&UrlRule{}).Where("enabled = ?", true).Find(&list)
	return
}

func ExistUrlRuleByRuleId(ruleId string) bool {
	var r UrlRule
	GlobalDB.Model(&UrlRule{}).Where("rule_id = ?", ruleId).First(&r)
	return r.Id > 0
}

// NextUrlRuleId 生成自定义规则标识：custom-N（递增且不冲突）
func NextUrlRuleId() string {
	var maxId int64
	GlobalDB.Model(&UrlRule{}).Where("rule_id like 'custom-%'").Count(&maxId)
	for i := int64(1); ; i++ {
		id := fmt.Sprintf("custom-%d", maxId+i)
		if !ExistUrlRuleByRuleId(id) {
			return id
		}
	}
}
