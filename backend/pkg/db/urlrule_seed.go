package db

import (
	_ "embed"
	"fmt"
	"log"

	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

//go:embed seeds/urlrules.yaml
var builtinUrlRulesYaml []byte

// urlRulesYaml 内置 URL 检测规则集（源自 webloghunter rules.default.yaml）
type urlRulesYaml struct {
	AttackRegex []struct {
		Id         int    `yaml:"id"`
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

// builtinUrlRules 解析内置规则集为 UrlRule 行（攻击/扫描器/其他三类）
func builtinUrlRules() []UrlRule {
	var y urlRulesYaml
	if err := yaml.Unmarshal(builtinUrlRulesYaml, &y); err != nil {
		log.Println("parse builtin url rules failed:", err)
		return nil
	}
	var out []UrlRule
	for i, r := range y.AttackRegex {
		place := r.Place
		if place == "" {
			place = "url"
		}
		name := r.ActionDesc
		if name == "" {
			name = r.TypeName
		}
		out = append(out, UrlRule{
			RuleId: fmt.Sprintf("attack-%d", i+1), Name: name, Regex: r.Regex,
			Place: place, Level: MapUrlRuleLevel(r.Level),
			TypeName: r.TypeName, ActionDesc: r.ActionDesc,
			Enabled: true, Builtin: true, Source: "builtin",
		})
	}
	for i, r := range y.ScannerRegex {
		out = append(out, UrlRule{
			RuleId: fmt.Sprintf("scanner-%d", i+1), Name: "扫描器指纹：" + r.TypeName, Regex: r.Regex,
			Place: "useragent", Level: "info",
			TypeName: "扫描器", ActionDesc: "识别到扫描器/爬虫 UA：" + r.TypeName,
			Enabled: true, Builtin: true, Source: "builtin",
		})
	}
	for i, r := range y.Other {
		place := r.Place
		if place == "" {
			place = "url"
		}
		out = append(out, UrlRule{
			RuleId: fmt.Sprintf("other-%d", i+1), Name: r.TypeName, Regex: r.Regex,
			Place: place, Level: "info",
			TypeName: "其他特征", ActionDesc: r.TypeName,
			Enabled: false, Builtin: true, Source: "builtin",
		})
	}
	return out
}

// SeedBuiltinUrlRules 一次性导入内置 URL 检测规则。
// 按 rule_id 去重——已存在的规则（含被用户改过启停的）不覆盖，
// 用户删除的内置规则也不会在重启时回补。
func SeedBuiltinUrlRules() {
	if GetNucleiSetting("builtin_urlrule:v1") != "" {
		return
	}
	rows := builtinUrlRules()
	existing := map[string]bool{}
	var ids []string
	if err := GlobalDB.Model(&UrlRule{}).Pluck("rule_id", &ids).Error; err != nil {
		log.Println("query existing url rules failed:", err)
		return
	}
	for _, id := range ids {
		existing[id] = true
	}
	var fresh []UrlRule
	for _, r := range rows {
		if !existing[r.RuleId] {
			fresh = append(fresh, r)
		}
	}
	inserted := len(fresh)
	if len(fresh) > 0 {
		err := GlobalDB.Transaction(func(tx *gorm.DB) error {
			return tx.CreateInBatches(fresh, 200).Error
		})
		if err != nil {
			log.Println("seed url rules failed:", err)
			inserted = 0
		}
	}
	if err := SetNucleiSetting("builtin_urlrule:v1", "1"); err != nil {
		log.Println("seed url rule flag failed:", err)
	}
	log.Printf("seed builtin url rules: %d/%d inserted\n", inserted, len(rows))
}
