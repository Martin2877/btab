package db

import (
	"gorm.io/gorm"
)

type RiskWebshell struct {
	gorm.Model
	Id              int       `gorm:"primary_key" json:"id"`
	State           int       `json:"state"` // 任务状态
	Result          string    `json:"result"`
	Code            string    `json:"code"`  // 解码后代码
	Chain           string    `json:"chain"` // 调用链
	Webshell        int       `gorm:"column:webshell" json:"webshell"`
	ForeignWebshell *Webshell `gorm:"foreignKey:Webshell"`
}

type RiskWebshellSearchField struct {
	Search string
}

func GetRiskWebshell(id int) (riskwebshell RiskWebshell) {
	GlobalDB.Model(&RiskWebshell{}).Where("id = ?", id).First(&riskwebshell)
	return
}

func GetRiskWebshellByState(state int) (riskwebshells []RiskWebshell) {
	GlobalDB.Model(&RiskWebshell{}).Where("state = ?", state).Find(&riskwebshells)
	return
}

func EditRiskWebshell(id int, riskwebshell RiskWebshell) bool {
	GlobalDB.Model(&RiskWebshell{}).Model(&RiskWebshell{}).Where("id = ?", id).Updates(riskwebshell)
	return true
}

func AddRiskWebshell(riskwebshell RiskWebshell) bool {
	GlobalDB.Create(&riskwebshell)
	return true
}

func DeleteRiskWebshell(id int) bool {
	GlobalDB.Model(&RiskWebshell{}).Where("id = ?", id).Delete(&RiskWebshell{})
	return true
}

func GetRiskWebshells(page int, pageSize int, field *RiskWebshellSearchField) (riskwebshells []RiskWebshell) {
	db := GlobalDB.Preload("ForeignWebshell")

	// 搜索名字、Sha1 或 uid
	if field.Search != "" {
		db = db.Where(
			GlobalDB.Where("ForeignWebshell.name like ?", "%"+field.Search+"%"))
	}
	//	分页
	if page > 0 && pageSize > 0 {
		db = db.Offset((page - 1) * pageSize).Order("id desc").Limit(pageSize).Find(&riskwebshells)
	}
	return
}

func GetRiskWebshellTotal(field *RiskWebshellSearchField) (total int64) {
	db := GlobalDB.Model(&RiskWebshell{})

	// 搜索名字、Sha1 或 uid
	if field.Search != "" {
		db = db.Where(
			GlobalDB.Where("name like ?", "%"+field.Search+"%").
				Or("sha_1 like ?", "%"+field.Search+"%"))
	}
	db.Count(&total)
	return
}

func ExistRiskWebshellById(id int) bool {
	var riskwebshell RiskWebshell
	GlobalDB.Model(&RiskWebshell{}).Where("id = ?", id).First(&riskwebshell)
	if riskwebshell.Id > 0 {
		return true
	}
	return false
}

func ExistRiskWebshellByName(name string) bool {
	var riskwebshell RiskWebshell
	GlobalDB.Model(&RiskWebshell{}).Where("name = ?", name).First(&riskwebshell)
	if riskwebshell.Id > 0 {
		return true
	}
	return false
}

func ExistRiskWebshellByState(state int) bool {
	var riskwebshell RiskWebshell
	GlobalDB.Model(&RiskWebshell{}).Where("state = ?", state).First(&riskwebshell)
	if riskwebshell.Id > 0 {
		return true
	}
	return false
}
