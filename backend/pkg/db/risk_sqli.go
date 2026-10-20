package db

import (
	"gorm.io/gorm"
)

type RiskSqli struct {
	gorm.Model
	Id     int    `gorm:"primary_key" json:"id"`
	State  int    `json:"state"` // 任务状态
	Result string `json:"result"`

	Payload        int      `gorm:"column:payload" json:"payload"`
	ForeignPayload *Payload `gorm:"foreignKey:Payload"`
}

type RiskSqliSearchField struct {
	Search string
}

func GetRiskSqli(id int) (risksqli RiskSqli) {
	GlobalDB.Model(&RiskSqli{}).Where("id = ?", id).First(&risksqli)
	return
}

func GetRiskSqliByState(state int) (risksqlis []RiskSqli) {
	GlobalDB.Model(&RiskSqli{}).Where("state = ?", state).Find(&risksqlis)
	return
}

func EditRiskSqli(id int, risksqli RiskSqli) bool {
	GlobalDB.Model(&RiskSqli{}).Model(&RiskSqli{}).Where("id = ?", id).Updates(risksqli)
	return true
}

func AddRiskSqli(risksqli RiskSqli) bool {
	GlobalDB.Create(&risksqli)
	return true
}

func DeleteRiskSqli(id int) bool {
	GlobalDB.Model(&RiskSqli{}).Where("id = ?", id).Delete(&RiskSqli{})
	return true
}

func GetRiskSqlis(page int, pageSize int, field *RiskSqliSearchField) (risksqlis []RiskSqli) {
	db := GlobalDB.Preload("ForeignPayload", func(db *gorm.DB) *gorm.DB {
		return db.Omit("Content")
	})

	// 按关联的 payload 文件名搜索（需 Joins，关联表别名为 ForeignPayload）
	if field.Search != "" {
		db = db.Joins("ForeignPayload").Where("ForeignPayload.name like ?", "%"+field.Search+"%")
	}
	//	分页
	if page > 0 && pageSize > 0 {
		db = db.Offset((page - 1) * pageSize).Order("id").Limit(pageSize)
	}
	db.Find(&risksqlis)
	return
}

func GetRiskSqliTotal(field *RiskSqliSearchField) (total int64) {
	db := GlobalDB.Model(&RiskSqli{})

	// 按关联的 payload 文件名搜索
	if field.Search != "" {
		db = db.Joins("ForeignPayload").Where("ForeignPayload.name like ?", "%"+field.Search+"%")
	}
	db.Count(&total)
	return
}

func ExistRiskSqliById(id int) bool {
	var risksqli RiskSqli
	GlobalDB.Model(&RiskSqli{}).Where("id = ?", id).First(&risksqli)
	if risksqli.Id > 0 {
		return true
	}
	return false
}

func ExistRiskSqliByName(name string) bool {
	var risksqli RiskSqli
	GlobalDB.Model(&RiskSqli{}).Where("name = ?", name).First(&risksqli)
	if risksqli.Id > 0 {
		return true
	}
	return false
}

func ExistRiskSqliByState(state int) bool {
	var risksqli RiskSqli
	GlobalDB.Model(&RiskSqli{}).Where("state = ?", state).First(&risksqli)
	if risksqli.Id > 0 {
		return true
	}
	return false
}
