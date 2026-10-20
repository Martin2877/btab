package db

import (
	"gorm.io/gorm"
)

type RiskXSS struct {
	gorm.Model
	Id     int    `gorm:"primary_key" json:"id"`
	State  int    `json:"state"` // 任务状态
	Result string `json:"result"`

	Payload        int      `gorm:"column:payload" json:"payload"`
	ForeignPayload *Payload `gorm:"foreignKey:Payload"`
}

type RiskXSSSearchField struct {
	Search string
}

func GetRiskXSS(id int) (riskxss RiskXSS) {
	GlobalDB.Model(&RiskXSS{}).Where("id = ?", id).First(&riskxss)
	return
}

func GetRiskXSSByState(state int) (riskxsss []RiskXSS) {
	GlobalDB.Model(&RiskXSS{}).Where("state = ?", state).Find(&riskxsss)
	return
}

func EditRiskXSS(id int, riskxss RiskXSS) bool {
	GlobalDB.Model(&RiskXSS{}).Model(&RiskXSS{}).Where("id = ?", id).Updates(riskxss)
	return true
}

func AddRiskXSS(riskxss RiskXSS) bool {
	GlobalDB.Create(&riskxss)
	return true
}

func DeleteRiskXSS(id int) bool {
	GlobalDB.Model(&RiskXSS{}).Where("id = ?", id).Delete(&RiskXSS{})
	return true
}

func GetRiskXSSs(page int, pageSize int, field *RiskXSSSearchField) (riskxsss []RiskXSS) {
	db := GlobalDB.Preload("ForeignPayload", func(db *gorm.DB) *gorm.DB {
		return db.Omit("Content")
	})

	// 按关联的 payload 文件名搜索（需 Joins，关联表别名为 ForeignPayload）
	if field.Search != "" {
		db = db.Joins("ForeignPayload").Where("ForeignPayload.name like ?", "%"+field.Search+"%")
	}
	//  分页
	if page > 0 && pageSize > 0 {
		db = db.Offset((page - 1) * pageSize).Order("id").Limit(pageSize)
	}
	db.Find(&riskxsss)
	return
}

func GetRiskXSSTotal(field *RiskXSSSearchField) (total int64) {
	db := GlobalDB.Model(&RiskXSS{})

	// 按关联的 payload 文件名搜索
	if field.Search != "" {
		db = db.Joins("ForeignPayload").Where("ForeignPayload.name like ?", "%"+field.Search+"%")
	}
	db.Count(&total)
	return
}

func ExistRiskXSSById(id int) bool {
	var riskxss RiskXSS
	GlobalDB.Model(&RiskXSS{}).Where("id = ?", id).First(&riskxss)
	if riskxss.Id > 0 {
		return true
	}
	return false
}

func ExistRiskXSSByName(name string) bool {
	var riskxss RiskXSS
	GlobalDB.Model(&RiskXSS{}).Where("name = ?", name).First(&riskxss)
	if riskxss.Id > 0 {
		return true
	}
	return false
}

func ExistRiskXSSByState(state int) bool {
	var riskxss RiskXSS
	GlobalDB.Model(&RiskXSS{}).Where("state = ?", state).First(&riskxss)
	if riskxss.Id > 0 {
		return true
	}
	return false
}
