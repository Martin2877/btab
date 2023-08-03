package db

import (
	"gorm.io/gorm"
)

type RiskBASH struct {
	gorm.Model
	Id        int     `gorm:"primary_key" json:"id"`
	State       int     `json:"state"`  // 任务状态
	Result      string  `json:"result"`

	Payload        int      `gorm:"column:payload" json:"payload"`
	ForeignPayload *Payload   `gorm:"foreignKey:Payload"`
}


type RiskBASHSearchField struct {
	Search       string
}

func GetRiskBASH(id int) (riskbash RiskBASH){
	GlobalDB.Model(&RiskBASH{}).Where("id = ?", id).First(&riskbash)
	return
}

func GetRiskBASHByState(state int) (riskbashs []RiskBASH){
	GlobalDB.Model(&RiskBASH{}).Where("state = ?", state).Find(&riskbashs)
	return
}

func EditRiskBASH(id int, riskbash RiskBASH) bool {
	GlobalDB.Model(&RiskBASH{}).Model(&RiskBASH{}).Where("id = ?", id).Updates(riskbash)
	return true
}

func AddRiskBASH(riskbash RiskBASH) bool {
	GlobalDB.Create(&riskbash)
	return true
}

func DeleteRiskBASH(id int) bool {
	GlobalDB.Model(&RiskBASH{}).Where("id = ?", id).Delete(&RiskBASH{})
	return true
}


func GetRiskBASHs(page int, pageSize int, field *RiskBASHSearchField) (riskbashs []RiskBASH){
	db := GlobalDB.Preload("ForeignPayload")

	// 搜索名字、Sha1 或 uid
	if field.Search != ""{
		db = db.Where(
			GlobalDB.Where("ForeignPayload.name like ?", "%"+field.Search+"%"))
	}
	//  分页
	if page > 0 && pageSize > 0 {
		db = db.Offset((page - 1) * pageSize).Order("id").Limit(pageSize).Find(&riskbashs)
	}
	return
}

func GetRiskBASHTotal(field *RiskBASHSearchField) (total int64){
	db := GlobalDB.Model(&RiskBASH{})

	// 搜索名字、Sha1 或 uid
	if field.Search != ""{
		db = db.Where(
			GlobalDB.Where("name like ?", "%"+field.Search+"%").
				Or("sha_1 like ?", "%"+field.Search+"%"))
	}
	db.Count(&total)
	return
}


func ExistRiskBASHById(id int) bool {
	var riskbash RiskBASH
	GlobalDB.Model(&RiskBASH{}).Where("id = ?", id).First(&riskbash)
	if riskbash.Id >0 {
		return true
	}
	return false
}

func ExistRiskBASHByName(name string) bool {
	var riskbash RiskBASH
	GlobalDB.Model(&RiskBASH{}).Where("name = ?", name).First(&riskbash)
	if riskbash.Id >0 {
		return true
	}
	return false
}

func ExistRiskBASHByState(state int) bool {
	var riskbash RiskBASH
	GlobalDB.Model(&RiskBASH{}).Where("state = ?", state).First(&riskbash)
	if riskbash.Id >0 {
		return true
	}
	return false
}