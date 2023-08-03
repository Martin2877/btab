package db

import (
	"gorm.io/gorm"
)


type RiskSqli struct {
	gorm.Model
	Id       	int     `gorm:"primary_key" json:"id"`
	State       int     `json:"state"`  // 任务状态
	Result      string  `json:"result"`

	Payload        int      `gorm:"column:payload" json:"payload"`
	ForeignPayload *Payload 	`gorm:"foreignKey:Payload"`
}


type RiskSqliSearchField struct {
	Search       string
}

func GetRiskSqli(id int) (risksqli RiskSqli){
	GlobalDB.Model(&RiskSqli{}).Where("id = ?", id).First(&risksqli)
	return
}

func GetRiskSqliByState(state int) (risksqlis []RiskSqli){
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


func GetRiskSqlis(page int, pageSize int, field *RiskSqliSearchField) (risksqlis []RiskSqli){
	db := GlobalDB.Preload("ForeignPayload")

	// 搜索名字、Sha1 或 uid
	if field.Search != ""{
		db = db.Where(
			GlobalDB.Where("ForeignPayload.name like ?", "%"+field.Search+"%"))
	}
	//	分页
	if page > 0 && pageSize > 0 {
		db = db.Offset((page - 1) * pageSize).Order("id").Limit(pageSize).Find(&risksqlis)
	}
	return
}

func GetRiskSqliTotal(field *RiskSqliSearchField) (total int64){
	db := GlobalDB.Model(&RiskSqli{})

	// 搜索名字、Sha1 或 uid
	if field.Search != ""{
		db = db.Where(
			GlobalDB.Where("name like ?", "%"+field.Search+"%").
				Or("sha_1 like ?", "%"+field.Search+"%"))
	}
	db.Count(&total)
	return
}


func ExistRiskSqliById(id int) bool {
	var risksqli RiskSqli
	GlobalDB.Model(&RiskSqli{}).Where("id = ?", id).First(&risksqli)
	if risksqli.Id >0 {
		return true
	}
	return false
}

func ExistRiskSqliByName(name string) bool {
	var risksqli RiskSqli
	GlobalDB.Model(&RiskSqli{}).Where("name = ?", name).First(&risksqli)
	if risksqli.Id >0 {
		return true
	}
	return false
}

func ExistRiskSqliByState(state int) bool {
	var risksqli RiskSqli
	GlobalDB.Model(&RiskSqli{}).Where("state = ?", state).First(&risksqli)
	if risksqli.Id >0 {
		return true
	}
	return false
}