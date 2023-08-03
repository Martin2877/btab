package db

import (
	"gorm.io/gorm"
)

type Payload struct {
	gorm.Model
	Id       	int         `gorm:"primary_key" json:"id"`
	Name        string  `gorm:"column:name" json:"name" binding:"required"`
	Sha1        string   `gorm:"column:sha_1" json:"sha_1"`
	Lines		int      `json:"lines"`
	Size 		int      `json:"size"`
	Description        string    `json:"description"`
}


type PayloadSearchField struct {
	Search       string
}


func GetPayload(id int) (pcap Payload){
	GlobalDB.Model(&Payload{}).Where("id = ?", id).First(&pcap)
	return
}

func EditPayload(id int, pcap Payload) bool {
	GlobalDB.Model(&Payload{}).Model(&Payload{}).Where("id = ?", id).Updates(pcap)
	return true
}

func AddPayload(pcap Payload) bool {
	GlobalDB.Create(&pcap)
	return true
}

func DeletePayload(id int) bool {
	GlobalDB.Model(&Payload{}).Where("id = ?", id).Delete(&Payload{})
	return true
}


func GetPayloads(page int, pageSize int, field *PayloadSearchField) (payloads []Payload){
	db := GlobalDB.Model(&Payload{})

	// 搜索名字、Sha1
	if field.Search != ""{
		db = db.Where(
			GlobalDB.Where("name like ?", "%"+field.Search+"%").
				Or("sha_1 like ?", "%"+field.Search+"%"))
	}
	//	分页
	if !(page > 0 && pageSize > 0) {
		page = 1
		pageSize = 10
	}
	db = db.Offset((page - 1) * pageSize).Order("id").Limit(pageSize).Find(&payloads)
	return
}

func GetPayloadTotal(field *PayloadSearchField) (total int64){
	db := GlobalDB.Model(&Payload{})

	// 搜索名字、Sha1 或 uid
	if field.Search != ""{
		db = db.Where(
			GlobalDB.Where("name like ?", "%"+field.Search+"%").
				Or("sha_1 like ?", "%"+field.Search+"%"))
	}
	db.Count(&total)
	return
}


func ExistPayloadById(id int) bool {
	var pcap Payload
	GlobalDB.Model(&Payload{}).Where("id = ?", id).First(&pcap)
	if pcap.Id >0 {
		return true
	}
	return false
}

func ExistPayloadByName(name string) bool {
	var pcap Payload
	GlobalDB.Model(&Payload{}).Where("name = ?", name).First(&pcap)
	if pcap.Id >0 {
		return true
	}
	return false
}

func ExistPayloadBySha1(sha1 int) bool {
	var pcap Payload
	GlobalDB.Model(&Payload{}).Where("sha_1 = ?", sha1).First(&pcap)
	if pcap.Id >0 {
		return true
	}
	return false
}