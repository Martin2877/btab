package db

import "gorm.io/gorm"

type Pcap struct {
	gorm.Model
	Id       	int         `gorm:"primary_key" json:"id"`
	Name        string  `gorm:"column:name" json:"name" binding:"required"`
	Sha1        string   `gorm:"column:sha_1" json:"sha_1"`
	Size 		int      `json:"size"`
	Description        string    `json:"description"`
}


type PcapSearchField struct {
	Search       string
}



func GetPcap(id int) (pcap Pcap){
	GlobalDB.Model(&Pcap{}).Where("id = ?", id).First(&pcap)
	return
}

func EditPcap(id int, pcap Pcap) bool {
	GlobalDB.Model(&Pcap{}).Model(&Pcap{}).Where("id = ?", id).Updates(pcap)
	return true
}

func AddPcap(pcap Pcap) bool {
	GlobalDB.Create(&pcap)
	return true
}

func DeletePcap(id int) bool {
	GlobalDB.Model(&Pcap{}).Where("id = ?", id).Delete(&Pcap{})
	return true
}


func GetPcaps(page int, pageSize int, field *PcapSearchField) (pcaps []Pcap){
	db := GlobalDB.Model(&Pcap{})

	// 搜索名字、Sha1 或 uid
	if field.Search != ""{
		db = db.Where(
			GlobalDB.Where("name like ?", "%"+field.Search+"%").
				Or("sha_1 like ?", "%"+field.Search+"%"))
	}
	//	分页
	if page > 0 && pageSize > 0 {
		db = db.Offset((page - 1) * pageSize).Order("id").Limit(pageSize).Find(&pcaps)
	}
	return
}

func GetPcapTotal(field *PcapSearchField) (total int64){
	db := GlobalDB.Model(&Pcap{})

	// 搜索名字、Sha1 或 uid
	if field.Search != ""{
		db = db.Where(
			GlobalDB.Where("name like ?", "%"+field.Search+"%").
				Or("sha_1 like ?", "%"+field.Search+"%"))
	}
	db.Count(&total)
	return
}


func ExistPcapById(id int) bool {
	var pcap Pcap
	GlobalDB.Model(&Pcap{}).Where("id = ?", id).First(&pcap)
	if pcap.Id >0 {
		return true
	}
	return false
}

func ExistPcapByName(name string) bool {
	var pcap Pcap
	GlobalDB.Model(&Pcap{}).Where("name = ?", name).First(&pcap)
	if pcap.Id >0 {
		return true
	}
	return false
}

func ExistPcapBySha1(sha1 int) bool {
	var pcap Pcap
	GlobalDB.Model(&Pcap{}).Where("sha_1 = ?", sha1).First(&pcap)
	if pcap.Id >0 {
		return true
	}
	return false
}