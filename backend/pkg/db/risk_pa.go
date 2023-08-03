package db

import (
	"gorm.io/gorm"
)

const (
	PAStateFree    = 0
	PAStateRunning = 1
	PAStatePaused  = 2
	PAStateStopped = 3
	PAStateFinish  = 4
	PAStateFailed  = 5
)

type PcapAnalyse struct {
	gorm.Model
	Id          int    `gorm:"primary_key" json:"id"`
	Uuid        string `json:"uuid"`
	Name        string `gorm:"column:name" json:"name" binding:"required"` // 任务名称
	State       int    `json:"state"`                                      // 任务状态
	Result      string `json:"result"`
	Description string `json:"description"`

	SecType        int      `gorm:"column:sec_type" json:"sec_type"`
	ForeignSecType *SecType `gorm:"foreignKey:SecType"`

	Strategy        int       `gorm:"column:strategy" json:"strategy"`
	ForeignStrategy *Strategy `gorm:"foreignKey:Strategy"`

	Pcap        int   `gorm:"column:pcap" json:"pcap"`
	ForeignPcap *Pcap `gorm:"foreignKey:Pcap"`
}

type PcapAnalyseSearchField struct {
	Search string
}

func GetPcapAnalyse(id int) (pa PcapAnalyse) {
	GlobalDB.Model(&PcapAnalyse{}).Where("id = ?", id).First(&pa)
	return
}

func GetPcapAnalyseByState(state int) (pas []PcapAnalyse) {
	GlobalDB.Model(&PcapAnalyse{}).Where("state = ?", state).Find(&pas)
	return
}

func EditPcapAnalyse(id int, pa PcapAnalyse) bool {
	GlobalDB.Model(&PcapAnalyse{}).Where("id = ?", id).Updates(pa)
	return true
}

func EditPcapAnalyseByUUID(uuid string, pa PcapAnalyse) bool {
	GlobalDB.Model(&PcapAnalyse{}).Where("uuid = ?", uuid).Updates(pa)
	return true
}

func AddPcapAnalyse(pa PcapAnalyse) bool {
	GlobalDB.Create(&pa)
	return true
}

func DeletePcapAnalyse(id int) bool {
	GlobalDB.Model(&PcapAnalyse{}).Where("id = ?", id).Delete(&PcapAnalyse{})
	return true
}

func GetPcapAnalyses(page int, pageSize int, field *PcapAnalyseSearchField) (pas []PcapAnalyse) {
	db := GlobalDB.Preload("ForeignSecType", func(db *gorm.DB) *gorm.DB {
		return db.Unscoped()
	}).Preload("ForeignStrategy", func(db *gorm.DB) *gorm.DB {
		return db.Unscoped()
	}).Preload("ForeignPcap", func(db *gorm.DB) *gorm.DB {
		return db.Unscoped()
	})

	// 搜索名字、Sha1 或 uid
	if field.Search != "" {
		db = db.Where(
			GlobalDB.Where("name like ?", "%"+field.Search+"%"))
	}
	//	分页
	if page > 0 && pageSize > 0 {
		db = db.Offset((page - 1) * pageSize).Order("id desc").Limit(pageSize).Find(&pas)
	}
	return
}

func GetPcapAnalyseTotal(field *PcapAnalyseSearchField) (total int64) {
	db := GlobalDB.Model(&PcapAnalyse{})

	// 搜索名字、Sha1 或 uid
	if field.Search != "" {
		db = db.Where(
			GlobalDB.Where("name like ?", "%"+field.Search+"%").
				Or("sha_1 like ?", "%"+field.Search+"%"))
	}
	db.Count(&total)
	return
}

func ExistPcapAnalyseById(id int) bool {
	var pa PcapAnalyse
	GlobalDB.Model(&PcapAnalyse{}).Where("id = ?", id).First(&pa)
	if pa.Id > 0 {
		return true
	}
	return false
}

func ExistPcapAnalyseByName(name string) bool {
	var pa PcapAnalyse
	GlobalDB.Model(&PcapAnalyse{}).Where("name = ?", name).First(&pa)
	if pa.Id > 0 {
		return true
	}
	return false
}

func ExistPcapAnalyseByState(state int) bool {
	var pa PcapAnalyse
	GlobalDB.Model(&PcapAnalyse{}).Where("state = ?", state).First(&pa)
	if pa.Id > 0 {
		return true
	}
	return false
}
