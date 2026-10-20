package db

import (
	"github.com/Martin2877/blue-team-box/pkg/file"
	"gorm.io/gorm"
)

type Payload struct {
	gorm.Model
	Id          int    `gorm:"primary_key" json:"id"`
	Name        string `gorm:"column:name" json:"name" binding:"required"`
	Sha1        string `gorm:"column:sha_1" json:"sha_1"`
	Lines       int    `json:"lines"`
	Size        int    `json:"size"`
	Description string `json:"description"`
	// Content 以 gzip 压缩存储的文件内容，不通过 JSON 输出
	Content []byte `gorm:"column:content" json:"-"`
}

// SetContent 以 gzip 压缩形式写入原始内容
func (payload *Payload) SetContent(raw []byte) {
	if compressed, err := file.GzipBytes(raw); err == nil {
		payload.Content = compressed
	}
}

// GetContent 解压返回原始内容
func (payload *Payload) GetContent() ([]byte, error) {
	return file.GunzipBytes(payload.Content)
}

type PayloadSearchField struct {
	Search string
}

func GetPayload(id int) (pcap Payload) {
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

func GetPayloads(page int, pageSize int, field *PayloadSearchField) (payloads []Payload) {
	// 列表查询排除 content 大字段，避免每次拉取全量二进制内容
	db := GlobalDB.Model(&Payload{}).Omit("Content")

	// 搜索名字、Sha1
	if field.Search != "" {
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

func GetPayloadTotal(field *PayloadSearchField) (total int64) {
	db := GlobalDB.Model(&Payload{})

	// 搜索名字、Sha1 或 uid
	if field.Search != "" {
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
	if pcap.Id > 0 {
		return true
	}
	return false
}

func ExistPayloadByName(name string) bool {
	var pcap Payload
	GlobalDB.Model(&Payload{}).Where("name = ?", name).First(&pcap)
	if pcap.Id > 0 {
		return true
	}
	return false
}

func ExistPayloadBySha1(sha1 string) bool {
	var pcap Payload
	GlobalDB.Model(&Payload{}).Where("sha_1 = ?", sha1).First(&pcap)
	if pcap.Id > 0 {
		return true
	}
	return false
}
