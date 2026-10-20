package db

import (
	"github.com/Martin2877/blue-team-box/pkg/file"
	"gorm.io/gorm"
)

type Webshell struct {
	gorm.Model
	Id          int    `gorm:"primary_key" json:"id"`
	Name        string `gorm:"column:name" json:"name" binding:"required"`
	Sha1        string `gorm:"column:sha_1" json:"sha_1"`
	Size        int    `json:"size"`
	Description string `json:"description"`
	// Content 以 gzip 压缩存储的文件内容，不通过 JSON 输出
	Content []byte `gorm:"column:content" json:"-"`
}

// SetContent 以 gzip 压缩形式写入原始内容
func (webshell *Webshell) SetContent(raw []byte) {
	if compressed, err := file.GzipBytes(raw); err == nil {
		webshell.Content = compressed
	}
}

// GetContent 解压返回原始内容
func (webshell *Webshell) GetContent() ([]byte, error) {
	return file.GunzipBytes(webshell.Content)
}

type WebshellSearchField struct {
	Search string
}

func GetWebshell(id int) (webshell Webshell) {
	GlobalDB.Model(&Webshell{}).Where("id = ?", id).First(&webshell)
	return
}

func EditWebshell(id int, webshell Webshell) bool {
	GlobalDB.Model(&Webshell{}).Model(&Webshell{}).Where("id = ?", id).Updates(webshell)
	return true
}

func AddWebshell(webshell Webshell) bool {
	GlobalDB.Create(&webshell)
	return true
}

func DeleteWebshell(id int) bool {
	GlobalDB.Model(&Webshell{}).Where("id = ?", id).Delete(&Webshell{})
	return true
}

func GetWebshells(page int, pageSize int, field *WebshellSearchField) (webshells []Webshell) {
	// 列表查询排除 content 大字段，避免每次拉取全量二进制内容
	db := GlobalDB.Model(&Webshell{}).Omit("Content")

	// 搜索名字、Sha1 或 uid
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
	db = db.Offset((page - 1) * pageSize).Order("id").Limit(pageSize).Find(&webshells)
	return
}

func GetWebshellTotal(field *WebshellSearchField) (total int64) {
	db := GlobalDB.Model(&Webshell{})

	// 搜索名字、Sha1 或 uid
	if field.Search != "" {
		db = db.Where(
			GlobalDB.Where("name like ?", "%"+field.Search+"%").
				Or("sha_1 like ?", "%"+field.Search+"%"))
	}
	db.Count(&total)
	return
}

func ExistWebshellById(id int) bool {
	var webshell Webshell
	GlobalDB.Model(&Webshell{}).Where("id = ?", id).First(&webshell)
	if webshell.Id > 0 {
		return true
	}
	return false
}

func ExistWebshellByName(name string) bool {
	var webshell Webshell
	GlobalDB.Model(&Webshell{}).Where("name = ?", name).First(&webshell)
	if webshell.Id > 0 {
		return true
	}
	return false
}

func ExistWebshellBySha1(sha1 string) bool {
	var webshell Webshell
	GlobalDB.Model(&Webshell{}).Where("sha_1 = ?", sha1).First(&webshell)
	if webshell.Id > 0 {
		return true
	}
	return false
}
