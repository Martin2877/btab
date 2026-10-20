package db

import (
	"github.com/Martin2877/blue-team-box/pkg/file"
	"gorm.io/gorm"
)

// Weblog 威胁仓库中的 web 访问日志样本（nginx/apache 等）
type Weblog struct {
	gorm.Model
	Id          int    `gorm:"primary_key" json:"id"`
	Name        string `gorm:"column:name" json:"name" binding:"required"`
	Sha1        string `gorm:"column:sha_1" json:"sha_1"`
	Format      string `json:"format"` // combined | common
	Lines       int    `json:"lines"`
	Size        int    `json:"size"`
	Description string `json:"description"`
	// Content 以 gzip 压缩存储的日志内容，不通过 JSON 输出
	Content []byte `gorm:"column:content" json:"-"`
}

// SetContent 以 gzip 压缩形式写入原始内容
func (w *Weblog) SetContent(raw []byte) {
	if compressed, err := file.GzipBytes(raw); err == nil {
		w.Content = compressed
	}
}

// GetContent 解压返回原始内容
func (w *Weblog) GetContent() ([]byte, error) {
	return file.GunzipBytes(w.Content)
}

type WeblogSearchField struct {
	Search string
}

func GetWeblog(id int) (w Weblog) {
	GlobalDB.Model(&Weblog{}).Where("id = ?", id).First(&w)
	return
}

func AddWeblog(w *Weblog) bool {
	GlobalDB.Create(w)
	return true
}

func DeleteWeblog(id int) bool {
	GlobalDB.Model(&Weblog{}).Where("id = ?", id).Delete(&Weblog{})
	return true
}

func GetWeblogs(page int, pageSize int, field *WeblogSearchField) (list []Weblog) {
	db := GlobalDB.Model(&Weblog{}).Omit("Content")
	if field.Search != "" {
		db = db.Where(
			GlobalDB.Where("name like ?", "%"+field.Search+"%").
				Or("sha_1 like ?", "%"+field.Search+"%").
				Or("format like ?", "%"+field.Search+"%"))
	}
	if !(page > 0 && pageSize > 0) {
		page = 1
		pageSize = 10
	}
	db.Offset((page - 1) * pageSize).Order("id").Limit(pageSize).Find(&list)
	return
}

func GetWeblogTotal(field *WeblogSearchField) (total int64) {
	db := GlobalDB.Model(&Weblog{})
	if field.Search != "" {
		db = db.Where(
			GlobalDB.Where("name like ?", "%"+field.Search+"%").
				Or("sha_1 like ?", "%"+field.Search+"%").
				Or("format like ?", "%"+field.Search+"%"))
	}
	db.Count(&total)
	return
}

func ExistWeblogByName(name string) bool {
	var w Weblog
	GlobalDB.Model(&Weblog{}).Where("name = ?", name).First(&w)
	return w.Id > 0
}

func ExistWeblogBySha1(sha1 string) bool {
	var w Weblog
	GlobalDB.Model(&Weblog{}).Where("sha_1 = ?", sha1).First(&w)
	return w.Id > 0
}

func ExistWeblogById(id int) bool {
	var w Weblog
	GlobalDB.Model(&Weblog{}).Where("id = ?", id).First(&w)
	return w.Id > 0
}
