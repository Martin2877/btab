package db

import (
	"gorm.io/gorm"
)

type Webshell struct {
	gorm.Model
	Id       	int         `gorm:"primary_key" json:"id"`
	Name        string  `gorm:"column:name" json:"name" binding:"required"`
	Sha1        string   `gorm:"column:sha_1" json:"sha_1"`
	Size 		int      `json:"size"`
	Description        string    `json:"description"`
}


type WebshellSearchField struct {
	Search       string
}



func GetWebshell(id int) (webshell Webshell){
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


func GetWebshells(page int, pageSize int, field *WebshellSearchField) (webshells []Webshell){
	db := GlobalDB.Model(&Webshell{})

	// 搜索名字、Sha1 或 uid
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
	db = db.Offset((page - 1) * pageSize).Order("id").Limit(pageSize).Find(&webshells)
	return
}

func GetWebshellTotal(field *WebshellSearchField) (total int64){
	db := GlobalDB.Model(&Webshell{})

	// 搜索名字、Sha1 或 uid
	if field.Search != ""{
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
	if webshell.Id >0 {
		return true
	}
	return false
}

func ExistWebshellByName(name string) bool {
	var webshell Webshell
	GlobalDB.Model(&Webshell{}).Where("name = ?", name).First(&webshell)
	if webshell.Id >0 {
		return true
	}
	return false
}

func ExistWebshellBySha1(sha1 int) bool {
	var webshell Webshell
	GlobalDB.Model(&Webshell{}).Where("sha_1 = ?", sha1).First(&webshell)
	if webshell.Id >0 {
		return true
	}
	return false
}