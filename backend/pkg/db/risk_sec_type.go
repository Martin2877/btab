package db

import "gorm.io/gorm"

type SecType struct {
	gorm.Model
	Id int `gorm:"primary_key" json:"id"`
	//Name string `gorm:"column:name" json:"name" binding:"required"`
	Name string `gorm:"column:name" json:"name"`
}

type SecTypeSearchField struct {
	Search string
}

func GetSecType(id int) (secType SecType) {
	GlobalDB.Model(&SecType{}).Where("id = ?", id).First(&secType)
	return
}

func EditSecType(id int, secType SecType) bool {
	GlobalDB.Model(&SecType{}).Model(&SecType{}).Where("id = ?", id).Updates(secType)
	return true
}

func AddSecType(secType SecType) bool {
	GlobalDB.Create(&secType)
	return true
}

func DeleteSecType(id int) bool {
	GlobalDB.Model(&SecType{}).Where("id = ?", id).Delete(&SecType{})
	return true
}

func GetSecTypes(page int, pageSize int, field *SecTypeSearchField) (secTypes []SecType) {
	db := GlobalDB.Model(&SecType{})

	// 搜索名字、Sha1 或 uid
	if field.Search != "" {
		db = db.Where(
			GlobalDB.Where("name like ?", "%"+field.Search+"%"))
	}
	//	分页
	if page > 0 && pageSize > 0 {
		db = db.Offset((page - 1) * pageSize).Order("id").Limit(pageSize).Find(&secTypes)
	}
	return
}

func GetSecTypeTotal(field *SecTypeSearchField) (total int64) {
	db := GlobalDB.Model(&SecType{})

	// 搜索名字、Sha1 或 uid
	if field.Search != "" {
		db = db.Where(
			GlobalDB.Where("name like ?", "%"+field.Search+"%"))
	}
	db.Count(&total)
	return
}

func ClearSecType() bool {
	GlobalDB.Model(&SecType{}).Where("1 = 1").Delete(&SecType{})
	return true
}

func ExistSecTypeById(id int) bool {
	var secType SecType
	GlobalDB.Model(&SecType{}).Where("id = ?", id).First(&secType)
	if secType.Id > 0 {
		return true
	}
	return false
}

func ExistSecTypeByName(name string) bool {
	var secType SecType
	GlobalDB.Model(&SecType{}).Where("name = ?", name).First(&secType)
	if secType.Id > 0 {
		return true
	}
	return false
}

func ExistSecTypeBySha1(sha1 int) bool {
	var secType SecType
	GlobalDB.Model(&SecType{}).Where("sha_1 = ?", sha1).First(&secType)
	if secType.Id > 0 {
		return true
	}
	return false
}
