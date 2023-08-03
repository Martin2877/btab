package db

import "gorm.io/gorm"

type Strategy struct {
	gorm.Model
	Id       	int     `gorm:"primary_key" json:"id"`
	Name        string  `gorm:"column:name" json:"name" binding:"required"`
}



type StrategySearchField struct {
	Search       string
}


func GetStrategy(id int) (strategy Strategy){
	GlobalDB.Model(&Strategy{}).Where("id = ?", id).First(&strategy)
	return
}

func EditStrategy(id int, strategy Strategy) bool {
	GlobalDB.Model(&Strategy{}).Model(&Strategy{}).Where("id = ?", id).Updates(strategy)
	return true
}

func ClearStrategy() bool {
	GlobalDB.Model(&Strategy{}).Where("1 = 1").Delete(&Strategy{})
	return true
}

func AddStrategy(strategy Strategy) bool {
	GlobalDB.Create(&strategy)
	return true
}

func DeleteStrategy(id int) bool {
	GlobalDB.Model(&Strategy{}).Where("id = ?", id).Delete(&Strategy{})
	return true
}


func GetStrategys(page int, pageSize int, field *StrategySearchField) (strategys []Strategy){
	db := GlobalDB.Model(&Strategy{})

	// 搜索名字、Sha1 或 uid
	if field.Search != ""{
		db = db.Where(
			GlobalDB.Where("name like ?", "%"+field.Search+"%"))
	}
	//	分页
	if page > 0 && pageSize > 0 {
		db = db.Offset((page - 1) * pageSize).Order("id").Limit(pageSize).Find(&strategys)
	}
	return
}

func GetStrategyTotal(field *StrategySearchField) (total int64){
	db := GlobalDB.Model(&Strategy{})

	// 搜索名字、Sha1 或 uid
	if field.Search != ""{
		db = db.Where(
			GlobalDB.Where("name like ?", "%"+field.Search+"%"))
	}
	db.Count(&total)
	return
}


func ExistStrategyById(id int) bool {
	var strategy Strategy
	GlobalDB.Model(&Strategy{}).Where("id = ?", id).First(&strategy)
	if strategy.Id >0 {
		return true
	}
	return false
}

func ExistStrategyByName(name string) bool {
	var strategy Strategy
	GlobalDB.Model(&Strategy{}).Where("name = ?", name).First(&strategy)
	if strategy.Id >0 {
		return true
	}
	return false
}

func ExistStrategyBySha1(sha1 int) bool {
	var strategy Strategy
	GlobalDB.Model(&Strategy{}).Where("sha_1 = ?", sha1).First(&strategy)
	if strategy.Id >0 {
		return true
	}
	return false
}

