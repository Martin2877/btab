package db

import "gorm.io/gorm"

// auths 表

type Auth struct {
	gorm.Model
	Id       int    `gorm:"primary_key" json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// CheckAuth checks if authentication information exists
func CheckAuth(username, password string) (bool, *Auth) {
	var auth Auth
	// 空用户名或密码直接拒绝，避免 gorm 结构体条件忽略零值字段造成的绕过
	if username == "" || password == "" {
		return false, nil
	}
	GlobalDB.Select("id").Where("username = ? AND password = ?", username, password).First(&auth)
	if auth.Id > 0 {
		return true, &auth
	}
	return false, nil
}

// ResetPassword
func ResetPassword(id int, newpassword string) {
	if id <= 0 || newpassword == "" {
		return
	}
	GlobalDB.Model(&Auth{}).Where("id = ?", id).Update("password", newpassword)
}
