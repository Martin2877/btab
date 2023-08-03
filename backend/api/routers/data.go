package routers


var Admininfo = map[string]interface{}{
	"userId": "1",
	"username": "admin",
	"realName": "Admin",
	"avatar": "avatar",
	"desc": "manager",
	"password": "666666",
	"token": "666666",
	"permissions": []interface{}{
		map[string]interface{}{
			"label": "主控台",
			"value": "dashboard_console",
		},
		map[string]interface{}{
			"label": "交易监控",
			"value": "dashboard_monitor",
		},
		map[string]interface{}{
			"label": "监控",
			"value": "dashboard_traderbot",
		},
		map[string]interface{}{
			"label": "工作台",
			"value": "dashboard_workplace",
		},
		map[string]interface{}{
			"label": "基础列表",
			"value": "basic_list",
		},
		map[string]interface{}{
			"label": "基础列表删除",
			"value": "basic_list_delete",
		},
	},
}