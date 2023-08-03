package httpparse

import (
	"strings"
)

// 基本信息
var engine = [...]string{"AppleWebKit", "WebKit", "Trident", "Gecko", "Presto", "KHTML"}
var browser = [...]string{"Safari", "Chrome", "Edge", "IE", "Firefox", "Firefox Focus", "Chromium", "Opera", "Vivaldi", "Yandex", "Brave", "Arora", "Lunascape", "QupZilla", "Coc Coc", "Kindle", "Iceweasel", "Konqueror", "Iceape", "SeaMonkey", "Epiphany", "XiaoMi", "Vivo", "OPPO", "360", "360SE", "360EE", "UC", "QQBrowser", "QQ", "Huawei", "Baidu", "Maxthon", "Sogou", "Liebao", "2345Explorer", "115Browser", "TheWorld", "Quark", "Qiyu", "Wechat", "WechatWork", "Taobao", "Alipay", "Weibo", "Douban", "Suning", "iQiYi", "DingTalk", "Douyin", "Googlebot", "Baiduspider", "Sogouspider", "Bingbot", "360Spider", "Bytespider", "YisouSpider", "YodaoBot", "YandexBot", "MicroMessage"}
var system = [...]string{"Linux", "Mac OS", "Android", "HarmonyOS", "Ubuntu", "FreeBSD", "Debian", "iOS", "Windows Phone", "BlackBerry", "MeeGo", "Symbian", "Chrome OS", "WebOS", "Windows"}
var device = [...]string{"Mobile", "Tablet", "PC"}
var scanner = [...]string{"hydra", "arachni/", "BFAC", "brutus", "cgichk", "core-project/1.0", "crimscanner/", "datacha0s", "dirbuster", "dominohunter", "dotdotpwn", "FHScanCore", "floodgate", "get-minimal", "gootkitauto-rooterscanner", "grendel-scan", "inspath", "internetninja", "jaascois", "zmeu", "masscan", "metis", "morfeusfuckingscanner", "n-stealth", "nsauditor", "pmafind", "securityscan", "springenwerk", "tehforestlobster", "toatadragostea", "vega/", "voideye", "webshag", "webvulnscan", "whcc/", "Havij", "absinthe", "bsqlbf", "mysqloit", "pangolin", "sqlpowerinjector", "sqlmap", "sqlninja", "uil2pn", "ruler", "HTTrack", "Apache-HttpClient", "harvest", "audit", "nmap", "sqln", "Parser", "libwww", "BBBike", "w3af", "owasp", "Nikto", "fimap", "BabyKrokodil", "httperf", "scan", "PycURL", "netsparker", "bench", "jio", "Python", "go", "lua", "Acunetix"}

// 返回UA引擎
func get_engine(ua string) string {
	for _, v := range engine {
		if strings.Index(strings.ToLower(ua), strings.ToLower(v)) > 0 {
			return v
		}
	}
	return ""
}

// 返回UA浏览器类型
func get_browser(ua string) string {
	for _, v := range browser {
		if strings.Index(strings.ToLower(ua), strings.ToLower(v)) > 0 {
			return v
		}
	}
	return ""
}

// 返回终端类型
func get_device(ua string) string {
	for _, v := range device {
		if strings.Index(strings.ToLower(ua), strings.ToLower(v)) > 0 {
			return v
		}
	}
	return ""
}

// 返回操作系统
func get_system(ua string) string {
	for _, v := range system {
		if strings.Index(strings.ToLower(ua), strings.ToLower(v)) > 0 {
			return v
		}
	}
	return ""
}

// 返回扫描器
func get_scanner(ua string) string {
	for _, v := range scanner {
		if strings.Index(strings.ToLower(ua), strings.ToLower(v)) > 0 {
			return v
		}
	}
	return ""
}
