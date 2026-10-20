package conf

import (
	"encoding/json"
	"errors"
)

var defaultYamlByte = []byte(`
dbConfig:
    enabledefault: false
#    mysql:
#        database: btab
#        host: 127.0.0.1
#        password: ""
#        port: "3306"
#        timeout: 3s
#        user: root
    sqlite: btab.sqlite
httpConfig:
    dail_timeout: 5
    headers:
        user_agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
    http_timeout: 10
    max_qps: 100
    max_redirect: 5
    proxy: ""
#    proxy: "socks5://127.0.0.1:3210"  # 使用代理
    udp_timeout: 5
    cache: False  # 是否使用缓存
logConfig:
    compress: false
    max_age: 365
    max_backups: 1
    max_size: 50
serverConfig:
    jwt_secret: btab
    run_mode: release
    open_browser: true  # 启动时自动打开浏览器
    license_dateline: ""  # 已废弃：认证有效期限制已去除，无需配置
grpcConfig:
    address: :50051
websocketConfig:
    address: :5003
pcapAnalyseConfig:
#    tsharkPath: tshark  # unix、 mac 下使用
    tsharkPath: C:\Program Files\Wireshark\tshark.exe  # win 下使用；路径无效时自动从 TSHARK 环境变量、PATH 及常见安装目录探测，亦可在「系统设置」页面在线修改
    tsharkTimeout: 120  # tshark 单次执行超时时间（秒）
`)

const DefaultPort = "8001"
const ConfigFileName = "config.yaml"
const ServiceName = "blue-team-analysis-box"
const Website = "https://github.com/Martin2877"

const Version = "1.1.0"
const Banner = `
 ██████   ██████████     ██     ██████  
░█░░░░██ ░░░░░██░░░     ████   ░█░░░░██ 
░█   ░██     ░██       ██░░██  ░█   ░██ 
░██████      ░██      ██  ░░██ ░██████  
░█░░░░ ██    ░██     ██████████░█░░░░ ██
░█    ░██    ░██    ░██░░░░░░██░█    ░██
░███████     ░██    ░██     ░██░███████ 
░░░░░░░      ░░     ░░      ░░ ░░░░░░░
`

var runMode = []string{"debug", "release"}

func ArrayToString(array []string) string {
	str, _ := json.Marshal(array)
	return string(str)
}

func StrInArray(str string, array []string) error {
	for _, element := range array {
		if str == element {
			return nil
		}
	}
	return errors.New(str + "must in" + ArrayToString(array))
}

func VerifyConfig() error {
	var err error
	err = StrInArray(GlobalConfig.ServerConfig.RunMode, runMode)
	if err != nil {
		return err
	}
	return nil
}
