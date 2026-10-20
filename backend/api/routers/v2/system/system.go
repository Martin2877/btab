package system

import (
	"strings"

	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/pkg/conf"
	"github.com/Martin2877/blue-team-box/pkg/pcap"
	"github.com/gin-gonic/gin"
)

func GetVersion(c *gin.Context) {
	msg.ResultSuccess(c, conf.Version)
	return
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// configView 返回可在 UI 上展示/编辑的配置项
func configView() gin.H {
	cfg := conf.GlobalConfig
	return gin.H{
		"pcapAnalyseConfig.tsharkPath":    cfg.PcapAnalyseConfig.TsharkPath,
		"pcapAnalyseConfig.tsharkTimeout": cfg.PcapAnalyseConfig.TsharkTimeout,
		"httpConfig.proxy":                cfg.HttpConfig.Proxy,
		"serverConfig.open_browser":       cfg.ServerConfig.OpenBrowser,
	}
}

// GetConfig GET /api/system/config 返回可编辑配置 + tshark 探测状态
func GetConfig(c *gin.Context) {
	msg.ResultSuccess(c, gin.H{
		"config":      configView(),
		"tshark":      pcap.TsharkStatus(),
		"config_file": conf.ConfigFile(),
	})
}

// UpdateConfig POST /api/system/config 在线更新白名单内配置项
// 请求体为 {"yaml路径": 值}，如 {"pcapAnalyseConfig.tsharkPath": "tshark"}；
// 也兼容 form/query 单条更新 key=&value=
func UpdateConfig(c *gin.Context) {
	updates := map[string]interface{}{}
	if strings.HasPrefix(c.ContentType(), "application/json") {
		if err := c.ShouldBindJSON(&updates); err != nil {
			msg.ResultFailed(c, "参数不合法: "+err.Error())
			return
		}
	} else if k := firstNonEmpty(c.PostForm("key"), c.Query("key")); k != "" {
		updates[k] = firstNonEmpty(c.PostForm("value"), c.Query("value"))
	}
	if len(updates) == 0 {
		msg.ResultFailed(c, "参数不合法: 需要 {\"配置项\": 值} 或 key=&value=")
		return
	}
	if err := conf.UpdateConfig(updates); err != nil {
		msg.ResultFailed(c, err.Error())
		return
	}
	msg.ResultSuccess(c, gin.H{
		"config":      configView(),
		"tshark":      pcap.TsharkStatus(),
		"config_file": conf.ConfigFile(),
	})
}

// GetTshark GET /api/system/tshark 探测 tshark 可用性与候选路径（供自动检测）
func GetTshark(c *gin.Context) {
	msg.ResultSuccess(c, pcap.TsharkStatus())
}
