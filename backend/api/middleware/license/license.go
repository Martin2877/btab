package license

import (
	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/gin-gonic/gin"
	"time"
)

const DateLine = "2025-10-01T08:18:46+08:00"

func License() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取当前日期
		todayStr := time.Now()
		dl, err := time.Parse(time.RFC3339, DateLine)
		if err != nil {
			msg.ResultSelfDefined(c, "日期解析错误")
			c.Abort()
			return
		}
		if dl.Before(todayStr) {
			msg.ResultSelfDefined(c, "认证已经过期，请下载最新版本")
			c.Abort()
			return
		}
		c.Next()
		return
	}
}

func GetDateLine(c *gin.Context) {
	msg.ResultSuccess(c, DateLine)
	return
}
