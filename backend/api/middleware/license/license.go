package license

import (
	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/gin-gonic/gin"
)

// BTAB 为开源工具，认证有效期已去除，无截止日期限制。
// 保留 /license/dateline 接口仅为前端 About 页面展示兼容。

// GetDateLine 返回固定的“永久有效”
func GetDateLine(c *gin.Context) {
	msg.ResultSuccess(c, "永久有效")
}
