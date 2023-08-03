package system

import (
	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/pkg/conf"
	"github.com/gin-gonic/gin"
)

func GetVersion(c *gin.Context) {
	msg.ResultSuccess(c, conf.Version)
	return
}
