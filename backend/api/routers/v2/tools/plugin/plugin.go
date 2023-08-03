package plugin

import (
	"fmt"
	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/engine/plugin"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/gin-gonic/gin"
)


type Params struct {
	Plugin string `json:"plugin"`
	Payloads map[string]string `json:"payloads"`
}

func SubmitOnce(c *gin.Context) {
	paJson := Params{}
	err := c.ShouldBindJSON(&paJson)
	if err != nil {
		msg.ResultFailed(c,"参数不合法:"+err.Error())
		return
	}
	fmt.Println(paJson)

	// 初始化插件
	plugins := plugin.Plugins{}
	err = plugins.Init(paJson.Plugin)
	if err != nil {
		msg.ResultFailed(c,err.Error())
		return
	}

	// 插件示例的处理
	plugins.Plugin.Init()
	for k,v := range paJson.Payloads{
		plugins.Plugin.Set(k,v)
	}
	err = plugins.Plugin.Check()
	if err != nil {
		msg.ResultFailed(c,err.Error())
		return
	}
	// 执行
	err = plugins.Plugin.Exec()
	if err != nil {
		msg.ResultFailed(c,err.Error())
		return
	}
	if plugins.Plugin.GetState() == db.StateFinish{
		// 返回结果
		jres := msg.JsonResponse{
			Code:    20000,
			Message: "执行成功",
			Result:  plugins.Plugin.GetResult(),
			Type:    "success",
		}
		msg.ResultSuccess(c,jres)
		return
	} else {
		// 返回结果
		jres := msg.JsonResponse{
			Code:    40400,
			Message: "执行失败",
			Result:  plugins.Plugin.GetResult(),
			Type:    "failed",
		}
		msg.ResultSuccess(c,jres)
		return
	}
}


