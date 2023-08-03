package bash

import (
	"encoding/json"
	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/api/routers/v2/stores/payload"
	onlinebash "github.com/Martin2877/blue-team-box/engine/online/bash"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/Martin2877/blue-team-box/pkg/file"
	"github.com/gin-gonic/gin"
	"github.com/unknwon/com"
	"math"
	"path"
	"strings"
)

type TableResult struct {
	Page int `json:"page"`
	PageCount int `json:"pageCount"`
	PageSize int   `json:"pageSize"`
	List []db.RiskBASH `json:"list"`
}


func Get(c *gin.Context) {
	// 获取整个表
	field := db.RiskBASHSearchField{Search: ""}

	// 分页
	page, _ := com.StrTo(c.Query("page")).Int()
	pageSize, _ := com.StrTo(c.Query("pageSize")).Int()

	// 查询条件
	if arg := c.Query("search"); arg != "" {
		field.Search = arg
	}

	infos := db.GetRiskBASHs(page, pageSize, &field)
	total := int(db.GetRiskBASHTotal(&field))
	tableResult := TableResult{Page: page, PageSize:pageSize,List: infos}
	tableResult.PageCount = int(math.Ceil(float64(total / pageSize)))

	msg.ResultSuccess(c,tableResult)
	return


}

func Submit(c *gin.Context) {
	paJson := db.RiskBASH{}
	err := c.ShouldBindJSON(&paJson)
	if err != nil {
		msg.ResultFailed(c,"参数不合法:"+err.Error())
		return
	}
	paJson.ForeignPayload = &db.Payload{}
	*paJson.ForeignPayload = db.GetPayload(paJson.Payload)

	bashInstance := onlinebash.NewBASH()
	// 上传 bash
	filePath := path.Join(payload.Dir(),paJson.ForeignPayload.Name)
	if !file.Exists(filePath){
		msg.ResultFailed(c,"文件不存在")
		return
	}
	// 读取文件
	contents := file.ReadingLines(filePath)
	if len(contents) == 0{
		msg.ResultFailed(c,"无检测内容")
		return
	}

	// 提交
	jres, err := bashInstance.SubmitLines(contents)
	if err != nil {
		msg.ResultFailed(c,err.Error())
		return
	}

	res,_ := json.Marshal(jres.Result)
	paJson.State = db.PAStateFinish
	paJson.Result = string(res)
	db.AddRiskBASH(paJson)
	msg.ResultSuccess(c,"检测完成")
	return
}


type BASHOnce struct {
	Payload string `json:"payload"`
}

func SubmitOnce(c *gin.Context) {
	paJson := BASHOnce{}
	err := c.ShouldBindJSON(&paJson)
	if err != nil {
		msg.ResultFailed(c,"参数不合法:"+err.Error())
		return
	}

	owInstance := onlinebash.NewBASH()
	jres, err := owInstance.Submit(paJson.Payload)
	if err != nil {
		msg.ResultFailed(c,err.Error())
		return
	}
	if strings.Contains(jres.ReturnCode,"-31") || strings.Contains(jres.ReturnCode,"31") || strings.Contains(jres.ReturnCode,"159"){
		// 返回结果
		msg.ResultSuccess(c,"检测到 bash 命令 , 执行过程为 :"+jres.Result)
		return
	}else {
		// 返回结果
		jres2 := msg.JsonResponse{
			Code:    40400,
			Message: "未检测到bash",
			Result:  "",
			Type:    "success",
		}
		msg.ResultSuccess(c,jres2)
		return
	}
}



func Delete(c *gin.Context) {
	paJson := db.RiskBASH{}
	err := c.ShouldBindJSON(&paJson)
	if err != nil {
		msg.ResultFailed(c,"参数不合法:"+err.Error())
		return
	}
	if db.ExistRiskBASHById(paJson.Id) {
		// 删除数据库
		db.DeleteRiskBASH(paJson.Id)
		msg.ResultSuccess(c,"删除成功")
		return
	} else {
		msg.ResultFailed(c,"删除失败")
		return
	}
}
