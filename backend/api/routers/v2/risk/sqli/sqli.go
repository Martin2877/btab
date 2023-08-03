package sqli

import (
	"encoding/json"
	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/api/routers/v2/stores/payload"
	localsqli "github.com/Martin2877/blue-team-box/engine/local/sqli"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/Martin2877/blue-team-box/pkg/file"
	"github.com/gin-gonic/gin"
	"github.com/unknwon/com"
	"math"
	"path"
)

type TableResult struct {
	Page int `json:"page"`
	PageCount int `json:"pageCount"`
	PageSize int   `json:"pageSize"`
	List []db.RiskSqli `json:"list"`
}



func Get(c *gin.Context) {
	// 获取整个表
	field := db.RiskSqliSearchField{Search: ""}

	// 分页
	page, _ := com.StrTo(c.Query("page")).Int()
	pageSize, _ := com.StrTo(c.Query("pageSize")).Int()

	// 查询条件
	if arg := c.Query("search"); arg != "" {
		field.Search = arg
	}

	infos := db.GetRiskSqlis(page, pageSize, &field)
	total := int(db.GetRiskSqliTotal(&field))
	tableResult := TableResult{Page: page, PageSize:pageSize,List: infos}
	tableResult.PageCount = int(math.Ceil(float64(total / pageSize)))

	msg.ResultSuccess(c,tableResult)
	return
}




// Submit 按行处理整个文件
func Submit(c *gin.Context) {
	paJson := db.RiskSqli{}
	err := c.ShouldBindJSON(&paJson)
	if err != nil {
		msg.ResultFailed(c,"参数不合法:"+err.Error())
		return
	}
	paJson.ForeignPayload = &db.Payload{}
	*paJson.ForeignPayload = db.GetPayload(paJson.Payload)

	sqliInstance := localsqli.Sqli{}
	// 上传 webshell
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
	jres, err := sqliInstance.SubmitLines(contents)
	if err != nil {
		msg.ResultFailed(c,err.Error())
		return
	}
	res,_ := json.Marshal(jres.Result)
	paJson.State = db.PAStateFinish
	paJson.Result = string(res)
	db.AddRiskSqli(paJson)
	msg.ResultSuccess(c,"检测完成")
	return
}


type SqliOnce struct {
	Payload string `json:"payload"`
}

func SubmitOnce(c *gin.Context) {
	paJson := SqliOnce{}
	err := c.ShouldBindJSON(&paJson)
	if err != nil {
		msg.ResultFailed(c,"参数不合法:"+err.Error())
		return
	}
	if paJson.Payload == ""{
		msg.ResultFailed(c,"无检测内容")
		return
	}

	sqliInstance := localsqli.Sqli{}
	jres, err := sqliInstance.SubmitOnce(paJson.Payload)
	if err != nil {
		msg.ResultFailed(c,err.Error())
		return
	}
	msg.ResultSuccess(c,jres)
	return
}



func Delete(c *gin.Context) {
	paJson := db.RiskSqli{}
	err := c.ShouldBindJSON(&paJson)
	if err != nil {
		msg.ResultFailed(c,"参数不合法:"+err.Error())
		return
	}
	if db.ExistRiskXSSById(paJson.Id) {
		// 删除数据库
		db.DeleteRiskXSS(paJson.Id)
		msg.ResultSuccess(c,"删除成功")
		return
	} else {
		msg.ResultFailed(c,"删除失败")
		return
	}
}

