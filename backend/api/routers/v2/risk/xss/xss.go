package xss

import (
	"encoding/json"

	"github.com/Martin2877/blue-team-box/api/msg"
	localxss "github.com/Martin2877/blue-team-box/engine/local/xss"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/Martin2877/blue-team-box/pkg/file"
	"github.com/gin-gonic/gin"
	"github.com/unknwon/com"
)

type TableResult struct {
	Page      int          `json:"page"`
	PageCount int          `json:"pageCount"`
	PageSize  int          `json:"pageSize"`
	List      []db.RiskXSS `json:"list"`
}

func Get(c *gin.Context) {
	// 获取整个表
	field := db.RiskXSSSearchField{Search: ""}

	// 分页
	page, _ := com.StrTo(c.Query("page")).Int()
	pageSize, _ := com.StrTo(c.Query("pageSize")).Int()

	// 查询条件
	if arg := c.Query("search"); arg != "" {
		field.Search = arg
	}

	page, pageSize = msg.NormalizePageParams(page, pageSize)
	infos := db.GetRiskXSSs(page, pageSize, &field)
	total := db.GetRiskXSSTotal(&field)
	tableResult := TableResult{Page: page, PageSize: pageSize, List: infos}
	tableResult.PageCount = msg.PageCount(total, pageSize)

	msg.ResultSuccess(c, tableResult)
	return
}

// Submit 按行处理整个文件
func Submit(c *gin.Context) {
	paJson := db.RiskXSS{}
	err := c.ShouldBindJSON(&paJson)
	if err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	paJson.ForeignPayload = &db.Payload{}
	*paJson.ForeignPayload = db.GetPayload(paJson.Payload)
	if paJson.ForeignPayload.Id <= 0 {
		msg.ResultFailed(c, "payload 不存在")
		return
	}

	xssInstance := localxss.XSS{}
	// 从数据库读取 payload 内容
	content, err := paJson.ForeignPayload.GetContent()
	if err != nil {
		msg.ResultFailed(c, "payload 内容读取失败")
		return
	}
	contents := file.SplitLines(content)
	if len(contents) == 0 {
		msg.ResultFailed(c, "无检测内容")
		return
	}

	// 提交
	jres, err := xssInstance.SubmitLines(contents)
	if err != nil {
		msg.ResultFailed(c, err.Error())
		return
	}
	res, _ := json.Marshal(jres.Result)
	paJson.State = db.PAStateFinish
	paJson.Result = string(res)
	db.AddRiskXSS(paJson)
	msg.ResultSuccess(c, "检测完成")
	return
}

type XSSOnce struct {
	Payload string `json:"payload"`
}

func SubmitOnce(c *gin.Context) {
	paJson := XSSOnce{}
	err := c.ShouldBindJSON(&paJson)
	if err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	if paJson.Payload == "" {
		msg.ResultFailed(c, "无检测内容")
		return
	}

	xssInstance := localxss.XSS{}
	jres, err := xssInstance.SubmitOnce(paJson.Payload)
	if err != nil {
		msg.ResultFailed(c, err.Error())
		return
	}
	msg.ResultSuccess(c, jres)
	return
}

func Delete(c *gin.Context) {
	paJson := db.RiskXSS{}
	err := c.ShouldBindJSON(&paJson)
	if err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	if db.ExistRiskXSSById(paJson.Id) {
		// 删除数据库
		db.DeleteRiskXSS(paJson.Id)
		msg.ResultSuccess(c, "删除成功")
		return
	} else {
		msg.ResultFailed(c, "删除失败")
		return
	}
}
