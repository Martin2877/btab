package webshell

import (
	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/gin-gonic/gin"
	"github.com/unknwon/com"
	"math"
)

type TableResult struct {
	Page      int               `json:"page"`
	PageCount int               `json:"pageCount"`
	PageSize  int               `json:"pageSize"`
	List      []db.RiskWebshell `json:"list"`
}

func Get(c *gin.Context) {
	// 获取整个表
	field := db.RiskWebshellSearchField{Search: ""}

	// 分页
	page, _ := com.StrTo(c.Query("page")).Int()
	pageSize, _ := com.StrTo(c.Query("pageSize")).Int()

	// 查询条件
	if arg := c.Query("search"); arg != "" {
		field.Search = arg
	}

	infos := db.GetRiskWebshells(page, pageSize, &field)
	total := int(db.GetRiskWebshellTotal(&field))
	tableResult := TableResult{Page: page, PageSize: pageSize, List: infos}
	tableResult.PageCount = int(math.Ceil(float64(total / pageSize)))

	msg.ResultSuccess(c, tableResult)
	return

}

func Submit(c *gin.Context) {
	msg.ResultFailed(c, "开源版本无此功能")
	return
}

type WebshellOnce struct {
	Webshell string `json:"webshell"`
}

func SubmitOnce(c *gin.Context) {
	msg.ResultFailed(c, "开源版本无此功能")
	return
}

func Delete(c *gin.Context) {
	paJson := db.RiskWebshell{}
	err := c.ShouldBindJSON(&paJson)
	if err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	if db.ExistRiskWebshellById(paJson.Id) {
		// 删除数据库
		db.DeleteRiskWebshell(paJson.Id)
		msg.ResultSuccess(c, "删除成功")
		return
	} else {
		msg.ResultFailed(c, "删除失败")
		return
	}
}
