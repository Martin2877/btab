package webshell

import (
	"github.com/Martin2877/blue-team-box/api/msg"
	localwebshell "github.com/Martin2877/blue-team-box/engine/local/webshell"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/gin-gonic/gin"
	"github.com/unknwon/com"
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

	page, pageSize = msg.NormalizePageParams(page, pageSize)
	infos := db.GetRiskWebshells(page, pageSize, &field)
	total := db.GetRiskWebshellTotal(&field)
	tableResult := TableResult{Page: page, PageSize: pageSize, List: infos}
	tableResult.PageCount = msg.PageCount(total, pageSize)

	msg.ResultSuccess(c, tableResult)
	return

}

// Submit 检测 webshell 仓库中上传的样本文件
func Submit(c *gin.Context) {
	paJson := db.RiskWebshell{}
	err := c.ShouldBindJSON(&paJson)
	if err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	paJson.ForeignWebshell = &db.Webshell{}
	*paJson.ForeignWebshell = db.GetWebshell(paJson.Webshell)
	if paJson.ForeignWebshell.Id <= 0 {
		msg.ResultFailed(c, "webshell 不存在")
		return
	}

	// 从数据库读取样本内容
	content, err := paJson.ForeignWebshell.GetContent()
	if err != nil {
		msg.ResultFailed(c, "webshell 内容读取失败")
		return
	}
	if len(content) == 0 {
		msg.ResultFailed(c, "无检测内容")
		return
	}

	res := localwebshell.Check(content)
	paJson.State = db.PAStateFinish
	paJson.Chain = res.Chain
	paJson.Code = res.Code
	paJson.Result = res.Result
	db.AddRiskWebshell(paJson)
	msg.ResultSuccess(c, "检测完成")
	return
}

type WebshellOnce struct {
	Webshell string `json:"webshell"`
}

// SubmitOnce 即时检测粘贴的 webshell 内容
func SubmitOnce(c *gin.Context) {
	paJson := WebshellOnce{}
	err := c.ShouldBindJSON(&paJson)
	if err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	if paJson.Webshell == "" {
		msg.ResultFailed(c, "无检测内容")
		return
	}
	jres, err := localwebshell.SubmitOnce(paJson.Webshell)
	if err != nil {
		msg.ResultFailed(c, err.Error())
		return
	}
	msg.ResultSuccess(c, jres)
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
