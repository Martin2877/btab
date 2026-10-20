package payload

import (
	"io"
	"mime/multipart"

	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/Martin2877/blue-team-box/pkg/file"
	utils "github.com/Martin2877/blue-team-box/pkg/util"
	"github.com/gin-gonic/gin"
	"github.com/unknwon/com"
)

// MaxUploadSize payload 单文件上传上限 10MB
const MaxUploadSize = 10 << 20

// @Summary payload upload
// @Tags Payload
// @Description 上传 payload 字典，内容压缩存入数据库
// @Produce  json
// @Security token
// @Success 200 {object} msg.Response
// @Failure 200 {object} msg.Response
// @Router /api/stores/payload/upload [post]
func Upload(c *gin.Context) {
	_file, header, err := c.Request.FormFile("file")
	if err != nil {
		msg.ResultSelfDefined(c, err.Error())
		return
	}
	defer func(_file multipart.File) {
		_ = _file.Close()
	}(_file)

	filename := file.SafeFileName(header.Filename)
	if filename == "" {
		msg.ResultSelfDefined(c, "非法文件名")
		return
	}
	if header.Size > MaxUploadSize {
		msg.ResultSelfDefined(c, "文件过大")
		return
	}
	if db.ExistPayloadByName(filename) {
		msg.ResultSelfDefined(c, "文件已存在")
		return
	}

	content, err := io.ReadAll(io.LimitReader(_file, MaxUploadSize+1))
	if err != nil {
		msg.ResultSelfDefined(c, err.Error())
		return
	}
	if len(content) == 0 || len(content) > MaxUploadSize {
		msg.ResultSelfDefined(c, "文件为空或过大")
		return
	}

	payload := db.Payload{
		Name:  filename,
		Sha1:  utils.Sha1Bytes(content),
		Lines: len(file.SplitLines(content)),
		Size:  len(content),
	}
	payload.SetContent(content)
	db.AddPayload(payload)

	msg.ResultSuccess(c, "true")
}

type TableResult struct {
	Page      int          `json:"page"`
	PageCount int          `json:"pageCount"`
	PageSize  int          `json:"pageSize"`
	List      []db.Payload `json:"list"`
}

// @Summary payload list
// @Tags Payload
// @Description 列表
// @Produce  json
// @Security token
// @Param page query int true "Page"
// @Param pagesize query int true "Pagesize"
// @Param object query db.PluginSearchField false "field"
// @Success 200 {object} msg.Response
// @Failure 200 {object} msg.Response
// @Router /api/v1/poc/ [get]
func Get(c *gin.Context) {
	field := db.PayloadSearchField{Search: ""}

	// 分页
	page, _ := com.StrTo(c.Query("page")).Int()
	pageSize, _ := com.StrTo(c.Query("pageSize")).Int()

	// 查询条件
	if arg := c.Query("search"); arg != "" {
		field.Search = arg
	}

	page, pageSize = msg.NormalizePageParams(page, pageSize)
	payloads := db.GetPayloads(page, pageSize, &field)
	total := db.GetPayloadTotal(&field)
	tableResult := TableResult{Page: page, PageSize: pageSize, List: payloads}
	tableResult.PageCount = msg.PageCount(total, pageSize)

	msg.ResultSuccess(c, tableResult)
	return
}

// @Summary payload delete
// @Tags Payload
// @Description 删除
// @Produce  json
// @Security token
// @Param id path int true "ID"
// @Success 200 {object} msg.Response
// @Failure 200 {object} msg.Response
// @Router /api/v1/poc/{id}/ [delete]
func Delete(c *gin.Context) {
	id := com.StrTo(c.Query("id")).MustInt()
	if db.ExistPayloadById(id) {
		// 删除数据库记录（内容随记录一起删除）
		db.DeletePayload(id)
		msg.ResultSuccess(c, "删除成功")
		return
	}
	msg.ResultFailed(c, "删除失败")
}

func Detail(c *gin.Context) {
	field := db.PayloadSearchField{Search: ""}

	// 分页
	page, _ := com.StrTo(c.Query("page")).Int()
	pageSize, _ := com.StrTo(c.Query("pageSize")).Int()

	// 查询条件
	if arg := c.Query("search"); arg != "" {
		field.Search = arg
	}
	page, pageSize = msg.NormalizePageParams(page, pageSize)
	payloads := db.GetPayloads(page, pageSize, &field)
	if len(payloads) == 0 {
		msg.ResultFailed(c, "数据库找不到文件")
		return
	}
	payload := db.GetPayload(payloads[0].Id)
	content, err := payload.GetContent()
	if err != nil {
		msg.ResultFailed(c, "内容解析失败")
		return
	}
	msg.ResultSuccess(c, string(content))
	return
}
