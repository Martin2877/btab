package weblog

import (
	"io"
	"mime/multipart"

	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/engine/local/weblog"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/Martin2877/blue-team-box/pkg/file"
	utils "github.com/Martin2877/blue-team-box/pkg/util"
	"github.com/gin-gonic/gin"
	"github.com/unknwon/com"
)

// MaxUploadSize web 日志单文件上传上限 50MB（gzip 压缩入库）
const MaxUploadSize = 50 << 20

// Upload 上传 web 访问日志（nginx/apache 等），压缩存入数据库
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
	if db.ExistWeblogByName(filename) {
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
	if !weblog.LooksLikeLog(string(content)) {
		msg.ResultSelfDefined(c, "无法识别为 web 访问日志（支持 nginx/apache 的 combined/common 格式）")
		return
	}

	w := db.Weblog{
		Name:   filename,
		Sha1:   utils.Sha1Bytes(content),
		Format: "combined",
		Lines:  len(file.SplitLines(content)),
		Size:   len(content),
	}
	w.SetContent(content)
	db.AddWeblog(&w)

	msg.ResultSuccess(c, "true")
}

type TableResult struct {
	Page      int         `json:"page"`
	PageCount int         `json:"pageCount"`
	PageSize  int         `json:"pageSize"`
	List      []db.Weblog `json:"list"`
}

// Get web 日志列表（分页 + 搜索）
func Get(c *gin.Context) {
	field := db.WeblogSearchField{Search: ""}

	page, _ := com.StrTo(c.Query("page")).Int()
	pageSize, _ := com.StrTo(c.Query("pageSize")).Int()
	if arg := c.Query("search"); arg != "" {
		field.Search = arg
	}

	page, pageSize = msg.NormalizePageParams(page, pageSize)
	list := db.GetWeblogs(page, pageSize, &field)
	total := db.GetWeblogTotal(&field)
	tableResult := TableResult{Page: page, PageSize: pageSize, List: list}
	tableResult.PageCount = msg.PageCount(total, pageSize)

	msg.ResultSuccess(c, tableResult)
}

// Delete 删除日志
func Delete(c *gin.Context) {
	id := com.StrTo(c.Query("id")).MustInt()
	if db.ExistWeblogById(id) {
		db.DeleteWeblog(id)
		msg.ResultSuccess(c, "删除成功")
		return
	}
	msg.ResultFailed(c, "删除失败")
}

// Detail 返回单条日志内容（按 id 参数）
func Detail(c *gin.Context) {
	id := com.StrTo(c.Query("id")).MustInt()
	if id <= 0 || !db.ExistWeblogById(id) {
		msg.ResultFailed(c, "数据库找不到文件")
		return
	}
	w := db.GetWeblog(id)
	content, err := w.GetContent()
	if err != nil {
		msg.ResultFailed(c, "内容解析失败")
		return
	}
	msg.ResultSuccess(c, string(content))
}
