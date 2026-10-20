package pcap

import (
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"

	"github.com/Martin2877/blue-team-box/api/msg"
	pluginpcap "github.com/Martin2877/blue-team-box/engine/plugin/pcap"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/Martin2877/blue-team-box/pkg/file"
	utils "github.com/Martin2877/blue-team-box/pkg/util"
	"github.com/gin-gonic/gin"
	"github.com/unknwon/com"
)

// MaxUploadSize pcap 单文件上传上限 200MB
const MaxUploadSize = 200 << 20

// @Summary pcap upload
// @Tags Pcap
// @Description 上传 pcap 样本，数据库仅记录元数据（内容不入库，
// 分析时通过 /api/analyze/pcap multipart 上传走临时文件）
// @Produce  json
// @Security token
// @Success 200 {object} msg.Response
// @Failure 200 {object} msg.Response
// @Router /api/stores/pcap/upload [post]
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
	if db.ExistPcapByName(filename) {
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

	// 落盘到 stores/pcap，供流量包检测任务直接引用
	if err := os.MkdirAll(pluginpcap.Dir(), 0755); err != nil {
		msg.ResultSelfDefined(c, "创建存储目录失败: "+err.Error())
		return
	}
	if err := file.WriteFileBinary(content, filepath.Join(pluginpcap.Dir(), filename), false); err != nil {
		msg.ResultSelfDefined(c, "文件保存失败: "+err.Error())
		return
	}

	pcap := db.Pcap{
		Name: filename,
		Sha1: utils.Sha1Bytes(content),
		Size: len(content),
	}
	db.AddPcap(pcap)

	msg.ResultSuccess(c, "true")
}

type TableResult struct {
	Page      int       `json:"page"`
	PageCount int       `json:"pageCount"`
	PageSize  int       `json:"pageSize"`
	List      []db.Pcap `json:"list"`
}

// syncStoreDir 将 stores/pcap 目录中已落盘但未登记入库的文件补录元数据，
// 使内置示例流量包开箱即可在列表与检测任务中选择
func syncStoreDir() {
	entries, err := os.ReadDir(pluginpcap.Dir())
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".pcap" && ext != ".pcapng" {
			continue
		}
		if db.ExistPcapByName(name) {
			continue
		}
		content, err := os.ReadFile(filepath.Join(pluginpcap.Dir(), name))
		if err != nil || len(content) == 0 {
			continue
		}
		db.AddPcap(db.Pcap{
			Name: name,
			Sha1: utils.Sha1Bytes(content),
			Size: len(content),
		})
	}
}

// @Summary pcap list
// @Tags Pcap
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
	syncStoreDir()
	field := db.PcapSearchField{Search: ""}

	// 分页
	page, _ := com.StrTo(c.Query("page")).Int()
	pageSize, _ := com.StrTo(c.Query("pageSize")).Int()

	// 查询条件
	if arg := c.Query("search"); arg != "" {
		field.Search = arg
	}

	page, pageSize = msg.NormalizePageParams(page, pageSize)
	pcaps := db.GetPcaps(page, pageSize, &field)
	total := db.GetPcapTotal(&field)
	tableResult := TableResult{Page: page, PageSize: pageSize, List: pcaps}
	tableResult.PageCount = msg.PageCount(total, pageSize)

	msg.ResultSuccess(c, tableResult)
	return
}

// @Summary pcap delete
// @Tags Pcap
// @Description 删除
// @Produce  json
// @Security token
// @Param id path int true "ID"
// @Success 200 {object} msg.Response
// @Failure 200 {object} msg.Response
// @Router /api/v1/poc/{id}/ [delete]
func Delete(c *gin.Context) {
	id := com.StrTo(c.Query("id")).MustInt()
	p := db.GetPcap(id)
	if p.Id > 0 {
		// 删除数据库记录与落盘文件
		db.DeletePcap(id)
		if p.Name != "" {
			_ = os.Remove(filepath.Join(pluginpcap.Dir(), filepath.Base(p.Name)))
		}
		msg.ResultSuccess(c, "删除成功")
		return
	}
	msg.ResultFailed(c, "删除失败")
}
