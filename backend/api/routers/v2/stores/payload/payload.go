package payload

import (
	"fmt"
	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/Martin2877/blue-team-box/pkg/file"
	files "github.com/Martin2877/blue-team-box/pkg/file"
	utils "github.com/Martin2877/blue-team-box/pkg/util"
	"github.com/gin-gonic/gin"
	"github.com/unknwon/com"
	"io"
	"log"
	"math"
	"mime/multipart"
	"os"
	"path"
)

const STORES = "/stores/payload"



func Dir() string {
	pwd,_ := os.Getwd()
	targetDir := path.Join(pwd,STORES)
	return targetDir
}

func GetDir(c *gin.Context) {
	msg.ResultSuccess(c,Dir())
	return
}



// @Summary result list
// @Tags Result
// @Description 列表
// @Produce  json
// @Security token
// @Param page query int true "Page"
// @Param pagesize query int true "Pagesize"
// @Param object query db.ResultSearchField false "field"
// @Success 200 {object} msg.Response
// @Failure 200 {object} msg.Response
// @Router /api/v1/result/ [get]
func Upload(c *gin.Context) {
	// 1、上传文件
	// FormFile方法会读取参数“upload”后面的文件名，返回值是一个File指针，和一个FileHeader指针，和一个err错误。
	_file, header, err := c.Request.FormFile("file")
	if err != nil {
		//msg.ResultFailed(c,"Bad request")
		msg.ResultSelfDefined(c,err.Error())
		return
	}
	// header调用Filename方法，就可以得到文件名
	filename := header.Filename
	// 创建一个文件，文件名为filename，这里的返回值out也是一个File指针
	pwd,_ := os.Getwd()
	targetDir := path.Join(pwd,STORES)
	targetFile := path.Join(targetDir,filename)

	if files.Exists(targetFile){
		msg.ResultSelfDefined(c,"文件已存在")
		return
	}

	if db.ExistPayloadByName(filename){
		msg.ResultSelfDefined(c,"文件已存在")
		return
	}


	// 创建多层级目录
	os.MkdirAll(targetDir, os.ModePerm)

	content, err4 := io.ReadAll(_file)
	if err4 != nil {
		msg.ResultSelfDefined(c,err4.Error())
		return
	}
	defer func(_file multipart.File) {
		err5 := _file.Close()
		if err5 != nil {
			log.Fatalln(err5.Error())
		}
	}(_file)
	file.WriteFileBinary(content,targetFile,false)


	payloadSha1 := utils.Sha1f(targetFile)
	//newTargetFile := path.Join(targetDir,payloadSha1 + path.Ext(targetFile))
	//fmt.Println(newTargetFile)
	//err2 := os.Rename(targetFile, newTargetFile)
	//if err2 != nil {
	//	msg.ResultSelfDefined(c,err.Error())
	//	return
	//}

	// 2、写入数据库
	payload :=  db.Payload{
		Name:        filename,
		Sha1:        payloadSha1,
		Size:        int(header.Size),
	}

	db.AddPayload(payload)

	msg.ResultSuccess(c,"true")
	return
}


type TableResult struct {
	Page int `json:"page"`
	PageCount int `json:"pageCount"`
	PageSize int   `json:"pageSize"`
	List []db.Payload `json:"list"`
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

	payloads := db.GetPayloads(page, pageSize, &field)
	total := int(db.GetPayloadTotal(&field))
	tableResult := TableResult{Page: page, PageSize:pageSize,List: payloads}
	tableResult.PageCount = int(math.Ceil(float64(total / pageSize)))

	msg.ResultSuccess(c,tableResult)
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
	filename := c.Query("name")
	// 创建一个文件，文件名为filename，这里的返回值out也是一个File指针
	pwd,_ := os.Getwd()
	targetDir := path.Join(pwd,STORES)
	targetFile := path.Join(targetDir,filename)

	if db.ExistPayloadById(id) {
		// 删除文件
		err := os.Remove(targetFile)
		if err != nil {
			msg.ResultFailed(c,err.Error())
			return
		}
		// 删除数据库
		db.DeletePayload(id)

		msg.ResultSuccess(c,"删除成功")
		return
	} else {
		msg.ResultFailed(c,"删除失败")
		return
	}
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
	fmt.Println("search",field)
	payloads := db.GetPayloads(page, pageSize, &field)
	if len(payloads) > 0{
		pwd,_ := os.Getwd()
		targetDir := path.Join(pwd,STORES)
		targetFile := path.Join(targetDir,payloads[0].Name)
		readFile, err := file.ReadFile(targetFile)
		if err != nil {
			msg.ResultFailed(c,"文件读取失败")
			return
		}
		msg.ResultSuccess(c,readFile)
		return
	}
	msg.ResultFailed(c,"数据库找不到文件")
	return
}

