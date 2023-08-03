package pcapanalyse

import (
	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/gin-gonic/gin"
	"github.com/unknwon/com"
	"log"
	"math"
)

type TableResult struct {
	Page      int              `json:"page"`
	PageCount int              `json:"pageCount"`
	PageSize  int              `json:"pageSize"`
	List      []db.PcapAnalyse `json:"list"`
}

func Get(c *gin.Context) {
	// 获取整个表
	// 先进行更新
	//fmt.Println("get")
	//go UpdateTable()
	field := db.PcapAnalyseSearchField{Search: ""}

	// 分页
	page, _ := com.StrTo(c.Query("page")).Int()
	pageSize, _ := com.StrTo(c.Query("pageSize")).Int()

	// 查询条件
	if arg := c.Query("search"); arg != "" {
		field.Search = arg
	}

	infos := db.GetPcapAnalyses(page, pageSize, &field)
	total := int(db.GetPcapAnalyseTotal(&field))
	tableResult := TableResult{Page: page, PageSize: pageSize, List: infos}
	tableResult.PageCount = int(math.Ceil(float64(total) / float64(pageSize)))

	msg.ResultSuccess(c, tableResult)
	return
}

type PATask struct {
	Item       string `json:"item"`
	Name       string `json:"name"`
	Pcap       int    `json:"pcap"`
	SecType    int    `json:"sec_type"`
	Strategies []int  `json:"strategy"`
}

func Submit(c *gin.Context) {
	msg.ResultFailed(c, "开源版本无此功能")
	return
}

func UpdateTable() {
	// 获取表中还未更新的 uuid , 全部进行 fetch 更新
	pas := db.GetPcapAnalyseByState(db.PAStateRunning)
	for _, v := range pas {
		err := Fetch(v.Id)
		if err != nil {
			log.Println(err.Error())
		}
	}
}

func Delete(c *gin.Context) {
	paJson := db.PcapAnalyse{}
	//fmt.Println(paJson)
	err := c.ShouldBindJSON(&paJson)
	if err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	if db.ExistPcapAnalyseById(paJson.Id) {
		// 删除数据库
		db.DeletePcapAnalyse(paJson.Id)
		msg.ResultSuccess(c, "删除成功")
		return
	} else {
		msg.ResultFailed(c, "删除失败")
		return
	}
}

func Fetch(id int) error {

	return nil
}
