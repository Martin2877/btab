package risk

import (
	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/engine/online/pcapanalyse"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/gin-gonic/gin"
)

func init() {

}

type SecTypeTableResult struct {
	Page      int          `json:"page"`
	PageCount int          `json:"pageCount"`
	PageSize  int          `json:"pageSize"`
	List      []db.SecType `json:"list"`
}

type StrategyTableResult struct {
	Page      int           `json:"page"`
	PageCount int           `json:"pageCount"`
	PageSize  int           `json:"pageSize"`
	List      []db.Strategy `json:"list"`
}

func UpdateOLSecType() error {
	pa := pcapanalyse.NewPA()
	items, err := pa.GetSecType()
	if err != nil {
		return err
	}

	// TODO: 判断与原来的是否一样，一样则不修改

	// 清空并添加
	db.ClearSecType()

	for _, k := range items {
		info := db.SecType{
			Name: k,
		}
		db.AddSecType(info)
	}
	return nil
}

func UpdateSecType() error {

	return nil
}

// 获取 secType 列表
// @Summary sec_type list
// @Tags SecType
// @Description 列表
// @Produce  json
// @Security token
// @Param page query int true "Page"
// @Param pagesize query int true "Pagesize"
// @Param object query db.PluginSearchField false "field"
// @Success 200 {object} msg.Response
// @Failure 200 {object} msg.Response
// @Router /api/v1/poc/ [get]
func GetSecType(c *gin.Context) {
	msg.ResultFailed(c, "开源版本暂无此功能")
	return
}

// 获取 Strategy 列表

func UpdateStrategy() error {

	return nil
}

func UpdateOLStrategy() error {
	pa := pcapanalyse.NewPA()
	items, err := pa.GetStrategy()
	if err != nil {
		return err
	}
	// 清空并添加
	db.ClearStrategy()

	for _, k := range items {
		info := db.Strategy{
			Name: k,
		}
		db.AddStrategy(info)
	}
	return nil
}

// @Summary strategy list
// @Tags Strategy
// @Description 列表
// @Produce  json
// @Security token
// @Param page query int true "Page"
// @Param pagesize query int true "Pagesize"
// @Param object query db.PluginSearchField false "field"
// @Success 200 {object} msg.Response
// @Failure 200 {object} msg.Response
// @Router /api/v1/poc/ [get]
func GetStrategy(c *gin.Context) {
	msg.ResultFailed(c, "开源版本暂无此功能")
	return
}
