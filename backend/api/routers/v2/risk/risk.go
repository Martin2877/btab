package risk

import (
	"sort"

	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/engine/pcapjs"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/gin-gonic/gin"
	"github.com/unknwon/com"
)

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

// SyncStrategies 将内置 JS 检测策略同步到数据库（供检测任务按 ID 选择），名称集合变化时才重建
func SyncStrategies() {
	strategies := pcapjs.Default().List()
	names := map[string]bool{}
	secTypes := map[string]bool{}
	for _, s := range strategies {
		if s.Disabled {
			continue // 停用策略不同步到检测选项
		}
		names[s.Name] = true
		if s.Type != "" {
			secTypes[s.Type] = true
		}
	}
	sync := func(have []string, want map[string]bool, reset func(), add func(string)) {
		same := len(have) == len(want)
		for _, n := range have {
			same = same && want[n]
		}
		if same {
			return
		}
		reset()
		keys := make([]string, 0, len(want))
		for k := range want {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			add(k)
		}
	}
	var haveStrategy, haveSecType []string
	for _, s := range db.GetStrategys(1, 100000, &db.StrategySearchField{}) {
		haveStrategy = append(haveStrategy, s.Name)
	}
	for _, s := range db.GetSecTypes(1, 100000, &db.SecTypeSearchField{}) {
		haveSecType = append(haveSecType, s.Name)
	}
	sync(haveStrategy, names, func() { db.ClearStrategy() }, func(n string) { db.AddStrategy(db.Strategy{Name: n}) })
	sync(haveSecType, secTypes, func() { db.ClearSecType() }, func(n string) { db.AddSecType(db.SecType{Name: n}) })
}

// GetSecType 获取检测分类列表（来自内置策略的 type）
func GetSecType(c *gin.Context) {
	SyncStrategies()
	page, _ := com.StrTo(c.Query("page")).Int()
	pageSize, _ := com.StrTo(c.Query("pageSize")).Int()
	field := db.SecTypeSearchField{Search: c.Query("search")}
	page, pageSize = msg.NormalizePageParams(page, pageSize)
	list := db.GetSecTypes(page, pageSize, &field)
	total := db.GetSecTypeTotal(&field)
	msg.ResultSuccess(c, SecTypeTableResult{Page: page, PageSize: pageSize, List: list, PageCount: msg.PageCount(total, pageSize)})
}

// GetStrategy 获取检测策略列表（来自内置 JS 策略）
func GetStrategy(c *gin.Context) {
	SyncStrategies()
	page, _ := com.StrTo(c.Query("page")).Int()
	pageSize, _ := com.StrTo(c.Query("pageSize")).Int()
	field := db.StrategySearchField{Search: c.Query("search")}
	page, pageSize = msg.NormalizePageParams(page, pageSize)
	list := db.GetStrategys(page, pageSize, &field)
	total := db.GetStrategyTotal(&field)
	msg.ResultSuccess(c, StrategyTableResult{Page: page, PageSize: pageSize, List: list, PageCount: msg.PageCount(total, pageSize)})
}
