package risk

import (
	"fmt"
	"strings"

	"github.com/Martin2877/blue-team-box/api/msg"
	localbash "github.com/Martin2877/blue-team-box/engine/local/bash"
	"github.com/Martin2877/blue-team-box/engine/local/btt"
	localsqli "github.com/Martin2877/blue-team-box/engine/local/sqli"
	localwebshell "github.com/Martin2877/blue-team-box/engine/local/webshell"
	localxss "github.com/Martin2877/blue-team-box/engine/local/xss"
	"github.com/Martin2877/blue-team-box/engine/nuclei"
	"github.com/Martin2877/blue-team-box/engine/vuln"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/gin-gonic/gin"
)

// DetectReq 统一载荷识别请求
type DetectReq struct {
	Payload string `json:"payload"`
}

// DetectItem 单个引擎的检测结果
type DetectItem struct {
	Type   string      `json:"type"`   // webshell / bash / log4j2 / sqli / xss
	Title  string      `json:"title"`  // 展示名
	Found  bool        `json:"found"`  // 是否命中
	Score  int         `json:"score"`  // 置信度（用于分类排序）
	Result interface{} `json:"result"` // 引擎原始结论
}

// DetectResult 统一识别结果
type DetectResult struct {
	Found bool         `json:"found"` // 是否有引擎命中
	Type  string       `json:"type"`  // 判定类别，未命中为 ""
	Title string       `json:"title"` // 判定类别展示名
	Items []DetectItem `json:"items"` // 各引擎明细
}

// DetectOnce 统一入口：自动识别载荷类别，并由各引擎分别检测
func DetectOnce(c *gin.Context) {
	paJson := DetectReq{}
	if err := c.ShouldBindJSON(&paJson); err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	content := strings.TrimSpace(paJson.Payload)
	if content == "" {
		msg.ResultFailed(c, "无检测内容")
		return
	}

	res := DetectContent(content)
	code := 40400
	message := "未识别出攻击类别"
	if res.Found {
		code = 20000
		message = "识别为 " + res.Title
	}
	msg.ResultSuccess(c, msg.JsonResponse{
		Code:    code,
		Message: message,
		Result:  res,
		Type:    "success",
	})
}

// DetectContent 对载荷内容执行各检测引擎并判定类别（供统一入口与分析任务复用）
func DetectContent(content string) DetectResult {
	items := make([]DetectItem, 0, 5)

	// webshell：解码链还原 + 规则评分
	wres := localwebshell.Check([]byte(content))
	items = append(items, DetectItem{
		Type: "webshell", Title: "Webshell",
		Found: wres.Webshell, Score: wres.Score, Result: wres.Result,
	})

	// bash：反混淆 + 规则评分
	bres := localbash.Check(content)
	items = append(items, DetectItem{
		Type: "bash", Title: "Bash命令",
		Found: bres.Found, Score: bres.Score, Result: bres.Result,
	})

	// log4j2：JNDI lookup 解析
	lookups, danger := btt.ParseLog4j2(content)
	log4j2Result := "未检测到 lookup 表达式"
	if len(lookups) > 0 {
		log4j2Result = "解析到 lookup 表达式"
		if danger {
			log4j2Result = "检测到 JNDI 注入风险"
		}
	}
	items = append(items, DetectItem{
		Type: "log4j2", Title: "Log4j2 JNDI",
		Found: danger, Score: scoreOf(danger, 5), Result: log4j2Result,
	})

	// sqli：libinjection
	sqliJ, _ := (&localsqli.Sqli{}).SubmitOnce(content)
	sqliFound := sqliJ != nil && sqliJ.Code == 20000
	var sqliResult interface{} = "未发现SQL注入"
	if sqliJ != nil {
		sqliResult = sqliJ.Result
	}
	items = append(items, DetectItem{
		Type: "sqli", Title: "SQL注入",
		Found: sqliFound, Score: scoreOf(sqliFound, 5), Result: sqliResult,
	})

	// xss：libinjection
	xssJ, _ := (&localxss.XSS{}).SubmitOnce(content)
	xssFound := xssJ != nil && xssJ.Code == 20000
	var xssResult interface{} = "未发现 XSS"
	if xssJ != nil {
		xssResult = xssJ.Result
	}
	items = append(items, DetectItem{
		Type: "xss", Title: "XSS",
		Found: xssFound, Score: scoreOf(xssFound, 5), Result: xssResult,
	})

	// nuclei：用启用模板的请求字面量特征识别载荷疑似对应的攻击规则
	if db.GlobalDB != nil {
		eng, _ := vuln.Load()
		if len(eng.Templates) > 0 {
			hits := eng.SignatureMatch(content, 5)
			var names []string
			var bestHit *nuclei.SigHit
			for i := range hits {
				names = append(names, hits[i].Name+"["+hits[i].Literal+"]")
			}
			if len(hits) > 0 {
				bestHit = &hits[0]
			}
			score := 0
			var nres interface{} = "未匹配到 nuclei 模板特征"
			if bestHit != nil {
				score = 4
				nres = fmt.Sprintf("与 %d 个模板的攻击特征匹配: %s", len(hits), strings.Join(names, "; "))
			}
			items = append(items, DetectItem{
				Type: "nuclei", Title: "Nuclei规则特征",
				Found: bestHit != nil, Score: score, Result: nres,
			})
		}
	}

	// 分类：取命中的最高分项；同分时按 items 顺序（webshell > bash > log4j2 > sqli > xss）
	res := DetectResult{Items: items}
	best := -1
	for i, it := range items {
		if !it.Found {
			continue
		}
		res.Found = true
		if best < 0 || it.Score > items[best].Score {
			best = i
		}
	}
	if best >= 0 {
		res.Type = items[best].Type
		res.Title = items[best].Title
	}
	return res
}

func scoreOf(found bool, score int) int {
	if found {
		return score
	}
	return 0
}
