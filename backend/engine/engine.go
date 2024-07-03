package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Martin2877/blue-team-box/engine/local/sqli"
	"github.com/Martin2877/blue-team-box/engine/local/xss"
	"github.com/Martin2877/blue-team-box/engine/online/bash"
	"github.com/tidwall/gjson"
	"regexp"
	"strconv"
	"strings"

	"github.com/Martin2877/blue-team-box/engine/plugin"
	"github.com/Martin2877/blue-team-box/pkg/util"
)

// 可以调用多个引擎的

const (
	PluginEngine = "PluginEngine"
	BashEngine   = "BashEngine"
	SqliEngine   = "SqliEngine"
	XSSEngine    = "XSSEngine"

	LastResult = "{{R}}"

	EventType = "eventType"
)

var PluginEngines []string
var BashEngines = []string{"bash", "Bash"}
var SqliEngines = []string{"sqli", "SQLi"}
var XSSEngines = []string{"xss", "XSS"}

func init() {
	for p := range plugin.PluginMap {
		PluginEngines = append(PluginEngines, p)
	}
}

type Step struct {
	EngineType string            `json:"engine_type"`
	Engine     string            `json:"engine"`
	Payloads   map[string]string `json:"payloads"`
	Result     string            `json:"result"`
}

type Engines struct {
	GlobalPayloads map[string]string `json:"global_payloads"`
	Steps          []*Step           `json:"steps"`

	Plugins    plugin.Plugins `json:"plugin"`
	Bash       bash.BASH      `json:"bash"`
	SQLi       sqli.Sqli      `json:"sq_li"`
	XSS        xss.XSS        `json:"xss"`
	LastEngine string         `json:"last_engine"`
}

func NewEngines() *Engines {
	return &Engines{GlobalPayloads: make(map[string]string)}
}

func (ins *Engines) ClearSteps() {
	ins.Steps = make([]*Step, 0)
}

func (ins *Engines) LoadQueries(content string) error {
	// TODO: 解析 query
	//parser.DSL(paJson.Query)

	// 使用自定义解析
	queries := strings.Split(content, "\n")
	for _, q := range queries {
		q = strings.TrimSpace(q)
		if len(q) == 0 {
			continue
		}
		if len(q) < 2 {
			return errors.New(fmt.Sprint("语句有误 : ", q))
		}

		// 以 // 开始，为注释
		if q[:2] == "//" {
			continue
		}

		// 引擎自身的操作
		if strings.HasPrefix(q, "- ") {
			order := strings.Replace(q, "- ", "", 1)
			switch order {
			case "break":
				return nil
			}
		}

		// 以 : 开始，为设置全局参数
		if q[:2] == ": " {
			q = strings.TrimSpace(strings.TrimLeft(q, ": "))
			if len(q) == 0 {
				return errors.New("格式有误,: 需要为【: a b】或【: a】的格式进行参数设置")
			}
			if !strings.Contains(q, " ") {
				// 空值
				ins.SetGlobalFieldValues(q, "")
			} else {
				// key value 进行设置参数
				key := strings.TrimSpace(strings.SplitN(q, " ", 2)[0])
				value := strings.TrimSpace(strings.SplitN(q, " ", 2)[1])
				//fmt.Println("查询条件:", q, "->", key, "->", value)
				ins.SetGlobalFieldValues(key, value)
			}
			continue
		}

		// 以 | 开始，为引擎开始
		if q[:2] == "| " {
			// 删除掉 "|"
			q = strings.TrimSpace(strings.TrimLeft(q, "|"))
			// 没有带参数，设置引擎
			if !strings.Contains(q, " ") {
				err := ins.SetEngine(q)
				if err != nil {
					return err
				}
				continue
			}
		}
		// 以 |: 开始，为设置参数
		if q[:2] == "|:" {
			q = strings.TrimSpace(strings.TrimLeft(q, "|:"))
			if len(q) == 0 {
				return errors.New("格式有误,|: 需要为【|: a b】或【|: a】的格式进行参数设置")
			}
			if !strings.Contains(q, " ") {
				// 空值
				ins.SetFieldValues(q, "")
			} else {
				// key value 进行设置参数
				key := strings.TrimSpace(strings.SplitN(q, " ", 2)[0])
				value := strings.TrimSpace(strings.SplitN(q, " ", 2)[1])
				//fmt.Println("查询条件:", q, "->", key, "->", value)
				ins.SetFieldValues(key, value)
			}
			continue
		}
	}
	return nil
}

func (ins *Engines) SetEngine(engineTarget string) error {
	//fmt.Println("设置引擎:", engineTarget)
	if util.SliceContains(PluginEngines, engineTarget) {
		ins.Steps = append(ins.Steps, &Step{
			EngineType: PluginEngine,
			Engine:     engineTarget,
			Payloads:   make(map[string]string),
		})
		return nil
	}
	if util.SliceContains(BashEngines, engineTarget) {
		ins.Steps = append(ins.Steps, &Step{
			EngineType: BashEngine,
			Engine:     engineTarget,
			Payloads:   make(map[string]string),
		})
		return nil
	}
	if util.SliceContains(SqliEngines, engineTarget) {
		ins.Steps = append(ins.Steps, &Step{
			EngineType: SqliEngine,
			Engine:     engineTarget,
			Payloads:   make(map[string]string),
		})
		return nil
	}
	if util.SliceContains(XSSEngines, engineTarget) {
		ins.Steps = append(ins.Steps, &Step{
			EngineType: XSSEngine,
			Engine:     engineTarget,
			Payloads:   make(map[string]string),
		})
		return nil
	}
	return errors.New(fmt.Sprint("找不到对应的引擎:", engineTarget))
}

func (ins *Engines) SetFieldValues(key string, value string) {
	if len(ins.Steps) == 0 {
		return
	}
	ins.Steps[len(ins.Steps)-1].Payloads[key] = value
}

func (ins *Engines) SetGlobalFieldValues(key string, value string) {
	ins.GlobalPayloads[key] = value
}

func (ins *Engines) GetResult(i int) string {
	return ins.Steps[i].Result
}

func (ins *Engines) GetFinalResult() string {
	if len(ins.Steps) == 0 {
		return ""
	}
	return ins.Steps[len(ins.Steps)-1].Result
}

func (ins *Engines) getFiledValue(v string, i int, value *string) error {
	reg, _ := regexp.Compile(`R\[([0-9])]`)
	reg2, _ := regexp.Compile(`{{(\w+)}}`)
	v = strings.TrimSpace(v)
	if !(strings.HasPrefix(v, "{{") && strings.HasSuffix(v, "}}")) {
		*value = v
		return nil
	}
	// 固定变量可以后续添加
	switch v {
	case LastResult:
		*value = ins.GetResult(i - 1)
		return nil
	}
	// 提取其中的序号
	if strings.Contains(v, "[") && strings.Contains(v, "]") {
		match := reg.FindStringSubmatch(v)
		atoi, err := strconv.Atoi(match[1])
		if err != nil {
			return err
		}
		if len(ins.Steps) < atoi+1 {
			return errors.New("指定的获取结果数值过大")
		}
		*value = ins.GetResult(atoi)
		return nil
	}
	match := reg2.FindStringSubmatch(v)
	if len(match) == 2 {
		//fmt.Println(match[1])
		payload, ok := ins.GlobalPayloads[match[1]]
		if ok {
			*value = payload
			return nil
		}
	}
	return errors.New(fmt.Sprint("设置了 {{}}, 但找不到相关变量", v))
}

func (ins *Engines) Run() error {
	var err error
	for i, step := range ins.Steps {
		//fmt.Println(i, ": 开始执行引擎 -> ", step.Engine)
		//fmt.Printf("payloads: %#v\n", step.Payloads)
		switch step.EngineType {
		case PluginEngine:
			err = ins.Plugins.Init(step.Engine)
			if err != nil {
				return err
			}
			ins.Plugins.Plugin.Init()
			for k, v := range step.Payloads {
				if k == EventType {
					continue
				}
				var value string
				err = ins.getFiledValue(v, i, &value)
				if err != nil {
					return err
				}
				ins.Plugins.Plugin.Set(k, value)
			}
			err = ins.Plugins.Plugin.Check()
			if err != nil {
				return err
			}
			err = ins.Plugins.Plugin.Exec()
			if err != nil {
				return err
			}
			step.Result = ins.Plugins.Plugin.GetResult()
		case SqliEngine:
			for k, v := range step.Payloads {
				if k == EventType {
					continue
				}
				var value string
				err = ins.getFiledValue(v, i, &value)
				if err != nil {
					return err
				}
				if k == "content" {
					if !gjson.Valid(value) {
						//fmt.Println("检测 String :",value)
						jres, err := ins.SQLi.SubmitOnce(value)
						if err != nil {
							return err
						}
						jresString, _ := json.Marshal(jres) //转换成JSON返回的是byte[]
						step.Result = string(jresString)
						return nil
					}
					vjson := gjson.Parse(value)
					switch vjson.Type {
					case gjson.String:
						//fmt.Println("检测 String :",value)
						jres, err := ins.SQLi.SubmitOnce(value)
						if err != nil {
							return err
						}
						jresString, _ := json.Marshal(jres) //转换成JSON返回的是byte[]
						step.Result = string(jresString)
						return nil
					case gjson.JSON:
						if !vjson.IsArray() {
							return errors.New("检测到非字符串、非数组的数据格式，无法处理")
						}
						for _, _v := range vjson.Array() {
							//fmt.Println("检测 JSON：",_v.String())
							jres, err := ins.SQLi.SubmitOnce(_v.String())
							if err != nil {
								return err
							}
							jresString, _ := json.Marshal(jres) //转换成JSON返回的是byte[]
							step.Result = string(jresString)
							return nil
						}
					}
				}
			}
		}
	}
	return nil
}
