package jq

import (
	"encoding/json"
	"errors"

	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/itchyny/gojq"
	"github.com/tidwall/gjson"
)

type JQ struct {
	State       int    `json:"state"`        // 任务进度
	FinalStatus int    `json:"final_status"` // 执行结果
	Filter      string `json:"filter"`
	Content     string `json:"content"`
	Result      string `json:"result"`
}

func (plugin *JQ) Init() {
	plugin.State = db.StateFree
}

func (plugin *JQ) Set(key string, value interface{}) {
	switch key {
	case "filter":
		plugin.Filter = value.(string)
	case "content":
		plugin.Content = value.(string)
	}
}

func (plugin *JQ) Check() error {
	if plugin.Content == "" {
		return errors.New("参数检查不通过, content 为空")
	}
	return nil
}

func (plugin *JQ) Exec() error {
	plugin.State = db.StateRunning

	// 解析 json 内容
	if !gjson.Valid(plugin.Content) {
		return errors.New("非法json:" + plugin.Content)
	}
	input, ok := gjson.Parse(plugin.Content).Value().(interface{})
	if !ok {
		return errors.New("gjson 加载数据失败")
	}

	// 解析过滤语句
	query, err := gojq.Parse(plugin.Filter)
	code, err := gojq.Compile(query)
	if err != nil {
		plugin.State = db.StateFinish
		plugin.FinalStatus = db.FinalStatusFailed
		return err
	}
	// 加载 json 内容
	var result []interface{}
	iter := code.Run(input)
	for {
		v, ok := iter.Next()
		if !ok {
			break
		}
		if err, ok := v.(error); ok {
			return err
		}
		result = append(result, v)
	}

	plugin.State = db.StateFinish
	plugin.FinalStatus = db.FinalStatusSuccess
	var resultJsonByte []byte
	if len(result) == 1 {
		resultJsonByte, _ = json.Marshal(result[0])
	}
	resultJsonByte, _ = json.Marshal(result)
	plugin.Result = gjson.ParseBytes(resultJsonByte).String()
	return nil
}

func (plugin *JQ) GetState() int {
	return plugin.State
}

func (plugin *JQ) GetFinalStatus() int {
	return plugin.FinalStatus
}

func (plugin *JQ) GetResult() string {
	return plugin.Result
}
