package jq

import (
	"encoding/json"
	"errors"
	"fmt"

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

	fail := func(err error) error {
		plugin.State = db.StateFinish
		plugin.FinalStatus = db.FinalStatusFailed
		return err
	}

	// 解析 json 内容
	if !gjson.Valid(plugin.Content) {
		return fail(errors.New("非法json:" + plugin.Content))
	}
	input := gjson.Parse(plugin.Content).Value()

	// 解析过滤语句
	query, err := gojq.Parse(plugin.Filter)
	if err != nil {
		return fail(fmt.Errorf("jq 语法错误: %v", err))
	}
	code, err := gojq.Compile(query)
	if err != nil {
		return fail(fmt.Errorf("jq 编译错误: %v", err))
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
			if err, ok := err.(*gojq.HaltError); ok && err.Value() == nil {
				break
			}
			return fail(fmt.Errorf("jq 执行错误: %v", err))
		}
		result = append(result, v)
	}

	plugin.State = db.StateFinish
	plugin.FinalStatus = db.FinalStatusSuccess
	var resultJsonByte []byte
	if len(result) == 1 {
		resultJsonByte, _ = json.Marshal(result[0])
	} else {
		resultJsonByte, _ = json.Marshal(result)
	}
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
