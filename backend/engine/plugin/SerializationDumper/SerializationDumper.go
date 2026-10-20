package SerializationDumper

import (
	"errors"

	"github.com/Martin2877/blue-team-box/pkg/db"
)

type SerializationDumper struct {
	State       int    `json:"state"`        // 任务进度
	FinalStatus int    `json:"final_status"` // 执行结果
	Content     string `json:"content"`
	Result      string `json:"result"`
}

func (plugin *SerializationDumper) Init() {
	plugin.State = db.StateFree
}

func (plugin *SerializationDumper) Set(key string, value interface{}) {
	switch key {
	case "content":
		plugin.Content = value.(string)
	}
}

func (plugin *SerializationDumper) Check() error {
	if plugin.Content == "" {
		return errors.New("参数检查不通过, content 为空")
	}
	return nil
}

func (plugin *SerializationDumper) Exec() error {
	plugin.State = db.StateRunning
	defer func() { plugin.State = db.StateFinish }()
	data, err := decodeInput(plugin.Content)
	if err != nil {
		plugin.FinalStatus = db.FinalStatusFailed
		return err
	}
	out, err := Dump(data)
	if err != nil && out == "" {
		plugin.FinalStatus = db.FinalStatusFailed
		return err
	}
	if err != nil {
		// 已解析出部分结构，保留并附带错误信息
		out += "\n[解析中断] " + err.Error() + "\n"
	}
	plugin.FinalStatus = db.FinalStatusSuccess
	plugin.Result = out
	return nil
}

func (plugin *SerializationDumper) GetState() int {
	return plugin.State
}

func (plugin *SerializationDumper) GetFinalStatus() int {
	return plugin.FinalStatus
}

func (plugin *SerializationDumper) GetResult() string {
	return plugin.Result
}
