package example

import (
	"errors"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"time"
)

type Sample struct {
	State       int    `json:"state"`        // 任务进度
	FinalStatus int    `json:"final_status"` // 执行结果
	Content     string `json:"content"`
	Result      string `json:"result"`
}

func (plugin *Sample) Init() {
	plugin.State = db.StateFree
}

func (plugin *Sample) Set(key string, value interface{}) {
	switch key {
	case "content":
		plugin.Content = value.(string)
	}
}

func (plugin *Sample) Check() error {
	if plugin.Content == "" {
		return errors.New("参数检查不通过, content 为空")
	}
	return nil
}

func (plugin *Sample) Exec() error {
	var err error
	plugin.State = db.StateRunning
	time.Sleep(2 * time.Second)
	if err != nil {
		plugin.State = db.StateFinish
		plugin.FinalStatus = db.FinalStatusFailed
		return err
	}
	plugin.State = db.StateFinish
	plugin.FinalStatus = db.FinalStatusSuccess
	plugin.Result = "<Result>"
	return nil
}

func (plugin *Sample) GetState() int {
	return plugin.State
}

func (plugin *Sample) GetFinalStatus() int {
	return plugin.FinalStatus
}

func (plugin *Sample) GetResult() string {
	return plugin.Result
}
