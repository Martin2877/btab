package pcapcheck

import (
	"errors"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/Martin2877/blue-team-box/pkg/pocloader"
	"time"
)

type PcapCheck struct {
	PocLoader *pocloader.PocLoader

	State       int    `json:"state"`        // 任务进度
	FinalStatus int    `json:"final_status"` // 执行结果
	FilePath    string `json:"filePath"`
	Content     string `json:"content"`
	Result      string `json:"result"`
}

func (plugin *PcapCheck) Init() {
	plugin.State = db.StateFree
}

func (plugin *PcapCheck) Set(key string, value interface{}) {
	switch key {
	case "filePath":
		plugin.FilePath = value.(string)
	case "content":
		plugin.Content = value.(string)
	}
}

func (plugin *PcapCheck) Check() error {
	if plugin.Content == "" {
		return errors.New("参数检查不通过, content 为空")
	}

	return nil
}

func (plugin *PcapCheck) Exec() error {
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

func (plugin *PcapCheck) GetState() int {
	return plugin.State
}

func (plugin *PcapCheck) GetFinalStatus() int {
	return plugin.FinalStatus
}

func (plugin *PcapCheck) GetResult() string {
	return plugin.Result
}
