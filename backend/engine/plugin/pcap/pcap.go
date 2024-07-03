package pcap

import (
	"errors"
	"fmt"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/Martin2877/blue-team-box/pkg/file"
	"github.com/Martin2877/blue-team-box/pkg/pcap"
	"github.com/tidwall/gjson"
	"os"
	"path"
)

const STORES = "/stores/pcap"

func Dir() string {
	pwd, _ := os.Getwd()
	targetDir := path.Join(pwd, STORES)
	return targetDir
}

type Pcap struct {
	State       int      `json:"state"`        // 任务进度
	FinalStatus int      `json:"final_status"` // 执行结果
	File        string   `json:"file"`
	Fields      []string `json:"fields"`
	Condition   string   `json:"condition"`
	Result      string   `json:"result"`
}

func (plugin *Pcap) Init() {
	plugin.State = db.StateFree
	plugin.File = ""
	plugin.Fields = []string{}
	plugin.Condition = ""
}

func (plugin *Pcap) Set(key string, value interface{}) {
	switch key {
	case "file":
		plugin.File = value.(string)
	case "fields":
		fieldsSource := fmt.Sprintf(`{"fields": %s}`, value.(string))
		fields := gjson.Get(fieldsSource, "fields")
		for _, v := range fields.Array() {
			plugin.Fields = append(plugin.Fields, v.String())
		}
	case "condition":
		plugin.Condition = value.(string)
	}
}

func (plugin *Pcap) Check() error {
	if plugin.File == "" {
		return errors.New("参数检查不通过, file 为空")
	}
	return nil
}

func (plugin *Pcap) Exec() error {
	plugin.State = db.StateRunning

	// 处理
	pcaper := pcap.CreatePcaper()

	filePath := path.Join(Dir(), plugin.File)
	if !file.Exists(filePath) {
		plugin.State = db.StateFinish
		plugin.FinalStatus = db.FinalStatusFailed
		return errors.New("文件不存在")
	}
	err := pcaper.Load(filePath)
	if err != nil {
		plugin.State = db.StateFinish
		plugin.FinalStatus = db.FinalStatusFailed
		return err
	}

	pcaper.SetFields(plugin.Fields)

	query, _, err := pcaper.Query(plugin.Condition)
	if err != nil {
		plugin.State = db.StateFinish
		plugin.FinalStatus = db.FinalStatusFailed
		return err
	}

	// 加载 json 内容
	layers := gjson.GetBytes(query, "#._source.layers")
	plugin.Result = layers.String()
	plugin.State = db.StateFinish
	plugin.FinalStatus = db.FinalStatusSuccess
	return nil
}

func (plugin *Pcap) GetState() int {
	return plugin.State
}

func (plugin *Pcap) GetFinalStatus() int {
	return plugin.FinalStatus
}

func (plugin *Pcap) GetResult() string {
	return plugin.Result
}
