package pcap

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/Martin2877/blue-team-box/pkg/file"
	"github.com/Martin2877/blue-team-box/pkg/pcap"
	"github.com/tidwall/gjson"
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
	plugin.FinalStatus = 0
	plugin.File = ""
	plugin.Fields = []string{}
	plugin.Condition = ""
	plugin.Result = ""
}

func (plugin *Pcap) Set(key string, value interface{}) {
	str, ok := value.(string)
	if !ok {
		return
	}
	switch key {
	case "file":
		plugin.File = str
	case "fields":
		fieldsSource := fmt.Sprintf(`{"fields": %s}`, str)
		fields := gjson.Get(fieldsSource, "fields")
		for _, v := range fields.Array() {
			plugin.Fields = append(plugin.Fields, v.String())
		}
	case "condition":
		plugin.Condition = str
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

	// 处理：优先使用绝对路径；相对路径则限定在 stores/pcap 目录内解析，防止路径穿越
	pcaper := pcap.CreatePcaper()
	filePath := filepath.Clean(plugin.File)
	if !filepath.IsAbs(filePath) {
		filePath = filepath.Join(Dir(), filepath.Base(filePath))
	}
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
	result := layers.String()
	if result == "" {
		plugin.State = db.StateFinish
		plugin.FinalStatus = db.FinalStatusFailed
		return errors.New("pcap 解析结果为空，请检查文件格式与过滤条件")
	}
	plugin.Result = result
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
