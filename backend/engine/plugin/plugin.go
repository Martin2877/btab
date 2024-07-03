package plugin

import (
	"errors"
	"github.com/Martin2877/blue-team-box/engine/plugin/SerializationDumper"
	"github.com/Martin2877/blue-team-box/engine/plugin/jq"
	"github.com/Martin2877/blue-team-box/engine/plugin/pcap"
)

type Plugin interface {
	Init()
	Set(key string, value interface{})
	Check() error
	Exec() error
	GetState() int
	GetFinalStatus() int
	GetResult() string
}

var PluginMap = make(map[string]Plugin)

func init() {
	// 初始化内容
	// .. 在这里补充
	PluginMap["jq"] = &jq.JQ{}
	PluginMap["SerializationDumper"] = &SerializationDumper.SerializationDumper{}
	PluginMap["pcap"] = &pcap.Pcap{}
}

type Plugins struct {
	Plugin Plugin `json:"plugin"`
}

func (plugins *Plugins) Init(plugin string) error {
	value, ok := PluginMap[plugin]
	if ok {
		plugins.Plugin = value
		return nil
	}
	return errors.New("找不到相应插件")
}
