package plugin

import (
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

// MapPluginGlb 插件工厂表：每次调用返回全新实例，避免并发请求共享状态
var MapPluginGlb = map[string]func() Plugin{
	"jq":                  func() Plugin { return &jq.JQ{} },
	"SerializationDumper": func() Plugin { return &SerializationDumper.SerializationDumper{} },
	"pcap":                func() Plugin { return &pcap.Pcap{} },
	//"pcapcheck":         func() Plugin { return &pcapcheck.PcapCheck{} },
}
