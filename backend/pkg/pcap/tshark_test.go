package pcap

import (
	"testing"

	"github.com/Martin2877/blue-team-box/pkg/conf"
)

// 本机装有 tshark（PATH 可寻）时应能兜底解析；同时验证配置优先
func TestResolveTsharkPath(t *testing.T) {
	conf.GlobalConfig = &conf.Config{}
	conf.GlobalConfig.PcapAnalyseConfig.TsharkPath = `C:\nonexistent\tshark.exe`
	p, err := ResolveTsharkPath()
	if err != nil {
		t.Skipf("本机无 tshark，跳过: %v", err)
	}
	t.Logf("resolved: %s", p)

	// 配置有效路径时优先使用配置
	conf.GlobalConfig.PcapAnalyseConfig.TsharkPath = p
	if p2, err := ResolveTsharkPath(); err != nil || p2 != p {
		t.Fatalf("配置路径应优先: %s %v", p2, err)
	}
}
