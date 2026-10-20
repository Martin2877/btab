package conf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUpdateConfig(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgFile, defaultYamlByte, 0644); err != nil {
		t.Fatal(err)
	}
	configFilePath = cfgFile
	if err := ReadYamlConfig(cfgFile); err != nil {
		t.Fatal(err)
	}

	err := UpdateConfig(map[string]interface{}{
		"pcapAnalyseConfig.tsharkPath":    `E:\tools\Wireshark\tshark.exe`,
		"pcapAnalyseConfig.tsharkTimeout": 60,
		"serverConfig.open_browser":       false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if GlobalConfig.PcapAnalyseConfig.TsharkPath != `E:\tools\Wireshark\tshark.exe` {
		t.Fatalf("tsharkPath 未更新: %s", GlobalConfig.PcapAnalyseConfig.TsharkPath)
	}
	if GlobalConfig.PcapAnalyseConfig.TsharkTimeout != 60 {
		t.Fatalf("tsharkTimeout 未更新: %d", GlobalConfig.PcapAnalyseConfig.TsharkTimeout)
	}
	if GlobalConfig.ServerConfig.OpenBrowser != false {
		t.Fatal("open_browser 未更新")
	}

	data, _ := os.ReadFile(cfgFile)
	content := string(data)
	if !strings.Contains(content, `E:\tools\Wireshark\tshark.exe`) {
		t.Fatalf("配置文件未写入新值:\n%s", content)
	}
	if !strings.Contains(content, "# win 下使用") && !strings.Contains(content, "unix") {
		t.Fatalf("配置文件注释丢失:\n%s", content)
	}
	if !strings.Contains(content, "open_browser: false") {
		t.Fatalf("open_browser 未写入:\n%s", content)
	}
}

func TestUpdateConfigRejectUnknownKey(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgFile, defaultYamlByte, 0644); err != nil {
		t.Fatal(err)
	}
	configFilePath = cfgFile
	if err := ReadYamlConfig(cfgFile); err != nil {
		t.Fatal(err)
	}
	if err := UpdateConfig(map[string]interface{}{"serverConfig.jwt_secret": "x"}); err == nil {
		t.Fatal("非白名单配置项应被拒绝")
	}
	if err := UpdateConfig(map[string]interface{}{}); err == nil {
		t.Fatal("空更新应被拒绝")
	}
}
