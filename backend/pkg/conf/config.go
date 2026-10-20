package conf

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"strings"

	"github.com/Martin2877/blue-team-box/pkg/file"
	"github.com/spf13/viper"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"
)

type Headers struct {
	UserAgent string `mapstructure:"user_agent"`
}

type Mysql struct {
	Host     string `mapstructure:"host"`
	Password string `mapstructure:"password"`
	Port     string `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Database string `mapstructure:"database"`
	Timeout  string `mapstructure:"timeout"`
}

type DbConfig struct {
	EnableDefault bool   `mapstructure:"enableDefault"`
	Sqlite        string `mapstructure:"sqlite"`
	Mysql         Mysql  `mapstructure:"mysql"`
}

type GRPCConfig struct {
	Address string `mapstructure:"address"`
}

type Config struct {
	HttpConfig        HttpConfig        `mapstructure:"httpConfig"`
	DbConfig          DbConfig          `mapstructure:"dbConfig"`
	ServerConfig      ServerConfig      `mapstructure:"serverConfig"`
	LogConfig         LogConfig         `mapstructure:"logConfig"`
	GRPCConfig        GRPCConfig        `mapstructure:"grpcConfig"`
	PcapAnalyseConfig PcapAnalyseConfig `mapstructure:"pcapAnalyseConfig"`
}
type PcapAnalyseConfig struct {
	TsharkPath    string `mapstructure:"tsharkPath"`
	TsharkTimeout int    `mapstructure:"tsharkTimeout"` // tshark 单次执行超时时间（秒）
}
type ServerConfig struct {
	JwtSecret       string `mapstructure:"jwt_secret"`
	RunMode         string `mapstructure:"run_mode"`
	OpenBrowser     bool   `mapstructure:"open_browser"`
	LicenseDateline string `mapstructure:"license_dateline"` // 已废弃：认证有效期限制已去除，保留字段仅为兼容旧配置
}

type HttpConfig struct {
	Headers     Headers `mapstructure:"headers"`
	Proxy       string  `mapstructure:"proxy"`
	HttpTimeout int     `mapstructure:"http_timeout"`
	DailTimeout int     `mapstructure:"dail_timeout"`
	UdpTimeout  int     `mapstructure:"udp_timeout"`
	MaxQps      int     `mapstructure:"max_qps"`
	MaxRedirect int     `mapstructure:"max_redirect"`
	Cache       bool    `mapstructure:"cache"`
}

type LogConfig struct {
	MaxSize    int  `mapstructure:"max_size"`
	MaxBackups int  `mapstructure:"max_backups"`
	MaxAge     int  `mapstructure:"max_age"`
	Compress   bool `mapstructure:"compress"`
}

var GlobalConfig *Config

// configFilePath 当前生效的配置文件路径（Setup 时记录）
var configFilePath string

// ConfigFile 返回当前加载的配置文件路径
func ConfigFile() string {
	return configFilePath
}

func (cfg *Config) Level() zapcore.Level {
	if cfg.ServerConfig.RunMode == "debug" {
		return zapcore.DebugLevel
	}
	return zapcore.InfoLevel
}

func (cfg *Config) MaxLogSize() int {
	return cfg.LogConfig.MaxSize
}

func (cfg *Config) LogPath() string {
	return ""
}

func (cfg *Config) ServiceName() string {
	return ServiceName
}

func (cfg *Config) InfoOutput() string {
	return ""
}

func (cfg *Config) ErrorOutput() string {
	return ""
}

func (cfg *Config) DebugOutput() string {
	return ""
}

// 加载配置
func Setup() {
	dir, err := os.Getwd()
	if err != nil {
		log.Fatalf("conf.Setup, fail to get current path: %v", err)
	}
	//配置文件路径 当前文件夹 + config.yaml
	configFile := path.Join(dir, "config.yaml")
	configFilePath = configFile
	fmt.Println(configFile)
	// 检测配置文件是否存在
	if !file.Exists(configFile) {
		WriteYamlConfig(configFile)
	}
	if err := ReadYamlConfig(configFile); err != nil {
		log.Fatalf("%v", err)
	}

}

func ReadYamlConfig(configFile string) error {
	// 加载config
	viper.SetConfigType("yaml")
	viper.SetConfigFile(configFile)

	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("conf.Setup, fail to read 'config.yaml': %v", err)
	}
	cfg := new(Config)
	if err := viper.Unmarshal(cfg); err != nil {
		return fmt.Errorf("conf.Setup, fail to parse 'config.yaml', check format: %v", err)
	}
	GlobalConfig = cfg
	if err := VerifyConfig(); err != nil {
		return fmt.Errorf("conf.Setup, fail to verify 'config.yaml', check format: %v", err)
	}
	return nil
}

func WriteYamlConfig(configFile string) {
	// 生成默认config
	viper.SetConfigType("yaml")
	err := viper.ReadConfig(bytes.NewBuffer(defaultYamlByte))
	if err != nil {
		log.Fatalf("conf.Setup, fail to read default config bytes: %v", err)
	}
	// 写文件
	err = viper.SafeWriteConfigAs(configFile)
	if err != nil {
		log.Fatalf("conf.Setup, fail to write 'config.yaml': %v", err)
	}
}

// EditableKeys 允许通过 API/UI 在线修改的配置项（yaml 点分路径 -> 值类型）
var EditableKeys = map[string]string{
	"pcapAnalyseConfig.tsharkPath":    "string",
	"pcapAnalyseConfig.tsharkTimeout": "int",
	"httpConfig.proxy":                "string",
	"serverConfig.open_browser":       "bool",
}

// canonicalKey 按白名单做大小写不敏感匹配，返回规范 key
func canonicalKey(key string) (string, bool) {
	for k := range EditableKeys {
		if strings.EqualFold(k, key) {
			return k, true
		}
	}
	return "", false
}

func coerceValue(v interface{}, kind string) (interface{}, error) {
	switch kind {
	case "string":
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("值 %v 应为字符串", v)
		}
		return s, nil
	case "int":
		switch n := v.(type) {
		case int:
			return n, nil
		case int64:
			return int(n), nil
		case float64:
			return int(n), nil
		case string:
			var i int
			if _, err := fmt.Sscanf(n, "%d", &i); err != nil {
				return nil, fmt.Errorf("值 %v 应为整数", v)
			}
			return i, nil
		default:
			return nil, fmt.Errorf("值 %v 应为整数", v)
		}
	case "bool":
		switch b := v.(type) {
		case bool:
			return b, nil
		case string:
			return b == "true" || b == "1", nil
		default:
			return nil, fmt.Errorf("值 %v 应为布尔值", v)
		}
	}
	return nil, fmt.Errorf("未知类型 %s", kind)
}

// UpdateConfig 更新白名单内的配置项：先改配置文件（保留注释），再刷新内存配置
func UpdateConfig(updates map[string]interface{}) error {
	if configFilePath == "" || !file.Exists(configFilePath) {
		return errors.New("配置文件不存在，无法在线更新")
	}
	norm := map[string]interface{}{}
	for k, v := range updates {
		ck, ok := canonicalKey(k)
		if !ok {
			return fmt.Errorf("配置项 %s 不支持在线修改", k)
		}
		cv, err := coerceValue(v, EditableKeys[ck])
		if err != nil {
			return fmt.Errorf("配置项 %s: %v", k, err)
		}
		norm[ck] = cv
	}
	if len(norm) == 0 {
		return errors.New("无可更新的配置项")
	}
	if err := updateYAMLFile(configFilePath, norm); err != nil {
		return err
	}
	for k, v := range norm {
		viper.Set(k, v)
	}
	return viper.Unmarshal(GlobalConfig)
}

// updateYAMLFile 以 yaml.Node 方式更新配置文件，保留原有注释与结构
func updateYAMLFile(configFile string, updates map[string]interface{}) error {
	data, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("解析配置文件失败: %v", err)
	}
	if len(doc.Content) == 0 {
		return errors.New("配置文件为空")
	}
	for k, v := range updates {
		if err := setYAMLPath(doc.Content[0], strings.Split(k, "."), v); err != nil {
			return fmt.Errorf("更新配置项 %s 失败: %v", k, err)
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(4)
	if err := enc.Encode(&doc); err != nil {
		return err
	}
	enc.Close()
	return os.WriteFile(configFile, buf.Bytes(), 0644)
}

// setYAMLPath 在 mapping 节点上按键路径设置值，缺失层级自动创建
func setYAMLPath(mapping *yaml.Node, path []string, value interface{}) error {
	if mapping.Kind == yaml.DocumentNode {
		return setYAMLPath(mapping.Content[0], path, value)
	}
	if mapping.Kind != yaml.MappingNode {
		return errors.New("配置层级不是 map 结构")
	}
	for i := 0; i+1 < len(mapping.Content); i += 2 {
		if strings.EqualFold(mapping.Content[i].Value, path[0]) {
			if len(path) == 1 {
				return mapping.Content[i+1].Encode(value)
			}
			return setYAMLPath(mapping.Content[i+1], path[1:], value)
		}
	}
	kn := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: path[0]}
	vn := &yaml.Node{}
	if len(path) == 1 {
		if err := vn.Encode(value); err != nil {
			return err
		}
	} else {
		vn.Kind, vn.Tag = yaml.MappingNode, "!!map"
		if err := setYAMLPath(vn, path[1:], value); err != nil {
			return err
		}
	}
	mapping.Content = append(mapping.Content, kn, vn)
	return nil
}
