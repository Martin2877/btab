package conf

import (
	"bytes"
	"fmt"
	"github.com/Martin2877/blue-team-box/pkg/file"
	"github.com/spf13/viper"
	"go.uber.org/zap/zapcore"
	"log"
	"os"
	"path"
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

type EngineConfig struct {
	WebshellHost    string `mapstructure:"webshell_host"`
	PcapAnalyseHost string `mapstructure:"pcapanalyse_host"`
	Bash_Host       string `mapstructure:"bash_host"`
}

type PRSConfig struct {
	Host  string `mapstructure:"host"`
	Token string `mapstructure:"token"`
}

type GRPCConfig struct {
	Address string `mapstructure:"address"`
}

type Config struct {
	HttpConfig        HttpConfig        `mapstructure:"httpConfig"`
	DbConfig          DbConfig          `mapstructure:"dbConfig"`
	EngineConfig      EngineConfig      `mapstructure:"engineConfig"`
	ServerConfig      ServerConfig      `mapstructure:"serverConfig"`
	LogConfig         LogConfig         `mapstructure:"logConfig"`
	PRSConfig         []PRSConfig       `mapstructure:"prsConfig"`
	GRPCConfig        GRPCConfig        `mapstructure:"grpcConfig"`
	PcapAnalyseConfig PcapAnalyseConfig `mapstructure:"pcapAnalyseConfig"`
}
type PcapAnalyseConfig struct {
	TsharkPath string `mapstructure:"tsharkPath"`
}
type ServerConfig struct {
	JwtSecret   string `mapstructure:"jwt_secret"`
	RunMode     string `mapstructure:"run_mode"`
	OpenBrowser bool   `mapstructure:"open_browser"`
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

func (cfg *Config) Level() zapcore.Level {
	return zapcore.DebugLevel
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
	//cwd := "/Users/amadeus/Desktop/tophant/blue-team-box/backend/config.yaml"
	//dir, err := filepath.Abs(filepath.Dir(cwd))
	//if err != nil {
	//	log.Fatalf("conf.Setup, fail to get current path: %v", err)
	//}
	dir, err := os.Getwd()
	if err != nil {
		log.Fatalf("conf.Setup, fail to get current path: %v", err)
	}
	//配置文件路径 当前文件夹 + config.yaml
	configFile := path.Join(dir, "config.yaml")
	fmt.Println(configFile)
	// 检测配置文件是否存在
	if !file.Exists(configFile) {
		WriteYamlConfig(configFile)
	}
	ReadYamlConfig(configFile)

}

func ReadYamlConfig(configFile string) {
	// 加载config
	viper.SetConfigType("yaml")
	viper.SetConfigFile(configFile)

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("conf.Setup, fail to read 'config.yaml': %v", err)
	}
	err = viper.Unmarshal(&GlobalConfig)
	if err != nil {
		log.Fatalf("conf.Setup, fail to parse 'config.yaml', check format: %v", err)
	}
	err = VerifyConfig()
	if err != nil {
		log.Fatalf("conf.Setup, fail to verify 'config.yaml', check format: %v", err)
	}
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
