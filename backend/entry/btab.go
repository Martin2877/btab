package entry

import (
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/Martin2877/blue-team-box/api/routers"
	"github.com/Martin2877/blue-team-box/pkg/conf"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/Martin2877/blue-team-box/pkg/logging"
	"github.com/Martin2877/blue-team-box/pkg/util"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"
)

func init() {
	fmt.Printf("%s\n", conf.Banner)
	fmt.Printf("\t\tv" + conf.Version + "\n\n")
	fmt.Printf("\t\t" + conf.Website + "\n\n")
}

func InitAll() {
	// config 必须最先加载
	conf.Setup()
	logging.Setup()
	db.Setup()
	routers.Setup()
	util.Setup()
}

// HotConf 使用viper 对配置热加载
func HotConf() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatalf("cmd.HotConf, fail to get current path: %v", err)
	}
	// 配置文件路径 当前文件夹 + config.yaml
	configFile := path.Join(dir, conf.ConfigFileName)
	viper.SetConfigType("yaml")
	viper.SetConfigFile(configFile)
	// watch 监控配置文件变化
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		// 配置文件发生变更之后会调用的回调函数
		log.Println("config file changed:", e.Name)
		InitAll()
	})
}

func RunApp() {
	app := cli.NewApp()
	app.Name = conf.ServiceName
	app.Usage = conf.Website
	app.Version = conf.Version

	app.Flags = []cli.Flag{
		&cli.StringFlag{
			// 后端端口
			Name:    "port",
			Aliases: []string{"p"},
			Value:   conf.DefaultPort,
			Usage:   "web server `PORT`",
		},
	}
	app.Action = RunServer

	// 监听所有 中断
	util.SetupCloseHandler()

	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("cli.RunApp err: %v", err)
		return
	}
}

func RunServer(c *cli.Context) error {
	InitAll()
	HotConf()
	// 运行 web
	port := c.String("port")
	routers.InitRouter(port)
	return nil
}
