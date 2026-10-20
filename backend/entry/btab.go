package entry

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/Martin2877/blue-team-box/engine"
	"github.com/Martin2877/blue-team-box/engine/options"
	"github.com/Martin2877/blue-team-box/engine/vuln"
	"github.com/Martin2877/blue-team-box/engine/workflow"
	"github.com/Martin2877/blue-team-box/pkg/file"
	"github.com/Martin2877/blue-team-box/pkg/proto"

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
	// 后台预热漏洞检测引擎缓存：全量模板编译需数秒，
	// 提前构建可避免引擎概览页与首次流量检测长时间阻塞
	vuln.Warmup()
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
		// 配置解析失败时不重启子系统，避免打断运行中的服务
		if err := conf.ReadYamlConfig(e.Name); err != nil {
			log.Println("config reload failed, keep current config:", err)
			return
		}
		// 仅热加载日志级别等轻量配置；db/router 不支持热重载
		logging.Setup()
		util.Setup()
	})
}

func RunApp() {
	var err error
	app := cli.NewApp()
	app.Name = conf.ServiceName
	app.Usage = conf.Website
	app.Version = conf.Version

	app.Commands = []*cli.Command{
		{
			Name:   "server",
			Usage:  "run with server",
			Action: RunServer,
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "port",
					Aliases: []string{"p"},
					Value:   conf.DefaultPort,
					Usage:   "web server `PORT`",
				},
				&cli.BoolFlag{
					Name:  "grpc",
					Value: false,
					Usage: "run with only grpc",
				},
				&cli.StringFlag{
					Name:  "grpc-port",
					Usage: "specify the grpc port",
				},
			},
		},
		{
			Name:   "engine",
			Usage:  "execute the engine of detection or tools",
			Action: RunEngine,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:    "list",
					Aliases: []string{"l"},
					Value:   false,
					Usage:   "list the engine names",
				},
				&cli.StringFlag{
					Name:    "engine",
					Aliases: []string{"e"},
					Usage:   "specify engine name",
				},
				&cli.StringFlag{
					Name:    "file",
					Aliases: []string{"f"},
					Usage:   "specify file for engine",
				},
				&cli.StringFlag{
					Name:    "dir",
					Aliases: []string{"d"},
					Usage:   "specify directory",
				},
				&cli.StringFlag{
					Name:    "content",
					Aliases: []string{"c"},
					Usage:   "specify the content",
				},
			},
		},
		{
			Name:    "workflow",
			Usage:   "run work flow",
			Aliases: []string{"wf"},
			Action:  RunWorkflow,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:    "list",
					Aliases: []string{"l"},
					Value:   false,
					Usage:   "list the template names",
				},
				&cli.StringFlag{
					Name:    "template",
					Aliases: []string{"t"},
					Usage:   "specify template",
				},
				&cli.StringFlag{
					Name:    "template-file",
					Aliases: []string{"tf"},
					Usage:   "specify template file",
				},
				&cli.StringFlag{
					Name:    "file",
					Aliases: []string{"f"},
					Usage:   "specify file for workflow",
				},
				&cli.StringFlag{
					Name:    "content",
					Aliases: []string{"c"},
					Usage:   "specify the content",
				},
				&cli.StringFlag{
					Name:    "dir",
					Aliases: []string{"d"},
					Usage:   "specify directory",
				},
			},
		},
	}
	util.SetupCloseHandler()
	err = app.Run(os.Args)
	if err != nil {
		log.Fatalf("cli.RunApp err: %v\n", err)
		return
	}
}

func RunServer(c *cli.Context) error {
	InitAll()
	HotConf()

	isGrpc := c.Bool("grpc")
	grpcPort := c.String("grpc-port")
	if isGrpc {
		log.Println("run only with grpc")
		proto.RunGRPCServer(grpcPort)
		return nil
	}

	// 运行 grpc
	go proto.RunGRPCServer(grpcPort)

	// 运行 web
	port := c.String("port")
	routers.InitRouter(port)
	return nil
}

func RunEngine(c *cli.Context) (err error) {
	InitAll()
	HotConf()

	var engines = engine.NewEngines()

	isList := c.Bool("list")
	if isList {
		fmt.Println("engines :")
		for i, n := range engines.GetEngines() {
			fmt.Printf("%d - %s\n", i+1, n)
		}
		return nil
	}

	eg := c.String("engine")
	if eg == "" {
		return errors.New("engine not specified, use -e to specify or -l to list")
	}

	// 清除原有的 steps
	engines.ClearSteps()
	//content := c.String("content")
	filePath := c.String("file")
	switch eg {
	case "pcap":
		if !file.Exists(filePath) {
			return fmt.Errorf("file %s not found", filePath)
		}
	case "sqli":
	default:
		return fmt.Errorf("engine not found : %s", eg)
	}

	if eg == "pcap" {
		search := fmt.Sprintf(`
| pcap
|: file %s
|: fields ["ip.src", "tcp.srcport", "ip.dst", "tcp.dstport"]
|: condition
`, filePath)
		err := engines.LoadQueries(search)
		if err != nil {
			return err
		}
		err = engines.Run()
		if err != nil {
			return err
		}
		for i := 1; i <= len(engines.Steps); i++ {
			log.Println(i-1, " ->", engines.GetResult(i-1))
		}
		log.Println("result :", engines.GetFinalResult())
	}
	return nil
}

func RunWorkflow(c *cli.Context) (err error) {
	InitAll()
	HotConf()
	isList := c.Bool("list")
	if isList {
		fmt.Println("workflow list :")
		wf := workflow.Workflow{}
		for i, n := range wf.GetTemplates() {
			fmt.Printf("%d - %s\n", i+1, n)
		}
		return nil
	}
	// load args
	content := c.String("content")
	filePath := c.String("file")
	templateFilePath := c.String("template-file")
	wf := workflow.NewWorkflow(
		options.WithTemplateFilePath(templateFilePath),
		options.WithFilePath(filePath),
		options.WithContent(content),
	)
	// run template
	tp := c.String("template")
	err = wf.RunTemplate(tp)
	if err != nil {
		return err
	}

	return nil
}
