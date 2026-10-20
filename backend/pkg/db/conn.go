package db

import (
	"fmt"
	"time"

	"github.com/Martin2877/blue-team-box/pkg/conf"
	"github.com/Martin2877/blue-team-box/pkg/file"
	"gorm.io/driver/mysql"

	//"gorm.io/driver/sqlite"
	"log"
	"os"
	"path"
	"path/filepath"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

const (
	DefaultDb = "btab.db"
)

var GlobalDB *gorm.DB

func Setup() {
	var err error
	dbConfig := conf.GlobalConfig.DbConfig
	// release 模式下全局静默 gorm 日志（含 AutoMigrate 期间的 SLOW SQL 噪音）
	// IgnoreRecordNotFoundError: 代码中以 First 命中零值表示"不存在"，属正常流程，不逐条打印 record not found
	gormLogger := logger.New(log.New(os.Stdout, "\r\n", log.LstdFlags), logger.Config{
		SlowThreshold:             200 * time.Millisecond,
		LogLevel:                  logger.Warn,
		IgnoreRecordNotFoundError: true,
		Colorful:                  true,
	})
	if conf.GlobalConfig.ServerConfig.RunMode == "release" {
		gormLogger = gormLogger.LogMode(logger.Silent)
	}
	if conf.GlobalConfig.DbConfig.Sqlite == "" {
		log.Println("使用 mysql")
		// 配置mysql数据源
		if dbConfig.Mysql.User == "" ||
			dbConfig.Mysql.Password == "" ||
			dbConfig.Mysql.Host == "" ||
			dbConfig.Mysql.Port == "" ||
			dbConfig.Mysql.Database == "" {
			log.Fatalf("db.Setup err: config.yaml mysql config not set")
		}
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local&timeout=%s",
			dbConfig.Mysql.User,
			dbConfig.Mysql.Password,
			dbConfig.Mysql.Host,
			dbConfig.Mysql.Port,
			dbConfig.Mysql.Database,
			dbConfig.Mysql.Timeout)

		GlobalDB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{Logger: gormLogger})
		if err != nil {
			log.Fatalf("db.Setup err: %v", err)
		}
	} else {
		// 配置sqlite数据源
		if dbConfig.Sqlite == "" {
			log.Fatalf("db.Setup err: config.yaml sqlite config not set")
		}
		if dbConfig.EnableDefault {
			fmt.Println(os.Args[0])
			dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
			if err != nil {
				log.Fatalf("db.Setup, fail to get current path: %v", err)
			}
			//配置文件路径 当前文件夹 + config.yaml
			defaultSqliteFile := path.Join(dir, DefaultDb)
			// 检测 sqlite 文件是否存在
			if !file.Exists(defaultSqliteFile) {
				log.Fatalf("db.Setup err: btab.db not exist")
			}
		}

		GlobalDB, err = gorm.Open(sqlite.Open(dbConfig.Sqlite), &gorm.Config{
			DisableForeignKeyConstraintWhenMigrating: true,
			Logger:                                   gormLogger,
		})
		if err != nil {
			log.Fatalf("db.Setup err: %v", err)
		}
	}

	if GlobalDB == nil {
		log.Fatalf("db.Setup err: db connect failed")
	}

	err = GlobalDB.AutoMigrate(&Auth{}, &PcapAnalyse{}, &Pcap{}, &Payload{}, &Webshell{}, &Weblog{}, &UrlRule{}, &NucleiTemplate{}, &NucleiResource{}, &NucleiSetting{}, &SecType{}, &Strategy{}, &RiskWebshell{}, &RiskSqli{}, &RiskXSS{}, &RiskBASH{}, &AnalyzeTask{})

	if err != nil {
		log.Fatalf("db.Setup err: %v", err)
	}

	// 进程重启后残留的"分析中"任务已不可能继续，标记为中断
	InterruptStaleAnalyzeTasks()

	// 将 stores/ 目录中的存量文件与种子文件迁移入库，之后删除本地文件
	MigrateStoresFromDisk()

	// 导入编译进二进制的内置示例样本（一次性，用户删除后不回补）
	SeedBuiltinSamples()

	// 导入内置 URL 检测规则集（一次性，用户删除后不回补）
	SeedBuiltinUrlRules()
}
