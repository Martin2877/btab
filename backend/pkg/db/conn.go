package db

import (
	"fmt"
	"github.com/Martin2877/blue-team-box/pkg/conf"
	"github.com/Martin2877/blue-team-box/pkg/file"
	"gorm.io/driver/mysql"
	//"gorm.io/driver/sqlite"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"log"
	"os"
	"path"
	"path/filepath"
)

const (
	DefaultDb = "btab.db"
)

var GlobalDB *gorm.DB

func Setup() {
	var err error
	dbConfig := conf.GlobalConfig.DbConfig
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

		GlobalDB, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
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
		})
		if err != nil {
			log.Fatalf("db.Setup err: %v", err)
		}
	}

	if GlobalDB == nil {
		log.Fatalf("db.Setup err: db connect failed")
	}

	err = GlobalDB.AutoMigrate(&Auth{}, &PcapAnalyse{}, &Pcap{}, &Payload{}, &Webshell{}, &SecType{}, &Strategy{}, &RiskWebshell{}, &RiskSqli{}, &RiskXSS{}, &RiskBASH{})

	if err != nil {
		log.Fatalf("db.Setup err: %v", err)
	}

	if conf.GlobalConfig.ServerConfig.RunMode == "release" {
		// release下
		GlobalDB.Logger = logger.Default.LogMode(logger.Silent)
	}
}
