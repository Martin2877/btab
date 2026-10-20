// Command import_nuclei 将本地 nuclei-templates 目录树全量同步进 btab.sqlite：
// 复用 engine/vuln 的入库管线（Classify/CleanPath/SaveTemplate/SaveResource），
// 导入后删除数据库中不存在于本次目录树的旧模板，使内置库与目录树一致。
//
// 用法（在 backend/ 下执行）：
//
//	go run ./tools/import_nuclei -dir ../tmp/nt/nuclei-templates-main [-db btab.sqlite] [-source nuclei-templates-main]
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/Martin2877/blue-team-box/engine/vuln"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

type entry struct {
	path  string // 规范化后的相对路径（如 http/cves/2024/CVE-2024-xxx.yaml）
	raw   []byte
	kind  string // 资源类别；模板为 ""
	isTpl bool
}

func main() {
	dir := flag.String("dir", "", "nuclei-templates 目录（含 http/ 等子目录）")
	dbPath := flag.String("db", "btab.sqlite", "sqlite 数据库路径")
	source := flag.String("source", "nuclei-templates-main", "写入 source 字段的来源标记")
	flag.Parse()
	if *dir == "" {
		log.Fatal("missing -dir")
	}

	gdb, err := gorm.Open(sqlite.Open(*dbPath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	if err := gdb.AutoMigrate(&db.NucleiTemplate{}, &db.NucleiResource{}, &db.NucleiSetting{}); err != nil {
		log.Fatalf("migrate: %v", err)
	}

	// 全量写入包在一个事务里，避免逐行 fsync 拖慢导入
	tx := gdb.Begin()
	if tx.Error != nil {
		log.Fatalf("begin tx: %v", tx.Error)
	}
	db.GlobalDB = tx

	var tpls, ress []entry
	var walked, skipped int
	err = filepath.WalkDir(*dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		walked++
		rel, err := filepath.Rel(*dir, p)
		if err != nil {
			return err
		}
		cp := vuln.CleanPath(strings.ReplaceAll(rel, "\\", "/"))
		if cp == "" {
			skipped++
			return nil
		}
		kind, isTpl := vuln.Classify(cp)
		if kind == "skip" {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil || len(raw) == 0 || len(raw) > vuln.MaxFileSize {
			skipped++
			return nil
		}
		e := entry{path: cp, raw: raw, kind: kind, isTpl: isTpl}
		if isTpl {
			tpls = append(tpls, e)
		} else {
			ress = append(ress, e)
		}
		return nil
	})
	if err != nil {
		log.Fatalf("walk: %v", err)
	}
	log.Printf("scanned %d files: %d templates, %d resources, %d skipped", walked, len(tpls), len(ress), skipped)

	// 先入库字典/资源，保证模板解析时引用可读
	var resAdded int
	for _, e := range ress {
		if vuln.SaveResource(e.path, e.kind, e.raw) {
			resAdded++
		}
	}

	st, rr := vuln.GetSettings(), vuln.ResourceReader()
	var added, updated, unchanged int
	imported := make(map[string]bool, len(tpls))
	for i, e := range tpls {
		imported[e.path] = true
		a, c := vuln.SaveTemplate(e.path, *source, e.raw, st, rr)
		switch {
		case a:
			added++
		case c:
			updated++
		default:
			unchanged++
		}
		if (i+1)%1000 == 0 {
			log.Printf("progress: %d/%d", i+1, len(tpls))
		}
	}

	// 全量同步：删除不在本次目录树中的旧模板
	var rows []struct {
		Id   int
		Path string
	}
	tx.Model(&db.NucleiTemplate{}).Select("id, path").Find(&rows)
	var del []int
	for _, r := range rows {
		if !imported[r.Path] {
			del = append(del, r.Id)
		}
	}
	if len(del) > 0 {
		tx.Unscoped().Where("id in ?", del).Delete(&db.NucleiTemplate{})
	}
	if err := tx.Commit().Error; err != nil {
		log.Fatalf("commit: %v", err)
	}
	db.GlobalDB = gdb
	gdb.Exec("VACUUM")

	var total, enabled, parseErr, missing int64
	m := func() *gorm.DB { return gdb.Model(&db.NucleiTemplate{}) }
	m().Count(&total)
	m().Where("enabled = ?", true).Count(&enabled)
	m().Where("parse_error <> ''").Count(&parseErr)
	m().Where("missing_refs <> ''").Count(&missing)
	var resTotal int64
	gdb.Model(&db.NucleiResource{}).Count(&resTotal)

	fmt.Printf("templates: added=%d updated=%d unchanged=%d deleted=%d\n", added, updated, unchanged, len(del))
	fmt.Printf("resources: added=%d total=%d\n", resAdded, resTotal)
	fmt.Printf("db: total=%d enabled=%d parse_error=%d missing_refs=%d\n", total, enabled, parseErr, missing)
}
