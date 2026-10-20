package db

import (
	"log"
	"os"
	"path/filepath"

	"github.com/Martin2877/blue-team-box/pkg/file"
	"github.com/Martin2877/blue-team-box/pkg/util"
)

// MigrateStoresFromDisk 将本地 stores/{webshell,payload,nuclei} 目录中的文件
// （旧版本遗留文件、发布包内置的种子文件）统一迁移进数据库，
// 入库成功后删除本地文件，保证恶意内容不再落盘。
// pcap 仅存元数据不入库，stores/pcap 目录不做处理。
func MigrateStoresFromDisk() {
	pwd, err := os.Getwd()
	if err != nil {
		return
	}
	migrateStoreDir(filepath.Join(pwd, "stores", "webshell"), importWebshellFile)
	migrateStoreDir(filepath.Join(pwd, "stores", "payload"), importPayloadFile)
	migrateStoreDir(filepath.Join(pwd, "stores", "nuclei"), importNucleiFile)
}

// migrateStoreDir 遍历目录下所有文件，调用 importFn 入库，成功后删除文件
func migrateStoreDir(dir string, importFn func(name string, raw []byte) error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		path := filepath.Join(dir, name)
		raw, err := os.ReadFile(path)
		if err != nil || len(raw) == 0 {
			continue
		}
		if err := importFn(name, raw); err != nil {
			log.Println("stores migrate: import failed:", path, err)
			continue
		}
		if err := os.Remove(path); err != nil {
			log.Println("stores migrate: remove file failed:", path, err)
		}
		log.Println("stores migrate: migrated:", path)
	}
}

// importWebshellFile 文件内容回填已有记录或新建记录
func importWebshellFile(name string, raw []byte) error {
	var row Webshell
	GlobalDB.Model(&Webshell{}).Where("name = ?", name).First(&row)
	if row.Id > 0 && len(row.Content) > 0 {
		return nil
	}
	compressed, err := file.GzipBytes(raw)
	if err != nil {
		return err
	}
	if row.Id > 0 {
		return GlobalDB.Model(&Webshell{}).Where("id = ?", row.Id).Update("content", compressed).Error
	}
	row = Webshell{Name: name, Sha1: util.Sha1Bytes(raw), Size: len(raw)}
	row.SetContent(raw)
	return GlobalDB.Create(&row).Error
}

func importPayloadFile(name string, raw []byte) error {
	var row Payload
	GlobalDB.Model(&Payload{}).Where("name = ?", name).First(&row)
	if row.Id > 0 && len(row.Content) > 0 {
		return nil
	}
	compressed, err := file.GzipBytes(raw)
	if err != nil {
		return err
	}
	if row.Id > 0 {
		return GlobalDB.Model(&Payload{}).Where("id = ?", row.Id).
			Updates(map[string]interface{}{"content": compressed, "lines": len(file.SplitLines(raw))}).Error
	}
	row = Payload{
		Name:  name,
		Sha1:  util.Sha1Bytes(raw),
		Lines: len(file.SplitLines(raw)),
		Size:  len(raw),
	}
	row.SetContent(raw)
	return GlobalDB.Create(&row).Error
}

func importNucleiFile(name string, raw []byte) error {
	var row NucleiTemplate
	GlobalDB.Model(&NucleiTemplate{}).Where("name = ?", name).First(&row)
	if row.Id > 0 && len(row.Content) > 0 {
		return nil
	}
	compressed, err := file.GzipBytes(raw)
	if err != nil {
		return err
	}
	if row.Id > 0 {
		return GlobalDB.Model(&NucleiTemplate{}).Where("id = ?", row.Id).Update("content", compressed).Error
	}
	row = NucleiTemplate{
		Name:    name,
		Path:    name,
		Sha1:    util.Sha1Bytes(raw),
		Size:    len(raw),
		Enabled: true,
	}
	row.SetContent(raw)
	return GlobalDB.Create(&row).Error
}
