package db

import (
	"embed"
	"log"

	"github.com/Martin2877/blue-team-box/pkg/file"
	"github.com/Martin2877/blue-team-box/pkg/util"
)

//go:embed samples
var builtinSampleFS embed.FS

// builtinSample 内置样本：编译进二进制，启动时一次性导入样本仓库
type builtinSample struct {
	store string // webshell | payload
	name  string
	desc  string
}

var builtinSamples = []builtinSample{
	{store: "webshell", name: "1.jsp", desc: "内置示例：JSP webshell 检测样本"},
	{store: "payload", name: "SQL-Inj-Payload.txt", desc: "内置示例：SQL 注入攻击载荷字典"},
	{store: "weblog", name: "access_log.txt", desc: "内置示例：Nginx 访问日志（目录爆破→后台登录、SQLi 探测、webshell 访问）"},
}

// SeedBuiltinSamples 将内置示例样本导入样本仓库。
// 每个样本按 sha1 记录一次性导入标记（存于 NucleiSetting 键值表），
// 用户手动删除样本后不会在重启时反复回补。
func SeedBuiltinSamples() {
	for _, s := range builtinSamples {
		raw, err := builtinSampleFS.ReadFile("samples/" + s.name)
		if err != nil || len(raw) == 0 {
			continue
		}
		sha1 := util.Sha1Bytes(raw)
		flagKey := "builtin_sample:" + s.store + ":" + sha1
		if GetNucleiSetting(flagKey) != "" {
			continue
		}
		switch s.store {
		case "webshell":
			if !ExistWebshellByName(s.name) && !ExistWebshellBySha1(sha1) {
				row := Webshell{Name: s.name, Sha1: sha1, Size: len(raw), Description: s.desc}
				row.SetContent(raw)
				if err := GlobalDB.Create(&row).Error; err != nil {
					log.Println("seed builtin sample failed:", s.name, err)
				}
			}
		case "payload":
			if !ExistPayloadByName(s.name) && !ExistPayloadBySha1(sha1) {
				row := Payload{
					Name:        s.name,
					Sha1:        sha1,
					Lines:       len(file.SplitLines(raw)),
					Size:        len(raw),
					Description: s.desc,
				}
				row.SetContent(raw)
				if err := GlobalDB.Create(&row).Error; err != nil {
					log.Println("seed builtin sample failed:", s.name, err)
				}
			}
		case "weblog":
			if !ExistWeblogByName(s.name) && !ExistWeblogBySha1(sha1) {
				row := Weblog{
					Name:        s.name,
					Sha1:        sha1,
					Format:      "combined",
					Lines:       len(file.SplitLines(raw)),
					Size:        len(raw),
					Description: s.desc,
				}
				row.SetContent(raw)
				if err := GlobalDB.Create(&row).Error; err != nil {
					log.Println("seed builtin sample failed:", s.name, err)
				}
			}
		}
		if err := SetNucleiSetting(flagKey, "1"); err != nil {
			log.Println("seed builtin sample flag failed:", flagKey, err)
		}
	}
}
