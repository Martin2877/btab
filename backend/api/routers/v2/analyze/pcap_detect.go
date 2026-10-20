package analyze

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/engine/pcapjs"
	"github.com/Martin2877/blue-team-box/pkg/file"
	"github.com/gin-gonic/gin"
)

// GET /api/analyze/strategies
// 列出内置的流量包检测策略（JS）
func Strategies(c *gin.Context) {
	msg.ResultSuccess(c, gin.H{"strategies": pcapjs.Default().List()})
}

// POST /api/analyze/pcap_detect
// 使用内置 JS 策略引擎对 pcap 做攻击检测，无需 python / suricata：
//  1. multipart/form-data: -F "file=@x.pcap" [-F "strategies=log4j,sqli"]
//  2. application/json: {"file": "/path/to/x.pcap", "strategies": ["log4j"]}
//
// strategies 留空表示执行全部策略，可填策略 ID 或名称。
func PcapDetect(c *gin.Context) {
	var req struct {
		File       string   `json:"file"`
		Strategies []string `json:"strategies"`
	}
	if strings.HasPrefix(c.ContentType(), "multipart/form-data") {
		header, err := c.FormFile("file")
		if err != nil {
			msg.ResultFailed(c, "缺少上传文件: "+err.Error())
			return
		}
		name := file.SafeFileName(header.Filename)
		if name == "" {
			msg.ResultFailed(c, "非法文件名")
			return
		}
		tmp := filepath.Join(os.TempDir(), fmt.Sprintf("btab_%d_%s", time.Now().UnixNano(), name))
		if err := c.SaveUploadedFile(header, tmp); err != nil {
			msg.ResultFailed(c, err.Error())
			return
		}
		defer os.Remove(tmp)
		req.File = tmp
		for _, s := range strings.Split(c.PostForm("strategies"), ",") {
			if s = strings.TrimSpace(s); s != "" {
				req.Strategies = append(req.Strategies, s)
			}
		}
	} else {
		if err := c.ShouldBindJSON(&req); err != nil {
			msg.ResultFailed(c, "参数不合法:"+err.Error())
			return
		}
		abs, err := filepath.Abs(req.File)
		if err != nil || req.File == "" || !file.Exists(abs) {
			msg.ResultFailed(c, "文件不存在: "+req.File)
			return
		}
		req.File = abs
	}

	results, err := pcapjs.Default().Run(&pcapjs.TsharkSource{File: req.File}, req.Strategies)
	if err != nil {
		msg.ResultFailed(c, err.Error())
		return
	}
	events := []pcapjs.Event{}
	hit := 0
	for _, r := range results {
		if r.Hit {
			hit++
		}
		events = append(events, r.Events...)
	}
	msg.ResultSuccess(c, gin.H{
		"summary": gin.H{"strategies": len(results), "hit": hit, "events": len(events)},
		"events":  events,
		"results": results,
	})
}
