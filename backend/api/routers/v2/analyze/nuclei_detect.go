package analyze

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/engine/nuclei"
	"github.com/Martin2877/blue-team-box/engine/vuln"
	"github.com/Martin2877/blue-team-box/pkg/file"
	"github.com/gin-gonic/gin"
)

type NucleiDetectRequest struct {
	// File 服务端本地 pcap 路径（与 exchanges 二选一；multipart 上传时用 file 表单字段）
	File string `json:"file"`
	// Exchanges 调用方（如 Wireshark Lua tap）已提取的 HTTP 交互
	Exchanges []*nuclei.Exchange `json:"exchanges"`
	// Templates 内联模板：文件名 -> yaml 内容
	Templates map[string]string `json:"templates"`
	// TemplatesDir 服务端本地模板目录
	TemplatesDir string `json:"templates_dir"`
	// UseStore 是否同时加载数据库中启用的模板，默认 true（提供了内联模板或目录时默认 false）
	UseStore    *bool    `json:"use_store"`
	MinSeverity string   `json:"min_severity"`
	Tags        []string `json:"tags"`
}

// GET /api/analyze/nuclei/templates 列出数据库中启用的 nuclei 模板
func NucleiTemplates(c *gin.Context) {
	eng, errs := loadNucleiEngine(&NucleiDetectRequest{})
	list := make([]gin.H, 0, len(eng.Templates))
	for _, t := range eng.Templates {
		list = append(list, gin.H{"id": t.ID, "name": t.Info.Name, "severity": t.Info.Severity, "tags": t.Info.Tags, "file": t.File})
	}
	msg.ResultSuccess(c, gin.H{"total": len(list), "templates": list, "errors": errStrings(errs)})
}

func errStrings(errs []error) []string {
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, e.Error())
	}
	return out
}

func loadNucleiEngine(req *NucleiDetectRequest) (*nuclei.Engine, []error) {
	var eng *nuclei.Engine
	var errs []error
	custom := len(req.Templates) > 0 || req.TemplatesDir != ""
	if req.UseStore == nil || *req.UseStore || !custom {
		eng, errs = vuln.LoadWith(req.MinSeverity, req.Tags)
		// 追加内联/目录模板时复制一份，避免污染缓存的引擎
		cp := *eng
		cp.Templates = append([]*nuclei.Template(nil), eng.Templates...)
		eng = &cp
		errs = append([]error(nil), errs...)
	} else {
		eng = vuln.NewEngine()
		eng.Opts = nuclei.Options{MinSeverity: req.MinSeverity, Tags: req.Tags}
	}
	for name, content := range req.Templates {
		if err := eng.AddTemplate(name, []byte(content)); err != nil {
			errs = append(errs, err)
		}
	}
	if req.TemplatesDir != "" {
		_, es := eng.LoadDir(req.TemplatesDir)
		errs = append(errs, es...)
	}
	return eng, errs
}

// parseDetectRequest 解析 pcap 文件（上传/本地路径）或结构化 exchanges 输入；失败时已写出响应
func parseDetectRequest(c *gin.Context) (*NucleiDetectRequest, func(), bool) {
	req := &NucleiDetectRequest{}
	cleanup := func() {}
	if strings.HasPrefix(c.ContentType(), "multipart/form-data") {
		header, err := c.FormFile("file")
		if err != nil {
			msg.ResultFailed(c, "缺少上传文件: "+err.Error())
			return nil, cleanup, false
		}
		name := file.SafeFileName(header.Filename)
		if name == "" {
			msg.ResultFailed(c, "非法文件名")
			return nil, cleanup, false
		}
		tmp := filepath.Join(os.TempDir(), fmt.Sprintf("btab_%d_%s", time.Now().UnixNano(), name))
		if err := c.SaveUploadedFile(header, tmp); err != nil {
			msg.ResultFailed(c, err.Error())
			return nil, cleanup, false
		}
		cleanup = func() { os.Remove(tmp) }
		req.File = tmp
		req.MinSeverity = c.PostForm("min_severity")
		for _, s := range strings.Split(c.PostForm("tags"), ",") {
			if s = strings.TrimSpace(s); s != "" {
				req.Tags = append(req.Tags, s)
			}
		}
	} else {
		if err := c.ShouldBindJSON(&req); err != nil {
			msg.ResultFailed(c, "参数不合法:"+err.Error())
			return nil, cleanup, false
		}
		if req.File != "" {
			abs, err := filepath.Abs(req.File)
			if err != nil || !file.Exists(abs) {
				msg.ResultFailed(c, "文件不存在: "+req.File)
				return nil, cleanup, false
			}
			req.File = abs
		}
	}
	for _, ex := range req.Exchanges {
		ex.Normalize()
	}
	if req.File == "" && len(req.Exchanges) == 0 {
		msg.ResultFailed(c, "需要 pcap 文件或 exchanges")
		return nil, cleanup, false
	}
	return req, cleanup, true
}

// POST /api/analyze/nuclei
// 基于 nuclei 模板检测流量中的攻击/漏洞，无需 nuclei 引擎主动发包。输入三选一：
//  1. multipart/form-data: -F "file=@x.pcap" [-F "min_severity=high"] [-F "tags=rce,log4j"]
//  2. JSON {"file": "/path/x.pcap"}
//  3. JSON {"exchanges": [...]}（结构化 HTTP 交互，不要求与服务端同机）
func NucleiDetect(c *gin.Context) {
	req, cleanup, ok := parseDetectRequest(c)
	defer cleanup()
	if !ok {
		return
	}
	eng, loadErrs := loadNucleiEngine(req)
	if len(eng.Templates) == 0 {
		msg.ResultFailed(c, "没有可用的 nuclei 模板，请先在“检测引擎-漏洞检测引擎”中上传并启用，或通过 templates/templates_dir 提供")
		return
	}
	exchanges := req.Exchanges
	if req.File != "" {
		var err error
		if exchanges, err = nuclei.LoadExchanges(req.File); err != nil {
			msg.ResultFailed(c, err.Error())
			return
		}
	}
	findings := eng.Detect(exchanges)
	sev := map[string]int{}
	for _, f := range findings {
		sev[f.Severity]++
	}
	msg.ResultSuccess(c, gin.H{
		"summary": gin.H{
			"templates": len(eng.Templates), "exchanges": len(exchanges),
			"findings": len(findings), "severity": sev, "template_errors": len(loadErrs),
		},
		"findings": findings,
		"errors":   errStrings(loadErrs),
	})
}
