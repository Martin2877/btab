package workflow

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/Martin2877/blue-team-box/engine"
	"github.com/Martin2877/blue-team-box/engine/nuclei"
	. "github.com/Martin2877/blue-team-box/engine/options"
	"github.com/Martin2877/blue-team-box/engine/plugin"
	"github.com/Martin2877/blue-team-box/pkg/db"
	"github.com/Martin2877/blue-team-box/pkg/file"
	"github.com/fatih/color"
	"github.com/tidwall/gjson"

	"github.com/rodaine/table"
)

type Workflow struct {
	ArgOpts       ArgsOptions
	UnmarshalOpts UnmarshalerOptions
}

func (ins *Workflow) WithArgsOption(opts ...ArgsOption) *Workflow {
	for _, opt := range opts {
		opt(&ins.ArgOpts)
	}
	return ins
}

func (ins *Workflow) WithUnmarshalOption(opts ...UnmarshalerOption) *Workflow {
	for _, opt := range opts {
		opt(&ins.UnmarshalOpts)
	}
	return ins
}

func NewWorkflow(opts ...ArgsOption) *Workflow {
	wf := new(Workflow)
	wf.WithArgsOption(opts...)
	return wf
}

var Templates = []string{"sqli", "pcapcheck"}

func (ins *Workflow) GetTemplates() []string {
	return Templates
}

func (ins *Workflow) RunTemplate(template string) error {
	switch template {
	case "sqli":
		err := ins.DetectSQLi()
		if err != nil {
			return err
		}
	case "pcapcheck", "pc":
		err := ins.DetectionPcapCheck()
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("workflow template not found: %s", template)
	}
	return nil
}

func (ins *Workflow) DetectSQLi() error {
	var engines = engine.NewEngines()

	// 清除原有的 steps
	engines.ClearSteps()

	search := fmt.Sprintf(`
| sqli
|: content %s
`, ins.ArgOpts.Content)
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
	return nil
}

type HttpRequest struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body,omitempty"`
}
type HttpResponse struct {
	Status     int                 `json:"status"`
	StatusCode string              `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body"`
}

type HttpSession struct {
	Stream       string       `json:"stream"`
	HttpRequest  HttpRequest  `json:"request"`
	HttpResponse HttpResponse `json:"response"`
}

type PcapCheckStatus struct {
	FilePath    string
	URL         string
	RuleName    string
	Result      bool
	FinalResult bool
	Error       string
}

func (ins *Workflow) LoadPcapHttp(filePath string) ([]HttpSession, error) {
	var httpSessions []HttpSession
	// 初始化插件
	pgs, err := plugin.NewPlugin("pcap")
	if err != nil {
		return nil, err
	}
	// 解析流量
	Payloads := map[string]string{
		"file":      filePath,
		"fields":    `["ip.src", "tcp.srcport", "ip.dst", "tcp.dstport","http.request.method","http.request.uri","http.file_data","tcp.stream"]`,
		"condition": "http",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	err = pgs.Run(ctx, Payloads)
	if err != nil {
		return nil, err
	}
	resultSource := fmt.Sprintf(`{
			"result": %s 
		}`, pgs.Plugin.GetResult())
	datas := gjson.Get(resultSource, "result")
	if len(datas.Array()) == 0 {
		return nil, errors.New("pcap file no data")
	}
	// 组装 http 数据, http stream 序列组装
	for _, d := range datas.Array() {
		// handle the file_data
		stream := d.Get("tcp\\.stream.0")
		var bodyBuilder strings.Builder
		// http.file_data 可能是多个分片，全部解码后拼接
		for _, fd := range d.Get("http\\.file_data").Array() {
			decodeString, err := hex.DecodeString(fd.String())
			if err != nil {
				// 分片可能不是合法 hex（如文本），直接拼接原文
				bodyBuilder.WriteString(fd.String())
				continue
			}
			bodyBuilder.Write(decodeString)
		}

		httpSession := HttpSession{
			Stream: stream.String(),
			HttpRequest: HttpRequest{
				Method:  d.Get("http\\.request\\.method.0").String(),
				URL:     d.Get("http\\.request\\.uri.0").String(),
				Headers: nil,
				Body:    bodyBuilder.String(),
			},
		}
		httpSessions = append(httpSessions, httpSession)
	}
	return httpSessions, nil
}

func (ins *Workflow) DetectionPcapCheck() error {
	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	tbl := table.New("ID", "PcapName", "Frame", "URL", "Severity", "RuleName", "Result", "Error")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	// 从数据库加载所有启用的 yaml 规则，由 btab 自带的 nuclei 解析器与检测引擎处理
	eng := nuclei.New()
	for _, t := range db.GetEnabledNucleiTemplates() {
		raw, err := t.GetContent()
		if err == nil {
			err = eng.AddTemplate(t.Name, raw)
		}
		if err != nil {
			log.Println("workflow: 模板加载失败:", t.Name, err)
		}
	}
	if len(eng.Templates) == 0 {
		return errors.New("没有可用的 nuclei 模板")
	}
	filePaths := file.GetFiles(ins.ArgOpts.FilePath)
	if len(filePaths) == 0 {
		return fmt.Errorf("no pcap file found in: %s", ins.ArgOpts.FilePath)
	}
	for i, filePath := range filePaths {
		log.Println("start analyse : ", filePath)
		findings, err := eng.DetectPcap(filePath)
		if err != nil {
			tbl.AddRow(i+1, filePath, "", "", "", "", false, err.Error())
			continue
		}
		if len(findings) == 0 {
			tbl.AddRow(i+1, filePath, "", "", "", "", false, "")
			continue
		}
		for _, f := range findings {
			tbl.AddRow(i+1, filePath, f.ReqFrame, strings.TrimSpace(f.URI), f.Severity, f.Name, true, "")
		}
	}
	tbl.Print()
	return nil
}

// 0 ignore, 1 true , 2 false
const (
	Ignore  = 0
	Catch   = 1
	NoCatch = 2
)

// m 为规则中的字段, n 为流量中的字段
func compareList(m []string, n string) int {
	for _, mm := range m {
		ret := compare(mm, n)
		if ret == Catch {
			return Catch
		}
		if ret == NoCatch {
			return NoCatch
		}
	}
	return Ignore
}

var templateVarPattern = regexp.MustCompile(`\{\{[^{}]+}}`)

// m 为规则中的字段, n 为流量中的字段
// 先剔除 {{BaseURL}} 等模板变量，再做包含匹配，避免变量拆分产生过宽的匹配
func compare(m string, n string) int {
	if m == "" {
		return Ignore
	}
	m = strings.TrimSpace(templateVarPattern.ReplaceAllString(m, ""))
	if m == "" {
		return Ignore
	}
	if n == "" {
		return NoCatch
	}
	if !strings.Contains(n, m) {
		return NoCatch
	}
	return Catch
}
