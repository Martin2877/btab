package analyze

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/engine/nuclei"
	"github.com/Martin2877/blue-team-box/engine/session"
	"github.com/gin-gonic/gin"
)

// Annotation 面向可视化的逐帧标注，供 Wireshark 后置解析器写入数据包详情
type Annotation struct {
	Frame    int    `json:"frame"`
	Severity string `json:"severity"`
	Kind     string `json:"kind"` // nuclei / webshell-behinder / webshell-form
	Rule     string `json:"rule"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
}

var severityOrder = map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

// POST /api/analyze/session
// 综合检测：nuclei 规则单交互检测 + 跨帧/跨会话关联检测（webshell 口令/密钥还原与流量解密）。
// 输入同 /api/analyze/nuclei（pcap 文件或结构化 exchanges）。若无可用 nuclei 模板，仅执行跨会话检测。
func SessionDetect(c *gin.Context) {
	req, cleanup, ok := parseDetectRequest(c)
	defer cleanup()
	if !ok {
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

	var nucleiFindings []nuclei.Finding
	eng, loadErrs := loadNucleiEngine(req)
	if len(eng.Templates) > 0 {
		nucleiFindings = eng.Detect(exchanges)
	}
	sessions := session.Analyze(exchanges)

	var anns []Annotation
	for _, f := range nucleiFindings {
		anns = append(anns, Annotation{Frame: f.ReqFrame, Severity: f.Severity, Kind: "nuclei", Rule: f.TemplateID, Title: f.Name,
			Detail: fmt.Sprintf("%s %s", f.Method, f.URI)})
		if f.RespFrame > 0 {
			detail := "响应命中"
			if len(f.RespEvidence) > 0 {
				detail = "响应命中 " + strings.Join(f.RespEvidence, "；")
			}
			anns = append(anns, Annotation{Frame: f.RespFrame, Severity: f.Severity, Kind: "nuclei", Rule: f.TemplateID, Title: f.Name, Detail: clipStr(detail, 600)})
		}
	}
	for _, s := range sessions {
		dec := map[int]Decoded{}
		for _, d := range s.Decoded {
			dec[d.Frame] = d
		}
		for _, fr := range s.Frames {
			detail := s.Detail
			if d, ok := dec[fr]; ok {
				detail = fmt.Sprintf("[%s %s] %s", d.Direction, d.Chain, d.Plain)
			} else if fr == s.KeyFrame {
				detail = fmt.Sprintf("密钥协商：响应中泄露密钥 %s", s.Key)
			}
			anns = append(anns, Annotation{Frame: fr, Severity: s.Severity, Kind: s.Type, Rule: s.Type, Title: s.Title, Detail: clipStr(detail, 600)})
		}
	}
	sort.SliceStable(anns, func(i, j int) bool { return anns[i].Frame < anns[j].Frame })

	worst := ""
	for _, a := range anns {
		if worst == "" || severityOrder[a.Severity] > severityOrder[worst] {
			worst = a.Severity
		}
	}
	msg.ResultSuccess(c, gin.H{
		"summary": gin.H{
			"exchanges": len(exchanges), "templates": len(eng.Templates),
			"nuclei_findings": len(nucleiFindings), "session_findings": len(sessions),
			"annotated_frames": len(anns), "max_severity": worst,
		},
		"nuclei":      nucleiFindings,
		"sessions":    sessions,
		"annotations": anns,
		"errors":      errStrings(loadErrs),
	})
}

// Decoded 为 session.Decoded 的别名，避免在注解构造处重复字段
type Decoded = session.Decoded

func clipStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}
