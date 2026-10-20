package xss

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/corazawaf/libinjection-go"
)

type Result struct {
	Found   bool     `json:"found"`
	Result  string   `json:"result"`
	Catch   []string `json:"catch"`
	NoCatch []string `json:"no_catch"`
}

type XSS struct {
}

func (xss *XSS) SubmitLines(contents []string) (*msg.JsonResponse, error) {
	res := Result{}
	for _, content := range contents {
		result := libinjection.IsXSS(content)
		if result {
			res.Catch = append(res.Catch, content)
		} else {
			res.NoCatch = append(res.NoCatch, content)
		}
	}
	if len(res.Catch) > 0 {
		res.Found = true
		res.Result = fmt.Sprintf("存在XSS，总数 %d 条, 检出 %d 条，未检出 %d 条", len(res.Catch)+len(res.NoCatch), len(res.Catch), len(res.NoCatch))
		jres := msg.JsonResponse{
			Code:    20000,
			Message: "",
			Result:  res,
			Type:    "success",
		}
		return &jres, nil
	} else {
		res.Found = false
		res.Result = "未发现XSS"
		jres := msg.JsonResponse{
			Code:    40400,
			Message: "",
			Result:  res,
			Type:    "success",
		}
		return &jres, nil
	}
}

// candidates 收集待检测的字符串：原始内容、URL参数值、POST表单值、URL解码值
func candidates(content string) []string {
	set := map[string]struct{}{content: {}}

	if u, err := url.Parse(content); err == nil && u != nil {
		for _, values := range u.Query() {
			for _, v := range values {
				set[v] = struct{}{}
			}
		}
	}
	// POST 表单形式 k=v&k=v
	if strings.Contains(content, "=") && !strings.Contains(content, "\n") {
		if m, err := url.ParseQuery(content); err == nil {
			for _, values := range m {
				for _, v := range values {
					set[v] = struct{}{}
				}
			}
		}
	}
	// URL 编码过的内容解码后再检测
	if decoded, err := url.QueryUnescape(content); err == nil && decoded != content {
		set[decoded] = struct{}{}
	}

	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	return out
}

func (xss *XSS) SubmitOnce(content string) (*msg.JsonResponse, error) {
	var hits []string
	for _, c := range candidates(content) {
		if libinjection.IsXSS(c) {
			hits = append(hits, c)
		}
	}

	if len(hits) > 0 {
		jres := msg.JsonResponse{
			Code:    20000,
			Message: "发现XSS",
			Result:  fmt.Sprintf("检测到 XSS，命中内容：【%s】", strings.Join(hits, " , ")),
			Type:    "success",
		}
		return &jres, nil
	}
	jres := msg.JsonResponse{
		Code:    40400,
		Message: "未检测到XSS",
		Result:  "未发现 XSS",
		Type:    "success",
	}
	return &jres, nil
}
