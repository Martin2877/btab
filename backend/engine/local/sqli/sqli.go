package sqli

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

type Sqli struct {
}

func (sqli *Sqli) SubmitLines(contents []string) (*msg.JsonResponse, error) {
	res := Result{}
	for _, content := range contents {
		result, _ := Check(content)
		if result {
			res.Catch = append(res.Catch, content)
		} else {
			res.NoCatch = append(res.NoCatch, content)
		}
	}
	if len(res.Catch) > 0 {
		res.Found = true
		res.Result = fmt.Sprintf("存在SQL注入，总数 %d 条, 检出 %d 条，未检出 %d 条", len(res.Catch)+len(res.NoCatch), len(res.Catch), len(res.NoCatch))
		jres := msg.JsonResponse{
			Code:    20000,
			Message: "",
			Result:  res,
			Type:    "success",
		}
		return &jres, nil
	} else {
		res.Found = false
		res.Result = "未发现SQL注入"
		jres := msg.JsonResponse{
			Code:    40400,
			Message: "",
			Result:  res,
			Type:    "success",
		}
		return &jres, nil
	}
}

// checkParams 对 key=value 参数集合中的每个 value 做 libinjection 检测
func checkParams(m url.Values) (bool, []string) {
	foundAny := false
	var results []string
	for name, values := range m {
		for _, v := range values {
			found, fingerprint := libinjection.IsSQLi(v)
			if found {
				foundAny = true
				results = append(results, fmt.Sprintf("参数【%s】内容【%s】命中词法【%s】", name, v, fingerprint))
			}
		}
	}
	return foundAny, results
}

func (sqli *Sqli) SubmitOnce(content string) (*msg.JsonResponse, error) {

	// 1、 对于带有 url 路径的情况进行处理
	// 需要处理一下，如果有 url 的情况，需要提取出 key=value 中的值
	// 如 /nagiosql/admin/commandline.php?cname=%27+union+select+concat%28md5%282001427499%29%29%23

	if strings.Contains(content, "?") && strings.Contains(content, "=") {
		if u, err := url.Parse(content); err == nil && u != nil {
			if m, err2 := url.ParseQuery(u.RawQuery); err2 == nil && len(m) > 0 {
				if foundAny, results := checkParams(m); foundAny {
					return &msg.JsonResponse{
						Code:    20000,
						Message: "发现sql注入",
						Result:  fmt.Sprint("检测情况：", strings.Join(results, " , ")),
						Type:    "success",
					}, nil
				}
				return &msg.JsonResponse{
					Code:    40400,
					Message: "未检测到sql注入",
					Result:  "未发现SQL注入",
					Type:    "success",
				}, nil
			}
		}
	}

	// 2、 对于 POST 表单 k=v&k=v 形式的内容进行处理
	if strings.Contains(content, "=") && !strings.Contains(content, "\n") {
		if m, err := url.ParseQuery(content); err == nil && len(m) > 0 {
			if foundAny, results := checkParams(m); foundAny {
				return &msg.JsonResponse{
					Code:    20000,
					Message: "发现sql注入",
					Result:  fmt.Sprint("检测情况：", strings.Join(results, " , ")),
					Type:    "success",
				}, nil
			}
		}
	}

	// 3、 对于只有 value 的情况进行处理（libinjection 词法 + 危险 SQL 结构签名）

	found, detail := Check(content)
	if found {
		// 返回结果
		jres := msg.JsonResponse{
			Code:    20000,
			Message: "发现sql注入",
			Result:  fmt.Sprintf("检测到SQL注入,内容为【%s】, %s", content, detail),
			Type:    "success",
		}
		return &jres, nil
	} else {
		jres := msg.JsonResponse{
			Code:    40400,
			Message: "未检测到sql注入",
			Result:  "未发现SQL注入",
			Type:    "success",
		}
		return &jres, nil
	}

}
