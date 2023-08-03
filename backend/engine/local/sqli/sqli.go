package sqli

import (
	"fmt"
	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/pkg/util"
	"github.com/corazawaf/libinjection-go"
	"net/url"
	"strings"
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
		result, _ := libinjection.IsSQLi(content)
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

func (sqli *Sqli) SubmitOnce(content string) (*msg.JsonResponse, error) {

	// 1、 对于带有路径的的情况进行处理
	// 需要处理一下，如果有 url 的情况，需要提取出 key=value 中的值
	// 如 /nagiosql/admin/commandline.php?cname=%27+union+select+concat%28md5%282001427499%29%29%23

	if strings.Contains(content, "?") && strings.Contains(content, "=") {
		u, err := url.Parse(content)
		if err != nil {
			fmt.Println(err.Error())
		}
		m, _ := url.ParseQuery(u.RawQuery)
		var founds []bool
		var results []string
		for _, ct := range m {
			found, fingerprint := libinjection.IsSQLi(ct[0])
			founds = append(founds, found)
			results = append(results, fmt.Sprintf("内容【%s】命中词法【%s】", ct[0], fingerprint))
		}
		if util.SliceBoolContains(founds, true) {
			// 返回结果
			jres := msg.JsonResponse{
				Code:    20000,
				Message: "发现sql注入",
				Result:  fmt.Sprint("检测情况：", strings.Join(results, " , ")),
				Type:    "success",
			}
			return &jres, nil
		} else {
			jres := msg.JsonResponse{
				Code:    40400,
				Message: "未检测到sql注入",
				Result:  fmt.Sprint("未发现SQL注入"),
				Type:    "success",
			}
			return &jres, nil
		}
	}
	//
	//if strings.Contains(content, "=") {
	//	m, _ := url.ParseQuery(content)
	//	var founds []bool
	//	var results []string
	//	for _, ct := range m {
	//		found, fingerprint := libinjection.IsSQLi(ct[0])
	//		founds = append(founds, found)
	//		if found {
	//			results = append(results, fmt.Sprintf("内容【%s】命中词法【%s】", ct[0], fingerprint))
	//		}
	//	}
	//	if util.SliceBoolContains(founds, true) {
	//		// 返回结果
	//		jres := msg.JsonResponse{
	//			Code:    20000,
	//			Message: "发现sql注入",
	//			Result:  fmt.Sprint("检测情况：", strings.Join(results, " , ")),
	//			Type:    "success",
	//		}
	//		return &jres, nil
	//	} else {
	//		jres := msg.JsonResponse{
	//			Code:    40400,
	//			Message: "未检测到sql注入",
	//			Result:  fmt.Sprint("未发现SQL注入"),
	//			Type:    "success",
	//		}
	//		return &jres, nil
	//	}
	//}

	// 2、 对于只有 value 的情况进行处理

	found, fingerprint := libinjection.IsSQLi(content)
	fmt.Println(found, fingerprint)
	if found {
		// 返回结果
		jres := msg.JsonResponse{
			Code:    20000,
			Message: "发现sql注入",
			Result:  fmt.Sprintf("检测到SQL注入,内容为【%s】, 词法为：【%s】", content, fingerprint),
			Type:    "success",
		}
		return &jres, nil
	} else {
		jres := msg.JsonResponse{
			Code:    40400,
			Message: "未检测到sql注入",
			Result:  fmt.Sprintln("未发现SQL注入", found, fingerprint),
			Type:    "success",
		}
		return &jres, nil
	}

}
