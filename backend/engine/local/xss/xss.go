package xss

import (
	"fmt"
	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/corazawaf/libinjection-go"
)


type Result struct {
	Found bool `json:"found"`
	Result string `json:"result"`
	Catch []string `json:"catch"`
	NoCatch []string `json:"no_catch"`
}

type XSS struct {
}

func (xss *XSS)SubmitLines(contents []string)(*msg.JsonResponse,error){
	res := Result{}
	for _,content := range contents{
		result := libinjection.IsXSS(content)
		if result{
			res.Catch = append(res.Catch, content)
		}else{
			res.NoCatch = append(res.NoCatch, content)
		}
	}
	if len(res.Catch) > 0{
		res.Found = true
		res.Result = fmt.Sprintf("存在XSS，总数 %d 条, 检出 %d 条，未检出 %d 条", len(res.Catch)+len(res.NoCatch), len(res.Catch), len(res.NoCatch))
		jres := msg.JsonResponse{
			Code:    20000,
			Message: "",
			Result:  res,
			Type:    "success",
		}
		return &jres,nil
	}else{
		res.Found = false
		res.Result = "未发现XSS"
		jres := msg.JsonResponse{
			Code:    40400,
			Message: "",
			Result:  res,
			Type:    "success",
		}
		return &jres,nil
	}
}


func (xss *XSS) SubmitOnce(content string) (*msg.JsonResponse,error){
	result := libinjection.IsXSS(content)

	if result{
		// 返回结果
		jres := msg.JsonResponse{
			Code:    20000,
			Message: "发现XSS",
			Result:  fmt.Sprintln("检测到 XSS"),
			Type:    "success",
		}
		return &jres,nil
	}else{
		jres := msg.JsonResponse{
			Code:    40400,
			Message: "未检测到XSS",
			Result:  fmt.Sprintln("未发现 XSS"),
			Type:    "success",
		}
		return &jres,nil
	}
}