package http_parse

import (
	"encoding/json"

	"github.com/Martin2877/blue-team-box/api/msg"
	localhttp_parse "github.com/Martin2877/blue-team-box/engine/local/http_parse"
	"github.com/gin-gonic/gin"
)

type Http_Request_ struct {
	Req_data string `json:"req_data"`
	Res_data string `json:"res_data"`
}

func Get_Tips(c *gin.Context) {
	req_map := make(map[string]string)
	res_map := make(map[string]string)
	req_url_args := make(map[string]map[string]string)
	req_client_args := make(map[string]map[string]string)
	var formdata localhttp_parse.Form_data
	flag := 1 // 判断请求和响应是否为空
	paJson := Http_Request_{}
	err := c.ShouldBindJSON(&paJson)
	if err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	http_parseInstance := localhttp_parse.HTTP_PARSE{}
	// 请求内容为空
	if paJson.Req_data == "" {
		flag++
	} else {
		req_map, req_url_args, req_client_args, formdata = http_parseInstance.Req_parse(paJson.Req_data)
	}

	// 响应内容为空
	if paJson.Res_data == "" {
		flag++
	} else {
		res_map = http_parseInstance.Res_parse(paJson.Res_data)
	}
	//请求和响应均无内容
	if flag == 2 {
		msg.ResultFailed(c, "无检测内容")
		return
	} else {
		var m map[string]interface{}
		js_req, _ := json.Marshal(req_map)
		js_res, _ := json.Marshal(res_map)
		js_req_url, _ := json.Marshal(req_url_args)
		js_req_client, _ := json.Marshal(req_client_args)
		js_formdata, _ := json.Marshal(formdata)
		json.Unmarshal(js_req, &m)
		json.Unmarshal(js_res, &m)
		json.Unmarshal(js_req_url, &m)
		json.Unmarshal(js_req_client, &m)
		json.Unmarshal(js_formdata, &m)
		// res, _ := json.Marshal(m)
		// fmt.Println(string(res))
		jres := msg.JsonResponse{
			Code:    20000,
			Message: "已成功解析",
			Result:  m,
			Type:    "success",
		}
		msg.ResultSuccess(c, &jres)
	}

}

// 合并同样类型的map
// func combi(req map[string]string, res map[string]string) map[string]string {
// 	result_map := make(map[string]string)
// 	for k1, v1 := range req {
// 		result_map[k1] = v1
// 	}
// 	for k2, v2 := range res {
// 		result_map[k2] = v2
// 	}
// 	return result_map
// }
