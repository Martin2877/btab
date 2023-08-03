package httpparse

import "strings"

type Res_type struct {
	Content_type  string // 响应头中的类型
	Res_body_type string // 响应体内容的格式
}

type Res_entity struct {
	status         string            //响应状态码
	Uri            string            //请求URI
	Res_header_all map[string]string // 所有请求头信息存入
	Res_body       string            //请求体内容
	Res_type       Res_type          //请求中解析到的相关类型
}

// 响应解析
func (http_parse *HTTP_PARSE) Res_parse(content string) map[string]string {
	final_result := make(map[string]string)
	header_flag := 1 // 初始值大于0，当header_flag值为0时，表明header_flag解析结束
	http_response := new(Res_entity)
	http_response.Res_header_all = map[string]string{}
	res := strings.Split(content, "\n") //先切分

	for i := 0; i < len(res); i++ {
		res_what := res[i]
		// 响应状态码解析
		if Is_Res_status(res_what) {
			http_response.status = strings.Split(res_what, " ")[1]
			continue
		}
		// 响应头解析
		if strings.Contains(res_what, ":") {
			if header_flag > 0 {
				temp_header := strings.Split(res_what, ":")
				k := temp_header[0]
				v := strings.Replace(temp_header[1], " ", "", -1)
				http_response.Res_header_all[k] = v
				continue
			}
		}
		header_flag = 0

		// 响应体解析
		if res_what != "" {
			http_response.Res_body = http_response.Res_body + "" + res_what
		}
	}
	// fmt.Println(http_response)

	// 暂时对200状态码的响应作识别类型输出
	// content_type类型
	if http_response.Res_header_all["Content-Type"] != "" {
		http_response.Res_type.Content_type = judge_content_type_header(http_response.Res_header_all["Content-Type"])

	} else {
		http_response.Res_type.Res_body_type = judge_content_type(http_response.Res_body)
	}
	// 响应内容类型
	final_result["res_content_type"] = http_response.Res_type.Content_type
	final_result["res_client_body_type"] = http_response.Res_type.Res_body_type
	return final_result
}

// 判断HTTP响应第一行是否有HTTP/x.x 200类型的数据
func Is_Res_status(content string) bool {
	status_num := []string{"100", "103", "200", "201", "204", "206", "301", "302", "303", "304", "307", "308", "401", "403", "404", "406", "407", "409", "410", "412", "416", "418", "425", "451", "500", "501", "502", "503", "504"} // 状态码
	s := strings.Split(content, " ")
	if strings.Contains(s[0], "HTTP") {
		if get_keywords(status_num, s[1]) != "" {
			return true
		}
	}
	return false
}
