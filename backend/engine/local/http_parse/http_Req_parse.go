package httpparse

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Req_type 存储HTTP请求中相关的类型
type Req_type struct {
	Url_type         string // 请求资源类型
	Content_type     string // 请求头content-type
	Client_body_type string // 请求体数据格式
}

// Form_data 存储POST数据，可存储kv和文件上传形式的数据
type Form_data struct {
	Files  map[string]map[string]string // {filename:{filetype:php,ismatch:true}}
	Key_va map[string]string
}

// 存储HTTP请求内容
// uri            string
// host           string
// useragent      string
// content_type   string
// authorization  string
// content_length int32
type Req_entity struct {
	Method         string                       //请求方法
	Uri            string                       //请求URI
	URLArgs        map[string]map[string]string //请求参数
	Req_header_all map[string]string            // 所有请求头信息存入
	Client_body    string                       //请求体内容
	Client_Args    map[string]map[string]string //请求体参数,主要针对application/x-www-form-urlencoded类型存储数据
	Req_type       Req_type                     //请求中解析到的相关类型
	UA_type        string                       // 请求User-Agent类型,目前只判断是否是漏扫工具或者各种语言写的脚本
	Formdata       Form_data                    // POST内容kv或者文件内容,主要针对multipart/form-data类型存储数据
}

// 请求解析
// 格式为如下
// 第一行必须有请求方法
// 后续行需要有以 : 分隔的请求头键值对
func (http_parse *HTTP_PARSE) Req_parse(content string) (map[string]string, map[string]map[string]string, map[string]map[string]string, Form_data) {

	final_result := make(map[string]string)
	http_request := new(Req_entity)
	http_request.Req_header_all = map[string]string{}
	http_request.Formdata.Key_va = map[string]string{}
	http_request.URLArgs = map[string]map[string]string{}
	http_request.Client_Args = map[string]map[string]string{}

	// 判断十六进制还是正常的请求包
	if judge_hex_string(content) {
		fmt.Println("hex内容")
		http_request = hex_req(http_request, content)
	} else {
		fmt.Println("正常请求")
		http_request = normal_req(http_request, content)
	}

	// 开始解析和判断请求类型
	var flag bool
	var result string
	var url_query map[string]map[string]string

	flag, result, url_query = judge_url_what_type_args("http://www.tophant.com" + http_request.Uri)

	// 存入web访问资源类型
	if flag {
		http_request.Req_type.Url_type = result
	}
	// 存入web请求查询参数
	http_request.URLArgs = url_query

	if http_request.Method == "GET" {
		// GET 类型，判断访问资源类型

	} else if http_request.Method == "POST" {
		// POST 类型，判断
		if http_request.Req_header_all["Content-Type"] != "" {
			http_request.Req_type.Content_type = judge_content_type_header(http_request.Req_header_all["Content-Type"])

		} else {
			http_request.Req_type.Client_body_type = judge_content_type(http_request.Client_body)
		}

		// 当POST时，根据请求类型解析请求体中的内容
		if http_request.Req_type.Content_type == "form_kv" || http_request.Req_type.Client_body_type == "form_kv" {
			http_request.Client_Args = Client_body_args(http_request.Client_body)
		}
	}
	scanner := judge_UA(http_request.Req_header_all["User-Agent"])
	if scanner != "" {
		http_request.UA_type = scanner
	} else {
		http_request.UA_type = "未识别到漏扫工具"
	}
	fmt.Println(http_request)
	final_result["req_url_type"] = http_request.Req_type.Url_type
	final_result["req_content_type"] = http_request.Req_type.Content_type
	final_result["req_client_body_type"] = http_request.Req_type.Client_body_type

	return final_result, http_request.URLArgs, http_request.Client_Args, http_request.Formdata //类型、参数、UA
}

// 文件上传类解析,十六进制,需要解析内容的
func hex_req(http_request *Req_entity, content string) *Req_entity {
	header_flag := 1                          // 初始值大于0，当header_flag值为0时，表明header_flag解析结束
	form_data_flag := false                   // formdata标志
	upload_file_flag := false                 // 文件上传标志
	kv_flag := false                          // kv标志
	var file_suffix_magic []map[string]string // 存放后缀magic和偏移量
	form_key := ""
	magic_num := 0
	newcontent := strings.Replace(content, "\n", "", -1)
	temps := strings.Split(newcontent, "0d0a") // 2个0d0a切分,将内容拆分
	http_request.Formdata.Files = map[string]map[string]string{}
	file_type_temp := make(map[string]string)
	for _, temp := range temps {
		data, err := hex.DecodeString(temp)
		if err == nil {
			// 解析HTTP内容
			req_what := string(data)
			temp_h := strings.Split(req_what, " ")
			if Is_Req_Method(temp_h[0]) {
				http_request.Method = temp_h[0]
				http_request.Uri = temp_h[1]
				continue
			}
			// 请求头信息会包含:
			if strings.Contains(req_what, ":") {
				if header_flag > 0 {
					temp_header := strings.SplitN(req_what, ":", 2)
					k := temp_header[0]
					v := strings.Replace(temp_header[1], " ", "", -1)
					http_request.Req_header_all[k] = v
					continue
				}
			}
			header_flag = 0
			// 请求体 内容多样,需要根据请求头信息判断,一般不为空
			if req_what != "" { // 存入原始post数据
				http_request.Client_body = http_request.Client_body + "" + temp
			}
			//分析post请求体中的文件信息
			// 出现WebKitFormBoundary，则表示新的一个输入框出现,相关内容可能需要重置
			if strings.Contains(req_what, "WebKitFormBoundary") {
				fmt.Println("文件上传")
				form_data_flag = true
				upload_file_flag = false
				magic_num = 0
				file_type_temp = make(map[string]string)
				continue
			}
			// form表单中可能有文件，也可能
			if form_data_flag {
				if strings.Contains(req_what, "Content-Disposition") {
					rex_str := "form-data;.*filename=\"(.*)\""
					reg_result := find_regx(rex_str, req_what)
					if reg_result != "" {
						upload_file_flag = true
						kv_flag = false
						upload_filename := strings.ReplaceAll(strings.ReplaceAll(req_what[strings.Index(req_what, "filename=")+9:], "\"", ""), " ", "")
						http_request.Formdata.Files[upload_filename] = file_type_temp
						file_suffix_magic = get_content_magic_offset(upload_filename) //获取该文件的magic和偏移值
						continue
					}
				}
				if strings.Contains(req_what, "Content-Disposition") && !upload_file_flag {
					rex_str := "form-data; name=\"(.*)\""
					reg_result := find_regx(rex_str, req_what)
					if reg_result != "" {
						kv_flag = true
						upload_file_flag = false
						form_key = strings.ReplaceAll(strings.ReplaceAll(req_what[strings.Index(req_what, "name=")+5:], "\"", ""), " ", "")
						fmt.Println("form_key 是 ", form_key)
						http_request.Formdata.Key_va[form_key] = ""
						continue
					}
				}

				// 文件相关提取
				if upload_file_flag {
					if strings.Contains(req_what, "Content-Type") {
						rex_str := "Content-Type: (.*)"
						reg_result := find_regx(rex_str, req_what)
						if reg_result != "" {
							upload_filetype := strings.ReplaceAll(strings.ReplaceAll(req_what[strings.Index(req_what, ":")+1:], "\"", ""), " ", "")
							file_type_temp["file_type"] = upload_filetype
						}
						continue
					}
					if temp != "" {
						for _, vals := range file_suffix_magic {
							fmt.Println("测试文件magic", vals)
							offset_int, err := strconv.Atoi(vals["offset"])
							fmt.Println(offset_int, "==><==", err)
							if err == nil {
								fmt.Println(temp, vals["magic"], offset_int)
								if judge_file_type_match_content(temp, vals["magic"], offset_int) {
									magic_num = magic_num + 1
								}
							}
						}
						if magic_num > 0 {
							file_type_temp["file_suffix_type"] = "True"
						} else {
							file_type_temp["file_suffix_type"] = "None"
						}
					}

				}
				if kv_flag && req_what != "" {
					fmt.Println(temp)
					fmt.Println(req_what)
					http_request.Formdata.Key_va[form_key] = req_what
					kv_flag = false
				}

			}
		}
	}
	return http_request
}

// 正常的请求
func normal_req(http_request *Req_entity, content string) *Req_entity {
	header_flag := 1                    // 初始值大于0，当header_flag值为0时，表明header_flag解析结束
	req := strings.Split(content, "\n") //先切分

	for i := 0; i < len(req); i++ {
		req_what := req[i]
		// 请求行 请求方法+URI+HTTP/版本
		temp := strings.Split(req_what, " ")
		if Is_Req_Method(temp[0]) {
			http_request.Method = temp[0]
			http_request.Uri = temp[1]
			continue
		}
		// 请求头信息会包含:
		if strings.Contains(req_what, ":") {
			if header_flag > 0 {
				temp_header := strings.Split(req_what, ":")
				k := temp_header[0]
				v := strings.Replace(temp_header[1], " ", "", -1)
				http_request.Req_header_all[k] = v
				continue
			}
		}

		header_flag = 0
		// 请求体 内容多样,需要根据请求头信息判断,一般不为空
		if req_what != "" {
			http_request.Client_body = http_request.Client_body + "" + req_what
		}
	}
	return http_request
}
