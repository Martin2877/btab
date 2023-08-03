package httpparse

import (
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	jsonvalue "github.com/Andrew-M-C/go.jsonvalue"
	etree "github.com/beevik/etree"
)

// 判断URL访问资源类型
// http://www.xxx.com/a.ico 即访问ico图片资源，返回对应类型
// http://www.xxx.com/a.php 无法确定返回内容，返回动态网页类型，后续根据返回内容进一步判断
// 以及返回URL查询参数信息
func judge_url_what_type_args(url_str string) (bool, string, map[string]map[string]string) {
	var flag bool
	var result string
	pa := make(map[string]string)
	pa2 := make(map[string]map[string]string)

	fmt.Println(" ====>>  ", url_str)
	u, err := url.Parse(url_str)
	if err != nil {
		// panic(err)
		return false, "", pa2
	}
	// 获取url访问资源类型
	url_path_split := strings.Split(u.Path, "/")
	suffixs := strings.Split(url_path_split[len(url_path_split)-1], ".")
	suffix := suffixs[len(suffixs)-1]

	// 获取查询参数
	q := u.Query()

	if len(q) > 0 {
		for k, v := range q {
			if len(v) > 0 {
				pa["url_arg_"+k] = v[0]
			}
		}
		for k1, v1 := range pa {
			temp := make(map[string]string)
			temp["value"] = v1
			temp["type"] = Judge_arg_value_type(v1)
			pa2[k1] = temp
		}
	}
	// =============返回内容=============

	// 静态页面
	flag, result = static_page(suffix)
	if flag {
		return true, result, pa2
	}

	// 动态页面
	flag, result = dynamic_page(suffix)
	if flag {
		return true, result, pa2
	} else {
		return false, "", pa2
	}

}

// 解析请求体数据
func Client_body_args(cba string) map[string]map[string]string {
	pa := make(map[string]string)
	pa2 := make(map[string]map[string]string)
	url_str := "http://www.baidu.com/?" + cba
	u, err := url.Parse(url_str)
	if err != nil {
		// panic(err)
		return nil
	}
	q := u.Query()
	if len(q) > 0 {
		for k, v := range q {
			if len(v) > 0 {
				pa["cba_"+k] = v[0]
			}
		}
		for k1, v1 := range pa {
			temp := make(map[string]string)
			temp["value"] = v1
			temp["type"] = Judge_arg_value_type(v1)
			// temp[v1] = Judge_arg_value_type(v1)
			pa2[k1] = temp
		}
	}
	return pa2
}

// 初步判断参数值的类型,可以提供个大概的分析路线
// 以下顺序不同，可能会影响到返回结果，存在误差，需要后期调整
func Judge_arg_value_type(str string) string {
	if len(str) == 0 {
		return "空内容"
	}
	if Is_Number(str) {
		return "纯数字"
	}
	if Is_AllLetter(str) {
		return "纯字母"
	}
	if Is_Base64(str) {
		return "Base64编码内容"
	}
	if Is_Md5(str) {
		return "可能为Md5字符串"
	}
	if Is_Sha1(str) {
		return "可能为SHA1字符串"
	}
	if Is_Urlencoded(str) {
		return "Urlencode编码内容"
	}
	return "可疑"
}

// 根据转换，判断字符串是否为数值型
func Is_Number(str string) bool {
	_, err := strconv.Atoi(str)
	return err == nil
}

// 判断字符串是否只有A-Za-z字符
func Is_AllLetter(str string) bool {
	match, _ := regexp.MatchString(`^[A-Za-z]+$`, str)
	return match
}

// 判断是否为16位或者32位的Md5字符串
func Is_Md5(str string) bool {
	match, _ := regexp.MatchString(`^[A-Fa-f0-9]{16}$`, str)
	match2, _ := regexp.MatchString(`^[A-Fa-f0-9]{32}$`, str)
	return match || match2
}

// 判断是否为Base64
func Is_Base64(str string) bool {
	_, err := base64.StdEncoding.DecodeString(str)
	return err == nil
}

// 判断是否SHA1
func Is_Sha1(str string) bool {
	match, _ := regexp.MatchString(`^[A-Fa-f0-9]{40}$`, str)
	return match
}

// 判断是否是URLEncoded,必须要包含%,否则无法判断是否编码过，如果没有特殊字符，源字符串和目标字符串是一样的
func Is_Urlencoded(str string) bool {
	if !strings.Contains(str, "%") {
		return false
	}
	_, err := url.QueryUnescape(str)
	return err == nil
}

// 判断是否动态页面，返回具体页面类型
// pa:=map[string]string{"php":"php","jsp":"jsp","asp":"asp","action":"java"}
func dynamic_page(suffix string) (bool, string) {
	pa := make(map[string]string)
	pa = Read_csv_2_map("resource/dynamic_page_suffix.csv")

	page_suffixs := []string{}
	page_suffixs = get_map_key(pa)

	key := get_keywords(page_suffixs, suffix)

	if key != "" {
		return true, pa[key]
	}
	return false, ""
}

// 判断是否静态页面，返回具体页面类型
// pa:=map[string]string{"js":"js","css":"css","png":"png","ico":"ico"}
func static_page(suffix string) (bool, string) {
	pa := make(map[string]string)
	// str, _ := os.Getwd()
	pa = Read_csv_2_map("resource/static_page_suffix.csv")

	page_suffixs := []string{}
	page_suffixs = get_map_key(pa)

	key := get_keywords(page_suffixs, suffix)

	if key != "" {
		return true, pa[key]
	}
	return false, ""

}

// 通用方法，判定某字符串是否存在指定数组内的字符
// 只要不包含即返回false
func get_keywords(a []string, suffix string) string {
	for i := 0; i < len(a); i++ {
		if suffix == a[i] {
			return a[i]
		}
		// flag := strings.Contains(suffix, a[i])
		// if flag {

		// }
	}
	return ""
}

// 传入map[string]string 返回string数组
func get_map_key(map_arr map[string]string) []string {
	page_suffixs := []string{}
	for k, _ := range map_arr {
		page_suffixs = append(page_suffixs, k)
	}
	return page_suffixs
}

// 直接根据头部的content_type返回内容类型
func judge_content_type_header(content string) string {
	pa := make(map[string]string)
	pa = Read_csv_2_map("resource/http_content_type.csv")

	page_suffixs := []string{}
	page_suffixs = get_map_key(pa)

	key := get_keywords(page_suffixs, content)

	if key != "" {
		return pa[key]
	}
	return ""
}

// 根据常见后缀，返回相关文件类型中固定的字符串
func normal_file_suffix(suffix string) string {
	switch suffix {
	case "php":
		return "<?php"
	case "jsp":
		return "<%"
	case "asp":
		return "<%"
	case "aspx":
		return "<%"
	case "pl":
		return "#!/usr/bin/perl"
	default:
		return ""
	}
}

// (string:[(string, int),... ],...)  make(map[string][]map[string]string)
func get_content_magic_offset(filename string) []map[string]string {
	suffixs := strings.Split(filename, ".")
	suffix := suffixs[len(suffixs)-1]
	pa := Read_csv_2_map_file_type_magic_offset("resource/file_type_magic_offset.csv")

	_, ok := pa[suffix]
	if ok {
		// 之前已存在,避免被覆盖，先赋值，再追加
		return pa[suffix]
	} else {
		fmt.Println("后缀值不存在")
		// normal_file_suffix(suffix)
	}
	return nil
}

// 分析UA，返回可能使用的设备
func judge_UA(uastr string) string {
	fmt.Println(uastr)
	engine := get_engine(uastr)
	browser := get_browser(uastr)
	device := get_device(uastr)
	system := get_system(uastr)
	scanner := get_scanner(uastr)
	fmt.Printf("Engine引擎为%s,浏览器为%s,设备为%s,系统为%s,扫描器为%s \n", engine, browser, device, system, scanner)
	return scanner
}

// 从csv中读取2列数据,第1列为key,第2列为value,作为map返回,csv暂时不需要标题
// key1,value1
// key2,value2
func Read_csv_2_map(filename string) map[string]string {
	pa := make(map[string]string)
	//fs1, err := os.Open(filename)
	fs1, err := resource.Open(filename)
	if err != nil {
		log.Fatalf("can not open the file, err is %+v", err)
	}
	defer fs1.Close()
	in := csv.NewReader(fs1)
	content, err := in.ReadAll()
	if err != nil {
		fmt.Printf("can not readall, err is %+v", err)
	}
	for _, row := range content {
		pa[row[0]] = row[1]
	}
	return pa
}

// 获取content_type魔法值和偏移量
// {png:[{magic:123,offset:0},{magic:234,offset:2}]}
func Read_csv_2_map_file_type_magic_offset(filename string) map[string][]map[string]string {
	pa := make(map[string][]map[string]string)

	//fs1, err := os.Open(filename)
	fs1, err := resource.Open(filename)
	if err != nil {
		log.Fatalf("can not open the file, err is %+v", err)
	}
	defer fs1.Close()
	in := csv.NewReader(fs1)
	content, err := in.ReadAll()
	if err != nil {
		fmt.Printf("can not readall, err is %+v", err)
	}
	for _, row := range content {
		var identifier []map[string]string
		_, ok := pa[row[0]]
		if ok {
			// 之前已存在,避免被覆盖，先赋值，再追加
			identifier = pa[row[0]]
		}
		if row[1] != "" && row[2] != "" {
			temp_k := make(map[string]string)
			temp_k["magic"] = row[1]
			temp_k["offset"] = row[2]
			identifier = append(identifier, temp_k)
			pa[row[0]] = identifier
		}

	}
	return pa
}

// 根据内容格式的类型，返回相应类型编号json、xml、keyvalue、text
// application/javascript	image/png	text/css
func judge_content_type(content string) string {
	if has_json_char(content) {
		if is_Json(content) {
			return "json"
		}
	}
	if has_xml_char(content) {
		//若有<head><body><html>之类的，则不判断为xml
		html_keyword := []string{"<head>", "<body>", "<html>", "</head>", "</body>", "</html>"}
		if !has_keywords(html_keyword, content) {
			if is_Xml(content) {
				return "xml"
			}
		}
	}
	if is_urlencoded(content) {
		return "form_kv"
	}

	return "text" //默认文本型
}

// 判断是否有明显的json字符
func has_json_char(content string) bool {
	json_keyword := []string{"{", "}", "\"", ":"}
	return has_keywords(json_keyword, content)
}

// 判断是否有明显的xml字符
func has_xml_char(content string) bool {
	xml_keyword := []string{"<", ">", "</"}
	return has_keywords(xml_keyword, content)
}

// 判断内容是否符合json格式
// unrecognized raw text, invalid character \u0070 at Position 0
func is_Json(content string) bool {
	pcap_json := string([]byte(content))
	_, err := jsonvalue.UnmarshalString(pcap_json)
	if err == nil {
		return true
	}
	return false
}

// 判断内容是否符合xml格式
// XML syntax error on line 1: invalid character entity &scheduleTime (no semicolon)
func is_Xml(content string) bool {
	doc := etree.NewDocument()
	if err := doc.ReadFromString(content); err != nil {
		// panic(err)
		return false
	}
	// 即使可以加载到doc中，但也不一定是xml，可以看源码_, err := d.ReadFrom(strings.NewReader(s))，只要可以加载进去就不回报错，所以需要通过以下步骤进一步判断
	// doc root==>  &{ xxxxx [] [0xc0000f4120 0xc0000f4360 0xc0000f45a0] 0xc0000ac080 1}
	// doc child==>  [0xc0002b57a0 0xc0000f40c0]
	if doc.Root() != nil { // 当可以解析，获取到根节点，才不会返回nil，通过源码可以观察到https://github.com/beevik/etree/blob/v1.1.0/etree.go#L180
		return true
	}
	return false
}

// 判断是否是k=v结构
// 理论只有一行，若有多行则直接不解析,以下3种情况可以判定为kv结构，其他的暂不做kv结构判定
// k1=v1&k2=v2&k3=v3...
// k1=v1&k2=
// k1=v1
func is_urlencoded(content string) bool {
	fmt.Println(content)
	// 先判断是否有换行符
	if strings.Contains(content, "\r") {
		fmt.Println("有换行符,不是kv结构\\r")
		return false
	}
	if strings.Contains(content, "\n") {
		fmt.Println("有换行符,不是kv结构\\n")
		return false
	}
	var url_str string
	url_str = "http://www.baidu.com/?" + content
	u, err := url.Parse(url_str)
	if err != nil {
		// panic(err)
		return false
	}
	// fmt.Println(u.Path) //+URL路径
	// fmt.Println(u.Fragment) //URL#后的定位
	// fmt.Println(u.RawQuery) //URL查询内容
	flag := true
	res := strings.Split(u.RawQuery, "&")
	for re := range res {
		flag = strings.Contains(res[re], "=")
		if !flag {
			break
		}
	}
	return flag
}

// 判断是否是HTTP方法
func Is_Req_Method(str string) bool {
	method := []string{"GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}
	return has_keywords(method, str)
}

// 如果匹配到HTTP方法，那么就返回
func has_keywords(a []string, content string) bool {
	for i := 0; i < len(a); i++ {
		flag := strings.Contains(content, a[i])
		if flag {
			return true
		}
	}
	return false
}

// 判断十六进制还是正常的请求包
func judge_hex_string(content string) bool {
	newcontent := strings.Replace(content, "\n", "", -1)
	match, _ := regexp.MatchString(`^[A-Fa-f0-9]+$`, newcontent)
	return match
}

// 判断文件内容和文件类型是否一致
// 开始的0d0a部分为了解决bug，后期需要调整
func judge_file_type_match_content(hexcontent string, signal string, offset int) bool {
	if strings.Contains(strings.ToLower(signal), "0d0a") {
		return strings.Contains(strings.ToLower(signal), strings.ToLower(hexcontent))
	}
	idx := strings.Index(hexcontent, signal)
	return idx == offset
}

// 传入正则和原始内容，返回匹配到的字符串,未匹配到则返回空
func find_regx(reg_str string, oldcontent string) string {
	re := regexp.MustCompile(reg_str)
	return re.FindString(oldcontent)
}
