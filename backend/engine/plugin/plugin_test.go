package plugin

import (
	"fmt"
	"github.com/Martin2877/blue-team-box/pkg/conf"
	"github.com/tidwall/gjson"
	"log"
	"testing"
)

func TestPcap(t *testing.T) {
	var err error
	conf.Setup()
	conf.GlobalConfig.PcapAnalyseConfig.TsharkPath = "F:\\1_program\\60_wireshark\\Wireshark\\tshark.exe"

	// 初始化插件
	plugins := Plugins{}
	err = plugins.Init("pcap")
	if err != nil {
		t.Fatal(err)
		return
	}
	Payloads := map[string]string{
		"file":      "log4j_test2.pcap",
		"fields":    `["ip.src", "tcp.srcport", "ip.dst", "tcp.dstport"]`,
		"condition": "",
	}
	fieldsPayload := `["ip.src", "tcp.srcport", "ip.dst", "tcp.dstport"]`
	fieldsSource := fmt.Sprintf(`{
	"fields": %s
}`, fieldsPayload)

	fields := gjson.Get(fieldsSource, "fields")
	for _, v := range fields.Array() {
		fmt.Println(v.String())
	}
	// 插件示例的处理
	plugins.Plugin.Init()
	for k, v := range Payloads {
		plugins.Plugin.Set(k, v)
	}
	err = plugins.Plugin.Check()
	if err != nil {
		t.Fatal(err)
		return
	}
	// 执行
	err = plugins.Plugin.Exec()
	if err != nil {
		t.Fatal(err)
		return
	}
	//log.Println(plugins.Plugin.GetResult())
	//t.Log(plugins.Plugin.GetResult())
}

func TestJQ(t *testing.T) {
	var err error

	// 初始化插件
	plugins := Plugins{}
	err = plugins.Init("jq")
	if err != nil {
		t.Fatal(err)
		return
	}
	Payloads := map[string]string{
		"filter": ".[0] | .[\"ip.src\"]",
		"content": `["{\"ip.src\":[\"10.0.89.244\"],\"tcp.srcport\":[\"56132\"],\"ip.dst\":[\"106.15.106.246\"],\"tcp.dstport\":[\"13333\"],\"text\":[\"Timestamps\",\"POST /login;jsessionid=A33037C775A7C42EC67B5FCC0DD99D67 HTTP/1.1\\\\r\\\\n\",\"\\\\r\\\\n\",\"Form item: \\\"a\\\" = \\\"${jndi:ld${:gfdsghsfdhsdfh:-a}p://127.0.0.1:1111/f${lower:s}ad}\\\"\"]}","{\"ip.src\":[\"106.15.106.246\"],\"tcp.srcport\":[\"13333\"],\"ip.dst\":[\"10.0.89.244\"],\"tcp.dstport\":[\"56132\"],\"text\":[\"Timestamps\",\"HTTP/1.1 200 \\\\r\\\\n\",\"\\\\r\\\\n\",\"HTTP chunked response\",\"Data chunk (2608 octets)\",\"End of chunked encoding\",\"\\\\r\\\\n\",\"\u003c!doctype html\u003e\\\\n\",\"\u003chtml lang=\\\"en\\\"\u003e\\\\n\",\"\u003chead\u003e\\\\n\",\"    \u003cmeta charset=\\\"utf-8\\\"\u003e\\\\n\",\"    \u003ctitle\u003eLogin Page\u003c\\/title\u003e\\\\n\",\"    \u003clink rel=\\\"stylesheet\\\" href=\\\"https://cdn.jsdelivr.net/npm/bootstrap@4.4.1/dist/css/bootstrap.min.css\\\" integrity=\\\"sha256-L/W5Wfqfa0sdBNIKN9cG6QA5F2qx4qICmU2VgLruv9Y=\\\" crossorigin=\\\"anonymous\\\"\u003e\\\\n\",\"    \u003cstyle\u003e\\\\n\",\"        .bd-placeholder-img {\\\\n\",\"            font-size: 1.125rem;\\\\n\",\"            text-anchor: middle;\\\\n\",\"            -webkit-user-select: none;\\\\n\",\"            -moz-user-select: none;\\\\n\",\"            -ms-user-select: none;\\\\n\",\"            user-select: none;\\\\n\",\"        }\\\\n\",\"\\\\n\",\"        @media (min-width: 768px) {\\\\n\",\"            .bd-placeholder-img-lg {\\\\n\",\"                font-size: 3.5rem;\\\\n\",\"            }\\\\n\",\"        }\\\\n\",\"\\\\n\",\"        html,\\\\n\",\"        body {\\\\n\",\"            height: 100%;\\\\n\",\"        }\\\\n\",\"\\\\n\",\"        body {\\\\n\",\"            display: -ms-flexbox;\\\\n\",\"            display: flex;\\\\n\",\"            -ms-flex-align: center;\\\\n\",\"            align-items: center;\\\\n\",\"            padding-top: 40px;\\\\n\",\"            padding-bottom: 40px;\\\\n\",\"            background-color: #f5f5f5;\\\\n\",\"        }\\\\n\",\"\\\\n\",\"        .form-signin {\\\\n\",\"            width: 100%;\\\\n\",\"            max-width: 330px;\\\\n\",\"            padding: 15px;\\\\n\",\"            margin: auto;\\\\n\",\"        }\\\\n\",\"        .form-signin .checkbox {\\\\n\",\"            font-weight: 400;\\\\n\",\"        }\\\\n\",\"        .form-signin .form-control {\\\\n\",\"            position: relative;\\\\n\",\"            box-sizing: border-box;\\\\n\",\"            height: auto;\\\\n\",\"            padding: 10px;\\\\n\",\"            font-size: 16px;\\\\n\",\"        }\\\\n\",\"        .form-signin .form-control:focus {\\\\n\",\"            z-index: 2;\\\\n\",\"        }\\\\n\",\"        .form-signin input[type=\\\"email\\\"] {\\\\n\",\"            margin-bottom: -1px;\\\\n\",\"            border-bottom-right-radius: 0;\\\\n\",\"            border-bottom-left-radius: 0;\\\\n\",\"        }\\\\n\",\"        .form-signin input[type=\\\"password\\\"] {\\\\n\",\"            margin-bottom: 10px;\\\\n\",\"            border-top-left-radius: 0;\\\\n\",\"            border-top-right-radius: 0;\\\\n\",\"        }\\\\n\",\"    \u003c\\/style\u003e\\\\n\",\"\u003c\\/head\u003e\\\\n\",\"\u003cbody class=\\\"text-center\\\"\u003e\\\\n\",\"    \u003cform class=\\\"form-signin\\\" action=\\\"/doLogin\\\" method=\\\"post\\\"\u003e\\\\n\",\"        \u003ch1 class=\\\"h3 mb-3 font-weight-normal\\\"\u003ePlease sign in\u003c\\/h1\u003e\\\\n\",\"        \u003clabel class=\\\"sr-only\\\"\u003eUsername\u003c\\/label\u003e\\\\n\",\"        \u003cinput type=\\\"text\\\" class=\\\"form-control\\\" placeholder=\\\"Username\\\" name=\\\"username\\\" required\u003e\\\\n\",\"        \u003clabel class=\\\"sr-only\\\"\u003ePassword\u003c\\/label\u003e\\\\n\",\"        \u003cinput type=\\\"password\\\" class=\\\"form-control\\\" placeholder=\\\"Password\\\" name=\\\"password\\\" required\u003e\\\\n\",\"        \u003cdiv class=\\\"checkbox mb-3\\\"\u003e\\\\n\",\"            \u003clabel\u003e\\\\n\",\"                \u003cinput type=\\\"checkbox\\\" name=\\\"rememberme\\\" value=\\\"remember-me\\\"\u003e Remember me\\\\n\",\"            \u003c\\/label\u003e\\\\n\",\"        \u003c\\/div\u003e\\\\n\",\"        \u003cbutton class=\\\"btn btn-lg btn-primary btn-block\\\" type=\\\"submit\\\"\u003eSign in\u003c\\/button\u003e\\\\n\",\"    \u003c\\/form\u003e\\\\n\",\"\u003c\\/body\u003e\\\\n\",\"\u003c\\/html\u003e\\\\n\"]}"]
`,
	}
	// 插件示例的处理
	plugins.Plugin.Init()
	for k, v := range Payloads {
		plugins.Plugin.Set(k, v)
	}
	err = plugins.Plugin.Check()
	if err != nil {
		t.Fatal(err)
		return
	}
	// 执行
	err = plugins.Plugin.Exec()
	if err != nil {
		t.Fatal(err)
		return
	}
	log.Println(plugins.Plugin.GetResult())
}
