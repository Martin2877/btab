package nuclei

import (
	"testing"

	"github.com/Martin2877/blue-team-box/pkg/conf"
	"github.com/Martin2877/blue-team-box/pkg/pcap"
)

func init() { conf.GlobalConfig = &conf.Config{} }

const tplLog4j = `
id: demo-sqli
info:
  name: demo sqli
  severity: high
  tags: sqli,demo
http:
  - method: GET
    path:
      - "{{BaseURL}}/index.php?id={{x}}&act=view"
    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "admin"
          - "ROOT"
        condition: and
      - type: status
        status:
          - 200
      - type: dsl
        dsl:
          - 'contains(tolower(body), "admin") && status_code == 200'
    extractors:
      - type: regex
        part: body
        regex:
          - 'user=(\w+)'
        group: 1
`

const tplRaw = `
id: demo-raw
info:
  name: demo raw
  severity: critical
requests:
  - raw:
      - |
        POST /api/run HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json

        {"cmd":"{{cmd}}"}
    matchers:
      - type: regex
        regex:
          - 'uid=\d+'
      - type: word
        part: header
        words: ["x-powered-by: php"]
        case-insensitive: true
    matchers-condition: or
`

func TestDetect(t *testing.T) {
	e := New()
	if err := e.AddTemplate("a.yaml", []byte(tplLog4j)); err != nil {
		t.Fatal(err)
	}
	if err := e.AddTemplate("b.yaml", []byte(tplRaw)); err != nil {
		t.Fatal(err)
	}
	exs := []*Exchange{
		{Stream: "0", ReqFrame: 1, Method: "GET", URI: "/index.php?act=view&id=1%27+or+1%3D1", HasResp: true, Status: 200, RespBody: "hello admin ROOT user=bob"},
		{Stream: "0", ReqFrame: 3, Method: "GET", URI: "/index.php?id=1", HasResp: true, Status: 200, RespBody: "admin ROOT"},
		{Stream: "1", ReqFrame: 5, Method: "POST", URI: "/api/run", HasResp: true, Status: 200, ReqHeaders: []Header{{"Content-Type", "application/json"}}, ReqBody: `{"cmd":"id"}`, RespBody: "uid=0(root)"},
		{Stream: "1", ReqFrame: 7, Method: "POST", URI: "/api/run", HasResp: true, Status: 200, ReqHeaders: []Header{{"Content-Type", "application/json"}}, ReqBody: `{"cmd":"id"}`, RespBody: "nothing"},
	}
	fs := e.Detect(exs)
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(fs), fs)
	}
	if fs[0].TemplateID != "demo-sqli" && fs[0].ReqFrame != 1 {
		t.Fatalf("unexpected %+v", fs[0])
	}
	if fs[0].Extracted["extractor_1"][0] != "bob" {
		t.Fatalf("extractor: %+v", fs[0].Extracted)
	}
	if fs[1].ReqFrame != 5 {
		t.Fatalf("unexpected %+v", fs[1])
	}
}

func TestDetectPcap(t *testing.T) {
	if _, err := pcap.ResolveTsharkPath(); err != nil {
		t.Skip("tshark not available:", err)
	}
	e := New()
	if n, errs := e.LoadDir("testdata"); n != 1 || len(errs) != 0 {
		t.Fatal(n, errs)
	}
	fs, err := e.DetectPcap("../../stores/pcap/log4j_test.pcap")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].TemplateID != "log4j-login-jndi" {
		t.Fatalf("unexpected: %+v", fs)
	}
}

const tplStruts = `
id: struts2-demo
info:
  name: Struts2 demo
  severity: critical
http:
  - method: POST
    path:
      - "{{BaseURL}}/struts2-showcase/index.action"
    headers:
      Content-Type: application/x-www-form-urlencoded
    body: "name=%25{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}"
    matchers:
      - type: status
        status: [200]
`

func TestSignatureMatch(t *testing.T) {
	e := New()
	if err := e.AddTemplate("s2.yaml", []byte(tplStruts)); err != nil {
		t.Fatal(err)
	}
	// 仅命中弱特征（普通表单请求的 Content-Type）不应产生疑似命中
	benign := "POST /form HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1&b=2"
	if hits := e.SignatureMatch(benign, 3); len(hits) != 0 {
		t.Fatalf("weak-only match should not hit: %+v", hits)
	}
	// 命中模板特有的强特征片段才应命中
	attack := "POST /x HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" +
		"name=%25{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)}"
	hits := e.SignatureMatch(attack, 3)
	if len(hits) != 1 || hits[0].TemplateID != "struts2-demo" {
		t.Fatalf("strong match missing: %+v", hits)
	}
}

// 模板 payload/query 中含 %AD、%C0%AF、windows-1251 等非 UTF-8 百分号编码时，
// 解码得到的原始字节曾导致 regexp 编译失败（error parsing regexp: invalid UTF-8），
// 现按位置替换为 U+FFFD 后应可解析且不影响请求匹配。
const tplNonUTF8 = `
id: demo-nonutf8
info:
  name: demo non-utf8 payload
  severity: medium
http:
  - method: GET
    path:
      - "{{BaseURL}}/bitrix/rk.php?id=28&event3=5+%2F+%5B129%5D+Garmin+%E1%EE%ED%F3%F1&goto=https://interact.sh"
      - "{{BaseURL}}/cgi-bin/php-cgi.exe?%ADd+allow_url_include%3D1"
    matchers:
      - type: status
        status: [302, 200]
`

func TestNonUTF8Payload(t *testing.T) {
	e := New()
	e.Parse = ParseOptions{ExpandPayloads: true}
	if err := e.AddTemplate("nonutf8.yaml", []byte(tplNonUTF8)); err != nil {
		t.Fatal(err)
	}
	exs := []*Exchange{
		{Stream: "0", ReqFrame: 1, Method: "GET", URI: "/bitrix/rk.php?id=28&event3=5+%2F+%5B129%5D+Garmin+%E1%EE%ED%F3%F1&goto=https://interact.sh", HasResp: true, Status: 302},
		{Stream: "0", ReqFrame: 2, Method: "GET", URI: "/bitrix/rk.php?id=28&event3=other&goto=https://interact.sh", HasResp: true, Status: 302},
	}
	fs := e.Detect(exs)
	if len(fs) != 1 || fs[0].ReqFrame != 1 {
		t.Fatalf("unexpected: %+v", fs)
	}
}

// xpath matcher/extractor（antchfx htmlquery）：节点命中即匹配，attribute 取属性值
const tplXpath = `
id: demo-xpath
info:
  name: demo xpath
  severity: high
http:
  - method: GET
    path: ["{{BaseURL}}/"]
    matchers-condition: and
    matchers:
      - type: xpath
        part: body
        xpath:
          - "/html/head/title[contains(text(), 'Meduza')]"
      - type: status
        status: [200]
    extractors:
      - type: xpath
        attribute: src
        xpath:
          - "//script[contains(@src,'//')]"
`

func TestXpathMatcher(t *testing.T) {
	e := New()
	if err := e.AddTemplate("xpath.yaml", []byte(tplXpath)); err != nil {
		t.Fatal(err)
	}
	body := `<html><head><title>Meduza Stealer panel</title></head><body><script src="//evil.example/x.js"></script></body></html>`
	exs := []*Exchange{
		{Stream: "0", ReqFrame: 1, Method: "GET", URI: "/", HasResp: true, Status: 200, RespBody: body},
		{Stream: "0", ReqFrame: 2, Method: "GET", URI: "/", HasResp: true, Status: 200, RespBody: `<html><head><title>other</title></head></html>`},
	}
	fs := e.Detect(exs)
	if len(fs) != 1 || fs[0].ReqFrame != 1 {
		t.Fatalf("unexpected: %+v", fs)
	}
	if got := fs[0].Extracted["extractor_1"]; len(got) != 1 || got[0] != "//evil.example/x.js" {
		t.Fatalf("extractor: %+v", fs[0].Extracted)
	}
}

// 检出要求请求与响应都命中：无响应、仅请求侧 matcher（part: request / 仅引用 request 的 dsl）
// 或响应侧 matcher 未命中，均不产生检出，避免仅凭攻击请求弱特征误报。
const tplReqOnly = `
id: demo-reqonly
info:
  name: demo request-only matcher
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/shell.jsp"
    matchers-condition: or
    matchers:
      - type: word
        part: request
        words: ["cmd="]
      - type: word
        part: body
        words: ["uid="]
`

const tplDslNoResp = `
id: demo-dsl-noresp
info:
  name: demo dsl empty-response
  severity: high
http:
  - method: GET
    path:
      - "{{BaseURL}}/conf"
    matchers:
      - type: dsl
        dsl:
          - 'content_length == 0'
`

func TestDetectRequiresResponseHit(t *testing.T) {
	e := New()
	if err := e.AddTemplate("a.yaml", []byte(tplReqOnly)); err != nil {
		t.Fatal(err)
	}
	if err := e.AddTemplate("b.yaml", []byte(tplDslNoResp)); err != nil {
		t.Fatal(err)
	}
	exs := []*Exchange{
		// 无响应：请求特征 + dsl 在空响应上判真，但不算检出
		{Stream: "0", ReqFrame: 1, Method: "GET", URI: "/conf"},
		// 有响应：仅请求侧 matcher 命中，响应 body 未命中，不算检出
		{Stream: "0", ReqFrame: 2, Method: "GET", URI: "/shell.jsp?cmd=id", HasResp: true, Status: 200, RespBody: "denied"},
		// 有响应：响应 body 命中，算检出
		{Stream: "0", ReqFrame: 3, Method: "GET", URI: "/shell.jsp?cmd=id", HasResp: true, Status: 200, RespBody: "uid=0(root)"},
		// 有响应：dsl 在真实响应上命中，算检出
		{Stream: "0", ReqFrame: 4, Method: "GET", URI: "/conf", HasResp: true, Status: 200},
	}
	fs := e.Detect(exs)
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(fs), fs)
	}
	if fs[0].ReqFrame != 3 || fs[0].TemplateID != "demo-reqonly" {
		t.Fatalf("unexpected %+v", fs[0])
	}
	if fs[1].ReqFrame != 4 || fs[1].TemplateID != "demo-dsl-noresp" {
		t.Fatalf("unexpected %+v", fs[1])
	}
}

func TestNormalizeHex(t *testing.T) {
	ex := &Exchange{ReqBodyHex: "6869", RespBodyHex: "4F4B", ReqHeaders: []Header{{"Host", "h"}}}
	ex.Normalize()
	if ex.ReqBody != "hi" || ex.RespBody != "OK" || ex.Host != "h" {
		t.Fatalf("%+v", ex)
	}
}
