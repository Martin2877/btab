package inject

import (
	"mime/multipart"
	"net/url"
	"strings"
	"testing"
)

func find(hits []Hit, engine, source, name string) *Hit {
	for i := range hits {
		if hits[i].Engine == engine && hits[i].Point.Source == source && hits[i].Point.Name == name {
			return &hits[i]
		}
	}
	return nil
}

func TestScan_QueryValue(t *testing.T) {
	hits := Scan("/x.php?id="+urlEscape(`' or 'x'='x`)+"&p=1", "", nil)
	if h := find(hits, "sqli", "query", "id"); h == nil {
		t.Fatalf("query 参数 sqli 未命中: %+v", hits)
	}
}

func TestScan_FormBody(t *testing.T) {
	hits := Scan("/submit", "a=1&b="+urlEscape(`' or 'x'='x`), map[string]string{
		"content-type": "application/x-www-form-urlencoded",
	})
	if h := find(hits, "sqli", "form", "b"); h == nil {
		t.Fatalf("form 参数 sqli 未命中: %+v", hits)
	}
}

func TestScan_JSONBody(t *testing.T) {
	hits := Scan("/api", `{"user":{"name":"IMG SRC=/ onerror=\"alert(1)"},"n":1}`, nil)
	if h := find(hits, "xss", "json", "user.name"); h == nil {
		t.Fatalf("json 参数 xss 未命中: %+v", hits)
	}
}

func TestScan_CookieAndXFF(t *testing.T) {
	hits := Scan("/", "", map[string]string{
		"cookie":          "sid=abc; uid=' or 'x'='x",
		"x-forwarded-for": "1.2.3.4",
	})
	if h := find(hits, "sqli", "cookie", "uid"); h == nil {
		t.Fatalf("cookie 参数 sqli 未命中: %+v", hits)
	}
	hits = Scan("/", "", map[string]string{"x-forwarded-for": `' or 'x'='x`})
	if h := find(hits, "sqli", "header", "X-Forwarded-For"); h == nil {
		t.Fatalf("xff 头 sqli 未命中: %+v", hits)
	}
}

func TestScan_HTMLPageNoFalsePositive(t *testing.T) {
	html := `<html><head><title>ok</title></head><body><h1>select name from users</h1><p>a=b</p></body></html>`
	if hits := Scan("/index.html", html, nil); len(hits) != 0 {
		t.Fatalf("HTML 页面不应命中: %+v", hits)
	}
}

func TestScan_NormalRequestNoHit(t *testing.T) {
	hits := Scan("/static/app.js?v=1.2", "", map[string]string{
		"cookie":     "sid=6f9619ff8b86d011",
		"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
	})
	if len(hits) != 0 {
		t.Fatalf("正常请求不应命中: %+v", hits)
	}
}

func TestScan_MultipartForm(t *testing.T) {
	var sb strings.Builder
	w := multipart.NewWriter(&sb)
	f, _ := w.CreateFormField("q")
	f.Write([]byte(`' or 'x'='x`))
	w.WriteField("note", "hello")
	w.Close()
	hits := Scan("/upload", sb.String(), map[string]string{
		"content-type": w.FormDataContentType(),
	})
	if h := find(hits, "sqli", "form", "q"); h == nil {
		t.Fatalf("multipart 表单参数 sqli 未命中: %+v", hits)
	}
}

func urlEscape(s string) string { return url.QueryEscape(s) }
