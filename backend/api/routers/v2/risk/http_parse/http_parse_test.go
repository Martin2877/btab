package http_parse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
)

func submit(t *testing.T, req, res string) map[string]interface{} {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	body, _ := json.Marshal(map[string]string{"req_data": req, "res_data": res})
	c.Request = httptest.NewRequest("POST", "/x", bytes.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	Get_Tips(c)
	var out map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("bad json: %v, body=%s", err, w.Body.String())
	}
	jr, ok := out["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("failed response: %s", w.Body.String())
	}
	r, ok := jr["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("failed result: %v", jr["message"])
	}
	return r
}

func TestStreamLog4j(t *testing.T) {
	raw, err := os.ReadFile("../../../../../../tmp/httpstream_log4j.txt")
	if err != nil {
		t.Skip("sample file missing:", err)
	}
	res := submit(t, string(raw), "")
	fmt.Println("exchanges:", res["stream_exchanges"], "is_stream:", res["is_stream"])
	risk := res["risk"].(map[string]interface{})
	fmt.Println("risk title:", risk["title"], "| verdict:", risk["verdict"])
	b, _ := json.MarshalIndent(risk["items"], "", "  ")
	fmt.Println("risk.items:", string(b))
	pb, _ := json.MarshalIndent(res["params"], "", "  ")
	fmt.Println("params:", string(pb))
	details := res["exchanges"].([]interface{})
	d0 := details[0].(map[string]interface{})
	fmt.Println("detail[0] url_type:", d0["req_url_type"], "ua:", d0["req_ua_type"], "headers:", len(d0["req_headers"].([]interface{})))
}

func TestStreamListScan(t *testing.T) {
	raw, err := os.ReadFile("../../../../../../tmp/httpstream_list_scan.txt")
	if err != nil {
		t.Skip("sample file missing:", err)
	}
	res := submit(t, string(raw), "")
	fmt.Println("exchanges:", res["stream_exchanges"], "summaries:", len(res["exchange_summaries"].([]interface{})))
}

func TestStreamInResBox(t *testing.T) {
	raw, err := os.ReadFile("../../../../../../tmp/httpstream_list_scan.txt")
	if err != nil {
		t.Skip("sample file missing:", err)
	}
	res := submit(t, "", string(raw))
	fmt.Println("res-box exchanges:", res["stream_exchanges"])
}
