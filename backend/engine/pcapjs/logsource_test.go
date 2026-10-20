package pcapjs

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Martin2877/blue-team-box/engine/local/weblog"
)

func mkLog(n int) []weblog.Line {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "9.9.9.9 - - [10/Oct/2024:13:55:%02d +0800] \"GET /probe_%d HTTP/1.1\" 404 100 \"-\" \"scanner/1.0\"\n", i%60, i)
	}
	// 末尾追加一次成功的后台登录
	sb.WriteString("9.9.9.9 - - [10/Oct/2024:13:59:00 +0800] \"POST /admin/login HTTP/1.1\" 302 0 \"-\" \"scanner/1.0\"\n")
	return weblog.ParseLines(sb.String())
}

func TestLogSourceQuery(t *testing.T) {
	lines := mkLog(40)
	src := &LogSource{Lines: lines}

	// 全量查询
	rows, err := src.Query("", []string{"ip", "status"})
	if err != nil || len(rows) != 41 {
		t.Fatalf("all query: rows=%d err=%v", len(rows), err)
	}
	// 条件过滤
	rows, err = src.Query("status=404 && method=GET", []string{"url"})
	if err != nil || len(rows) != 40 {
		t.Fatalf("filtered query: rows=%d err=%v", len(rows), err)
	}
	// 正则过滤：probe_10 ~ probe_19 共 10 行
	rows, err = src.Query("url~probe_1\\d", nil)
	if err != nil || len(rows) != 10 {
		t.Fatalf("regex query: rows=%d err=%v", len(rows), err)
	}
	// 非法字段
	if _, err = src.Query("", []string{"nope"}); err == nil {
		t.Fatal("expect error for unknown field")
	}
	if _, err = src.Query("nosuchfield=1", nil); err == nil {
		t.Fatal("expect error for unknown field in filter")
	}
}

func TestRunLogDirscanThenLogin(t *testing.T) {
	lines := mkLog(40)
	src := &LogSource{Lines: lines}
	results, err := Default().RunLog(src, []string{"log_dirscan_then_login"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expect 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Error != "" {
		t.Fatalf("strategy error: %s", r.Error)
	}
	if !r.Hit || len(r.Events) == 0 {
		t.Fatalf("expect hit, got %+v", r)
	}
	if r.Events[0].Severity != "critical" {
		t.Fatalf("expect critical severity, got %q", r.Events[0].Severity)
	}
	if len(r.Events[0].Src) == 0 || r.Events[0].Src[0] != "9.9.9.9" {
		t.Fatalf("bad src: %+v", r.Events[0])
	}
}

func TestLogStrategiesLoad(t *testing.T) {
	var logCount int
	for _, s := range Default().List() {
		if s.Input == "log" {
			logCount++
		}
	}
	if logCount < 4 {
		t.Fatalf("expect >=4 log strategies, got %d", logCount)
	}
}

func TestRunLogOnlyLogStrategies(t *testing.T) {
	// RunLog 全量运行时只应执行日志类策略，不应混入 pcap 策略
	results, err := Default().RunLog(&LogSource{Lines: mkLog(5)}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) < 4 {
		t.Fatalf("expect >=4 log strategy results, got %d", len(results))
	}
	for _, r := range results {
		if !strings.HasPrefix(r.Strategy, "log_") {
			t.Fatalf("pcap strategy leaked into log run: %s", r.Strategy)
		}
	}
}
