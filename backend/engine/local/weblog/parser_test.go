package weblog

import "testing"

const nginxLog = `192.168.1.10 - - [10/Oct/2024:13:55:36 +0800] "GET /index.html HTTP/1.1" 200 612 "https://example.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
192.168.1.10 - - [10/Oct/2024:13:55:37 +0800] "GET /admin/login.php?id=1%27%20or%20%271%27=%271 HTTP/1.1" 200 1024 "-" "sqlmap/1.7"
10.0.0.5 - - [10/Oct/2024:13:56:00 +0800] "POST /wp-login.php HTTP/1.1" 302 0 "-" "curl/7.68.0"
`

const apacheCommon = `127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
127.0.0.1 - frank [10/Oct/2000:13:55:37 -0700] "GET /missing.html HTTP/1.0" 404 310
127.0.0.1 - frank [10/Oct/2000:13:55:38 -0700] "POST /submit HTTP/1.0" 302 -
`

func TestParseCombined(t *testing.T) {
	lines := ParseLines(nginxLog)
	if len(lines) != 3 {
		t.Fatalf("expect 3 lines, got %d", len(lines))
	}
	l := lines[1]
	if l.IP != "192.168.1.10" || l.Method != "GET" || l.Status != 200 {
		t.Fatalf("bad parse: %+v", l)
	}
	if l.Path != "/admin/login.php" {
		t.Fatalf("bad path: %q", l.Path)
	}
	if l.UserAgent != "sqlmap/1.7" {
		t.Fatalf("bad ua: %q", l.UserAgent)
	}
	if lines[2].Bytes != 0 || lines[2].Status != 302 {
		t.Fatalf("bad bytes/status: %+v", lines[2])
	}
}

func TestParseCommon(t *testing.T) {
	lines := ParseLines(apacheCommon)
	if len(lines) != 3 {
		t.Fatalf("expect 3 lines, got %d", len(lines))
	}
	if lines[0].URL != "/apache_pb.gif" || lines[2].Method != "POST" {
		t.Fatalf("bad parse: %+v", lines)
	}
}

func TestLooksLikeLog(t *testing.T) {
	if !LooksLikeLog(nginxLog) {
		t.Fatal("nginx combined log not recognized")
	}
	if !LooksLikeLog(apacheCommon) {
		t.Fatal("apache common log not recognized")
	}
	if LooksLikeLog("GET /a HTTP/1.1\nHost: x\n\nbody") {
		t.Fatal("http request recognized as log")
	}
	if LooksLikeLog("just some text\nmore text\nthird line\nfourth line") {
		t.Fatal("plain text recognized as log")
	}
	// 部分脏行仍应识别（6/7 匹配）
	dirty := nginxLog + "garbage line without format\n"
	if !LooksLikeLog(dirty) {
		t.Fatal("log with one bad line not recognized")
	}
}

func TestSummarize(t *testing.T) {
	sum := Summarize(ParseLines(nginxLog))
	if sum.Lines != 3 || sum.Status[200] != 2 || sum.Status[302] != 1 {
		t.Fatalf("bad summary: %+v", sum)
	}
	if len(sum.TopIP) == 0 || sum.TopIP[0][0] != "192.168.1.10" {
		t.Fatalf("bad top ip: %+v", sum.TopIP)
	}
}
