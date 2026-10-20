package session

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Martin2877/blue-team-box/engine/local/webshell"
	"github.com/Martin2877/blue-team-box/engine/nuclei"
)

var reCallLike = regexp.MustCompile(`(?i)^\s*@?(eval|assert|system|exec|shell_exec|passthru)\s*\(|^\s*(Execute|Eval)\s*\(`)

func clip(s string) string {
	if len(s) > 1000 {
		return s[:1000] + "..."
	}
	return s
}

type formHit struct {
	ex     *nuclei.Exchange
	params url.Values
}

func detectFormShell(g []*nuclei.Exchange) *Finding {
	hits := map[string][]formHit{}
	for _, ex := range g {
		if !strings.EqualFold(ex.Method, "POST") && !strings.EqualFold(ex.Method, "GET") {
			continue
		}
		params := formParams(ex)
		for k, vs := range params {
			for _, v := range vs {
				if len(v) < 6 || !reShellCode.MatchString(v) {
					continue
				}
				if reCallLike.MatchString(v) || webshell.Check([]byte(v)).Webshell {
					hits[k] = append(hits[k], formHit{ex, params})
					break
				}
			}
		}
	}
	bestKey := ""
	for k, hs := range hits {
		if len(hs) > len(hits[bestKey]) || (len(hs) == len(hits[bestKey]) && k < bestKey) {
			bestKey = k
		}
	}
	hs := hits[bestKey]
	if len(hs) == 0 {
		return nil
	}
	f := &Finding{Type: "webshell-form", Severity: "critical", Host: g[0].Host, Password: bestKey}
	f.URI, _ = splitURI(g[0].URI)
	for _, h := range hs {
		f.Src = fmt.Sprintf("%s:%d", h.ex.SrcIP, h.ex.SrcPort)
		f.Frames = append(f.Frames, h.ex.ReqFrame)
		for _, v := range h.params[bestKey] {
			f.Decoded = append(f.Decoded, Decoded{Frame: h.ex.ReqFrame, Direction: "request", Chain: "form(" + bestKey + ")", Plain: clip(v)})
		}
		var names []string
		for k := range h.params {
			if k != bestKey {
				names = append(names, k)
			}
		}
		sort.Strings(names)
		for _, k := range names {
			for _, v := range h.params[k] {
				if plain, chain, ok := decodeArg(v); ok {
					f.Decoded = append(f.Decoded, Decoded{Frame: h.ex.ReqFrame, Direction: "request", Chain: k + ": " + chain, Plain: clip(plain)})
				}
			}
		}
		if h.ex.HasResp {
			f.Frames = append(f.Frames, h.ex.RespFrame)
		}
	}
	f.Title = "一句话 webshell 连接（口令型，蚁剑/菜刀类）"
	f.Detail = fmt.Sprintf("口令参数 %q 在 %d 个请求中携带可执行代码，其余参数经 base64 解码为实际命令", bestKey, len(hs))
	sort.Ints(f.Frames)
	return f
}
