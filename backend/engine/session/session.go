// Package session 实现跨帧、跨会话的流量关联检测。
//
// 单帧检测只看一个请求；而 webshell 管理工具（冰蝎/蚁剑/菜刀等）的特征分散在多个会话中：
// 前置会话完成密钥协商或暴露连接口令，后续会话的内容才能被解密还原。
// 本包把整个 pcap 的 HTTP 交互按“主机+脚本路径”聚合，从前置会话提取口令/密钥，
// 再回头解密后续会话中的请求与响应。
package session

import (
	"bytes"
	"crypto/aes"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Martin2877/blue-team-box/engine/nuclei"
)

// Decoded 一帧被还原的内容
type Decoded struct {
	Frame     int    `json:"frame"`
	Direction string `json:"direction"` // request / response
	Chain     string `json:"chain"`
	Plain     string `json:"plain"`
}

// Finding 一条跨会话检测结果
type Finding struct {
	Engine   string    `json:"engine"` // 检出引擎，固定为 session（跨会话关联分析）
	Type     string    `json:"type"`
	Severity string    `json:"severity"`
	Title    string    `json:"title"`
	Detail   string    `json:"detail"`
	Host     string    `json:"host"`
	URI      string    `json:"uri"`
	Src      string    `json:"src,omitempty"`
	Password string    `json:"password,omitempty"`
	Key      string    `json:"key,omitempty"`
	KeyFrame int       `json:"key_frame,omitempty"`
	Frames   []int     `json:"frames"`
	Decoded  []Decoded `json:"decoded,omitempty"`
}

// Analyze 对整个捕获的 HTTP 交互做跨会话关联检测
func Analyze(exs []*nuclei.Exchange) []Finding {
	groups := map[string][]*nuclei.Exchange{}
	var order []string
	for _, ex := range exs {
		path, _ := splitURI(ex.URI)
		k := ex.Host + "|" + path
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], ex)
	}
	var out []Finding
	for _, k := range order {
		g := groups[k]
		if f := detectBehinder(g); f != nil {
			out = append(out, *f)
			continue
		}
		if f := detectFormShell(g); f != nil {
			out = append(out, *f)
		}
	}
	for i := range out {
		out[i].Engine = "session"
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Frames[0] < out[j].Frames[0] })
	return out
}

func splitURI(uri string) (string, string) {
	if i := strings.Index(uri, "://"); i >= 0 {
		rest := uri[i+3:]
		if j := strings.Index(rest, "/"); j >= 0 {
			uri = rest[j:]
		} else {
			uri = "/"
		}
	}
	p, q, _ := strings.Cut(uri, "?")
	if i := strings.Index(p, ";"); i >= 0 {
		p = p[:i]
	}
	return p, q
}

func hostPath(ex *nuclei.Exchange) (string, string) {
	p, _ := splitURI(ex.URI)
	return ex.Host, p
}

//==================== 冰蝎 ====================

var (
	reKey16     = regexp.MustCompile(`^[0-9a-zA-Z]{16}$`)
	behinderDef = func() string { s := md5.Sum([]byte("rebeyond")); return hex.EncodeToString(s[:])[:16] }()
)

func aesECBDecrypt(key, data []byte) ([]byte, bool) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, false
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, false
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		blk.Decrypt(out[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}
	pad := int(out[len(out)-1])
	if pad < 1 || pad > aes.BlockSize || pad > len(out) {
		return nil, false
	}
	for _, b := range out[len(out)-pad:] {
		if int(b) != pad {
			return nil, false
		}
	}
	return out[:len(out)-pad], true
}

func b64Any(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 16 {
		return nil, false
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

func printable(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	n := 0
	for _, c := range b {
		if c == '\r' || c == '\n' || c == '\t' || (c >= 0x20 && c < 0x7f) {
			n++
		}
	}
	return float64(n) / float64(len(b))
}

// plausible 判断解密结果是否像有效内容：Java class / 序列化 / gzip / 可读文本
func plausible(b []byte) (string, bool) {
	switch {
	case len(b) > 4 && bytes.Equal(b[:4], []byte{0xca, 0xfe, 0xba, 0xbe}):
		return fmt.Sprintf("[Java class %d 字节，魔数 CAFEBABE]%s", len(b), classStrings(b)), true
	case len(b) > 4 && bytes.Equal(b[:4], []byte{0xac, 0xed, 0x00, 0x05}):
		return fmt.Sprintf("[Java 序列化数据 %d 字节]", len(b)), true
	case len(b) > 8 && printable(b) > 0.9:
		return string(b), true
	}
	return "", false
}

var reClassStr = regexp.MustCompile(`[A-Za-z0-9_/.$:;()\[\]-]{6,}`)

// classStrings 提取 class 常量池中的可读字符串，帮助判断载荷功能（如 Runtime/ProcessBuilder）
func classStrings(b []byte) string {
	ms := reClassStr.FindAll(b, 12)
	if len(ms) == 0 {
		return ""
	}
	var parts []string
	for _, m := range ms {
		parts = append(parts, string(m))
	}
	return " 关键字符串: " + strings.Join(parts, " ")
}

func tryBehinder(key string, body string) (string, string, bool) {
	k := []byte(key)
	raw := []byte(body)
	cands := [][]byte{raw}
	if b, ok := b64Any(body); ok {
		cands = append([][]byte{b}, cands...)
	}
	for i, c := range cands {
		if p, ok := aesECBDecrypt(k, c); ok {
			if s, ok := plausible(p); ok {
				chain := "aes128-ecb"
				if i == 0 && len(cands) == 2 {
					chain = "base64 -> aes128-ecb"
				}
				return s, chain, true
			}
		}
	}
	if b, ok := b64Any(body); ok { // 冰蝎 v4 xor 变种
		x := make([]byte, len(b))
		for i := range b {
			x[i] = b[i] ^ k[(i+1)&15]
		}
		if s, ok := plausible(x); ok {
			return s, "base64 -> xor(key)", true
		}
	}
	return "", "", false
}

func detectBehinder(g []*nuclei.Exchange) *Finding {
	type keyCand struct {
		key   string
		frame int
	}
	var posts []*nuclei.Exchange
	for _, ex := range g {
		if strings.EqualFold(ex.Method, "POST") && len(ex.ReqBody) >= 16 {
			posts = append(posts, ex)
		}
	}
	if len(posts) == 0 {
		return nil
	}
	firstPost := posts[0].ReqFrame
	cands := []keyCand{{behinderDef, 0}}
	for _, ex := range g {
		if ex.ReqFrame >= firstPost || !ex.HasResp {
			continue
		}
		if body := strings.TrimSpace(ex.RespBody); reKey16.MatchString(body) {
			cands = append(cands, keyCand{body, ex.RespFrame})
		}
	}
	for _, kc := range cands {
		f := &Finding{Type: "webshell-behinder", Severity: "critical", Host: g[0].Host, Key: kc.key, KeyFrame: kc.frame}
		f.URI, _ = splitURI(g[0].URI)
		for _, ex := range posts {
			plain, chain, ok := tryBehinder(kc.key, ex.ReqBody)
			if !ok {
				continue
			}
			f.Src = fmt.Sprintf("%s:%d", ex.SrcIP, ex.SrcPort)
			f.Frames = append(f.Frames, ex.ReqFrame)
			f.Decoded = append(f.Decoded, Decoded{Frame: ex.ReqFrame, Direction: "request", Chain: chain, Plain: clip(plain)})
			if ex.HasResp {
				if rp, rc, ok := tryBehinder(kc.key, ex.RespBody); ok {
					f.Frames = append(f.Frames, ex.RespFrame)
					f.Decoded = append(f.Decoded, Decoded{Frame: ex.RespFrame, Direction: "response", Chain: rc, Plain: clip(rp)})
				}
			}
		}
		if len(f.Decoded) == 0 {
			continue
		}
		src := "内置默认密钥(rebeyond)"
		if kc.frame > 0 {
			src = fmt.Sprintf("前置会话 frame %d 响应中的协商密钥", kc.frame)
			f.Frames = append(f.Frames, kc.frame)
		}
		f.Title = "冰蝎(Behinder) webshell 通信"
		f.Detail = fmt.Sprintf("使用 %s %q，成功解密 %d 帧加密通信", src, kc.key, len(f.Decoded))
		sort.Ints(f.Frames)
		return f
	}
	return nil
}

//==================== 表单口令型 webshell（蚁剑/菜刀/一句话） ====================

var reShellCode = regexp.MustCompile(`(?i)(eval\s*\(|assert\s*\(|system\s*\(|shell_exec|passthru|base64_decode|cmd\.exe|/bin/(ba)?sh|Runtime\.getRuntime|ProcessBuilder|Execute\s*\(|chr\s*\(\d+\))`)

func formParams(ex *nuclei.Exchange) url.Values {
	vals := url.Values{}
	if _, q := splitURI(ex.URI); q != "" {
		if v, err := url.ParseQuery(q); err == nil {
			for k, vs := range v {
				vals[k] = append(vals[k], vs...)
			}
		}
	}
	if ex.ReqBody != "" && !strings.HasPrefix(strings.TrimSpace(ex.ReqBody), "{") {
		if v, err := url.ParseQuery(ex.ReqBody); err == nil {
			for k, vs := range v {
				vals[k] = append(vals[k], vs...)
			}
		}
	}
	return vals
}

// decodeArg 解码蚁剑/菜刀的参数值：base64，兼容蚁剑随机前缀
func decodeArg(v string) (string, string, bool) {
	for skip := 0; skip <= 2; skip++ {
		if len(v) <= skip+8 {
			break
		}
		if b, ok := b64Any(v[skip:]); ok && printable(b) > 0.9 {
			chain := "base64"
			if skip > 0 {
				chain = fmt.Sprintf("strip(%d) -> base64", skip)
			}
			return string(b), chain, true
		}
	}
	return "", "", false
}
