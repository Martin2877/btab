package webshell

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"net/url"
	"regexp"
	"strings"
)

// maxDecodeDepth 递归解码最大层数
const maxDecodeDepth = 8

// maxDecodeNodes 单次检测最多展开的解码节点数，防止指数爆炸
const maxDecodeNodes = 256

// decodeNode 解码链路中的一个节点
type decodeNode struct {
	name string // 解码方式名，如 base64 / gzip / xor(0x41) / raw
	data []byte
}

var (
	reBase64Long   = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	reHexLong      = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}){8,}|(?:0x[0-9a-fA-F]{2}){8,}|(?:[0-9a-fA-F]{2}){24,}`)
	reURLEncoded   = regexp.MustCompile(`(?:%[0-9a-fA-F]{2}){6,}`)
	reOctal        = regexp.MustCompile(`(?:\\[0-7]{3}){6,}`)
	reChrChain     = regexp.MustCompile(`(?i)(?:chr\s*\(\s*\d+\s*\)\s*[.&]?\s*){4,}`)
	reCharCodeJsp  = regexp.MustCompile(`(?i)(?:String\.fromCharCode\s*\([^)]*\)|\\u[0-9a-fA-F]{4})`)
	reLooksBase64  = regexp.MustCompile(`^[A-Za-z0-9+/\s]+={0,2}$`)
	reMostlyPrint  = regexp.MustCompile(`[^\x20-\x7e\r\n\t]`)
)

// isGzip 判断 gzip 魔数
func isGzip(b []byte) bool {
	return len(b) > 3 && b[0] == 0x1f && b[1] == 0x8b
}

// isJavaClass 判断 Java class 文件魔数
func isJavaClass(b []byte) bool {
	return len(b) > 4 && b[0] == 0xca && b[1] == 0xfe && b[2] == 0xba && b[3] == 0xbe
}

// isJavaSerialized 判断 Java 序列化数据魔数
func isJavaSerialized(b []byte) bool {
	return len(b) > 4 && b[0] == 0xac && b[1] == 0xed && b[2] == 0x00 && b[3] == 0x05
}

// printableRatio 可打印字符占比
func printableRatio(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	return 1.0 - float64(len(reMostlyPrint.FindAllIndex(b, -1)))/float64(len(b))
}

// tryDecodes 对输入尝试所有解码方式，返回成功且更"像代码/文本"的候选层
func tryDecodes(data []byte) []decodeNode {
	var out []decodeNode
	s := strings.TrimSpace(string(data))

	// 1. gzip
	if isGzip(data) {
		if r, err := gzip.NewReader(bytes.NewReader(data)); err == nil {
			if raw, err := ioutil.ReadAll(r); err == nil && len(raw) > 0 {
				out = append(out, decodeNode{"gzip", raw})
			}
			r.Close()
		}
	}
	// 2. zlib
	if len(data) > 2 && data[0] == 0x78 {
		if r, err := zlib.NewReader(bytes.NewReader(data)); err == nil {
			if raw, err := ioutil.ReadAll(r); err == nil && len(raw) > 0 {
				out = append(out, decodeNode{"zlib", raw})
			}
			r.Close()
		}
	}
	// 3. raw deflate
	{
		if r := flate.NewReader(bytes.NewReader(data)); r != nil {
			if raw, err := ioutil.ReadAll(r); err == nil && len(raw) > 0 && printableRatio(raw) > 0.5 {
				out = append(out, decodeNode{"deflate", raw})
			}
			r.Close()
		}
	}
	// 4. 整体 base64
	if len(s) >= 8 && reLooksBase64.MatchString(s) {
		compact := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, s)
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			if raw, err := enc.DecodeString(compact); err == nil && len(raw) > 0 {
				out = append(out, decodeNode{"base64", raw})
				break
			}
		}
	}
	// 5. url 编码
	if reURLEncoded.MatchString(s) {
		if raw, err := url.QueryUnescape(s); err == nil && raw != s {
			out = append(out, decodeNode{"url", []byte(raw)})
		}
	}
	// 6. hex（\xNN / 0xNN / 连续 hex）
	if m := reHexLong.FindString(s); m != "" && len(m) >= len(s)*6/10 {
		h := strings.ReplaceAll(m, `\x`, "")
		h = strings.ReplaceAll(h, "0x", "")
		if raw, err := hex.DecodeString(h); err == nil && len(raw) > 0 {
			out = append(out, decodeNode{"hex", raw})
		}
	}
	// 7. 嵌入的长 base64 token（只取最长的一个，避免组合爆炸）
	if bm := longestBase64Token(s); bm != "" {
		if raw, err := base64.StdEncoding.DecodeString(bm); err == nil && len(raw) > 0 {
			out = append(out, decodeNode{"base64(inner)", raw})
		}
	}
	// 8. 内嵌 hex 转义串
	if hm := reHexLong.FindString(s); hm != "" {
		h := strings.ReplaceAll(hm, `\x`, "")
		h = strings.ReplaceAll(h, "0x", "")
		if raw, err := hex.DecodeString(h); err == nil && len(raw) > 0 {
			out = append(out, decodeNode{"hex(inner)", raw})
		}
	}
	// 9. PHP chr() 链
	if m := reChrChain.FindString(s); m != "" {
		nums := regexp.MustCompile(`\d+`).FindAllString(m, -1)
		var raw []byte
		for _, n := range nums {
			var v int
			fmt.Sscanf(n, "%d", &v)
			raw = append(raw, byte(v))
		}
		if len(raw) > 0 {
			out = append(out, decodeNode{"chr()", raw})
		}
	}
	// 10. 八进制转义串
	if m := reOctal.FindString(s); m != "" {
		var raw []byte
		om := regexp.MustCompile(`\\([0-7]{3})`).FindAllStringSubmatch(m, -1)
		for _, g := range om {
			var v int
			fmt.Sscanf(g[1], "%o", &v)
			raw = append(raw, byte(v))
		}
		if len(raw) > 0 {
			out = append(out, decodeNode{"octal", raw})
		}
	}
	// 11. 单字节 XOR（仅当数据本身不像文本时尝试）
	if printableRatio(data) < 0.7 {
		for k := 1; k < 256; k++ {
			raw := make([]byte, len(data))
			for i, b := range data {
				raw[i] = b ^ byte(k)
			}
			if printableRatio(raw) > 0.85 && looksLikeCode(raw) {
				out = append(out, decodeNode{fmt.Sprintf("xor(0x%02x)", k), raw})
			}
		}
	}
	return out
}

// longestBase64Token 找出文本中最长的合法 base64 token
func longestBase64Token(s string) string {
	best := ""
	for _, m := range reBase64Long.FindAllString(s, -1) {
		// 排除明显纯数字/纯字母单词
		if !strings.ContainsAny(m, "+/=") && regexp.MustCompile(`^[a-zA-Z]+$|^[0-9]+$`).MatchString(m) {
			continue
		}
		if len(m) > len(best) {
			best = m
		}
	}
	return best
}

// looksLikeCode 快速判断解码结果是否像脚本代码
func looksLikeCode(b []byte) bool {
	s := string(b)
	for _, kw := range []string{
		"<?", "<%", "eval", "exec", "system", "request", "$_POST", "$_GET",
		"Runtime", "Process", "function", "String", "class", "new ", "->", "=>",
	} {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// decodeChain BFS 递归解码，返回所有候选链路（含原始 raw）
func decodeChain(content []byte) [][]decodeNode {
	var results [][]decodeNode
	seen := map[uint32]bool{}
	nodes := 0

	type item struct {
		chain []decodeNode
	}
	queue := []item{{chain: []decodeNode{{name: "raw", data: content}}}}
	results = append(results, queue[0].chain)

	for len(queue) > 0 && nodes < maxDecodeNodes {
		cur := queue[0]
		queue = queue[1:]
		if len(cur.chain) >= maxDecodeDepth {
			continue
		}
		data := cur.chain[len(cur.chain)-1].data
		sum := crc32.ChecksumIEEE(data)
		if seen[sum] {
			continue
		}
		seen[sum] = true

		for _, n := range tryDecodes(data) {
			nodes++
			if nodes > maxDecodeNodes {
				break
			}
			nsum := crc32.ChecksumIEEE(n.data)
			if seen[nsum] {
				continue
			}
			next := append(append([]decodeNode{}, cur.chain...), n)
			results = append(results, next)
			queue = append(queue, item{chain: next})
		}
	}
	return results
}

// chainName 输出解码链描述
func chainName(chain []decodeNode) string {
	var parts []string
	for _, n := range chain {
		parts = append(parts, n.name)
	}
	return strings.Join(parts, " -> ")
}
