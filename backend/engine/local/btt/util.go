// Package btt 将 BlueTeamTools.jar 中的核心安全分析能力以纯 Go 实现：
// 冰蝎(Behinder)流量解密、哥斯拉(Godzilla)流量解密、Shiro rememberMe 密钥检测、Log4j2 lookup 解析/生成。
package btt

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	sd "github.com/Martin2877/blue-team-box/engine/plugin/SerializationDumper"
)

// aesKeyFromPassMD5 冰蝎密钥：md5(pass) 前16字节（十六进制字符串）
func aesKeyFromPassMD5(pass string) []byte {
	sum := md5.Sum([]byte(pass))
	return []byte(hex.EncodeToString(sum[:]))[:16]
}

// aesKeyFromPassKeyMD5 哥斯拉密钥：md5(pass + key) 前16字节
func aesKeyFromPassKeyMD5(pass, key string) []byte {
	sum := md5.Sum([]byte(pass + key))
	return []byte(hex.EncodeToString(sum[:]))[:16]
}

// aesECBDecrypt AES-128-ECB 解密（自动去 PKCS7 填充）
func aesECBDecrypt(data, key []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("密文长度非法: %d", len(data))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Decrypt(out[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}
	return pkcs7Unpad(out), nil
}

// aesCBCDecrypt AES-CBC 解密
func aesCBCDecrypt(data, key, iv []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("密文长度非法: %d", len(data))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, data)
	return pkcs7Unpad(out), nil
}

func pkcs7Unpad(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	n := int(b[len(b)-1])
	if n < 1 || n > aes.BlockSize || n > len(b) {
		return b // 填充非法时返回原文（可能是无填充场景）
	}
	for _, v := range b[len(b)-n:] {
		if int(v) != n {
			return b
		}
	}
	return b[:len(b)-n]
}

// xorCrypt 循环密钥 XOR
func xorCrypt(data, key []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)]
	}
	return out
}

func gunzip(data []byte) ([]byte, bool) {
	if len(data) < 3 || data[0] != 0x1f || data[1] != 0x8b {
		return nil, false
	}
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, false
	}
	defer r.Close()
	raw, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, false
	}
	return raw, true
}

// looseBase64Decode 宽松 base64 解码
func looseBase64Decode(s string) ([]byte, error) {
	compact := strings.Map(func(r rune) rune {
		if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(compact); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("base64 解码失败")
}

var reHexRun = regexp.MustCompile(`[0-9a-fA-F]{16,}`)

// extractHexPayload 提取十六进制负载：清理空白后整体解码，失败则取最长 hex 片段
func extractHexPayload(s string) ([]byte, error) {
	cleaned := strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') {
			return r
		}
		return -1
	}, s)
	if len(cleaned)%2 != 0 {
		cleaned = cleaned[:len(cleaned)-1]
	}
	if b, err := hex.DecodeString(cleaned); err == nil && len(b) > 0 {
		return b, nil
	}
	// 退化：取最长连续 hex 串
	best := ""
	for _, m := range reHexRun.FindAllString(s, -1) {
		if len(m) > len(best) {
			best = m
		}
	}
	if len(best)%2 != 0 {
		best = best[:len(best)-1]
	}
	if best == "" {
		return nil, fmt.Errorf("未找到十六进制数据")
	}
	return hex.DecodeString(best)
}

// postProcess 对解密结果做后处理：gzip 解压 / Java 序列化 dump / class 识别 / 文本输出
func postProcess(b []byte) (string, string) {
	if len(b) == 0 {
		return "", "空结果"
	}
	if raw, ok := gunzip(b); ok {
		s, note := postProcess(raw)
		return s, "gzip解压后" + note
	}
	switch {
	case len(b) > 4 && b[0] == 0xca && b[1] == 0xfe && b[2] == 0xba && b[3] == 0xbe:
		return fmt.Sprintf("[Java class 文件, %d 字节]", len(b)), "class字节码"
	case len(b) > 4 && b[0] == 0xac && b[1] == 0xed && b[2] == 0x00 && b[3] == 0x05:
		dump, err := sd.Dump(b)
		if err != nil {
			return dump + fmt.Sprintf("\n[序列化解析中断: %v]", err), "Java序列化(部分)"
		}
		return dump, "Java序列化"
	default:
		if printable := printableRatioB(b); printable > 0.6 {
			return string(b), "文本"
		}
		return hex.EncodeToString(b), "二进制(hex)"
	}
}

func printableRatioB(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	p := 0
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c <= 0x7e) || c >= 0x80 {
			p++
		}
	}
	return float64(p) / float64(len(b))
}
