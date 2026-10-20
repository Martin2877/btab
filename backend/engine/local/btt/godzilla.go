package btt

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
)

// GodzillaResult 哥斯拉流量解密结果
type GodzillaResult struct {
	Enc    string `json:"enc"`    // 实际使用的加密方式
	Key    string `json:"key"`    // 使用的密钥
	Output string `json:"output"` // 解密后内容
	Note   string `json:"note"`   // 内容类型说明
}

// godzillaKeyCandidates 哥斯拉密钥候选
func godzillaKeyCandidates(pass, key string) [][]byte {
	primary := aesKeyFromPassKeyMD5(pass, key)
	s := md5.Sum([]byte(pass))
	passMD5 := []byte(hex.EncodeToString(s[:]))[:16]
	out := [][]byte{primary, passMD5}
	if key != "" {
		out = append(out, []byte(key))
	}
	if pass != "" {
		out = append(out, []byte(pass))
	}
	return out
}

// godzillaDecryptRaw 输入密文原始字节，按加密模式解密
func godzillaDecryptRaw(raw []byte, pass, key, enc string) ([]byte, string, string, error) {
	candidates := godzillaKeyCandidates(pass, key)
	switch enc {
	case "base64":
		if b, err := looseBase64Decode(string(raw)); err == nil {
			return b, "", "base64", nil
		}
		return nil, "", "", fmt.Errorf("base64 解码失败")
	case "aes_raw":
		return tryKeysAES(raw, candidates, "aes_raw")
	case "xor_raw":
		return tryKeysXOR(raw, candidates, "xor_raw")
	default:
		return nil, "", "", fmt.Errorf("未知加密模式: %s", enc)
	}
}

func tryKeysAES(raw []byte, candidates [][]byte, enc string) ([]byte, string, string, error) {
	var lastErr error
	for _, k := range candidates {
		if len(k) != 16 {
			continue
		}
		if plain, err := aesECBDecrypt(raw, k); err == nil {
			return plain, string(k), enc, nil
		} else {
			lastErr = err
		}
	}
	return nil, "", "", fmt.Errorf("AES 解密失败: %v", lastErr)
}

func tryKeysXOR(raw []byte, candidates [][]byte, enc string) ([]byte, string, string, error) {
	var best []byte
	var bestKey string
	bestScore := -1.0
	for _, k := range candidates {
		if len(k) == 0 {
			continue
		}
		plain := xorCrypt(raw, k)
		if sc := scorePlain(plain); sc > bestScore {
			bestScore = sc
			best = plain
			bestKey = string(k)
		}
	}
	if best == nil {
		return nil, "", "", fmt.Errorf("XOR 解密失败")
	}
	return best, bestKey, enc, nil
}

// scorePlain 对解密结果打分：可打印比例 + 关键词加分 + gzip/序列化魔数加分
func scorePlain(b []byte) float64 {
	if len(b) == 0 {
		return -1
	}
	score := printableRatioB(b) * 10
	if len(b) > 3 && b[0] == 0x1f && b[1] == 0x8b {
		score += 20
	}
	if len(b) > 4 && b[0] == 0xac && b[1] == 0xed {
		score += 20
	}
	if len(b) > 4 && b[0] == 0xca && b[1] == 0xfe {
		score += 20
	}
	s := string(b)
	for _, kw := range []string{"eval", "exec", "request", "class", "function", "<?php", "<%", "pass", "key", "cmd"} {
		if strings.Contains(s, kw) {
			score += 2
		}
	}
	return score
}

// GodzillaDecrypt 哥斯拉流量解密
// data: 报文内容(base64/hex/原文); pass: 连接密码; key: 密钥; enc: 加密方式
// enc: auto / aes_base64 / aes_raw / xor_base64 / xor_raw / base64
func GodzillaDecrypt(data, pass, key, enc string) (*GodzillaResult, error) {
	data = strings.TrimSpace(data)
	if data == "" {
		return nil, fmt.Errorf("内容为空")
	}

	// 统一把输入转成密文字节 + 传输编码
	var raw []byte
	var transport string
	if enc == "" || enc == "auto" {
		// 自动判定传输编码
		if b, err := looseBase64Decode(data); err == nil && len(b) > 0 {
			raw = b
			transport = "base64"
		} else if b, err := extractHexPayload(data); err == nil && len(b) > 0 {
			raw = b
			transport = "hex"
		} else {
			raw = []byte(data)
			transport = "raw"
		}
		enc = "auto"
	} else {
		switch {
		case strings.HasSuffix(enc, "_base64"):
			b, err := looseBase64Decode(data)
			if err != nil {
				return nil, fmt.Errorf("base64 解码失败: %v", err)
			}
			raw = b
			transport = "base64"
			enc = strings.TrimSuffix(enc, "_base64") + "_raw"
		case enc == "base64":
			b, err := looseBase64Decode(data)
			if err != nil {
				return nil, fmt.Errorf("base64 解码失败: %v", err)
			}
			out, note := postProcess(b)
			return &GodzillaResult{Enc: "base64", Output: out, Note: note}, nil
		default:
			// *_raw: 可能是 hex 或原始字节
			if b, err := extractHexPayload(data); err == nil && len(b) > 0 && len(b)%16 == 0 {
				raw = b
				transport = "hex"
			} else {
				raw = []byte(data)
				transport = "raw"
			}
		}
	}

	tryModes := []string{}
	if enc == "auto" {
		tryModes = []string{"aes_raw", "xor_raw", "base64"}
	} else {
		tryModes = []string{enc}
	}

	var lastErr error
	for _, mode := range tryModes {
		plain, usedKey, usedEnc, err := godzillaDecryptRaw(raw, pass, key, mode)
		if err != nil {
			lastErr = err
			continue
		}
		out, note := postProcess(plain)
		res := &GodzillaResult{
			Enc:    strings.TrimSuffix(usedEnc, "_raw") + "_" + transport,
			Key:    usedKey,
			Output: out,
			Note:   note,
		}
		if mode == "aes_raw" || scorePlain(plain) > 6 {
			return res, nil
		}
		return res, nil
	}
	return nil, fmt.Errorf("解密失败: %v", lastErr)
}
