package btt

import (
	"fmt"
	"strings"
)

// BehinderResult 冰蝎流量解密结果
type BehinderResult struct {
	Direction string `json:"direction"` // c2s / s2c
	Key       string `json:"key"`       // 使用的 AES 密钥(hex md5前16)
	Output    string `json:"output"`    // 解密后内容
	Note      string `json:"note"`      // 内容类型说明
}

// BehinderDecryptC2S 冰蝎 客户端->服务端 请求体解密：base64 -> AES-128-ECB(md5(pass)[:16])
func BehinderDecryptC2S(data, pass string) (*BehinderResult, error) {
	raw, err := looseBase64Decode(data)
	if err != nil {
		return nil, fmt.Errorf("base64 解码失败: %v", err)
	}
	key := aesKeyFromPassMD5(pass)
	plain, err := aesECBDecrypt(raw, key)
	if err != nil {
		return nil, fmt.Errorf("AES 解密失败: %v", err)
	}
	out, note := postProcess(plain)
	return &BehinderResult{
		Direction: "c2s",
		Key:       string(key),
		Output:    out,
		Note:      note,
	}, nil
}

// BehinderDecryptS2C 冰蝎 服务端->客户端 响应体解密：去除干扰字符 -> hex -> AES-128-ECB
func BehinderDecryptS2C(data, pass string) (*BehinderResult, error) {
	raw, err := extractHexPayload(data)
	if err != nil {
		// 部分版本响应也是 base64
		raw, err = looseBase64Decode(data)
		if err != nil {
			return nil, fmt.Errorf("响应体解析失败(非 hex/base64): %v", err)
		}
	}
	key := aesKeyFromPassMD5(pass)
	plain, err := aesECBDecrypt(raw, key)
	if err != nil {
		return nil, fmt.Errorf("AES 解密失败: %v", err)
	}
	out, note := postProcess(plain)
	return &BehinderResult{
		Direction: "s2c",
		Key:       string(key),
		Output:    out,
		Note:      note,
	}, nil
}

// BehinderDecrypt 按方向解密冰蝎流量；direction: c2s/s2c/auto
func BehinderDecrypt(data, pass, direction string) (*BehinderResult, error) {
	data = strings.TrimSpace(data)
	if pass == "" {
		pass = "rebeyond" // 冰蝎默认密码
	}
	switch direction {
	case "c2s":
		return BehinderDecryptC2S(data, pass)
	case "s2c":
		return BehinderDecryptS2C(data, pass)
	default:
		// auto: 先尝试 C2S(base64)，失败后尝试 S2C(hex)
		if r, err := BehinderDecryptC2S(data, pass); err == nil && looksDecrypted(r.Output) {
			return r, nil
		}
		return BehinderDecryptS2C(data, pass)
	}
}

// looksDecrypted 粗略判断解密结果是否有意义
func looksDecrypted(s string) bool {
	return len(s) > 0 && !strings.HasPrefix(s, "[二进制(hex)]")
}
