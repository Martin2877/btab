package btt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

// ShiroResult Shiro rememberMe 检测结果
type ShiroResult struct {
	Found bool   `json:"found"` // 是否找到正确密钥
	Mode  string `json:"mode"`  // cbc / gcm
	Key   string `json:"key"`   // 命中的密钥(base64)
	Data  string `json:"data"`  // 解密后的内容(hex 或文本)
	Total int    `json:"total"` // 尝试的密钥数
}

// isShiroPlaintext 校验解密结果是否为 Shiro 序列化数据
// rememberMe 明文是序列化的 PrincipalCollection: ac ed 00 05 + org.apache.shiro 类名
func isShiroPlaintext(b []byte) bool {
	if len(b) < 6 {
		return false
	}
	if b[0] != 0xac || b[1] != 0xed || b[2] != 0x00 || b[3] != 0x05 {
		return false
	}
	// 序列化流中应出现 shiro 相关类名
	return bytes.Contains(b, []byte("org.apache.shiro")) ||
		bytes.Contains(b, []byte("PrincipalCollection")) ||
		bytes.Contains(b, []byte("SimplePrincipal"))
}

// decodeShiroCookie base64 解码 rememberMe cookie
func decodeShiroCookie(rememberMe string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(rememberMe)
	if err != nil {
		return nil, fmt.Errorf("cookie base64 解码失败: %v", err)
	}
	if len(b) < 32 {
		return nil, fmt.Errorf("cookie 长度过短: %d", len(b))
	}
	return b, nil
}

// CheckShiroCBC 用指定密钥做 AES-CBC 解密（Shiro <=1.4.1 默认）
// 数据格式: base64( iv(16) || ciphertext )
func CheckShiroCBC(rememberMe, key string) ([]byte, error) {
	raw, err := decodeShiroCookie(rememberMe)
	if err != nil {
		return nil, err
	}
	k, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("key base64 解码失败: %v", err)
	}
	iv, ct := raw[:16], raw[16:]
	return aesCBCDecrypt(ct, k, iv)
}

// CheckShiroGCM 用指定密钥做 AES-GCM 解密（Shiro 1.4.2+ 默认）
// 数据格式: base64( iv(16) || ciphertext+tag )
func CheckShiroGCM(rememberMe, key string) ([]byte, error) {
	raw, err := decodeShiroCookie(rememberMe)
	if err != nil {
		return nil, err
	}
	k, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("key base64 解码失败: %v", err)
	}
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCMWithNonceSize(block, 16)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, raw[:16], raw[16:], nil)
}

// ShiroCheck 检测 rememberMe cookie；key 为空时遍历内置常用密钥爆破
// mode: cbc / gcm / auto（auto 依次尝试 gcm、cbc）
func ShiroCheck(rememberMe, key, mode string) (*ShiroResult, error) {
	keys := shiroKeys
	if key != "" {
		keys = []string{key}
	}
	res := &ShiroResult{Total: 0}

	try := func(m string) (string, []byte, bool) {
		for _, k := range keys {
			res.Total++
			var plain []byte
			var err error
			if m == "gcm" {
				plain, err = CheckShiroGCM(rememberMe, k)
			} else {
				plain, err = CheckShiroCBC(rememberMe, k)
			}
			if err == nil && isShiroPlaintext(plain) {
				return k, plain, true
			}
		}
		return "", nil, false
	}

	if mode == "cbc" || mode == "auto" || mode == "" {
		if k, plain, ok := try("cbc"); ok {
			res.Found, res.Mode, res.Key = true, "cbc", k
			out, _ := postProcess(plain)
			res.Data = out
			return res, nil
		}
	}
	if mode == "gcm" || mode == "auto" || mode == "" {
		if k, plain, ok := try("gcm"); ok {
			res.Found, res.Mode, res.Key = true, "gcm", k
			out, _ := postProcess(plain)
			res.Data = out
			return res, nil
		}
	}
	return res, nil
}
