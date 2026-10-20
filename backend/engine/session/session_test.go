package session

import (
	"crypto/aes"
	"encoding/base64"
	"net/url"
	"testing"

	"github.com/Martin2877/blue-team-box/engine/nuclei"
)

func aesECBEncrypt(key, data []byte) []byte {
	pad := aes.BlockSize - len(data)%aes.BlockSize
	for i := 0; i < pad; i++ {
		data = append(data, byte(pad))
	}
	blk, _ := aes.NewCipher(key)
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += aes.BlockSize {
		blk.Encrypt(out[i:i+aes.BlockSize], data[i:i+aes.BlockSize])
	}
	return out
}

func TestBehinderNegotiatedKey(t *testing.T) {
	key := "a1b2c3d4e5f60718"
	enc := func(s string) string { return base64.StdEncoding.EncodeToString(aesECBEncrypt([]byte(key), []byte(s))) }
	exs := []*nuclei.Exchange{
		{ReqFrame: 1, RespFrame: 2, Host: "h", Method: "GET", URI: "/shell.jsp?pass=123", HasResp: true, Status: 200, RespBody: key},
		{ReqFrame: 3, RespFrame: 4, Host: "h", Method: "POST", URI: "/shell.jsp", ReqBody: enc("whoami command output please"), HasResp: true, Status: 200,
			RespBody: enc(`{"status":"c3VjY2Vzcw==","msg":"cm9vdA=="}`)},
		{ReqFrame: 5, Host: "h", Method: "GET", URI: "/other", HasResp: true, RespBody: "x"},
	}
	fs := Analyze(exs)
	if len(fs) != 1 || fs[0].Type != "webshell-behinder" || fs[0].Key != key || fs[0].KeyFrame != 2 || len(fs[0].Decoded) != 2 {
		t.Fatalf("unexpected: %+v", fs)
	}
}

func TestFormShell(t *testing.T) {
	post := func(frame int, cmd string) *nuclei.Exchange {
		body := url.Values{"pass": {"@eval(base64_decode($_POST[z0]));"}, "z0": {base64.StdEncoding.EncodeToString([]byte(cmd))}}.Encode()
		return &nuclei.Exchange{ReqFrame: frame, RespFrame: frame + 1, Host: "h", Method: "POST", URI: "/a.php", ReqBody: body, HasResp: true, Status: 200}
	}
	fs := Analyze([]*nuclei.Exchange{post(1, "cd /var/www;id"), post(3, "cat /etc/passwd")})
	if len(fs) != 1 || fs[0].Type != "webshell-form" || fs[0].Password != "pass" || len(fs[0].Decoded) != 4 {
		t.Fatalf("unexpected: %+v", fs)
	}
}

func TestBenign(t *testing.T) {
	fs := Analyze([]*nuclei.Exchange{{ReqFrame: 1, Host: "h", Method: "POST", URI: "/login", ReqBody: "user=a&pass=b", HasResp: true, RespBody: "ok"}})
	if len(fs) != 0 {
		t.Fatalf("false positive: %+v", fs)
	}
}
