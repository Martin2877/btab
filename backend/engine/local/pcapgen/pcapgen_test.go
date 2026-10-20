package pcapgen

import (
	"os"
	"testing"
)

func TestHTTP(t *testing.T) {
	req := []byte("POST /login HTTP/1.1\r\nHost: 10.0.0.1:8080\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 9\r\n\r\na=${jndi}")
	resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello")
	p := HTTP(Options{DstPort: 8080}, req, resp)
	if len(p) < 24 {
		t.Fatal("too short")
	}
	if p[0] != 0xd4 || p[1] != 0xc3 || p[2] != 0xb2 || p[3] != 0xa1 {
		t.Fatal("bad magic")
	}
	f, _ := os.CreateTemp("", "gen-*.pcap")
	defer os.Remove(f.Name())
	f.Write(p)
	f.Close()
	t.Log(f.Name(), len(p))
}
