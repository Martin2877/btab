package httpparse

import "testing"

const stream = "HEAD /a.php HTTP/1.1\r\nHost: h\r\n\r\n\r\nHTTP/1.1 404 Not Found\r\n\r\n\r\nPOST /b.php HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nx=1\r\nHTTP/1.1 200 OK\r\n\r\n<html>"

func TestParseStream(t *testing.T) {
	if !LooksLikeStream(stream) {
		t.Fatal("not detected")
	}
	exs := ParseStream(stream)
	if len(exs) != 2 {
		t.Fatalf("want 2 got %d", len(exs))
	}
	if exs[0].Request == "" || exs[0].Response == "" {
		t.Fatal("pairing failed")
	}
	if exs[1].Response[:9] != "HTTP/1.1 " {
		t.Fatalf("bad resp %q", exs[1].Response)
	}
}
