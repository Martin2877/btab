package SerializationDumper

import (
	"strings"
	"testing"
)

func TestDumpString(t *testing.T) {
	data, err := decodeInput("aced0005740004414243447071007e0000")
	if err != nil {
		t.Fatal(err)
	}
	out, err := Dump(data)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + out)
	for _, want := range []string{"STREAM_MAGIC - 0xac ed", "TC_STRING - 0x74", "Value - ABCD - 0x41424344", "TC_NULL - 0x70", "Handle - 8257536 - 0x00 7e 00 00"} {
		if !strings.Contains(out, want) {
			t.Errorf("缺少 %q", want)
		}
	}
}

func TestBadMagic(t *testing.T) {
	if _, err := Dump([]byte{1, 2, 3, 4}); err == nil {
		t.Fatal("应报错")
	}
}
