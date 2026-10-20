package pocloader

import "testing"

func TestHttp(t *testing.T) {
	pl, err := NewPocLoader("F:\\8_code\\git\\btab\\backend\\stores\\nuclei")
	if err != nil {
		t.Fatalf(err.Error())
	}
	err = pl.Http()
	if err != nil {
		t.Fatalf(err.Error())
	}
}
