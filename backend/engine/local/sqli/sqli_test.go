package sqli

import (
	"fmt"
	"testing"
)

func TestSqli_SubmitOnce(t *testing.T) {
	cases := []struct {
		Name   string
		Code   int
		result string
	}{
		{") or true--\",\"' or 'x'='x\",\"'", 2000, ""},
	}

	sqli := Sqli{}
	for _, c := range cases {
		t.Run("pos", func(t *testing.T) {
			once, err := sqli.SubmitOnce(c.Name)
			if err != nil {
				return
			}
			fmt.Print(once.Result)
			if once.Code != c.Code {
				t.Fatal("fail")
			}
		})
	}
}
