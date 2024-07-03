package engine

import (
	"log"
	"testing"
)

func TestNewEngines(t *testing.T) {
	var err error
	var engines = NewEngines()
	engines.ClearSteps()
	content := `
: a  ' union select concat(md5(2001427499))#
: b { "foo": { "bar": { "baz": 123 } } , "boo":"123"}
: c { "foo": { "bar": { "baz": "' union select concat(md5(2001427499))#" } } , "boo":"123"}

| jq
|: filter .foo.bar
|: content {{c}}

| jq
|: filter .foo.bar
|: content {{b}}

| jq
|: filter .baz
|: content {{R[0]}}


| sqli
|: content {{R}}
`
	err = engines.LoadQueries(content)
	err = engines.Run()
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= len(engines.Steps); i++ {
		log.Println(i-1, " ->", engines.GetResult(i-1))
	}
	log.Println("final: ", engines.GetFinalResult())
}
