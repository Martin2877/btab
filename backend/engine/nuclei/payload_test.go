package nuclei

import "testing"

const tplPayload = `
id: demo-lfi
info:
  name: demo lfi
  severity: high
  tags: lfi
http:
  - method: GET
    path:
      - "{{BaseURL}}/view?file={{file}}"
    payloads:
      file: helpers/wordlists/files.txt
    matchers:
      - type: word
        words:
          - "root:x"
`

func TestPayloadExpand(t *testing.T) {
	res := func(p string) ([]byte, bool) {
		if p == "helpers/wordlists/files.txt" {
			return []byte("/etc/passwd\r\n../../etc/shadow\n\n"), true
		}
		return nil, false
	}
	ok := &Exchange{Method: "GET", URI: "/view?file=/etc/passwd", HasResp: true, Status: 200, RespBody: "root:x:0"}
	bad := &Exchange{Method: "GET", URI: "/view?file=index.html", HasResp: true, Status: 200, RespBody: "root:x:0"}

	eng := New()
	eng.Parse = ParseOptions{Resources: res, ExpandPayloads: true}
	if err := eng.AddTemplate("lfi.yaml", []byte(tplPayload)); err != nil {
		t.Fatal(err)
	}
	if tpl := eng.Templates[0]; len(tpl.Refs) != 1 || len(tpl.MissingRefs) != 0 {
		t.Fatalf("refs=%v missing=%v", tpl.Refs, tpl.MissingRefs)
	}
	if n := len(eng.Detect([]*Exchange{ok})); n != 1 {
		t.Fatalf("expanded: want 1 finding, got %d", n)
	}
	if n := len(eng.Detect([]*Exchange{bad})); n != 0 {
		t.Fatalf("expanded: payload mismatch should not hit, got %d", n)
	}

	wild := New()
	wild.Parse = ParseOptions{Resources: res}
	_ = wild.AddTemplate("lfi.yaml", []byte(tplPayload))
	if n := len(wild.Detect([]*Exchange{bad})); n != 1 {
		t.Fatalf("wildcard: want 1 finding, got %d", n)
	}

	miss := New()
	_ = miss.AddTemplate("lfi.yaml", []byte(tplPayload))
	if len(miss.Templates[0].MissingRefs) != 1 {
		t.Fatalf("missing refs not recorded: %v", miss.Templates[0].MissingRefs)
	}
}

func TestInspect(t *testing.T) {
	m, err := Inspect([]byte("id: x\ninfo:\n  name: n\n  severity: High\n  tags: a, b\n  classification:\n    cve-id: CVE-2021-1\ndns:\n  - name: x\n"))
	if err != nil || m.Severity != "high" || len(m.Tags) != 2 || m.CVE != "CVE-2021-1" || len(m.Protocols) != 1 || m.Protocols[0] != "dns" {
		t.Fatalf("%+v %v", m, err)
	}
}
