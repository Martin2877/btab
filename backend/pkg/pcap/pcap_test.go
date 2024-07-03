package pcap

import (
	"encoding/json"
	"fmt"
	"github.com/Martin2877/blue-team-box/pkg/conf"
	"github.com/tidwall/gjson"
	"testing"
)

func TestPcaper(t *testing.T) {
	conf.Setup()
	conf.GlobalConfig.PcapAnalyseConfig.TsharkPath = "F:\\1_program\\60_wireshark\\Wireshark\\tshark.exe"
	f := "zabbix_unauthCVE-2022-23131.pcapng"
	pcaper := CreatePcaper()
	err := pcaper.Load(f)
	if err != nil {
		t.Fatal(err)
	}
	pcaper.SetFields([]string{"_ws.col.Time", "ip.src", "tcp.srcport", "ip.dst", "tcp.dstport", "http.request.uri", "http.cookie"})
	query, _, err := pcaper.Query("http.request.method == GET")
	if err != nil {
		t.Fatal(err)
	}
	var result []interface{}
	layers := gjson.GetBytes(query, "#._source.layers")
	for _, layer := range layers.Array() {
		result = append(result, layer.String())
	}
	//fmt.Println(result)

	resultJsonByte, _ := json.Marshal(result)
	fmt.Println(string(resultJsonByte))
}
