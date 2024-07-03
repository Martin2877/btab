package pcap

import (
	"bytes"
	"errors"
	"github.com/Martin2877/blue-team-box/pkg/conf"
	files "github.com/Martin2877/blue-team-box/pkg/file"
	"os/exec"
	"strings"
)

const ()

var PcapEnds = []string{".pcap", ".pcapng", ".cap"}

func checkEnds(name string) bool {
	for _, ext := range PcapEnds {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

type Pcaper struct {
	File   string   `json:"file"`   // 文件
	Fields []string `json:"fileds"` // 字段
}

func CreatePcaper() *Pcaper {
	return &Pcaper{
		File:   "",
		Fields: []string{"frame.time", "ip.src", "ip.dst"},
	}
}

func (ins *Pcaper) Load(file string) error {
	//for _, f := range files {
	//	if checkEnds(f) {
	//		ins.Files = append(ins.Files, f)
	//	}
	//}
	if file == "" || !files.Exists(file) {
		return errors.New("file not exist")
	}
	ins.File = file
	return nil
}

func (ins *Pcaper) SetFields(fields []string) {
	if len(fields) > 0 {
		ins.Fields = fields
	}
}

func (ins *Pcaper) Query(filter string) (rawMsg []byte, errByte []byte, err error) {
	tsharkPath := conf.GlobalConfig.PcapAnalyseConfig.TsharkPath
	var fieldList = []string{}
	for _, key := range ins.Fields {
		fieldList = append(fieldList, "-e")
		fieldList = append(fieldList, key)
	}
	args := []string{"-r", ins.File, "-T", "json"}
	args = append(args, fieldList...)
	if filter != "" {
		args = append(args, "-Y")
		args = append(args, filter)
	}
	cmd := exec.Command(tsharkPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout // 标准输出
	cmd.Stderr = &stderr // 标准错误
	err = cmd.Run()
	outByte := stdout.Bytes()
	errByte = stderr.Bytes()
	//outStr, errStr := string(stdout.Bytes()), string(stderr.Bytes())
	//fmt.Printf("out:\n%s\nerr:\n%s\n", outStr, errStr)
	rawMsg = outByte
	if err != nil {
		return
	}
	return
}
