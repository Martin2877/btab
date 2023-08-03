package bash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/pkg/conf"
	"io/ioutil"
	"net/http"
	"strings"
)

const Address = "http://127.0.0.1:8899"


type BASH struct {
	Address string `json:"address"`
}

func NewBASH()  *BASH{
	address := Address
	if conf.GlobalConfig.EngineConfig.Bash_Host != ""{
		address = conf.GlobalConfig.EngineConfig.Bash_Host
	}
	return &BASH{Address: address}
}


type BASHResult struct {
	Result string `json:"result"`
	ReturnCode string `json:"returncode"`
}

type Result struct {
	Found bool `json:"found"`
	Result string `json:"result"`
	Catch []string `json:"catch"`
	NoCatch []string `json:"no_catch"`
}


func (bash *BASH) Submit(data string) (*BASHResult,error){
	api := "/check"

	client := &http.Client{}
	req, err := http.NewRequest("POST",bash.Address+api,bytes.NewBufferString("cmd="+data))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err != nil {
		return nil,err
	}
	resp, err := client.Do(req)
	defer resp.Body.Close()//一定要关闭resp.Body
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil,err
	}
	res := BASHResult{}
	err = json.Unmarshal(content, &res)
	if err != nil {
		return nil, err
	}
	return &res,nil
}


func (bash *BASH)SubmitLines(contents []string)(*msg.JsonResponse,error){
	res := Result{}
	for _,content := range contents{
		jres,err := bash.Submit(content)
		if err != nil{
			continue
		}
		if strings.Contains(jres.ReturnCode,"-31") || strings.Contains(jres.ReturnCode,"31") || strings.Contains(jres.ReturnCode,"159"){
			res.Catch = append(res.Catch, content)
		}else{
			res.NoCatch = append(res.NoCatch, content)
		}
	}
	if len(res.Catch) > 0{
		res.Found = true
		res.Result = fmt.Sprintf("存在 bash 命令执行，总数 %d 条, 检出 %d 条，未检出 %d 条", len(res.Catch)+len(res.NoCatch), len(res.Catch), len(res.NoCatch))
		jres := msg.JsonResponse{
			Code:    20000,
			Message: "",
			Result:  res,
			Type:    "success",
		}
		return &jres,nil
	}else{
		res.Found = false
		res.Result = "未发现 bash 命令执行"
		jres := msg.JsonResponse{
			Code:    40400,
			Message: "",
			Result:  res,
			Type:    "success",
		}
		return &jres,nil
	}
}
