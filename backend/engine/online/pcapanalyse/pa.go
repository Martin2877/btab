package pcapanalyse

import (
	"bytes"
	"encoding/json"
	"errors"
	jsonvalue "github.com/Andrew-M-C/go.jsonvalue"
	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/pkg/conf"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
)

const Address = "http://127.0.0.1:5000"


type PA struct {
	Address string `json:"address"`
}

func NewPA()  *PA{
	address := Address
	if conf.GlobalConfig.EngineConfig.PcapAnalyseHost != ""{
		address = conf.GlobalConfig.EngineConfig.PcapAnalyseHost
	}
	return &PA{Address: address}
}


func (pa *PA) GetSecType() (result []string, err error){
	api := "/info/sec_type"
	response, err := http.Get(pa.Address + api)
	if err != nil {
		return nil, err
	}
	//程序在使用完回复后必须关闭回复的主体。
	defer response.Body.Close()

	body, _ := ioutil.ReadAll(response.Body)
	array, err := jsonvalue.MustUnmarshal(body).GetArray("result")
	if err != nil {
		return nil, err
	}
	for _,v := range array.ForRangeArr(){
		result = append(result, v.String())
	}
	return result,nil
}

func (pa *PA) GetStrategy()(result []string, err error){
	api := "/info/strategy"
	response, err := http.Get(pa.Address + api)
	if err != nil {
		return nil, err
	}
	//程序在使用完回复后必须关闭回复的主体。
	defer response.Body.Close()

	body, _ := ioutil.ReadAll(response.Body)
	array, err := jsonvalue.MustUnmarshal(body).GetArray("result")
	if err != nil {
		return nil, err
	}
	for _,v := range array.ForRangeArr(){
		result = append(result, v.String())
	}
	return result,nil
}

func (pa *PA) Upload(filePath string) ([]byte,error) {
	api := "/pa/upload"
	f, err := os.Open(filePath)
	if err != nil{
		return nil,err
	}
	defer f.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	fw, err := writer.CreateFormFile("file",  path.Base(filePath))
	if err != nil {
		return nil, err
	}
	_, err = io.Copy(fw, f)
	if err != nil {
		return nil, err
	}

	err = writer.Close() // close writer before POST request
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(pa.Address + api, writer.FormDataContentType(), body)
	if err != nil {
		return nil, err
	}

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil,err
	}
	result, err := jsonvalue.MustUnmarshal(content).GetString("result")
	if err != nil {
		return nil,err
	}
	return []byte(result), nil
}


func (pa *PA) Submit(uid string, secType string, strategy string) (*msg.JsonResponse,error){
	api := "/pa/submit"
	v := url.Values{}
	v.Set("pcapname", uid)
	v.Set("sec_type", secType)
	v.Set("strategy", strategy)
	resp, err := http.PostForm(pa.Address+api,v)
	if err != nil {
		return nil,err
	}
	defer resp.Body.Close()//一定要关闭resp.Body
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil,err
	}

	// 返回结果
	jres := msg.JsonResponse{}
	err3 := json.Unmarshal(content,&jres)
	if err3 != nil {
		return nil, err3
	}
	return &jres,nil
}

func (pa *PA) Fetch(uuid string) (*msg.JsonResponse,error){
	api := "/pa/fetch"
	v := url.Values{}
	v.Set("uuid", uuid)
	resp, err := http.PostForm(pa.Address+api,v)
	if err != nil {
		return nil,err
	}
	if err !=nil{
		return nil,err
	}
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil,err
	}
	// 返回结果
	jres := msg.JsonResponse{}
	err3 := json.Unmarshal(content,&jres)
	if err3 != nil {
		return nil, err3
	}
	err2 := resp.Body.Close()
	if err2 != nil {
		return nil,errors.New("access timeout")
	}
	return &jres,nil
}