package msg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"reflect"

	"github.com/gin-gonic/gin"
)

const (
	SuccessCode = 1
	ErrCode     = 0
)

// API Response 基础序列化器
type Response struct {
	Code  int         `json:"code"`
	Data  interface{} `json:"data"`
	Error string      `json:"error"`
}

// Err 通用错误处理
func ErrResp(errStr string) (int, Response) {
	res := Response{
		Code:  ErrCode,
		Data:  nil,
		Error: errStr,
	}
	return http.StatusOK, res
}

// SuccessResp 通用处理
func SuccessResp(data interface{}) (int, Response) {
	res := Response{
		Code:  SuccessCode,
		Data:  data,
		Error: "",
	}
	return http.StatusOK, res
}

// API Response 基础序列化器
type JsonResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Result  interface{} `json:"result"`
	Type    string      `json:"type"`
}

func HandleResult(result interface{}) []byte {
	switch result.(type) {
	case []byte:
		return result.([]byte)
	case string:
		return []byte(result.(string))
	default:
		marshal, err := json.Marshal(result)
		if err != nil {
			return nil
		}
		return marshal
	}
}

func ResultSuccess(c *gin.Context, result interface{}) {
	statusCode := http.StatusOK
	switch result.(type) {
	case string:
		c.JSON(
			statusCode,
			gin.H{
				"code":    statusCode,
				"message": "ok",
				"result":  result,
				"type":    "success",
			})
	default:
		var ret interface{}
		d := json.NewDecoder(bytes.NewReader(HandleResult(result)))
		d.UseNumber()
		err := d.Decode(&ret)
		if err != nil {
			fmt.Println(err)
		}
		c.JSON(
			statusCode,
			gin.H{
				"code":    statusCode,
				"message": "ok",
				"result":  &ret,
				"type":    "success",
			})
	}
}

func ResultFailed(c *gin.Context, result interface{}) {
	statusCode := http.StatusBadRequest
	switch result.(type) {
	case string:
		c.JSON(
			statusCode,
			gin.H{
				"code":    statusCode,
				"message": result,
				"result":  "",
				"type":    "failed",
			})
	default:
		var ret interface{}
		//json.Unmarshal(HandleResult(result),&ret)
		d := json.NewDecoder(bytes.NewReader(HandleResult(result)))
		d.UseNumber()
		err := d.Decode(&ret)
		if err != nil {
			fmt.Println(err)
		}
		c.JSON(
			statusCode,
			gin.H{
				"code":    statusCode,
				"message": &ret,
				"result":  "",
				"type":    "failed",
			})
	}

}

func ResultSelfDefined(c *gin.Context, result interface{}) {
	statusCode := http.StatusBadRequest
	switch result.(type) {
	case string:
		c.JSON(
			statusCode,
			gin.H{
				"code":    statusCode,
				"message": result,
				"result":  "",
				"type":    "failed",
			})
	default:
		var ret interface{}
		//json.Unmarshal(HandleResult(result),&ret)
		d := json.NewDecoder(bytes.NewReader(HandleResult(result)))
		d.UseNumber()
		err := d.Decode(&ret)
		if err != nil {
			log.Println(err)
		}
		c.JSON(
			statusCode,
			gin.H{
				"code":    statusCode,
				"message": &ret,
				"result":  "",
				"type":    "failed",
			})
	}

}

func Values2mapping(Values url.Values) map[string]interface{} {
	newValues := make(map[string]interface{})
	for k, v := range Values {
		if reflect.Indirect(reflect.ValueOf(v)).Kind() == reflect.String {
			newValues[k] = v[0]
			continue
		}
		newValues[k] = v[0]
	}
	return newValues
}

// NormalizePageParams 规范分页参数，避免除零 panic
func NormalizePageParams(page, pageSize int) (int, int) {
	if pageSize <= 0 {
		pageSize = 10
	}
	if page <= 0 {
		page = 1
	}
	return page, pageSize
}

// PageCount 计算总页数（向上取整）
func PageCount(total int64, pageSize int) int {
	if pageSize <= 0 {
		return 0
	}
	return int(math.Ceil(float64(total) / float64(pageSize)))
}
