package btt

import (
	"github.com/Martin2877/blue-team-box/api/msg"
	"github.com/Martin2877/blue-team-box/engine/local/btt"
	"github.com/gin-gonic/gin"
)

// BehinderReq 冰蝎解密请求
type BehinderReq struct {
	Data      string `json:"data"`      // 流量内容
	Pass      string `json:"pass"`      // 连接密码(默认 rebeyond)
	Direction string `json:"direction"` // c2s / s2c / auto
}

func BehinderDecrypt(c *gin.Context) {
	paJson := BehinderReq{}
	if err := c.ShouldBindJSON(&paJson); err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	if paJson.Data == "" {
		msg.ResultFailed(c, "无内容")
		return
	}
	res, err := btt.BehinderDecrypt(paJson.Data, paJson.Pass, paJson.Direction)
	if err != nil {
		msg.ResultSuccess(c, msg.JsonResponse{Code: 40400, Message: err.Error(), Type: "failed"})
		return
	}
	msg.ResultSuccess(c, msg.JsonResponse{Code: 20000, Message: "解密成功", Result: res, Type: "success"})
}

// GodzillaReq 哥斯拉解密请求
type GodzillaReq struct {
	Data string `json:"data"` // 流量内容
	Pass string `json:"pass"` // 连接密码
	Key  string `json:"key"`  // 密钥
	Enc  string `json:"enc"`  // 加密方式: auto/aes_base64/aes_raw/xor_base64/xor_raw/base64
}

func GodzillaDecrypt(c *gin.Context) {
	paJson := GodzillaReq{}
	if err := c.ShouldBindJSON(&paJson); err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	if paJson.Data == "" {
		msg.ResultFailed(c, "无内容")
		return
	}
	res, err := btt.GodzillaDecrypt(paJson.Data, paJson.Pass, paJson.Key, paJson.Enc)
	if err != nil {
		msg.ResultSuccess(c, msg.JsonResponse{Code: 40400, Message: err.Error(), Type: "failed"})
		return
	}
	msg.ResultSuccess(c, msg.JsonResponse{Code: 20000, Message: "解密成功", Result: res, Type: "success"})
}

// ShiroReq Shiro 检测请求
type ShiroReq struct {
	RememberMe string `json:"rememberMe"` // rememberMe cookie 值
	Key        string `json:"key"`        // 指定密钥(base64)，为空时爆破内置字典
	Mode       string `json:"mode"`       // cbc / gcm / auto
}

func ShiroCheck(c *gin.Context) {
	paJson := ShiroReq{}
	if err := c.ShouldBindJSON(&paJson); err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	if paJson.RememberMe == "" {
		msg.ResultFailed(c, "无 cookie 内容")
		return
	}
	res, err := btt.ShiroCheck(paJson.RememberMe, paJson.Key, paJson.Mode)
	if err != nil {
		msg.ResultSuccess(c, msg.JsonResponse{Code: 40400, Message: err.Error(), Type: "failed"})
		return
	}
	code := 40400
	message := "未找到可用密钥"
	if res.Found {
		code = 20000
		message = "检测到 Shiro 默认密钥"
	}
	msg.ResultSuccess(c, msg.JsonResponse{Code: code, Message: message, Result: res, Type: "success"})
}

// Log4j2ParseReq Log4j2 解析请求
type Log4j2ParseReq struct {
	Payload string `json:"payload"`
}

func Log4j2Parse(c *gin.Context) {
	paJson := Log4j2ParseReq{}
	if err := c.ShouldBindJSON(&paJson); err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	lookups, danger := btt.ParseLog4j2(paJson.Payload)
	code := 40400
	message := "未检测到 lookup 表达式"
	if len(lookups) > 0 {
		code = 20000
		message = "解析完成"
		if danger {
			message = "检测到 JNDI 注入风险"
		}
	}
	msg.ResultSuccess(c, msg.JsonResponse{
		Code:    code,
		Message: message,
		Result:  map[string]interface{}{"lookups": lookups, "danger": danger},
		Type:    "success",
	})
}

// Samples 返回各工具的示例输入（密文现场生成，保证可解密）
func Samples(c *gin.Context) {
	msg.ResultSuccess(c, btt.Samples())
}

// Log4j2GenReq Log4j2 payload 生成请求
type Log4j2GenReq struct {
	Target string `json:"target"` // 如 ldap://1.2.3.4:1389/Exploit 或 1.2.3.4:1389
}

func Log4j2Generate(c *gin.Context) {
	paJson := Log4j2GenReq{}
	if err := c.ShouldBindJSON(&paJson); err != nil {
		msg.ResultFailed(c, "参数不合法:"+err.Error())
		return
	}
	payloads := btt.GenerateLog4j2(paJson.Target)
	msg.ResultSuccess(c, msg.JsonResponse{
		Code:    20000,
		Message: "生成成功",
		Result:  map[string]interface{}{"payloads": payloads},
		Type:    "success",
	})
}
