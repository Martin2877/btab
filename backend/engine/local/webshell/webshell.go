package webshell

import (
	"fmt"

	"github.com/Martin2877/blue-team-box/api/msg"
)

// webshellScoreThreshold 判定为 webshell 的分数阈值
const webshellScoreThreshold = 5

// CheckResult 检测结果
type CheckResult struct {
	Webshell bool     `json:"webshell"`        // 是否判定为 webshell
	Score    int      `json:"score"`           // 规则评分
	Lang     string   `json:"lang"`            // 识别到的脚本语言
	Chain    string   `json:"chain"`           // 解码链，如 raw -> base64 -> gzip
	Code     string   `json:"code"`            // 最终解码后的代码内容
	Hits     []string `json:"hits"`            // 命中的规则名
	Result   string   `json:"result"`          // 文字结论
}

// Check 对内容做解码链还原 + 规则评分判定
func Check(content []byte) *CheckResult {
	lang := detectLang(content)
	best := &CheckResult{Lang: lang}

	for _, chain := range decodeChain(content) {
		data := chain[len(chain)-1].data
		score, hits := scoreResult(data, lang)
		if score > best.Score || (score == best.Score && len(hits) > len(best.Hits)) {
			best.Score = score
			best.Hits = hits
			best.Chain = chainName(chain)
			best.Code = printableText(data)
		}
	}
	if best.Chain == "" {
		best.Chain = "raw"
		best.Code = printableText(content)
	}
	best.Webshell = best.Score >= webshellScoreThreshold
	if best.Webshell {
		best.Result = fmt.Sprintf("发现 webshell，评分 %d，命中 %d 条特征", best.Score, len(best.Hits))
	} else {
		best.Result = fmt.Sprintf("未检测到 webshell，评分 %d", best.Score)
	}
	return best
}

// printableText 将内容转为可读文本；二进制则输出预览说明
func printableText(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	switch {
	case isJavaClass(b):
		return fmt.Sprintf("[Java class 文件，%d 字节，魔数 CAFEBABE]", len(b))
	case isJavaSerialized(b):
		return fmt.Sprintf("[Java 序列化数据，%d 字节，魔数 ACED0005]", len(b))
	case printableRatio(b) > 0.6:
		return string(b)
	default:
		return fmt.Sprintf("[二进制数据 %d 字节] %x", len(b), previewBytes(b, 64))
	}
}

func previewBytes(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// SubmitOnce 单次检测一段文本内容
func SubmitOnce(content string) (*msg.JsonResponse, error) {
	if content == "" {
		return nil, fmt.Errorf("无检测内容")
	}
	res := Check([]byte(content))
	code := 40400
	if res.Webshell {
		code = 20000
	}
	return &msg.JsonResponse{
		Code:    code,
		Message: res.Result,
		Result:  res,
		Type:    "success",
	}, nil
}

// Result SubmitLines 的结果结构（与其他载荷检测保持一致）
type Result struct {
	Found   bool     `json:"found"`
	Result  string   `json:"result"`
	Catch   []string `json:"catch"`
	NoCatch []string `json:"no_catch"`
}

// SubmitLines 按行逐条检测
func SubmitLines(contents []string) (*msg.JsonResponse, error) {
	res := Result{}
	for _, content := range contents {
		if Check([]byte(content)).Webshell {
			res.Catch = append(res.Catch, content)
		} else {
			res.NoCatch = append(res.NoCatch, content)
		}
	}
	jres := &msg.JsonResponse{Result: res, Type: "success"}
	if len(res.Catch) > 0 {
		res.Found = true
		res.Result = fmt.Sprintf("存在 webshell，总数 %d 条, 检出 %d 条，未检出 %d 条", len(res.Catch)+len(res.NoCatch), len(res.Catch), len(res.NoCatch))
		jres.Code = 20000
	} else {
		res.Result = "未发现 webshell"
		jres.Code = 40400
	}
	return jres, nil
}
