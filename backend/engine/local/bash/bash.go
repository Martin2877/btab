package bash

import (
	"fmt"

	"github.com/Martin2877/blue-team-box/api/msg"
)

// CheckResult 单条 bash 命令检测结果
type CheckResult struct {
	Found      bool     `json:"found"`       // 是否检出
	Score      int      `json:"score"`       // 评分
	Normalized string   `json:"normalized"`  // 反混淆还原后的命令
	Steps      []string `json:"steps"`       // 反混淆步骤
	Hits       []string `json:"hits"`        // 命中规则
	Result     string   `json:"result"`      // 文字结论
}

// Check 检测单条命令
func Check(content string) *CheckResult {
	normalized, steps := deobfuscate(content)
	score, hits := scoreCmd(normalized)
	// 原文也匹配一遍，防止还原破坏特征
	rawScore, rawHits := scoreCmd(content)
	if rawScore > score {
		score = rawScore
		hits = rawHits
	}
	res := &CheckResult{
		Score:      score,
		Normalized: normalized,
		Steps:      steps,
		Hits:       hits,
		Found:      score >= bashScoreThreshold,
	}
	if res.Found {
		res.Result = fmt.Sprintf("检测到危险 bash 命令，评分 %d，命中 %d 条特征", score, len(hits))
	} else {
		res.Result = fmt.Sprintf("未发现危险 bash 命令，评分 %d", score)
	}
	return res
}

// Result SubmitLines 的结果结构（与原在线实现保持一致）
type Result struct {
	Found   bool     `json:"found"`
	Result  string   `json:"result"`
	Catch   []string `json:"catch"`
	NoCatch []string `json:"no_catch"`
}

// SubmitOnce 即时检测
func SubmitOnce(content string) (*msg.JsonResponse, error) {
	if content == "" {
		return nil, fmt.Errorf("无检测内容")
	}
	res := Check(content)
	code := 40400
	if res.Found {
		code = 20000
	}
	return &msg.JsonResponse{
		Code:    code,
		Message: res.Result,
		Result:  res,
		Type:    "success",
	}, nil
}

// SubmitLines 按行逐条检测
func SubmitLines(contents []string) (*msg.JsonResponse, error) {
	res := Result{}
	for _, content := range contents {
		if content == "" {
			continue
		}
		if Check(content).Found {
			res.Catch = append(res.Catch, content)
		} else {
			res.NoCatch = append(res.NoCatch, content)
		}
	}
	jres := &msg.JsonResponse{Result: res, Type: "success"}
	if len(res.Catch) > 0 {
		res.Found = true
		res.Result = fmt.Sprintf("存在 bash 命令执行，总数 %d 条, 检出 %d 条，未检出 %d 条", len(res.Catch)+len(res.NoCatch), len(res.Catch), len(res.NoCatch))
		jres.Code = 20000
	} else {
		res.Result = "未发现 bash 命令执行"
		jres.Code = 40400
	}
	return jres, nil
}
