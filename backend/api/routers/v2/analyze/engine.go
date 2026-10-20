package analyze

import (
	"encoding/json"

	"github.com/Martin2877/blue-team-box/engine"
)

// engineRun 执行 DSL 查询，返回各步骤结果与最终结果
func engineRun(query string) (string, error) {
	engines := engine.NewEngines()
	engines.ClearSteps()
	if err := engines.LoadQueries(query); err != nil {
		return "", err
	}
	if err := engines.Run(); err != nil {
		return "", err
	}
	out := map[string]interface{}{
		"final": engines.GetFinalResult(),
	}
	var steps []string
	for i := range engines.Steps {
		steps = append(steps, engines.GetResult(i))
	}
	out["steps"] = steps
	b, _ := json.Marshal(out)
	return string(b), nil
}
