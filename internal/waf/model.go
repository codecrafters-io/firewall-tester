package waf

import (
	_ "embed"
	"encoding/json"
	"math"
	"sort"
	"strings"
)

//go:embed model.json
var modelData []byte

type scoringModel struct {
	Bias    float64            `json:"bias"`
	Weights map[string]float64 `json:"weights"`
}

var exerciseModel = func() scoringModel {
	var model scoringModel
	if err := json.Unmarshal(modelData, &model); err != nil {
		panic(err)
	}
	return model
}()

// Exercise inputs are already normalized by the WAF before inference.
func exerciseScore(inputs []string) int {
	text := []rune(strings.ToLower(strings.Join(inputs, "\n")))
	features := map[string]bool{}
	for index := 0; index+2 < len(text); index++ {
		features[string(text[index:index+3])] = true
	}
	tokens := make([]string, 0, len(exerciseModel.Weights))
	for token := range exerciseModel.Weights {
		tokens = append(tokens, token)
	}
	sort.Strings(tokens)
	logit := exerciseModel.Bias
	for _, token := range tokens {
		if features[token] {
			logit += exerciseModel.Weights[token]
		}
	}
	logit = max(-40, min(40, logit))
	return int(math.RoundToEven(100 / (1 + math.Exp(-logit))))
}
