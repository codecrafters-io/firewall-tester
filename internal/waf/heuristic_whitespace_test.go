package waf

import (
	"bytes"
	"encoding/json"
	"net/url"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"testing"
)

func portableWhitespaceScenario(t *testing.T) scenario {
	t.Helper()
	for _, test := range stageScenarios(6) {
		if test.Name == "heuristic whitespace is portable" {
			return test
		}
	}
	t.Fatal("portable whitespace scenario not found")
	return scenario{}
}

func whitespaceInputs(t *testing.T, target string) []string {
	t.Helper()
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		t.Fatal(err)
	}
	inputs := []string{parsed.Path}
	for _, values := range query {
		inputs = append(inputs, values...)
	}
	return inputs
}

// The supplied heuristic policy matches exactly the documented whitespace in Go.
func TestGoHeuristicWhitespace(t *testing.T) {
	// Arrange
	test := portableWhitespaceScenario(t)
	var policy struct {
		Heuristics struct {
			Signals []struct {
				ID, Pattern string
				Weight      int
			}
		}
	}
	if err := json.Unmarshal([]byte(test.Policy), &policy); err != nil {
		t.Fatal(err)
	}
	for _, check := range test.Probes {
		t.Run(check.Target, func(t *testing.T) {
			// Arrange
			inputs := whitespaceInputs(t, check.Target)
			score := 0
			var fired []string
			// Act
			for _, signal := range policy.Heuristics.Signals {
				pattern, err := regexp.Compile(signal.Pattern)
				if err != nil {
					t.Fatal(err)
				}
				for _, input := range inputs {
					if pattern.MatchString(input) {
						score += signal.Weight
						fired = append(fired, signal.ID)
						break
					}
				}
			}
			// Assert
			if strconv.Itoa(score) != check.WantHeaders["X-WAF-Score"] || !slices.Equal(fired, check.WantSignals) {
				t.Fatalf("expected score %s and signals %q, got %d and %q", check.WantHeaders["X-WAF-Score"], check.WantSignals, score, fired)
			}
		})
	}
}

// Python's default regex engine gives the same scores for the supplied policy.
func TestPythonHeuristicWhitespace(t *testing.T) {
	// Arrange
	test := portableWhitespaceScenario(t)
	var inputs [][]string
	for _, check := range test.Probes {
		inputs = append(inputs, whitespaceInputs(t, check.Target))
	}
	payload, err := json.Marshal(map[string]any{"policy": test.Policy, "inputs": inputs})
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("python3", "-c", `
import json
import re
import sys

data = json.load(sys.stdin)
signals = json.loads(data["policy"])["heuristics"]["signals"]
result = []
for inputs in data["inputs"]:
    fired = [signal for signal in signals if any(re.search(signal["pattern"], value) for value in inputs)]
    result.append({"score": sum(signal["weight"] for signal in fired), "signals": [signal["id"] for signal in fired]})
print(json.dumps(result))
`)
	command.Stdin = bytes.NewReader(payload)
	// Act
	output, err := command.CombinedOutput()
	// Assert
	if err != nil {
		t.Fatalf("Python scoring failed: %v: %s", err, output)
	}
	var results []struct {
		Score   int
		Signals []string
	}
	if err := json.Unmarshal(output, &results); err != nil {
		t.Fatal(err)
	}
	if len(results) != len(test.Probes) {
		t.Fatalf("expected %d scores, got %d", len(test.Probes), len(results))
	}
	for i, actual := range results {
		check := test.Probes[i]
		if strconv.Itoa(actual.Score) != check.WantHeaders["X-WAF-Score"] || !slices.Equal(actual.Signals, check.WantSignals) {
			t.Errorf("%s: expected score %s and signals %q, got %d and %q", check.Target, check.WantHeaders["X-WAF-Score"], check.WantSignals, actual.Score, actual.Signals)
		}
	}
}

// Whitespace scoring and its block decisions survive the full HTTP grading path.
func TestGraderAcceptsPortableHeuristicWhitespace(t *testing.T) {
	// Arrange
	test := portableWhitespaceScenario(t)
	launch := queryInspectionLaunch(t, true)
	// Act
	err := runScenario(test, launch, t.Logf)
	// Assert
	if err != nil {
		t.Fatal(err)
	}
}
