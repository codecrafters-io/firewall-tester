package waf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const queryInspectionCode = `            inputs = [self.path, body.decode("utf-8", errors="replace")]
            if policy.get("normalization"):
                def decode(text, plus=False):
                    if re.search(r"%(?![0-9a-fA-F]{2})", text):
                        raise ValueError("invalid percent escape")
                    if plus:
                        text = text.replace("+", " ")
                    return urllib.parse.unquote(text, errors="strict")

                try:
                    target = urllib.parse.urlsplit(self.path)
                    inputs = [decode(target.path)]
                    if target.query:
                        for part in target.query.split("&"):
                            name, separator, value = part.partition("=")
                            decode(name, plus=True)
                            if not separator and INSPECT_BARE:
                                value = name
                            inputs.append(decode(value, plus=True))
                    for name in policy.get("inspect_headers", []):
                        for value in self.headers.get_all(name, []):
                            inputs.append(value.encode("latin-1").decode("utf-8"))
                    inputs.append(body.decode("utf-8", errors="replace"))
                    inputs = [unicodedata.normalize("NFKC", value).casefold() for value in inputs]
                except (ValueError, UnicodeError):
                    self.reject(400, "invalid_request", diagnostics)
                    return`

const queryHeuristicCode = `            heuristic = policy.get("heuristics")
            if heuristic:
                fired = [signal for signal in heuristic["signals"]
                         if any(re.search(signal["pattern"], value) for value in inputs)]
                score = sum(signal["weight"] for signal in fired)
                diagnostics["X-WAF-Score"] = score
                if fired:
                    diagnostics["X-WAF-Signals"] = ",".join(signal["id"] for signal in fired)
                if not match and score >= heuristic["threshold"]:
                    if policy.get("mode", "block") == "block":
                        self.reject(403, "heuristic_score", diagnostics)
                        return
                    diagnostics["X-WAF-Match"] = "heuristic_score"
`

const queryClassifierCode = `            if policy.get("classifier"):
                detector = urllib.parse.urlsplit(args.detector)
                client = http.client.HTTPConnection(detector.hostname, detector.port, timeout=1)
                try:
                    client.request("POST", "/classify", json.dumps({"inputs": inputs}),
                                   {"Content-Type": "application/json"})
                    score = json.loads(client.getresponse().read())["score"]
                finally:
                    client.close()
                diagnostics["X-WAF-ML-Score"] = score
                diagnostics["X-WAF-Detector-Status"] = "ok"
                if score >= policy["classifier"]["threshold"]:
                    self.reject(403, "ml_score", diagnostics)
                    return
`

func queryInspectionLaunch(t *testing.T, inspectBare bool) launchFunc {
	t.Helper()
	source := filepath.Join(courseRoot(), "solutions", "python", "04-kg7", "code")
	target := t.TempDir()
	if err := os.Mkdir(filepath.Join(target, "app"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"app/main.py", "your_program.sh", "pyproject.toml", "uv.lock"} {
		data, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		if name == "app/main.py" {
			text := string(data)
			oldInputs := `            inputs = [self.path, body.decode("utf-8", errors="replace")]`
			origin := `            connection = http.client.HTTPConnection(origin.hostname, origin.port, timeout=3)`
			if strings.Count(text, oldInputs) != 1 || strings.Count(text, origin) != 1 {
				t.Fatal("stage 4 fixture insertion points changed")
			}
			bare := "False"
			if inspectBare {
				bare = "True"
			}
			text = "import re\nimport unicodedata\n" + text
			text = strings.Replace(text, oldInputs, strings.ReplaceAll(queryInspectionCode, "INSPECT_BARE", bare), 1)
			text = strings.Replace(text, origin, queryHeuristicCode+queryClassifierCode+origin, 1)
			data = []byte(text)
		}
		if err := os.WriteFile(filepath.Join(target, name), data, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return referenceLaunch(t, target)
}

func bareQueryScenarios(t *testing.T) []scenario {
	t.Helper()
	var tests []scenario
	for _, candidate := range append(stageScenarios(5), stageScenarios(7)...) {
		switch candidate.Name {
		case "bare query parameters are inspected independently",
			"bare query log mode preserves forwarding",
			"classifier receives separate normalized fields",
			"classifier receives bare query parameters":
			tests = append(tests, candidate)
		}
	}
	if len(tests) != 4 {
		t.Fatalf("expected four query-inspection scenarios, got %d", len(tests))
	}
	return tests
}

// Bare query text is inspected, decoded once, forwarded unchanged, and sent to the detector.
func TestGraderAcceptsBareQueryInspection(t *testing.T) {
	for _, test := range bareQueryScenarios(t) {
		t.Run(test.Name, func(t *testing.T) {
			// Arrange
			launch := queryInspectionLaunch(t, true)
			// Act
			err := runScenario(test, launch, t.Logf)
			// Assert
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Dropping bare query text fails literal matching, log diagnostics, and detector-input checks.
func TestGraderRejectsIgnoredBareQuery(t *testing.T) {
	for _, test := range bareQueryScenarios(t) {
		t.Run(test.Name, func(t *testing.T) {
			// Arrange
			launch := queryInspectionLaunch(t, false)
			want := "inspection inputs:"
			switch test.Name {
			case "bare query parameters are inspected independently":
				want = "GET /search?union+select+password+from+users: expected HTTP 403, got 200"
			case "bare query log mode preserves forwarding":
				want = `expected X-WAF-Match="sql-union", got ""`
			}
			// Act
			err := runScenario(test, launch, t.Logf)
			// Assert
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("expected bare-query failure containing %q, got %v", want, err)
			}
		})
	}
}
