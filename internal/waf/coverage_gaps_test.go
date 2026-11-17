package waf

import (
	"strings"
	"testing"
)

// Firewall errors allow JSON formatting differences but contain only error.rule.
func TestErrorBodyShape(t *testing.T) {
	for _, check := range []struct {
		name, body string
		valid      bool
	}{
		{"compact", `{"error":{"rule":"literal"}}`, true},
		{"whitespace", " { \"error\": { \"rule\": \"literal\" } } \n", true},
		{"escaped identifier", `{"error":{"rule":"\u006citeral"}}`, true},
		{"outer request echo", `{"error":{"rule":"literal"},"request":"secret"}`, false},
		{"inner request echo", `{"error":{"rule":"literal","request":"secret"}}`, false},
		{"duplicate rule", `{"error":{"rule":"secret","rule":"literal"}}`, false},
		{"wrong rule", `{"error":{"rule":"other"}}`, false},
		{"trailing data", `{"error":{"rule":"literal"}} {}`, false},
	} {
		t.Run(check.name, func(t *testing.T) {
			// Arrange
			body := []byte(check.body)
			// Act
			valid := validErrorBody(body, "literal")
			// Assert
			if valid != check.valid {
				t.Fatalf("expected valid=%t, got %t", check.valid, valid)
			}
		})
	}
}

// Each single-fault solution fails the stage that introduces its violated rule.
func TestGraderRejectsDescriptionCoverageGaps(t *testing.T) {
	for _, check := range []struct {
		name         string
		stage        int
		replacements []string
		failure      string
	}{
		{
			name: "request echo in denial", stage: 3,
			replacements: []string{`json.dumps({"error": {"rule": rule}})`, `json.dumps({"error": {"rule": rule}, "request": self.path})`},
			failure:      "expected JSON body containing only error.rule",
		},
		{
			name: "regex denylist term", stage: 3,
			replacements: []string{`if any(rule["term"] in value for value in inputs)`, `if any(re.search(rule["term"], value) for value in inputs)`},
			failure:      "denylist terms are literal substrings",
		},
		{
			name: "comma split header", stage: 4,
			replacements: []string{`for value in self.headers.get_all(name, []))`, `for value in [part for occurrence in self.headers.get_all(name, []) for part in occurrence.split(",")])`},
			failure:      "header values are not comma split",
		},
		{
			name: "first header occurrence only", stage: 4,
			replacements: []string{`self.headers.get_all(name, [])`, `self.headers.get_all(name, [])[:1]`},
			failure:      "every configured header occurrence is inspected",
		},
		{
			name: "path validation requires normalization field", stage: 4,
			replacements: []string{`decoded_path = decode_component(raw_path)`, `decoded_path = decode_component(raw_path) if "normalization" in policy else raw_path`},
			failure:      "path validation without normalization policy",
		},
		{
			name: "score headers reach origin", stage: 5,
			replacements: []string{`connection.putheader("Content-Length", str(len(body)))`, "for key, value in diagnostics.items():\n                    connection.putheader(key, value)\n                connection.putheader(\"Content-Length\", str(len(body)))"},
			failure:      "forwarded request header X-WAF-Score: expected absent",
		},
		{
			name: "validation errors include scores", stage: 5,
			replacements: []string{`payload = json.dumps({"error": {"rule": rule}}).encode()`, "if status == 400:\n                diagnostics = {\"X-WAF-Score\": \"0\"}\n            payload = json.dumps({\"error\": {\"rule\": rule}}).encode()"},
			failure:      "validation errors omit score diagnostics",
		},
		{
			name: "health includes scores", stage: 5,
			replacements: []string{"self.send_response(200)\n                self.send_header", "self.send_response(200)\n                self.send_header(\"X-WAF-Score\", \"0\")\n                self.send_header"},
			failure:      "unexpected X-WAF-Score",
		},
		{
			name: "heuristic joins inputs", stage: 5,
			replacements: []string{`if any(re.search(signal["pattern"], value) for value in inputs)`, `if re.search(signal["pattern"], "".join(inputs))`},
			failure:      "heuristic patterns keep input boundaries",
		},
		{
			name: "failed detector retry", stage: 6,
			replacements: []string{`ml_score = classify(args.detector, inputs)`, "ml_score = classify(args.detector, inputs)\n                if ml_score is None:\n                    ml_score = classify(args.detector, inputs)"},
			failure:      "expected 1 detector calls, got 2",
		},
		{
			name: "detector follows redirect", stage: 6,
			replacements: []string{`result = json.loads(response.read())`, "if response.status == 302:\n                response.read()\n                connection.close()\n                connection = http.client.HTTPConnection(url.hostname, url.port, timeout=0.2)\n                connection.request(\"GET\", response.getheader(\"Location\"))\n                response = connection.getresponse()\n            result = json.loads(response.read())"},
			failure:      "detector failure fallback: redirect",
		},
		{
			name: "ML overrides standalone heuristic", stage: 6,
			replacements: []string{`if not match and ml_score >= classifier["threshold"]:`, `if ml_score >= classifier["threshold"]:`},
			failure:      "standalone heuristic cutoff precedes ML",
		},
		{
			name: "JSON validation precedes size", stage: 8,
			replacements: []string{`if inspection and length > inspection["max_body_bytes"]:`, "if inspection and length > inspection[\"max_body_bytes\"]:\n                try:\n                    parse_json(self.rfile.read(length).decode(\"utf-8\"))\n                except (ValueError, UnicodeError):\n                    self.reject(400, \"invalid_request\")\n                    return\n            if inspection and length > inspection[\"max_body_bytes\"]:"},
			failure:      "request size precedes JSON validation",
		},
		{
			name: "JSON scalars become inputs", stage: 8,
			replacements: []string{"    return []\n\n\ndef classify", "    return [str(value)]\n\n\ndef classify"},
			failure:      "JSON values and media-type case",
		},
		{
			name: "log mode skips body validation", stage: 8,
			replacements: []string{`inspection = policy.get("inspection")`, `inspection = policy.get("inspection") if policy.get("mode") != "log" else None`},
			failure:      "log mode: request size precedes JSON validation",
		},
		{
			name: "form names skip validation", stage: 8,
			replacements: []string{`decode_component(key, True)`, `pass`},
			failure:      "nested and escaped duplicate keys",
		},
		{
			name: "patch path prefix matching", stage: 10,
			replacements: []string{`decoded_path == patch["path"]`, `decoded_path.startswith(patch["path"])`},
			failure:      "patch works without other inspection and in log mode",
		},
		{
			name: "patch duplicate keys use last value", stage: 10,
			replacements: []string{`value = parse_json(body.decode("utf-8"))`, `value = json.loads(body.decode("utf-8"))`},
			failure:      "patch works without other inspection and in log mode",
		},
		{
			name: "path plus becomes space", stage: 4,
			replacements: []string{`decoded_path = decode_component(raw_path)`, `decoded_path = decode_component(raw_path, True)`},
			failure:      "path plus and one-layer decoding",
		},
		{
			name: "route matches raw path", stage: 7,
			replacements: []string{`if decoded_path == route["path"]:`, `if raw_path == route["path"]:`},
			failure:      "route matching decodes once without normalization",
		},
		{
			name: "last matching route wins", stage: 7,
			replacements: []string{"thresholds = route\n                        break", "thresholds = route"},
			failure:      "first matching route wins",
		},
		{
			name: "response pattern precedes size", stage: 9,
			replacements: []string{`if len(content) > response_policy["max_bytes"]:`, `if len(content) > response_policy["max_bytes"] and not any(re.search(pattern, content.decode("utf-8", errors="replace")) for pattern in response_policy["deny_patterns"]):`},
			failure:      "response size precedes leak matching",
		},
		{
			name: "response denial drops scores", stage: 9,
			replacements: []string{`self.reject(403, "response_leak", diagnostics)`, `self.reject(403, "response_leak")`},
			failure:      "response denial retains detection diagnostics",
		},
		{
			name: "response joins decoded strings", stage: 9,
			replacements: []string{`for value in candidates):`, `for value in ["".join(candidates)]):`},
			failure:      "response strings keep their boundaries",
		},
		{
			name: "patch accepts string argument", stage: 10,
			replacements: []string{`isinstance(values, list) and len(values) > 0`, `(isinstance(values, list) or values in patch["allowed_values"]) and len(values) > 0`, `for item in values))`, `for item in ([values] if isinstance(values, str) else values)))`},
			failure:      "patch validates the complete JSON shape",
		},
	} {
		t.Run(check.name, func(t *testing.T) {
			// Arrange
			launch := mutatedReference(t, check.replacements...)
			// Act
			err := verify(check.stage, launch, t.Logf)
			// Assert
			if err == nil || !strings.Contains(err.Error(), check.failure) {
				t.Fatalf("expected rejection containing %q, got %v", check.failure, err)
			}
		})
	}
}
