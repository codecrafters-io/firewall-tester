package waf

import "time"

const normPolicy = `"normalization":true,"inspect_headers":["X-Search"]`
const rules = `"denylist":[{"id":"xss-script","term":"<script"},{"id":"sql-union","term":"union select"}]`
const heuristics = `"heuristics":{"threshold":5,"signals":[{"id":"sql-or","pattern":"or\\s+1\\s*=\\s*1","weight":3},{"id":"sql-comment","pattern":"--","weight":2}]}`
const classifier = `"classifier":{"threshold":70}`
const decisions = `"decisions":{"default":{"ml_high":90,"ml_medium":60,"heuristic_high":5,"heuristic_medium":3},"routes":[{"path":"/articles","ml_high":95,"ml_medium":80,"heuristic_high":8,"heuristic_medium":5}]}`
const inspect = `"inspection":{"max_body_bytes":64}`
const patch = `"virtual_patches":[{"id":"export-fields","method":"POST","path":"/api/export","argument":"fields","allowed_values":["customer_id","name"]}]`

func policy(parts ...string) string {
	s := "{"
	for i, p := range parts {
		if i > 0 {
			s += ","
		}
		s += p
	}
	return s + "}"
}
func allow(target string) probe {
	return probe{
		Target:  target,
		Status:  200,
		Forward: true,
		Absent: []string{
			"X-WAF-Match",
		},
	}
}
func deny(target, rule string) probe {
	return probe{
		Target: target,
		Status: 403,
		Rule:   rule,
	}
}
func invalid(target string) probe {
	return probe{
		Target: target,
		Status: 400,
		Rule:   "invalid_request",
	}
}
func invalidBody(contentType, body string) probe {
	return probe{
		Method: "POST",
		Target: "/echo",
		Body:   body,
		Headers: map[string]string{
			"Content-Type": contentType,
		},
		Status: 400,
		Rule:   "invalid_request",
	}
}
func stageScenarios(stage int) []scenario {
	switch stage {
	case 1:
		return []scenario{
			{
				Name:   "health remains available",
				Policy: "{}",
				Probes: []probe{
					{
						Target: "/health",
						Status: 200,
					},
					{
						Target: "/health",
						Status: 200,
					},
				},
			},
		}
	case 2:
		scenarios := []scenario{}
		for _, method := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
			// Each supported method preserves its request body and target.
			scenarios = append(scenarios, scenario{
				Name:   "proxy preserves " + method,
				Policy: "{}",
				Probes: []probe{
					{
						Method:  method,
						Target:  "/echo?method=original",
						Body:    `{ "value": "original" }`,
						Headers: map[string]string{"Content-Type": "application/json"},
						Status:  200,
						Forward: true,
					},
				},
			})
		}
		// An incomplete origin response becomes a safe gateway error.
		scenarios = append(scenarios, scenario{
			Name:   "incomplete origin response returns a gateway error",
			Policy: "{}", OriginTruncated: true,
			Probes: []probe{
				{Target: "/truncated", Status: 502, Rule: "origin_unavailable", Forward: true},
			},
		})
		return append(scenarios, []scenario{

			{
				Name:    "unavailable origin returns a gateway error",
				Policy:  "{}",
				Offline: true,
				Probes: []probe{
					{
						Target: "/products",
						Status: 502,
						Rule:   "origin_unavailable",
					},
				},
			},

			{
				Name:   "transparent web proxy",
				Policy: "{}",
				Probes: []probe{
					allow("/products?q=book%20case"),
					allow("/products/../admin?x=1"),
					{
						Method: "PATCH",
						Target: "/echo?source=course",
						Body:   `{ "name": "Mira", "extra": true }`,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
						Status:  200,
						Forward: true,
					},
				},
			},

			{
				Name:         "origin errors are relayed",
				Policy:       "{}",
				OriginStatus: 400,
				OriginBody:   `{"error":"origin"}`,
				Probes: []probe{
					{
						Target:  "/bad",
						Status:  400,
						Forward: true,
					},
				},
			},

			{
				Name:         "origin redirects are relayed",
				Policy:       "{}",
				OriginStatus: 302,
				Probes: []probe{
					{
						Target:  "/redirect",
						Status:  302,
						Forward: true,
					},
				},
			},
		}...)
	case 3:
		return []scenario{

			{
				Name:   "literal block prevents origin traffic",
				Policy: policy(`"mode":"block"`, rules),
				Probes: []probe{
					{
						Method: "POST",
						Target: "/preview",
						Body:   "<script>alert(1)</script>",
						Status: 403,
						Rule:   "xss-script",
					},
					allow("/products"),
				},
			},

			{
				Name:   "log mode preserves matched bytes",
				Policy: policy(`"mode":"log"`, rules),
				Probes: []probe{
					{
						Method:  "POST",
						Target:  "/preview",
						Body:    "<script>alert(1)</script>",
						Status:  200,
						Forward: true,
						WantHeaders: map[string]string{
							"X-WAF-Match": "xss-script",
						},
					},
					allow("/clean"),
				},
			},

			{
				Name:   "policy values and order control decisions",
				Policy: policy(`"denylist":[{"id":"first","term":"needle"},{"id":"second","term":"needle"}]`),
				Probes: []probe{
					deny("/needle", "first"),
					allow("/NEEDLE"),
				},
			},
		}
	case 4:
		return []scenario{

			{
				Name:   "decoded inputs and one-layer boundary",
				Policy: policy(normPolicy, rules),
				Probes: []probe{
					deny("/search?q=%3Cscript%3E", "xss-script"),
					allow("/search?q=%253Cscript%253E"),
					{
						Target: "/search",
						Headers: map[string]string{
							"x-search": "\uff1c\uff33\uff23\uff32\uff29\uff30\uff34",
						},
						Status: 403,
						Rule:   "xss-script",
					},
				},
			},

			{
				Name:   "normalization preserves forwarding",
				Policy: policy(normPolicy, rules, `"mode":"log"`),
				Probes: []probe{
					{
						Target:  "/search?q=%3Cscript%3E",
						Status:  200,
						Forward: true,
						WantHeaders: map[string]string{
							"X-WAF-Match": "xss-script",
						},
					},
				},
			},

			{
				Name:   "case folding and field boundaries",
				Policy: policy(normPolicy, `"denylist":[{"id":"fold","term":"strasse"},{"id":"boundary","term":"joined"}]`),
				Probes: []probe{
					deny("/search?q=Stra%C3%9Fe", "fold"),
					allow("/search?a=join&b=ed"),
					allow("/search?joined=clean"),
				},
			},

			{
				Name:   "invalid encodings are rejected before forwarding",
				Policy: policy(normPolicy, rules),
				Probes: []probe{
					invalid("/search?q=%ZZ"),
					invalid("/search?q=%FF"),
					invalid("/search?%ZZ=clean"),
					invalid("/search%FF"),
					{
						Target:  "/search%ZZ",
						Status:  400,
						AnyBody: true,
					},
				},
			},
		}
	case 5:
		return []scenario{

			{
				Name:   "weighted signal union",
				Policy: policy(normPolicy, heuristics),
				Probes: []probe{
					{
						Target: "/search?q=or+1%3D1+--",
						Status: 403,
						Rule:   "heuristic_score",
						WantHeaders: map[string]string{
							"X-WAF-Score": "5",
						},
						WantSignals: []string{"sql-or", "sql-comment"},
					},
					{
						Target:  "/search?a=or+1%3D1&b=or+1%3D1",
						Status:  200,
						Forward: true,
						WantHeaders: map[string]string{
							"X-WAF-Score": "3",
						},
						WantSignals: []string{"sql-or"},
					},
					{
						Target:  "/clean",
						Status:  200,
						Forward: true,
						WantHeaders: map[string]string{
							"X-WAF-Score": "0",
						},
						Absent: []string{
							"X-WAF-Signals",
							"X-WAF-Match",
						},
					},
				},
			},

			{
				Name:   "denylist precedence retains full diagnostics",
				Policy: policy(normPolicy, heuristics, `"denylist":[{"id":"literal","term":"or 1=1"}]`),
				Probes: []probe{
					{
						Target: "/search?q=or+1%3D1+--",
						Status: 403,
						Rule:   "literal",
						WantHeaders: map[string]string{
							"X-WAF-Score": "5",
						},
						WantSignals: []string{"sql-or", "sql-comment"},
					},
				},
			},
		}
	case 6:
		scenarios := []scenario{
			{
				Name:   "zero is a valid ML score",
				Policy: policy(normPolicy, classifier),
				Score:  0,
				Probes: []probe{
					{
						Target:  "/clean",
						Status:  200,
						Forward: true,
						WantHeaders: map[string]string{
							"X-WAF-ML-Score":        "0",
							"X-WAF-Detector-Status": "ok",
						},
					},
				},
			},
			{
				Name:   "classifier protocol and inclusive cutoff",
				Policy: policy(normPolicy, classifier),
				Score:  70,
				Probes: []probe{
					{
						Target: "/search?q=example",
						Status: 403,
						Rule:   "ml_score",
						WantHeaders: map[string]string{
							"X-WAF-ML-Score":        "70",
							"X-WAF-Detector-Status": "ok",
						},
						Inputs: []string{
							"/search",
							"example",
							"",
						},
					},
				},
			},
			{
				Name:   "denylist matches still consult the detector once",
				Policy: policy(normPolicy, rules, classifier),
				Score:  0,
				Probes: []probe{
					{
						Target: "/search?q=%3Cscript%3E",
						Status: 403,
						Rule:   "xss-script",
						WantHeaders: map[string]string{
							"X-WAF-ML-Score":        "0",
							"X-WAF-Detector-Status": "ok",
						},
						Inputs: []string{
							"/search",
							"<script>",
							"",
						},
					},
				},
			},
		}
		for _, mode := range []string{
			"error",
			"slow",
			"late",
			"slow_body",
			"slow_headers",
			"truncated",
			"fraction",
			"boolean",
			"missing",
			"trailing",
			"redirect",
			"null",
			"range",
		} {
			scenarios = append(scenarios, scenario{
				Name:         "detector failure fallback: " + mode,
				Policy:       policy(normPolicy, classifier),
				DetectorMode: mode,
				Probes: []probe{
					{
						Target:      "/search?q=clean",
						MaxDuration: 600 * time.Millisecond,
						Status:      200,
						Forward:     true,
						WantHeaders: map[string]string{
							"X-WAF-Detector-Status": "unavailable",
						},
						Absent: []string{
							"X-WAF-ML-Score",
						},
					},
				},
			})
		}
		return append(scenarios, scenario{
			Name:         "failed detector retains heuristic block",
			Policy:       policy(normPolicy, classifier, heuristics),
			DetectorMode: "error",
			Probes: []probe{
				deny("/search?q=or+1%3D1+--", "heuristic_score"),
			},
		})
	case 7:
		return []scenario{

			{
				Name:   "route-specific decisions",
				Policy: policy(normPolicy, heuristics, classifier, decisions),
				Score:  70,
				Probes: []probe{
					deny("/search?q=or+1%3D1", "combined_scores"),
					allow("/articles?q=or+1%3D1"),
					deny("/articles/extra?q=or+1%3D1", "combined_scores"),
					deny("/Articles?q=or+1%3D1", "combined_scores"),
				},
			},

			{
				Name:   "high cutoff and fallback",
				Policy: policy(normPolicy, heuristics, classifier, decisions),
				Score:  95,
				Probes: []probe{
					deny("/articles", "ml_high"),
				},
			},

			{
				Name:   "low classifier cannot cancel the route's heuristic floor",
				Policy: policy(normPolicy, heuristics, classifier, decisions),
				Score:  10,
				Probes: []probe{
					deny("/search?q=or+1%3D1+--", "heuristic_high"),
					allow("/articles?q=or+1%3D1+--"),
				},
			},

			{
				Name:   "heuristic floor precedes the ML cutoff",
				Policy: policy(normPolicy, heuristics, classifier, decisions),
				Score:  95,
				Probes: []probe{
					deny("/search?q=or+1%3D1+--", "heuristic_high"),
				},
			},

			{
				Name:   "route rules cannot bypass literal deny",
				Policy: policy(normPolicy, rules, heuristics, classifier, decisions),
				Score:  0,
				Probes: []probe{
					deny("/articles?q=%3Cscript%3E", "xss-script"),
				},
			},
		}
	case 8:
		return []scenario{
			// Structured inspection adds no body input for an empty request.
			{
				Name:   "empty inspected bodies contribute no strings",
				Policy: policy(normPolicy, inspect, classifier),
				Probes: []probe{
					{Target: "/echo", Status: 200, Forward: true, Inputs: []string{"/echo"}},
					{Method: "POST", Target: "/echo", Headers: map[string]string{"Content-Type": "application/json"}, Status: 200, Forward: true, Inputs: []string{"/echo"}},
				},
			},
			// Empty bodies are also omitted when normalization is disabled.
			{
				Name:   "empty inspected raw body contributes no string",
				Policy: policy(inspect, classifier),
				Probes: []probe{
					{Target: "/echo?q=original", Status: 200, Forward: true, Inputs: []string{"/echo?q=original"}},
				},
			},

			{
				Name:   "parsed string values reach the detector",
				Policy: policy(normPolicy, inspect, classifier),
				Score:  0,
				Probes: []probe{
					{
						Method: "POST",
						Target: "/echo",
						Body:   `{"key":["Mira","\u003cscript"]}`,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
						Status:  200,
						Forward: true,
						Inputs: []string{
							"/echo",
							"mira",
							"<script",
						},
					},
				},
			},

			{
				Name:   "decoded structured values",
				Policy: policy(normPolicy, rules, inspect),
				Probes: []probe{
					{
						Method: "POST",
						Target: "/echo",
						Body:   `{"nested":[{"value":"\u003cscript>"}]}`,
						Headers: map[string]string{
							"Content-Type": "application/json; charset=utf-8",
						},
						Status: 403,
						Rule:   "xss-script",
					},
					{
						Method: "POST",
						Target: "/echo",
						Body:   "q=%3Cscript%3E",
						Headers: map[string]string{
							"Content-Type": "application/x-www-form-urlencoded",
						},
						Status: 403,
						Rule:   "xss-script",
					},
					{
						Method: "POST",
						Target: "/echo",
						Body:   `{ "key": "Mira", "extra": [1,true] }`,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
						Status:  200,
						Forward: true,
					},
				},
			},

			{
				Name:   "uninspectable input never reaches detector or origin",
				Policy: policy(normPolicy, inspect, classifier),
				Score:  99,
				Probes: []probe{
					{
						Method: "POST",
						Target: "/echo",
						Body:   `{"value":"ok","value":"bad"}`,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
						Status: 400,
						Rule:   "invalid_request",
					},
					{
						Method: "POST",
						Target: "/echo",
						Body:   "<b>upload</b>",
						Headers: map[string]string{
							"Content-Type": "multipart/form-data",
						},
						Status: 415,
						Rule:   "unsupported_body",
					},
					{
						Method: "POST",
						Target: "/echo",
						Body:   "0123456789",
						Headers: map[string]string{
							"Content-Type":     "text/plain",
							"Content-Encoding": "gzip",
						},
						Status: 415,
						Rule:   "unsupported_body",
					},
					invalidBody("text/plain", "\xff\xfe"),
					invalidBody("application/json", `{"value":NaN}`),
					invalidBody("application/json", `{"value":"ok"} {"value":"bad"}`),
					invalidBody("application/x-www-form-urlencoded", "q=%ZZ"),
				},
			},

			{
				Name:   "body byte limit is inclusive",
				Policy: `{"inspection":{"max_body_bytes":4}}`,
				Probes: []probe{
					{
						Method: "POST",
						Target: "/echo",
						Body:   "\u00e9\u00e9",
						Headers: map[string]string{
							"Content-Type": "text/plain",
						},
						Status:  200,
						Forward: true,
					},
					{
						Method: "POST",
						Target: "/echo",
						Body:   "\u00e9\u00e9a",
						Headers: map[string]string{
							"Content-Type": "text/plain",
						},
						Status: 413,
						Rule:   "body_too_large",
					},
				},
			},
		}
	case 9:
		policyText := `{"mode":"log","response":{"max_bytes":128,"deny_patterns":["INTERNAL_KEY_[A-Z0-9]+"]}}`
		scenarios := []scenario{
			// Bounded inspection must not release an incomplete origin response.
			{
				Name:   "incomplete inspected response returns a gateway error",
				Policy: policyText, OriginTruncated: true,
				Probes: []probe{
					{Target: "/truncated", Status: 502, Rule: "origin_unavailable", Forward: true},
				},
			},
			{
				Name:       "response denial replaces a logged request match",
				Policy:     policy(`"mode":"log"`, `"denylist":[{"id":"request-match","term":"debug"}]`, `"response":{"max_bytes":128,"deny_patterns":["INTERNAL_KEY_[A-Z0-9]+"]}`),
				OriginBody: `{"debug":"INTERNAL_KEY_7F2A"}`,
				Probes: []probe{
					{
						Target:  "/debug",
						Status:  403,
						Rule:    "response_leak",
						Forward: true,
					},
				},
			},
			{
				Name:         "raw response leak is withheld",
				Policy:       policyText,
				OriginStatus: 500,
				OriginBody:   `{"debug":"INTERNAL_KEY_7F2A"}`,
				Probes: []probe{
					{
						Target:  "/debug",
						Status:  403,
						Rule:    "response_leak",
						Forward: true,
					},
				},
			},
			{
				Name:       "escaped and duplicate JSON values are inspected",
				Policy:     policyText,
				OriginBody: `{"debug":"\u0049NTERNAL_KEY_7F2A","debug":"clean"}`,
				Probes: []probe{
					{
						Target:  "/debug",
						Status:  403,
						Rule:    "response_leak",
						Forward: true,
					},
				},
			},
			{
				Name:       "escaped object keys are inspected",
				Policy:     policyText,
				OriginBody: `{"\u0049NTERNAL_KEY_7F2A":"value"}`,
				Probes: []probe{
					{
						Target:  "/debug",
						Status:  403,
						Rule:    "response_leak",
						Forward: true,
					},
				},
			},
			{
				Name:       "clean response is preserved",
				Policy:     policyText,
				OriginBody: `{ "value": "INTERNAL_", "extra": true }`,
				Probes: []probe{
					allow("/products"),
				},
			},
			// Invalid UTF-8 is replaced only in the inspection copy.
			{
				Name:       "invalid UTF-8 response bytes are searched with replacement",
				Policy:     `{"response":{"max_bytes":128,"deny_patterns":["\uFFFDsecret"]}}`,
				OriginBody: "\xffsecret",
				Probes: []probe{
					{Target: "/debug", Status: 403, Rule: "response_leak", Forward: true},
				},
			},
			// Allowed responses preserve invalid UTF-8 bytes unchanged.
			{
				Name:       "clean invalid UTF-8 response bytes are preserved",
				Policy:     policyText,
				OriginBody: "\xffclean",
				Probes:     []probe{allow("/products")},
			},
			// Raw scanning still catches unescaped secrets in invalid JSON.
			{
				Name:       "nonstandard JSON still receives raw inspection",
				Policy:     policyText,
				OriginBody: `{"secret":"INTERNAL_KEY_7F2A","number":NaN}`,
				Probes: []probe{
					{Target: "/debug", Status: 403, Rule: "response_leak", Forward: true},
				},
			},
			{
				Name:       "response limit is enforced",
				Policy:     `{"response":{"max_bytes":4,"deny_patterns":[]}}`,
				OriginBody: "\u00e9\u00e9a",
				Probes: []probe{
					{
						Target:  "/large",
						Status:  502,
						Rule:    "response_too_large",
						Forward: true,
					},
				},
			},
		}
		// Nonstandard constants disable decoded-string extraction.
		for _, constant := range []string{"NaN", "Infinity", "-Infinity"} {
			scenarios = append(scenarios, scenario{
				Name:       "nonstandard JSON uses raw inspection: " + constant,
				Policy:     policyText,
				OriginBody: `{"secret":"\u0049NTERNAL_KEY_7F2A","number":` + constant + `}`,
				Probes:     []probe{allow("/products")},
			})
		}
		return scenarios
	case 10:
		finale := []scenario{

			{
				Name:   "patch fields and routes come from policy",
				Policy: `{"virtual_patches":[{"id":"custom-export","method":"POST","path":"/report","argument":"columns","allowed_values":["public"]}]}`,
				Probes: []probe{
					{
						Method: "POST",
						Target: "/report",
						Body:   `{"columns":["private"]}`,
						Status: 403,
						Rule:   "custom-export",
					},
					{
						Method:  "POST",
						Target:  "/report",
						Body:    `{"columns":["public"]}`,
						Status:  200,
						Forward: true,
					},
					allow("/report"),
				},
			},

			{
				Name:   "virtual patch blocks a low-score private export",
				Policy: policy(normPolicy, rules, heuristics, classifier, decisions, inspect, patch),
				Score:  12,
				Probes: []probe{
					{
						Method: "POST",
						Target: "/api/export",
						Body:   `{"fields":["name","password_hash"]}`,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
						Status: 403,
						Rule:   "export-fields",
					},
					{
						Method: "POST",
						Target: "/api/%65xport",
						Body:   `{"fields":["password_hash"]}`,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
						Status: 403,
						Rule:   "export-fields",
					},
					{
						Method: "POST",
						Target: "/api/export",
						Body:   `{ "fields": ["customer_id", "name"] }`,
						Headers: map[string]string{
							"Content-Type": "application/json",
						},
						Status:  200,
						Forward: true,
					},
				},
			},

			{
				Name:   "patch works without other inspection and in log mode",
				Policy: policy(`"mode":"log"`, patch),
				Probes: []probe{
					{
						Method: "POST",
						Target: "/api/export",
						Body:   `{"fields":[]}`,
						Status: 403,
						Rule:   "export-fields",
					},
					{
						Method: "POST",
						Target: "/api/export",
						Body:   `{"fields":["Name"]}`,
						Status: 403,
						Rule:   "export-fields",
					},
					{
						Method: "POST",
						Target: "/api/export",
						Body:   `{"fields":["name"],"fields":["password_hash"]}`,
						Status: 403,
						Rule:   "export-fields",
					},
					allow("/api/export/extra"),
				},
			},

			{
				Name:         "detector outage does not disable the patch",
				Policy:       policy(classifier, patch),
				DetectorMode: "error",
				Probes: []probe{
					{
						Method: "POST",
						Target: "/api/export",
						Body:   `{"fields":["password_hash"]}`,
						Status: 403,
						Rule:   "export-fields",
					},
				},
			},
		}
		for earlier := 2; earlier < len(slugs); earlier++ {
			finale = append(finale, stageScenarios(earlier)...)
		}
		return finale
	}
	panic("unknown stage")
}
