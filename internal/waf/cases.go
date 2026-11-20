package waf

import "time"

const normPolicy = `"normalization":true,"inspect_headers":["X-Search"]`
const rules = `"denylist":[{"id":"xss-script","term":"<script"},{"id":"sql-union","term":"union select"}]`
const heuristics = `"heuristics":{"threshold":5,"signals":[{"id":"sql-or","pattern":"or[ \\t\\n\\f\\r]+1[ \\t\\n\\f\\r]*=[ \\t\\n\\f\\r]*1","weight":3},{"id":"sql-comment","pattern":"--","weight":2}]}`
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
				Name:    "health remains available",
				Offline: true,
				Policy:  "{}",
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
		scenarios = append(scenarios, []scenario{

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
						Target:      "/redirect",
						Status:      302,
						Forward:     true,
						WantHeaders: map[string]string{"Location": "/redirect-target"},
					},
				},
			},
		}...)
		for index := range scenarios {
			scenarios[index].BasicProxy = true
		}
		return scenarios
	case 3:
		scenarios := stageScenarios(2)
		for index := range scenarios {
			scenarios[index].BasicProxy = false
		}
		// An incomplete origin response becomes a safe gateway error.
		return append([]scenario{
			{Name: "incomplete origin response returns a gateway error", Policy: "{}", OriginTruncated: true,
				Probes: []probe{{Target: "/truncated", Status: 502, Rule: "origin_unavailable", Forward: true}}},
			{Name: "unavailable origin returns a gateway error", Policy: "{}", Offline: true,
				Probes: []probe{{Target: "/products", Status: 502, Rule: "origin_unavailable"}, {Target: "/health", Status: 200}}},
		}, scenarios...)
	case 4:
		return []scenario{
			// Denylist terms are literal even when they contain regex metacharacters.
			{Name: "denylist terms are literal substrings", Policy: policy(`"denylist":[{"id":"literal-dot","term":"a.b"}]`), Probes: []probe{
				allow("/axb"), deny("/a.b", "literal-dot"),
			}},
			// Policy order wins even when a later rule matches the target first.
			{Name: "rule precedence spans independent inputs", Policy: policy(`"denylist":[{"id":"body-first","term":"needle"},{"id":"target-second","term":"target"}]`), Probes: []probe{
				{Method: "POST", Target: "/target", Body: "needle", Status: 403, Rule: "body-first"},
				allow("/ne?x=edle"),
				allow("/n%65edle"),
			}},

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
	case 5:
		return []scenario{
			// A configured header value retains its comma during literal matching.
			{Name: "header values are not comma split", Policy: policy(normPolicy, `"denylist":[{"id":"comma","term":"union, select"}]`), Probes: []probe{
				{Target: "/search", Headers: map[string]string{"X-Search": "union, select"}, Status: 403, Rule: "comma"},
			}},
			// An attack in a later occurrence of a configured header is inspected.
			{Name: "every configured header occurrence is inspected", Policy: policy(normPolicy, rules), Probes: []probe{
				{Target: "/search", HeaderValues: map[string][]string{"X-Search": {"clean", "<script>"}}, Status: 403, Rule: "xss-script"},
			}},
			// Path validation also runs when the normalization field is omitted.
			{Name: "path validation without normalization policy", Policy: "{}", Probes: []probe{invalid("/search%FF")}},
			// Path validation is required even with normalization disabled.
			{Name: "raw inspection retains validation and case", Policy: policy(`"normalization":false`, `"inspect_headers":["X-Search"]`, `"denylist":[{"id":"raw","term":"Needle"}]`), Probes: []probe{
				invalid("/path%FF"),
				deny("/Needle", "raw"),
				allow("/needle?q=%ZZ"),
				{Target: "/clean", Headers: map[string]string{"X-Search": "Needle"}, Status: 200, Forward: true},
			}},
			// Bare query segments are inspected separately from name=value pairs.
			{Name: "bare query parameters are inspected independently", Policy: policy(normPolicy, rules), Probes: []probe{
				deny("/search?union+select+password+from+users", "sql-union"),
				deny("/search?%75nion%20select%20password%20from%20users", "sql-union"),
				deny("/search?q=clean&%3Cscript%3E&flag", "xss-script"),
				deny("/search?name%3D%3Cscript%3E", "xss-script"),
				allow("/search?tea+cup&flag&flag&empty="),
				allow("/search?union+select=clean"),
				allow("/search?union+select="),
				allow("/search?%253Cscript%253E"),
				allow("/search?union&+select"),
				invalid("/search?%ZZ"),
				invalid("/search?%FF"),
			}},
			// Log mode forwards the original bare parameter without rewriting it.
			{Name: "bare query log mode preserves forwarding", Policy: policy(normPolicy, rules, `"mode":"log"`), Probes: []probe{
				{Target: "/search?union+select+password+from+users", Status: 200, Forward: true, WantHeaders: map[string]string{"X-WAF-Match": "sql-union"}},
			}},
			// A plus in a path remains a plus, while queries decode it as space.
			{Name: "path plus and one-layer decoding", Policy: policy(normPolicy, `"denylist":[{"id":"space","term":"tea cup"}]`), Probes: []probe{
				allow("/tea+cup"), deny("/tea%20cup", "space"), allow("/tea%2520cup"),
			}},

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
	case 6:
		scenarios := []scenario{
			// A regex cannot match by spanning independently inspected query values.
			{Name: "heuristic patterns keep input boundaries", Policy: policy(normPolicy, `"heuristics":{"threshold":1,"signals":[{"id":"boundary","pattern":"left(.|\\n)*right","weight":1}]}`), Probes: []probe{
				{Target: "/search?a=left&b=right", Status: 200, Forward: true, WantHeaders: map[string]string{"X-WAF-Score": "0"}, Absent: []string{"X-WAF-Match", "X-WAF-Signals"}},
				deny("/search?q=leftright", "heuristic_score"),
			}},
			// Invalid requests return before any scoring diagnostics are emitted.
			{Name: "validation errors omit score diagnostics", Policy: policy(normPolicy, heuristics), Probes: []probe{
				{Target: "/search?q=%FF", Status: 400, Rule: "invalid_request", Absent: []string{"X-WAF-Score", "X-WAF-Signals"}},
			}},
			// Signals in separate inputs combine without repeated occurrences adding weight.
			{Name: "signals combine across inputs", Policy: policy(normPolicy, heuristics), Probes: []probe{
				{Target: "/search?a=or+1%3D1&b=--", Status: 403, Rule: "heuristic_score", WantHeaders: map[string]string{"X-WAF-Score": "5"}, WantSignals: []string{"sql-or", "sql-comment"}},
				{Target: "/search?q=or+1%3D1+or+1%3D1", Status: 200, Forward: true, WantHeaders: map[string]string{"X-WAF-Score": "3"}, WantSignals: []string{"sql-or"}},
			}},
			// Log mode reports the full policy-defined score while preserving traffic.
			{Name: "custom weighted signals in log mode", Policy: policy(`"mode":"log"`, `"heuristics":{"threshold":7,"signals":[{"id":"custom","pattern":"needle","weight":7}]}`), Probes: []probe{
				{Target: "/needle", Status: 200, Forward: true, WantHeaders: map[string]string{"X-WAF-Match": "heuristic_score", "X-WAF-Score": "7"}, WantSignals: []string{"custom"}},
				{Target: "/health", Status: 200, Absent: []string{"X-WAF-Match", "X-WAF-Score", "X-WAF-Signals"}},
			}},

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
		// The explicit policy class has identical whitespace semantics in both languages.
		whitespace := scenario{Name: "heuristic whitespace is portable", Policy: policy(normPolicy, heuristics)}
		for _, check := range []struct {
			encoded string
			matches bool
		}{
			{"%20", true}, {"%09", true}, {"%0A", true}, {"%0C", true}, {"%0D", true},
			{"%0B", false}, {"%E2%80%A8", false}, {"%C2%85", false},
		} {
			target := "/search?q=or" + check.encoded + "1%3D1"
			clean := allow(target)
			combined := allow(target + "&comment=--")
			if check.matches {
				clean.WantHeaders = map[string]string{"X-WAF-Score": "3"}
				clean.WantSignals = []string{"sql-or"}
				combined = deny(combined.Target, "heuristic_score")
				combined.WantHeaders = map[string]string{"X-WAF-Score": "5"}
				combined.WantSignals = []string{"sql-or", "sql-comment"}
			} else {
				clean.WantHeaders = map[string]string{"X-WAF-Score": "0"}
				clean.Absent = []string{"X-WAF-Signals", "X-WAF-Match"}
				combined.WantHeaders = map[string]string{"X-WAF-Score": "2"}
				combined.WantSignals = []string{"sql-comment"}
			}
			whitespace.Probes = append(whitespace.Probes, clean, combined)
		}
		return append(scenarios, whitespace)
	case 7:
		scenarios := []scenario{
			// The standalone heuristic cutoff wins when both score cutoffs fire.
			{Name: "standalone heuristic cutoff precedes ML", Policy: policy(normPolicy, heuristics, classifier), Score: 70, Probes: []probe{
				{Target: "/search?q=or+1%3D1+--", Status: 403, Rule: "heuristic_score", WantHeaders: map[string]string{"X-WAF-Score": "5", "X-WAF-ML-Score": "70", "X-WAF-Detector-Status": "ok"}, WantSignals: []string{"sql-or", "sql-comment"}},
			}},
			// An origin error is not an input-validation error and still uses detection.
			{Name: "origin errors retain detector diagnostics", Policy: policy(classifier), OriginStatus: 400, Probes: []probe{
				{Target: "/bad", Status: 400, Forward: true, WantHeaders: map[string]string{"X-WAF-ML-Score": "0", "X-WAF-Detector-Status": "ok"}},
			}},
			// Raw input boundaries remain intact when normalization is disabled.
			{Name: "classifier receives raw inputs", Policy: policy(`"classifier":{"threshold":75}`), Score: 74, Probes: []probe{
				{Method: "POST", Target: "/Search?q=A+B", Body: "MiXeD", Status: 200, Forward: true, Inputs: []string{"/Search?q=A+B", "MiXeD"}, WantHeaders: map[string]string{"X-WAF-ML-Score": "74"}},
				{Target: "/health", Status: 200, Absent: []string{"X-WAF-ML-Score", "X-WAF-Detector-Status"}},
			}},
			// Repeated query values remain distinct and configured headers are not comma-split.
			{Name: "classifier receives separate normalized fields", Policy: policy(normPolicy, classifier), Probes: []probe{
				{Method: "POST", Target: "/Search?ignored=One&q=Two&q=Two&blank", Body: "Raw%3C", Headers: map[string]string{"x-search": "A,B"}, Status: 200, Forward: true, Inputs: []string{"/search", "one", "two", "two", "blank", "a,b", "raw%3c"}},
			}},
			// Bare query text reaches the classifier with repetition and value boundaries intact.
			{Name: "classifier receives bare query parameters", Policy: policy(normPolicy, classifier), Probes: []probe{
				{Target: "/Search?FLAG&flag&empty=&name=One%3DTwo&tea+cup", Status: 200, Forward: true, Inputs: []string{"/search", "flag", "flag", "", "one=two", "tea cup", ""}},
			}},
			// Configured header occurrences remain separate inspection inputs.
			{Name: "classifier receives repeated header occurrences", Policy: policy(`"normalization":true,"inspect_headers":["X-Client-Tag"]`, classifier), Probes: []probe{
				{Target: "/clean", Status: 200, Forward: true, Inputs: []string{"/clean", "first", "second", ""}},
			}},
			// The upper endpoint of the score range is valid.
			{Name: "maximum ML score is valid", Policy: policy(classifier), Score: 100, Probes: []probe{
				{Target: "/clean", Status: 403, Rule: "ml_score", WantHeaders: map[string]string{"X-WAF-ML-Score": "100", "X-WAF-Detector-Status": "ok"}},
			}},
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
	case 8:
		return []scenario{
			// Outage fallback uses the standalone cutoff even on a tuned route.
			{Name: "route outage restores standalone heuristics", Policy: policy(normPolicy, heuristics, classifier, decisions), DetectorMode: "error", Probes: []probe{
				deny("/articles?q=or+1%3D1+--", "heuristic_score"), allow("/articles?q=or+1%3D1"),
			}},
			// Route decoding works independently of inspection normalization.
			{Name: "route matching decodes once without normalization", Policy: policy(classifier, decisions), Score: 92, Probes: []probe{
				allow("/%61rticles?x=1"), deny("/%2561rticles", "ml_high"), deny("/Articles", "ml_high"),
			}},
			// The first matching route wins when multiple policy entries match.
			{Name: "first matching route wins", Policy: policy(classifier, `"decisions":{"default":{"ml_high":90,"ml_medium":60,"heuristic_high":5,"heuristic_medium":3},"routes":[{"path":"/articles","ml_high":95,"ml_medium":80,"heuristic_high":8,"heuristic_medium":5},{"path":"/articles","ml_high":60,"ml_medium":50,"heuristic_high":8,"heuristic_medium":5}]}`), Score: 92, Probes: []probe{allow("/articles")}},
			// Moderate cutoffs require both scores at their inclusive boundaries.
			{Name: "combined score boundaries", Policy: policy(normPolicy, heuristics, classifier, decisions), Score: 60, Probes: []probe{
				deny("/search?q=or+1%3D1", "combined_scores"), allow("/search?q=--"), allow("/clean"),
			}},

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
	case 9:
		scenarios := []scenario{
			// Oversized malformed JSON is rejected by size before parsing or detection.
			{Name: "request size precedes JSON validation", Policy: policy(`"inspection":{"max_body_bytes":4}`, classifier), Probes: []probe{
				{Method: "POST", Target: "/echo", Body: `{"a":`, Headers: map[string]string{"Content-Type": "application/json"}, Status: 413, Rule: "body_too_large"},
			}},
			// Duplicate names are invalid even when nested or written with JSON escapes.
			{Name: "nested and escaped duplicate keys", Policy: policy(inspect, classifier), Probes: []probe{
				invalidBody("application/json", `{"outer":{"a":1,"a":2}}`),
				invalidBody("application/json", `{"name":1,"\u006eame":2}`),
				invalidBody("application/x-www-form-urlencoded", "q=%FF"),
				invalidBody("application/x-www-form-urlencoded", "%ZZ=clean"),
			}},
			// Only JSON string values are inspected, regardless of media-type case.
			{Name: "JSON values and media-type case", Policy: policy(normPolicy, inspect, classifier, rules), Probes: []probe{
				{Method: "POST", Target: "/echo", Body: `{ "<script": [1,true,null,{"x":"Mira"}] }`, Headers: map[string]string{"Content-Type": "Application/JSON; charset=UTF-8"}, Status: 200, Forward: true, Inputs: []string{"/echo", "mira"}},
				{Method: "POST", Target: "/echo", Body: `null`, Headers: map[string]string{"Content-Type": "application/json"}, Status: 200, Forward: true, Inputs: []string{"/echo"}},
			}},
			// Form repetitions are independent values and parsing does not require normalization.
			{Name: "form inputs without normalization", Policy: policy(inspect, classifier), Probes: []probe{
				{Method: "POST", Target: "/Echo?x=RAW", Body: "ignored=One&q=Two&q=Two&blank", Headers: map[string]string{"Content-Type": "Application/X-WWW-Form-Urlencoded"}, Status: 200, Forward: true, Inputs: []string{"/Echo?x=RAW", "One", "Two", "Two", ""}},
			}},
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
		// Log mode cannot bypass any of the body-validation failure classes.
		for _, test := range append([]scenario(nil), scenarios...) {
			logged := test
			logged.Name = "log mode: " + test.Name
			logged.Policy = `{"mode":"log",` + test.Policy[1:]
			logged.Probes = nil
			for _, check := range test.Probes {
				if check.Rule == "invalid_request" || check.Rule == "body_too_large" || check.Rule == "unsupported_body" {
					logged.Probes = append(logged.Probes, check)
				}
			}
			if len(logged.Probes) > 0 {
				scenarios = append(scenarios, logged)
			}
		}
		return scenarios
	case 10:
		policyText := `{"mode":"log","response":{"max_bytes":128,"deny_patterns":["INTERNAL_KEY_[A-Z0-9]+"]}}`
		scenarios := []scenario{
			// Inspection stops after max_bytes + 1 bytes without waiting for the tail.
			{Name: "oversized response stops before the slow tail", Policy: `{"response":{"max_bytes":4,"deny_patterns":[]}}`, OriginSlowTail: true, Probes: []probe{
				{Target: "/large", Status: 502, Rule: "response_too_large", Forward: true, MaxDuration: 600 * time.Millisecond},
			}},
			// A response exactly at the byte limit is still eligible for release.
			{Name: "response byte limit is inclusive", Policy: `{"response":{"max_bytes":4,"deny_patterns":[]}}`, OriginBody: "\u00e9\u00e9", Probes: []probe{allow("/exact")}},
			// Size rejection precedes pattern matching.
			{Name: "response size precedes leak matching", Policy: `{"response":{"max_bytes":4,"deny_patterns":["sec"]}}`, OriginBody: "secret", Probes: []probe{
				{Target: "/large", Status: 502, Rule: "response_too_large", Forward: true},
			}},
			// Separate decoded strings must not be joined into a protected marker.
			{Name: "response strings keep their boundaries", Policy: policyText, OriginBody: `["INTERNAL_KEY_","7F2A"]`, Probes: []probe{allow("/clean")}},
			// Malformed JSON falls back to scanning the raw body.
			{Name: "malformed response JSON gets raw inspection", Policy: policyText, OriginBody: `{"secret":"INTERNAL_KEY_7F2A"`, Probes: []probe{
				{Target: "/debug", Status: 403, Rule: "response_leak", Forward: true},
			}},
			// Request scores survive a response denial in log mode.
			{Name: "response denial retains detection diagnostics", Policy: policy(normPolicy, `"mode":"log"`, heuristics, classifier, `"response":{"max_bytes":128,"deny_patterns":["secret"]}`), Score: 70, OriginBody: "secret", Probes: []probe{
				{Target: "/search?q=or+1%3D1", Status: 403, Rule: "response_leak", Forward: true, WantHeaders: map[string]string{"X-WAF-Score": "3", "X-WAF-ML-Score": "70", "X-WAF-Detector-Status": "ok"}, WantSignals: []string{"sql-or"}},
			}},
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
		// Clean nonstandard JSON is preserved with strict or lenient parsers.
		for _, constant := range []string{"NaN", "Infinity", "-Infinity"} {
			scenarios = append(scenarios, scenario{
				Name:       "nonstandard JSON uses raw inspection: " + constant,
				Policy:     policyText,
				OriginBody: `{"value":"clean","number":` + constant + `}`,
				Probes:     []probe{allow("/products")},
			})
		}
		return scenarios
	case 11:
		finale := []scenario{
			// Every matching patch must pass and the first failing patch names the denial.
			{Name: "all matching patches enforce policy order", Policy: `{"virtual_patches":[{"id":"first","method":"POST","path":"/report","argument":"fields","allowed_values":["name"]},{"id":"second","method":"POST","path":"/report","argument":"columns","allowed_values":["public"]}]}`, Probes: []probe{
				{Method: "POST", Target: "/report", Body: `{"fields":["private"],"columns":["private"]}`, Status: 403, Rule: "first"},
				{Method: "POST", Target: "/report", Body: `{"fields":["name"],"columns":["private"]}`, Status: 403, Rule: "second"},
				{Method: "POST", Target: "/report?x=1", Body: `{"fields":["name"],"columns":["public"],"extra":true}`, Status: 200, Forward: true},
			}},
			// Invalid patch arguments fail even without general body inspection.
			{Name: "patch validates the complete JSON shape", Policy: policy(patch), Probes: []probe{
				{Method: "POST", Target: "/api/export", Body: `{}`, Status: 403, Rule: "export-fields"},
				{Method: "POST", Target: "/api/export", Body: `[]`, Status: 403, Rule: "export-fields"},
				{Method: "POST", Target: "/api/export", Body: `{"fields":"name"}`, Status: 403, Rule: "export-fields"},
				{Method: "POST", Target: "/api/export", Body: `{"fields":["name",1]}`, Status: 403, Rule: "export-fields"},
				{Method: "POST", Target: "/api/export", Body: `{"fields":["name"]} {}`, Status: 403, Rule: "export-fields"},
				{Method: "POST", Target: "/api/export", Body: `{"fields":["name"]`, Status: 403, Rule: "export-fields"},
			}},
			// An earlier request block supplies its rule before patch validation runs.
			{Name: "request blocks precede virtual patches", Policy: policy(rules, patch), Probes: []probe{
				{Method: "POST", Target: "/api/export", Body: "<script", Status: 403, Rule: "xss-script"},
			}},
			// A patch denial replaces a logged rule while retaining request diagnostics.
			{Name: "patch denial replaces a logged match", Policy: policy(`"mode":"log"`, heuristics, patch), Probes: []probe{
				{Method: "POST", Target: "/api/export", Body: `{"fields":[],"note":"or 1=1 --"}`, Status: 403, Rule: "export-fields", WantHeaders: map[string]string{"X-WAF-Score": "5"}, WantSignals: []string{"sql-or", "sql-comment"}},
			}},
			// Earlier body validation keeps its own status instead of becoming a patch denial.
			{Name: "body validation precedes virtual patching", Policy: policy(inspect, patch, classifier), Probes: []probe{
				{Method: "POST", Target: "/api/export", Body: `{"fields":[]`, Headers: map[string]string{"Content-Type": "application/json"}, Status: 400, Rule: "invalid_request"},
			}},

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
					// A last-value-wins JSON parser would incorrectly allow this duplicate key.
					{Method: "POST", Target: "/api/export", Body: `{"fields":["password_hash"],"fields":["name"]}`, Status: 403, Rule: "export-fields"},
					// The method matches, so only exact path matching can exempt this request.
					{Method: "POST", Target: "/api/export/extra", Body: `{"fields":["password_hash"]}`, Status: 200, Forward: true},
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
