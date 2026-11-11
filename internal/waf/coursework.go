package waf

import "strings"

const previewPayload = `<script>alert(1)</script>`
const previewHTML = `<!doctype html><title>Preview</title><div>Preview: <script>alert(1)</script></div>`
const productResults = `{"results":[{"item":"tea cup"}]}`
const articleText = `A security article explaining or 1=1 --`
const articleResult = `{"article":"A security article explaining or 1=1 --","published":true}`
const publicExport = `{"customer_id":"Customer-4829","name":"Mira"}`
const bodyInspection = `"inspection":{"max_body_bytes":4096}`
const responseInspection = `"response":{"max_bytes":65536,"deny_patterns":["INTERNAL_KEY_[A-Z0-9]+"]}`

// Every character is JSON-escaped so the pre-parsing model sees no script text.
const escapedPreview = `{"comment":"\u003c\u0073\u0063\u0072\u0069\u0070\u0074\u003e\u0061\u006c\u0065\u0072\u0074\u0028\u0031\u0029\u003c\u002f\u0073\u0063\u0072\u0069\u0070\u0074\u003e"}`

func productSearch() probe {
	return probe{Target: "/search?q=tea+cup", Status: 200, Forward: true, WantBody: productResults}
}

func previewAttack() probe {
	return probe{Method: "POST", Target: "/preview", Body: previewPayload,
		Headers: map[string]string{"Content-Type": "text/plain"}, Status: 403, Rule: "xss-script"}
}

func articleRequest() probe {
	return probe{Method: "POST", Target: "/articles", Body: articleText,
		Headers: map[string]string{"Content-Type": "text/plain"}, Status: 200, Forward: true, WantBody: articleResult}
}

func structuredPreview() probe {
	return probe{Method: "POST", Target: "/preview", Body: escapedPreview,
		Headers: map[string]string{"Content-Type": "application/json"}, Status: 403, Rule: "xss-script"}
}

func privateExportRequest() probe {
	return probe{Method: "POST", Target: "/api/export", Body: `{"fields":["name","password_hash"]}`,
		Headers: map[string]string{"Content-Type": "application/json"}, Status: 403, Rule: "export-fields"}
}

func publicExportRequest() probe {
	return probe{Method: "POST", Target: "/api/export", Body: `{"fields":["customer_id","name"]}`,
		Headers: map[string]string{"Content-Type": "application/json"}, Status: 200, Forward: true, WantBody: publicExport}
}

func courseworkScenarios(stage int) []scenario {
	base := []string{normPolicy, rules, heuristics, classifier, decisions}
	switch stage {
	case 1:
		return nil
	case 2:
		article := articleRequest()
		article.Body = "My first article"
		article.WantBody = `{"article":"My first article","published":true}`
		return []scenario{{Name: "Exercise: proxy a product search and publish an article", Coursework: true,
			Policy: "{}", Probes: []probe{productSearch(), article}}}
	case 3:
		logged := previewAttack()
		logged.Status, logged.Rule, logged.Forward, logged.WantBody = 200, "", true, previewHTML
		logged.WantHeaders = map[string]string{"X-WAF-Match": "xss-script", "Content-Type": "text/html; charset=utf-8"}
		return []scenario{
			{Name: "Exercise: observe reflected HTML in log mode", Coursework: true,
				Policy: policy(`"mode":"log"`, rules), Probes: []probe{logged}},
			{Name: "Exercise: block reflected HTML while clean previews work", Coursework: true,
				Policy: policy(`"mode":"block"`, rules), Probes: []probe{previewAttack(),
					{Method: "POST", Target: "/preview", Body: "Hello", Status: 200, Forward: true,
						Headers:  map[string]string{"Content-Type": "text/plain"},
						WantBody: "<!doctype html><title>Preview</title><div>Preview: Hello</div>"}}},
		}
	case 4:
		return []scenario{{Name: "Exercise: close the encoded search bypass", Coursework: true,
			Policy: policy(normPolicy, rules), Probes: []probe{
				deny("/search?q=union+select+password+from+users", "sql-union"), productSearch()}}}
	case 5:
		attack := deny("/search?q=or+1%3D1+--", "heuristic_score")
		attack.WantHeaders = map[string]string{"X-WAF-Score": "5"}
		attack.WantSignals = []string{"sql-or", "sql-comment"}
		return []scenario{{Name: "Exercise: combine two weak SQL signals", Coursework: true,
			Policy: policy(normPolicy, rules, heuristics), Probes: []probe{attack, productSearch()}}}
	case 6:
		attack := deny("/search?q=1%27+AND+SLEEP(5)%23", "ml_score")
		attack.WantHeaders = map[string]string{"X-WAF-Score": "0", "X-WAF-ML-Score": "77", "X-WAF-Detector-Status": "ok"}
		return []scenario{{Name: "Exercise: catch a new detection probe with real inference", Coursework: true,
			Policy: policy(normPolicy, rules, heuristics, classifier), Probes: []probe{attack, productSearch()}}}
	case 7:
		blocked := articleRequest()
		blocked.Status, blocked.Rule, blocked.Forward, blocked.WantBody = 403, "heuristic_high", false, ""
		withoutRoute := strings.Replace(decisions, `,"routes":[{"path":"/articles","ml_high":95,"ml_medium":80,"heuristic_high":8,"heuristic_medium":5}]`, "", 1)
		allowed := articleRequest()
		allowed.WantHeaders = map[string]string{"X-WAF-Score": "5", "X-WAF-ML-Score": "69"}
		return []scenario{
			{Name: "Exercise: see the article false positive under default thresholds", Coursework: true,
				Policy: policy(normPolicy, rules, heuristics, classifier, withoutRoute), Probes: []probe{blocked}},
			{Name: "Exercise: publish the article with route thresholds", Coursework: true,
				Policy: policy(base...), Probes: []probe{allowed, productSearch()}},
		}
	case 8:
		return []scenario{{Name: "Exercise: inspect JSON before it becomes HTML", Coursework: true,
			Policy: policy(append(base, bodyInspection)...), Probes: []probe{structuredPreview(),
				{Method: "POST", Target: "/preview", Body: `{"comment":"Hello"}`, Status: 200, Forward: true,
					Headers:  map[string]string{"Content-Type": "application/json"},
					WantBody: "<!doctype html><title>Preview</title><div>Preview: Hello</div>"}}}}
	case 9:
		return []scenario{{Name: "Exercise: withhold the application's debug secret", Coursework: true,
			Policy: policy(append(base, bodyInspection, responseInspection)...), Probes: []probe{
				{Target: "/debug", Status: 403, Rule: "response_leak", Forward: true}, productSearch()}}}
	case 10:
		attack := previewAttack()
		encoded := deny("/search?q=union+select+password+from+users", "sql-union")
		heuristic := deny("/search?q=or+1%3D1+--", "heuristic_high")
		structured := structuredPreview()
		leak := probe{Target: "/debug", Status: 403, Rule: "response_leak", Forward: true}
		private := privateExportRequest()
		probes := []probe{attack, encoded, heuristic, structured, leak, private}
		for index := range probes {
			probes[index].Traffic = "attack"
		}
		probeOnly := probe{Target: "/search?q=1%27+AND+SLEEP(5)%23", Status: 200, Forward: true,
			WantBody: productResults, Traffic: "probe", WantHeaders: map[string]string{"X-WAF-Score": "0", "X-WAF-ML-Score": "77"}}
		cleanPreview := probe{Method: "POST", Target: "/preview", Body: "Hello", Status: 200, Forward: true,
			Headers:  map[string]string{"Content-Type": "text/plain"},
			WantBody: "<!doctype html><title>Preview</title><div>Preview: Hello</div>"}
		hardSignature := articleRequest()
		hardSignature.Body = "Example: union select in a security article"
		hardSignature.Status, hardSignature.Rule, hardSignature.Forward, hardSignature.WantBody = 403, "sql-union", false, ""
		legitimate := []probe{productSearch(), cleanPreview, articleRequest(), hardSignature, publicExportRequest()}
		for index := range legitimate {
			legitimate[index].Traffic = "legitimate"
		}
		probes = append(probes, probeOnly)
		probes = append(probes, legitimate...)
		return []scenario{{Name: "Exercise: patch the export and replay attacks and legitimate traffic", Coursework: true,
			Policy: policy(append(base, bodyInspection, responseInspection, patch)...), Probes: probes}}
	}
	panic("unknown coursework stage")
}
