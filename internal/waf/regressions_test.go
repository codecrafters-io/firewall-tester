package waf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mutatedReference(t *testing.T, replacements ...string) launchFunc {
	t.Helper()
	source := referenceDirectory(t, "python", 11)
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
			for i := 0; i < len(replacements); i += 2 {
				if !strings.Contains(text, replacements[i]) {
					t.Fatalf("mutation target missing: %q", replacements[i])
				}
				text = strings.Replace(text, replacements[i], replacements[i+1], 1)
			}
			data = []byte(text)
		}
		if err := os.WriteFile(filepath.Join(target, name), data, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return referenceLaunch(t, target)
}

// A WAF that omits PUT forwarding cannot pass the proxy stage.
func TestGraderRejectsMissingPUT(t *testing.T) {
	// Arrange
	launch := mutatedReference(t, "do_GET = do_POST = do_PUT = do_PATCH = do_DELETE", "do_GET = do_POST = do_PATCH = do_DELETE")
	// Act
	err := verify(2, launch, t.Logf)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "proxy preserves PUT") {
		t.Fatal("missing PUT forwarding passed")
	}
}

// A WAF that omits DELETE forwarding cannot pass the proxy stage.
func TestGraderRejectsMissingDELETE(t *testing.T) {
	// Arrange
	launch := mutatedReference(t, "do_GET = do_POST = do_PUT = do_PATCH = do_DELETE", "do_GET = do_POST = do_PUT = do_PATCH")
	// Act
	err := verify(2, launch, t.Logf)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "proxy preserves DELETE") {
		t.Fatal("missing DELETE forwarding passed")
	}
}

// Missing fired-signal IDs cannot pass the scoring stage.
func TestGraderRejectsMissingSignalIDs(t *testing.T) {
	// Arrange
	launch := mutatedReference(t, "if signals:\n                    diagnostics[\"X-WAF-Signals\"]", "if False:\n                    diagnostics[\"X-WAF-Signals\"]")
	// Act
	err := verify(6, launch, t.Logf)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "expected signal IDs") {
		t.Fatal("missing signal IDs passed")
	}
}

// Fired-signal IDs may be reported in either order.
func TestGraderAcceptsReversedSignalIDs(t *testing.T) {
	// Arrange
	launch := mutatedReference(t, `",".join(signal["id"] for signal in signals)`, `",".join(signal["id"] for signal in reversed(signals))`)
	// Act
	err := verify(6, launch, t.Logf)
	// Assert
	if err != nil {
		t.Fatal(err)
	}
}

// Per-operation timeouts cannot substitute for a total detector deadline.
func TestGraderRejectsSocketTimeoutOnly(t *testing.T) {
	// Arrange
	launch := mutatedReference(t, "timer.start()", "pass", "time.monotonic() >= deadline or response.status != 200", "response.status != 200")
	// Act
	err := verify(7, launch, t.Logf)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "detector failure fallback: slow_body") {
		t.Fatal("socket timeout without total deadline passed")
	}
}

// Incomplete origin reads must become gateway errors instead of disconnects.
func TestGraderRejectsUncaughtOriginRead(t *testing.T) {
	// Arrange
	launch := mutatedReference(t, "except (OSError, http.client.HTTPException):", "except OSError:")
	// Act
	err := verify(3, launch, t.Logf)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "incomplete origin response returns a gateway error") {
		t.Fatal("uncaught origin read error passed")
	}
}

// Structured inspection must not send a placeholder for an empty body.
func TestGraderRejectsEmptyBodyPlaceholder(t *testing.T) {
	// Arrange
	launch := mutatedReference(t, "if inspection and not body:\n                inputs.pop()", "if inspection and not body:\n                pass")
	// Act
	err := verify(9, launch, t.Logf)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "inspection inputs:") {
		t.Fatal("empty body placeholder passed")
	}
}

// Both strict and lenient JSON parsers satisfy the response-inspection cases.
func TestGraderAcceptsStrictAndLenientResponseJSON(t *testing.T) {
	for _, mode := range []string{"strict", "lenient"} {
		for _, test := range stageScenarios(10) {
			switch test.Name {
			case "nonstandard JSON still receives raw inspection",
				"malformed response JSON gets raw inspection",
				"escaped and duplicate JSON values are inspected",
				"escaped object keys are inspected",
				"response strings keep their boundaries",
				"clean response is preserved",
				"raw response leak is withheld":
			default:
				if !strings.HasPrefix(test.Name, "nonstandard JSON uses raw inspection: ") {
					continue
				}
			}
			t.Run(mode+"/"+test.Name, func(t *testing.T) {
				// Arrange
				launch := responseJSONLaunch(t, mode)
				// Act
				err := runScenario(test, launch, t.Logf)
				// Assert
				if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

// Repeated application headers must survive Python's request construction.
func TestGraderRejectsCollapsedRequestHeaders(t *testing.T) {
	// Arrange
	launch := mutatedReference(t, "for key, value in self.headers.items():", "for key, value in dict(self.headers.items()).items():")
	// Act
	err := verify(2, launch, t.Logf)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "repeated end-to-end request headers changed") {
		t.Fatalf("collapsed request headers were not detected: %v", err)
	}
}

// Retrying a successful detector call violates the one-call contract.
func TestGraderRejectsRepeatedDetectorCalls(t *testing.T) {
	// Arrange
	launch := mutatedReference(t, "ml_score = classify(args.detector, inputs)", "ml_score = classify(args.detector, inputs)\n                classify(args.detector, inputs)")
	// Act
	err := verify(7, launch, t.Logf)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "expected 1 detector calls, got 2") {
		t.Fatalf("repeated detector calls were not detected: %v", err)
	}
}

// Route configuration cannot suppress the standalone heuristic outage fallback.
func TestGraderRejectsRouteFallbackBypass(t *testing.T) {
	// Arrange
	launch := mutatedReference(t, `if not match and score >= heuristic["threshold"]:`, `if not match and score >= heuristic["threshold"] and not policy.get("decisions"):`)
	// Act
	err := verify(8, launch, t.Logf)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "route outage restores standalone heuristics") {
		t.Fatalf("missing route fallback was not detected: %v", err)
	}
}

// JSON object keys must not substitute for body string values.
func TestGraderRejectsJSONKeyInspection(t *testing.T) {
	// Arrange
	launch := mutatedReference(t, "return [text for item in value.values() for text in strings(item)]", "return [*value.keys(), *[text for item in value.values() for text in strings(item)]]")
	// Act
	err := verify(9, launch, t.Logf)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "JSON values and media-type case") {
		t.Fatalf("JSON key inspection was not detected: %v", err)
	}
}

// Responses exactly at the configured byte limit must remain allowed.
func TestGraderRejectsExclusiveResponseLimit(t *testing.T) {
	// Arrange
	launch := mutatedReference(t, `if len(content) > response_policy["max_bytes"]:`, `if len(content) >= response_policy["max_bytes"]:`)
	// Act
	err := verify(10, launch, t.Logf)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "response byte limit is inclusive") {
		t.Fatalf("exclusive response limit was not detected: %v", err)
	}
}

// A passing first patch cannot bypass another matching patch.
func TestGraderRejectsFirstPatchOnly(t *testing.T) {
	// Arrange
	launch := mutatedReference(t, `for patch in policy.get("virtual_patches", []):`, `for patch in policy.get("virtual_patches", [])[:1]:`)
	// Act
	err := verify(11, launch, t.Logf)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "all matching patches enforce policy order") {
		t.Fatalf("skipped later patch was not detected: %v", err)
	}
}

// Response size enforcement must not wait for an unbounded body read to finish.
func TestGraderRejectsUnboundedResponseRead(t *testing.T) {
	// Arrange
	launch := mutatedReference(t, `response.read(response_policy["max_bytes"] + 1) if response_policy else response.read()`, `response.read()`)
	// Act
	err := verify(10, launch, t.Logf)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "oversized response stops before the slow tail") {
		t.Fatalf("unbounded response read was not detected: %v", err)
	}
}

// Optional whitespace in the comma-separated signal list is valid.
func TestGraderAcceptsSignalWhitespace(t *testing.T) {
	// Arrange
	launch := mutatedReference(t, `",".join(signal["id"] for signal in signals)`, `", ".join(signal["id"] for signal in signals)`)
	// Act
	err := verify(6, launch, t.Logf)
	// Assert
	if err != nil {
		t.Fatal(err)
	}
}

// List-valued application headers may be combined without dropping values.
func TestGraderAcceptsCombinedRequestHeaders(t *testing.T) {
	// Arrange
	launch := mutatedReference(t,
		"for key, value in self.headers.items():", "for key, value in self.headers.items():\n                    if key.lower() == 'x-client-tag':\n                        continue",
		`connection.putheader("Content-Length", str(len(body)))`, `connection.putheader("X-Client-Tag", ", ".join(self.headers.get_all("X-Client-Tag", [])))`+"\n                "+`connection.putheader("Content-Length", str(len(body)))`)
	// Act
	err := verify(2, launch, t.Logf)
	// Assert
	if err != nil {
		t.Fatal(err)
	}
}

// A redirect must be relayed without making a second origin request.
func TestGraderRejectsFollowingOriginRedirect(t *testing.T) {
	// Arrange
	launch := mutatedReference(t, "                with connection.getresponse() as response:", "                with connection.getresponse() as response:\n                    if response.status == 302:\n                        target = response.getheader('Location')\n                        connection.close()\n                        connection = http.client.HTTPConnection(origin.hostname, origin.port, timeout=3)\n                        connection.request('GET', target)\n                        response = connection.getresponse()")
	// Act
	err := verify(2, launch, t.Logf)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "origin redirects are relayed") {
		t.Fatalf("following an origin redirect was not detected: %v", err)
	}
}

// The safe-proxy stage rejects origin headers released before a complete body read.
func TestGraderRejectsEarlyOriginHeaders(t *testing.T) {
	// Arrange
	launch := mutatedReference(t,
		"with connection.getresponse() as response:\n                    response_policy",
		"with connection.getresponse() as response:\n                    self.send_response(response.status)\n                    self.end_headers()\n                    response_policy")
	// Act
	err := verify(3, launch, t.Logf)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "incomplete origin response returns a gateway error") {
		t.Fatalf("early origin headers were not detected: %v", err)
	}
}
