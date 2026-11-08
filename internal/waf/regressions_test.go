package waf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mutatedReference(t *testing.T, replacements ...string) launchFunc {
	t.Helper()
	root := os.Getenv("WAF_COURSE_DIR")
	if root == "" {
		root = "../../../build-your-own-firewall"
	}
	source := filepath.Join(root, "solutions", "python", "11-mu9", "code")
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
	err := verify(5, launch, t.Logf)
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
	err := verify(5, launch, t.Logf)
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
	err := verify(6, launch, t.Logf)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "detector failure fallback: slow_body") {
		t.Fatal("socket timeout without total deadline passed")
	}
}

// Incomplete origin reads must become gateway errors instead of disconnects.
func TestGraderRejectsUncaughtOriginRead(t *testing.T) {
	// Arrange
	launch := mutatedReference(t, "except (OSError, urllib.error.URLError, http.client.HTTPException):", "except (OSError, urllib.error.URLError):")
	// Act
	err := verify(2, launch, t.Logf)
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
	err := verify(8, launch, t.Logf)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "inspection inputs:") {
		t.Fatal("empty body placeholder passed")
	}
}
