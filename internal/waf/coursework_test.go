package waf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The origin interprets encoded spaces before exposing the simulated private row.
func TestApplicationSearchDecodesQuery(t *testing.T) {
	// Arrange
	request := httptest.NewRequest("GET", "/search?q=union+select%20password+from+users", nil)
	response := httptest.NewRecorder()
	// Act
	serveApplication(response, request)
	// Assert
	if response.Code != 200 || !strings.Contains(response.Body.String(), dummyHash) {
		t.Fatalf("expected the simulated private row: %d %s", response.Code, response.Body)
	}
}

// JSON escapes become unescaped HTML in the intentionally vulnerable preview.
func TestApplicationPreviewParsesJSON(t *testing.T) {
	// Arrange
	request := httptest.NewRequest("POST", "/preview", strings.NewReader(escapedPreview))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	// Act
	serveApplication(response, request)
	// Assert
	if response.Body.String() != previewHTML || response.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("expected unescaped HTML: %s %s", response.Header(), response.Body)
	}
}

// Form escapes are interpreted by the same vulnerable preview route.
func TestApplicationPreviewParsesForms(t *testing.T) {
	// Arrange
	request := httptest.NewRequest("POST", "/preview", strings.NewReader("comment=%3Cscript%3Ealert(1)%3C%2Fscript%3E"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	// Act
	serveApplication(response, request)
	// Assert
	if response.Body.String() != previewHTML {
		t.Fatalf("expected unescaped HTML: %s", response.Body)
	}
}

// A public-field export contains only the requested public record data.
func TestApplicationPublicExport(t *testing.T) {
	// Arrange
	request := httptest.NewRequest("POST", "/api/export", strings.NewReader(`{"fields":["customer_id","name"]}`))
	response := httptest.NewRecorder()
	// Act
	serveApplication(response, request)
	// Assert
	if response.Body.String() != publicExport {
		t.Fatalf("unexpected public export: %s", response.Body)
	}
}

// The model produces the measured Stage 6 inference score.
func TestExerciseModelProbeScore(t *testing.T) {
	// Arrange
	inputs := []string{"/search", "1' and sleep(5)#", ""}
	// Act
	score := exerciseScore(inputs)
	// Assert
	if score != 77 {
		t.Fatalf("expected 77, got %d", score)
	}
}

// The pre-parsing body stays below the combined cutoff in the Stage 8 exercise.
func TestExerciseModelEscapedBodyScore(t *testing.T) {
	// Arrange
	inputs := []string{"/preview", escapedPreview}
	// Act
	score := exerciseScore(inputs)
	// Assert
	if score != 26 {
		t.Fatalf("expected 26, got %d", score)
	}
}

func courseRoot() string {
	if root := os.Getenv("WAF_COURSE_DIR"); root != "" {
		return root
	}
	return "../../../build-your-own-firewall"
}

// The embedded model is identical to the independently evaluated course artifact.
func TestEmbeddedModelMatchesCourse(t *testing.T) {
	// Arrange
	expected, err := os.ReadFile(filepath.Join(courseRoot(), "model_development", "model.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Act
	matches := bytes.Equal(modelData, expected)
	// Assert
	if !matches {
		t.Fatal("tester model differs from the course's frozen model")
	}
}

// Go inference reproduces the Python evaluation's scores on the held-out set.
func TestExerciseModelHeldoutParity(t *testing.T) {
	// Arrange
	data, err := os.ReadFile(filepath.Join(courseRoot(), "model_development", "evaluation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Observations []struct {
			Text  string
			Score int
		}
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	// Act and Assert
	for _, observation := range report.Observations {
		if actual := exerciseScore([]string{observation.Text}); actual != observation.Score {
			t.Errorf("%q: expected %d, got %d", observation.Text, observation.Score, actual)
		}
	}
}

// The finale visibly distinguishes withheld responses, probes, and false positives.
func TestCourseworkReplayOutput(t *testing.T) {
	// Arrange
	directory := filepath.Join(courseRoot(), "solutions", "python", "10-mu9", "code")
	directory, err := filepath.Abs(directory)
	if err != nil {
		t.Fatal(err)
	}
	var output strings.Builder
	log := func(format string, args ...any) { fmt.Fprintf(&output, format+"\n", args...) }
	// Act
	err = runScenario(courseworkScenarios(10)[0], referenceLaunch(t, directory), log)
	// Assert
	if err != nil {
		t.Fatal(err, output.String())
	}
	for _, expected := range []string{
		"DUMMY_PRIVATE_HASH",
		"Response withheld after application processing.",
		"Replay totals: blocked requests=5, withheld responses=1, unblocked probes=1, preserved legitimate=4, false positives=1",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("missing visible result %q", expected)
		}
	}
}
