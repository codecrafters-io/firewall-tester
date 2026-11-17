package waf

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func fixedStatusLaunch(status int) launchFunc {
	return func(_, _, _ string) (func(), error) {
		listener, err := net.Listen("tcp", "127.0.0.1:8080")
		if err != nil {
			return nil, err
		}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.Copy(io.Discard, r.Body)
			w.WriteHeader(status)
		})}
		go server.Serve(listener)
		return func() { server.Close() }, nil
	}
}

// Each failed body-validation probe logs the exact body that triggered it.
func TestFailedBodyValidationLogsRequest(t *testing.T) {
	// Arrange
	var test scenario
	for _, candidate := range stageScenarios(8) {
		if candidate.Name == "uninspectable input never reaches detector or origin" {
			test = candidate
			break
		}
	}
	if len(test.Probes) == 0 {
		t.Fatal("body-validation probes not found")
	}
	for i, check := range test.Probes {
		t.Run(fmt.Sprintf("body-%d", i+1), func(t *testing.T) {
			// Arrange
			oneProbe := test
			oneProbe.Probes = []probe{check}
			var output strings.Builder
			log := func(format string, args ...any) { fmt.Fprintf(&output, format+"\n", args...) }
			// Act
			err := runScenario(oneProbe, fixedStatusLaunch(http.StatusForbidden), log)
			// Assert
			failure := fmt.Sprintf("POST /echo: expected HTTP %d, got 403", check.Status)
			if err == nil || !strings.Contains(err.Error(), failure) {
				t.Fatalf("expected status failure %q, got %v", failure, err)
			}
			for _, expected := range []string{
				"Request: POST /echo, headers:",
				fmt.Sprintf("Content-Type:[%s]", check.Headers["Content-Type"]),
				fmt.Sprintf("body: %q", check.Body),
			} {
				if !strings.Contains(output.String(), expected) {
					t.Errorf("missing request detail %q in failure output:\n%s\n%v", expected, output.String(), err)
				}
			}
		})
	}
}

// A failed normalization probe logs the header containing the attack.
func TestFailedHeaderNormalizationLogsRequest(t *testing.T) {
	// Arrange
	var test scenario
	for _, candidate := range stageScenarios(4) {
		if candidate.Name == "decoded inputs and one-layer boundary" {
			test = candidate
			break
		}
	}
	var check probe
	for _, candidate := range test.Probes {
		if candidate.Headers["x-search"] != "" {
			check = candidate
			break
		}
	}
	if check.Target == "" {
		t.Fatal("header-normalization probe not found")
	}
	test.Probes = []probe{check}
	var output strings.Builder
	log := func(format string, args ...any) { fmt.Fprintf(&output, format+"\n", args...) }
	// Act
	err := runScenario(test, fixedStatusLaunch(http.StatusOK), log)
	// Assert
	if err == nil || !strings.Contains(err.Error(), "GET /search: expected HTTP 403, got 200") {
		t.Fatalf("expected header-normalization status failure, got %v", err)
	}
	for _, expected := range []string{
		"Request: GET /search, headers:",
		fmt.Sprintf("X-Search:[%s]", check.Headers["x-search"]),
	} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("missing request detail %q in failure output:\n%s\n%v", expected, output.String(), err)
		}
	}
}
