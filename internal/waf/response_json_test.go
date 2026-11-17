package waf

import (
	"bytes"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

const responseJSONInspector = `
import json
import re
import sys

text = sys.stdin.buffer.read().decode("utf-8", "replace")
inputs = [text]

def reject_constant(value):
    raise ValueError(value)

def collect(value):
    if isinstance(value, str):
        inputs.append(value)
    elif isinstance(value, (list, tuple)):
        for child in value:
            collect(child)

options = {"object_pairs_hook": list}
if sys.argv[1] == "strict":
    options["parse_constant"] = reject_constant
try:
    collect(json.loads(text, **options))
except ValueError:
    pass

print("block" if any(re.search(r"INTERNAL_KEY_[A-Z0-9]+", value) for value in inputs) else "allow")
`

func responseJSONLaunch(t *testing.T, mode string) launchFunc {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	var originHost string
	return diagnosticProxyLaunch(func(r *http.Request) {}, func(response *http.Response) {
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			t.Errorf("read inspection fixture: %v", err)
			return
		}
		command := exec.Command(python, "-c", responseJSONInspector, mode)
		command.Stdin = bytes.NewReader(body)
		result, err := command.CombinedOutput()
		if err != nil {
			t.Errorf("inspect response fixture: %v: %s", err, result)
			return
		}
		if strings.TrimSpace(string(result)) == "block" {
			body = []byte(`{"error":{"rule":"response_leak"}}`)
			response.StatusCode = http.StatusForbidden
			response.Header = http.Header{}
			response.Header.Set("Content-Type", "application/json")
			response.Header.Set("X-WAF-Match", "response_leak")
		}
		response.Body = io.NopCloser(bytes.NewReader(body))
		response.ContentLength = int64(len(body))
		response.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}, &originHost)
}
