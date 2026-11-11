package waf

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const dummyHash = "DUMMY_PRIVATE_HASH"

var simulatedTautology = regexp.MustCompile(`or\s+1\s*=\s*1`)

// The exercise application deliberately exposes dummy data and unescaped HTML.
func serveApplication(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	status := http.StatusOK
	contentType := "application/json"
	var result any = map[string]string{"method": r.Method, "target": r.URL.RequestURI(), "body": string(body)}
	switch {
	case r.Method == "GET" && r.URL.Path == "/search":
		query := strings.ToLower(r.URL.Query().Get("q"))
		rows := []map[string]string{{"item": "tea cup"}}
		// This simulates SQL injection's consequence; no SQL is executed.
		if strings.Contains(query, "union select") || (simulatedTautology.MatchString(query) && strings.Contains(query, "--")) {
			rows = append(rows, map[string]string{"user": "admin", "password_hash": dummyHash})
		}
		result = map[string]any{"results": rows}
	case r.Method == "POST" && r.URL.Path == "/preview":
		text := string(body)
		valid := true
		mediaType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
		if mediaType == "application/json" {
			var value struct {
				Comment *string `json:"comment"`
			}
			valid = json.Unmarshal(body, &value) == nil && value.Comment != nil
			if valid {
				text = *value.Comment
			}
		} else if mediaType == "application/x-www-form-urlencoded" {
			values, err := url.ParseQuery(text)
			valid = err == nil
			text = values.Get("comment")
		}
		if valid {
			contentType = "text/html; charset=utf-8"
			result = "<!doctype html><title>Preview</title><div>Preview: " + text + "</div>"
		} else {
			status, result = 400, map[string]string{"error": "invalid preview"}
		}
	case r.Method == "POST" && r.URL.Path == "/articles":
		result = map[string]any{"published": true, "article": string(body)}
	case r.Method == "POST" && r.URL.Path == "/api/export":
		var value struct {
			Fields []string `json:"fields"`
		}
		if json.Unmarshal(body, &value) != nil || value.Fields == nil {
			status, result = 400, map[string]string{"error": "invalid export"}
		} else {
			record := map[string]string{"customer_id": "Customer-4829", "name": "Mira", "password_hash": dummyHash}
			exported := map[string]string{}
			for _, field := range value.Fields {
				if entry, exists := record[field]; exists {
					exported[field] = entry
				}
			}
			result = exported
		}
	case r.URL.Path == "/debug":
		status, result = 500, map[string]string{"debug": "INTERNAL_KEY_7F2A"}
	}
	var encoded []byte
	if strings.HasPrefix(contentType, "text/html") {
		encoded = []byte(result.(string))
	} else {
		encoded, _ = json.Marshal(result)
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Request-Id", "course-origin")
	w.WriteHeader(status)
	w.Write(encoded)
}
