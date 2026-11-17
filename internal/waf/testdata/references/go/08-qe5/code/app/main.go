package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/text/cases"
	"golang.org/x/text/unicode/norm"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var hop = map[string]bool{"Connection": true, "Keep-Alive": true, "Proxy-Authenticate": true,
	"Proxy-Authorization": true, "Te": true, "Trailer": true, "Transfer-Encoding": true,
	"Upgrade": true, "Content-Length": true}

func copyHeaders(destination, source http.Header) {
	excluded := map[string]bool{}
	for _, name := range strings.Split(strings.Join(source.Values("Connection"), ","), ",") {
		excluded[http.CanonicalHeaderKey(strings.TrimSpace(name))] = true
	}
	for key, values := range source {
		if hop[key] || excluded[key] || strings.HasPrefix(strings.ToLower(key), "x-waf-") {
			continue
		}
		destination[key] = append([]string(nil), values...)
	}
}

func reject(w http.ResponseWriter, status int, rule string, diagnostics http.Header) {
	for key, values := range diagnostics {
		w.Header()[key] = values
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-WAF-Match", rule)
	w.Header().Set("Connection", "close")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"rule": rule}})
}

type Rule struct {
	ID   string `json:"id"`
	Term string `json:"term"`
}
type Policy struct {
	Mode           string      `json:"mode"`
	Denylist       []Rule      `json:"denylist"`
	Normalization  bool        `json:"normalization"`
	InspectHeaders []string    `json:"inspect_headers"`
	Heuristics     *Heuristics `json:"heuristics"`
	Classifier     *Classifier `json:"classifier"`
	Decisions      *Decisions  `json:"decisions"`
	Inspection     *Inspection `json:"inspection"`
}

func literalMatch(policy Policy, inputs []string) string {
	for _, rule := range policy.Denylist {
		for _, value := range inputs {
			if strings.Contains(value, rule.Term) {
				return rule.ID
			}
		}
	}
	return ""
}

func formValues(raw string, inspectBare bool) ([]string, error) {
	values := []string{}
	for _, part := range strings.Split(raw, "&") {
		if part == "" {
			continue
		}
		key, value, hasValue := strings.Cut(part, "=")
		if !hasValue && inspectBare {
			value = key
		}
		decodedKey, err := url.QueryUnescape(key)
		if err != nil || !utf8.ValidString(decodedKey) {
			return nil, fmt.Errorf("invalid query key")
		}
		decoded, err := url.QueryUnescape(value)
		if err != nil || !utf8.ValidString(decoded) {
			return nil, fmt.Errorf("invalid query value")
		}
		values = append(values, decoded)
	}
	return values, nil
}

func canonical(value string) string { return cases.Fold().String(norm.NFKC.String(value)) }

type Signal struct {
	ID      string `json:"id"`
	Pattern string `json:"pattern"`
	Weight  int    `json:"weight"`
}
type Heuristics struct {
	Threshold int      `json:"threshold"`
	Signals   []Signal `json:"signals"`
}

func patternMatch(pattern string, inputs []string) bool {
	expression := regexp.MustCompile(pattern)
	for _, value := range inputs {
		if expression.MatchString(value) {
			return true
		}
	}
	return false
}

type Classifier struct {
	Threshold int `json:"threshold"`
}

func classify(endpoint string, inputs []string) *int {
	client := &http.Client{Timeout: 200 * time.Millisecond,
		Transport:     &http.Transport{DisableKeepAlives: true, DisableCompression: true},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	payload, _ := json.Marshal(map[string]any{"inputs": inputs})
	response, err := client.Post(strings.TrimRight(endpoint, "/")+"/classify", "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != 200 {
		return nil
	}
	var result struct {
		Score *int `json:"score"`
	}
	if json.Unmarshal(data, &result) != nil || result.Score == nil || *result.Score < 0 || *result.Score > 100 {
		return nil
	}
	return result.Score
}

type Thresholds struct {
	Path            string `json:"path"`
	MLHigh          int    `json:"ml_high"`
	MLMedium        int    `json:"ml_medium"`
	HeuristicHigh   int    `json:"heuristic_high"`
	HeuristicMedium int    `json:"heuristic_medium"`
}
type Decisions struct {
	Default Thresholds   `json:"default"`
	Routes  []Thresholds `json:"routes"`
}
type Inspection struct {
	MaxBodyBytes int64 `json:"max_body_bytes"`
}

func parseJSON(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var readValue func() (any, error)
	readValue = func() (any, error) {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		switch token {
		case json.Delim('{'):
			object := map[string]any{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key := keyToken.(string)
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("duplicate JSON key")
				}
				value, err := readValue()
				if err != nil {
					return nil, err
				}
				object[key] = value
			}
			_, err := decoder.Token()
			return object, err
		case json.Delim('['):
			array := []any{}
			for decoder.More() {
				value, err := readValue()
				if err != nil {
					return nil, err
				}
				array = append(array, value)
			}
			_, err := decoder.Token()
			return array, err
		default:
			return token, nil
		}
	}
	value, err := readValue()
	if err != nil {
		return nil, err
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing JSON data")
	}
	return value, nil
}

func stringValues(value any) []string {
	result := []string{}
	switch value := value.(type) {
	case string:
		result = append(result, value)
	case []any:
		for _, item := range value {
			result = append(result, stringValues(item)...)
		}
	case map[string]any:
		for _, item := range value {
			result = append(result, stringValues(item)...)
		}
	}
	return result
}

func main() {
	origin := flag.String("origin", "", "Origin web application URL")
	detector := flag.String("detector", "", "ML detector URL")
	policyPath := flag.String("policy", "", "Trusted policy JSON file")
	flag.Parse()
	data, err := os.ReadFile(*policyPath)
	if err != nil {
		panic(err)
	}
	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		panic(err)
	}
	client := &http.Client{Timeout: 3 * time.Second,
		Transport:     &http.Transport{DisableCompression: true},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.RequestURI() == "/health" {
			w.WriteHeader(200)
			return
		}
		diagnostics := http.Header{}
		var reader io.Reader = r.Body
		if policy.Inspection != nil {
			if r.ContentLength > policy.Inspection.MaxBodyBytes {
				reject(w, 413, "body_too_large", diagnostics)
				return
			}
			reader = io.LimitReader(r.Body, policy.Inspection.MaxBodyBytes+1)
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			reject(w, 400, "invalid_request", diagnostics)
			return
		}
		if policy.Inspection != nil && int64(len(body)) > policy.Inspection.MaxBodyBytes {
			reject(w, 413, "body_too_large", diagnostics)
			return
		}
		inputs := []string{r.URL.RequestURI(), string(body)}
		decodedPath := r.URL.Path
		if !utf8.ValidString(decodedPath) {
			reject(w, 400, "invalid_request", diagnostics)
			return
		}
		if policy.Normalization {
			values, err := formValues(r.URL.RawQuery, true)
			if err != nil {
				reject(w, 400, "invalid_request", diagnostics)
				return
			}
			inputs = []string{decodedPath}
			inputs = append(inputs, values...)
			for _, name := range policy.InspectHeaders {
				inputs = append(inputs, r.Header.Values(name)...)
			}
			inputs = append(inputs, string(body))
		}
		if policy.Inspection != nil && len(body) == 0 {
			inputs = inputs[:len(inputs)-1]
		}
		if policy.Inspection != nil && len(body) > 0 {
			if encoding := r.Header.Get("Content-Encoding"); encoding != "" && !strings.EqualFold(encoding, "identity") {
				reject(w, 415, "unsupported_body", diagnostics)
				return
			}
			if !utf8.Valid(body) {
				reject(w, 400, "invalid_request", diagnostics)
				return
			}
			mediaType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
			var values []string
			switch mediaType {
			case "application/json":
				value, err := parseJSON(body)
				if err != nil {
					reject(w, 400, "invalid_request", diagnostics)
					return
				}
				values = stringValues(value)
			case "application/x-www-form-urlencoded":
				values, err = formValues(string(body), false)
				if err != nil {
					reject(w, 400, "invalid_request", diagnostics)
					return
				}
			case "text/plain":
				values = []string{string(body)}
			default:
				reject(w, 415, "unsupported_body", diagnostics)
				return
			}
			inputs = append(inputs[:len(inputs)-1], values...)
		}
		if policy.Normalization {
			for index, value := range inputs {
				inputs[index] = canonical(value)
			}
		}
		match := literalMatch(policy, inputs)
		score := 0
		fired := []string{}
		if policy.Heuristics != nil {
			for _, signal := range policy.Heuristics.Signals {
				if patternMatch(signal.Pattern, inputs) {
					score += signal.Weight
					fired = append(fired, signal.ID)
				}
			}
			diagnostics.Set("X-WAF-Score", strconv.Itoa(score))
			if len(fired) > 0 {
				diagnostics.Set("X-WAF-Signals", strings.Join(fired, ","))
			}
			if match == "" && score >= policy.Heuristics.Threshold {
				match = "heuristic_score"
			}
		}
		var mlScore *int
		if policy.Classifier != nil {
			mlScore = classify(*detector, inputs)
			diagnostics.Set("X-WAF-Detector-Status", "unavailable")
			if mlScore != nil {
				diagnostics.Set("X-WAF-Detector-Status", "ok")
				diagnostics.Set("X-WAF-ML-Score", strconv.Itoa(*mlScore))
				if match == "" && *mlScore >= policy.Classifier.Threshold {
					match = "ml_score"
				}
			}
		}
		if policy.Decisions != nil && mlScore != nil {
			thresholds := policy.Decisions.Default
			for _, route := range policy.Decisions.Routes {
				if decodedPath == route.Path {
					thresholds = route
					break
				}
			}
			match = literalMatch(policy, inputs)
			if match == "" {
				if score >= thresholds.HeuristicHigh {
					match = "heuristic_high"
				} else if *mlScore >= thresholds.MLHigh {
					match = "ml_high"
				} else if *mlScore >= thresholds.MLMedium && score >= thresholds.HeuristicMedium {
					match = "combined_scores"
				}
			}
		}
		if match != "" {
			if policy.Mode != "log" {
				reject(w, 403, match, diagnostics)
				return
			}
			diagnostics.Set("X-WAF-Match", match)
		}
		request, err := http.NewRequestWithContext(r.Context(), r.Method, strings.TrimRight(*origin, "/")+r.URL.RequestURI(), bytes.NewReader(body))
		if err != nil {
			reject(w, 502, "origin_unavailable", diagnostics)
			return
		}
		copyHeaders(request.Header, r.Header)
		response, err := client.Do(request)
		if err != nil {
			reject(w, 502, "origin_unavailable", diagnostics)
			return
		}
		defer response.Body.Close()
		var responseReader io.Reader = response.Body
		content, err := io.ReadAll(responseReader)
		if err != nil {
			reject(w, 502, "origin_unavailable", diagnostics)
			return
		}
		copyHeaders(w.Header(), response.Header)
		for key, values := range diagnostics {
			w.Header()[key] = values
		}
		w.WriteHeader(response.StatusCode)
		w.Write(content)
	})
	server := &http.Server{Addr: "127.0.0.1:8080", Handler: handler}
	if err := server.ListenAndServe(); err != nil {
		os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}
}
