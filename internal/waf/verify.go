package waf

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type launchFunc func(origin, detector, policy string) (func(), error)
type probe struct {
	Method, Target, Body string
	WantBody             string
	Traffic              string
	Headers              map[string]string
	Status               int
	Rule                 string
	Forward              bool
	// AnyBody accepts a locally generated error whose body the stage does not
	// prescribe, such as an HTTP server rejecting a malformed request target.
	AnyBody     bool
	WantHeaders map[string]string
	Absent      []string
	WantSignals []string
	MaxDuration time.Duration
	Inputs      []string
}
type scenario struct {
	Coursework      bool
	Offline         bool
	Name            string
	Policy          string
	Probes          []probe
	Score           int
	DetectorMode    string
	OriginStatus    int
	OriginBody      string
	OriginTruncated bool
}

func verify(stage int, launch launchFunc, log func(string, ...any)) error {
	for _, test := range append(courseworkScenarios(stage), stageScenarios(stage)...) {
		log("%s", test.Name)
		if err := runScenario(test, launch, log); err != nil {
			return fmt.Errorf("%s: %w", test.Name, err)
		}
	}
	return nil
}

func runScenario(test scenario, launch launchFunc, log func(string, ...any)) error {
	var lock sync.Mutex
	received := []*http.Request{}
	bodies := [][]byte{}
	detectorInputs := [][]string{}
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		lock.Lock()
		received = append(received, r.Clone(r.Context()))
		bodies = append(bodies, body)
		lock.Unlock()
		if test.Coursework {
			r.Body = io.NopCloser(bytes.NewReader(body))
			serveApplication(w, r)
			return
		}
		status := test.OriginStatus
		if status == 0 {
			status = 200
		}
		bodyText := test.OriginBody
		if bodyText == "" {
			bodyText = `{ "ok": true }`
		}
		// Write the fixture's Connection nomination explicitly. Server helpers
		// otherwise replace it with close for clients that disable keep-alive.
		connection, writer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer connection.Close()
		length := len(bodyText)
		if test.OriginTruncated {
			length += 100
		}
		fmt.Fprintf(writer, "HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nContent-Length: %d\r\nX-Request-Id: origin-7\r\nX-WAF-Match: forged-origin\r\nConnection: X-Origin-Hop\r\nConnection: X-Second-Hop\r\nX-Second-Hop: remove-too\r\nX-Origin-Hop: remove-me\r\n\r\n%s", status, http.StatusText(status), length, bodyText)
		writer.Flush()
	}))
	defer origin.Close()
	if test.Offline {
		origin.Close()
	}
	detector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var value struct {
			Inputs []string `json:"inputs"`
		}
		json.NewDecoder(r.Body).Decode(&value)
		lock.Lock()
		detectorInputs = append(detectorInputs, value.Inputs)
		lock.Unlock()
		if r.Method != "POST" || r.URL.Path != "/classify" || r.Header.Get("Authorization") != "" || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(400)
			return
		}
		switch test.DetectorMode {
		case "slow_body":
			body := []byte(`{"score":70}`)
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			for _, value := range body {
				time.Sleep(70 * time.Millisecond)
				if _, err := w.Write([]byte{value}); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
			return
		case "slow_headers":
			connection, writer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer connection.Close()
			for _, value := range []byte("HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n{\"score\":70}") {
				time.Sleep(30 * time.Millisecond)
				if err := writer.WriteByte(value); err != nil {
					return
				}
				if err := writer.Flush(); err != nil {
					return
				}
			}
			return
		case "truncated":
			w.Header().Set("Content-Length", "100")
			io.WriteString(w, `{"score":70}`)
			return
		case "late":
			time.Sleep(250 * time.Millisecond)
		case "slow":
			time.Sleep(350 * time.Millisecond)
		case "error":
			w.WriteHeader(503)
			return
		case "null":
			io.WriteString(w, `{"score":null}`)
			return
		case "range":
			io.WriteString(w, `{"score":101}`)
			return
		case "fraction":
			io.WriteString(w, `{"score":90.5}`)
			return
		case "boolean":
			io.WriteString(w, `{"score":true}`)
			return
		case "missing":
			io.WriteString(w, `{}`)
			return
		case "trailing":
			io.WriteString(w, `{"score":90} {}`)
			return
		case "redirect":
			w.Header().Set("Location", "/second")
			w.WriteHeader(302)
			return
		}
		score := test.Score
		if test.Coursework {
			score = exerciseScore(value.Inputs)
		}
		json.NewEncoder(w).Encode(map[string]int{"score": score})
	}))
	defer detector.Close()
	stop, err := launch(origin.URL, detector.URL, test.Policy)
	if err != nil {
		return err
	}
	defer stop()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, DisableCompression: true}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	replayCounts := map[string]int{}
	for _, check := range test.Probes {
		if test.Coursework {
			method := check.Method
			if method == "" {
				method = "GET"
			}
			baseline, err := http.NewRequest(method, origin.URL+check.Target, strings.NewReader(check.Body))
			if err != nil {
				return err
			}
			for key, value := range check.Headers {
				baseline.Header.Set(key, value)
			}
			direct, err := client.Do(baseline)
			if err != nil {
				return fmt.Errorf("application baseline: %w", err)
			}
			exposed, err := io.ReadAll(direct.Body)
			direct.Body.Close()
			if err != nil {
				return err
			}
			log("Request: %s %s", method, check.Target)
			if check.Body != "" {
				log("Request body: %s", check.Body)
			}
			log("Application without firewall: HTTP %d, %s", direct.StatusCode, exposed)
		}
		lock.Lock()
		before := len(received)
		detectorBefore := len(detectorInputs)
		lock.Unlock()
		method := check.Method
		if method == "" {
			method = "GET"
		}
		target := check.Target
		if target == "" {
			target = "/products?q=book"
		}
		request, err := http.NewRequest(method, "http://127.0.0.1:8080"+target, strings.NewReader(check.Body))
		if err != nil {
			// A malformed escape cannot be parsed as a URL; send its bytes verbatim.
			request, err = http.NewRequest(method, "http://127.0.0.1:8080/", strings.NewReader(check.Body))
			if err != nil {
				return err
			}
			request.URL.Opaque = target
		}
		request.Header.Set("Authorization", "Bearer course-test-key")
		request.Header.Set("X-WAF-Match", "forged-client")
		request.Header.Set("Connection", "X-Client-Hop")
		request.Header.Set("X-Client-Hop", "remove-me")
		for key, value := range check.Headers {
			request.Header.Set(key, value)
		}
		started := time.Now()
		response, err := client.Do(request)
		if err != nil {
			return fmt.Errorf("request failed: %w", err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			return err
		}
		if check.MaxDuration > 0 && time.Since(started) > check.MaxDuration {
			return fmt.Errorf("request exceeded deadline tolerance %s", check.MaxDuration)
		}
		if response.StatusCode != check.Status {
			return fmt.Errorf("%s %s: expected HTTP %d, got %d: %s", method, target, check.Status, response.StatusCode, body)
		}
		if test.Coursework {
			log("Through your firewall: HTTP %d, %s", response.StatusCode, body)
			for _, header := range []string{"X-WAF-Match", "X-WAF-Score", "X-WAF-ML-Score", "X-WAF-Detector-Status"} {
				if value := response.Header.Get(header); value != "" {
					log("%s: %s", header, value)
				}
			}
		}
		if check.Rule != "" {
			if bytes.Contains(body, []byte("INTERNAL_KEY_7F2A")) || bytes.Contains(body, []byte("password_hash")) {
				return fmt.Errorf("protected input or origin data echoed in denial")
			}
			var result struct {
				Error struct {
					Rule string `json:"rule"`
				} `json:"error"`
			}
			if json.Unmarshal(body, &result) != nil || result.Error.Rule != check.Rule {
				return fmt.Errorf("expected JSON error.rule %q, got %s", check.Rule, body)
			}
			if response.Header.Get("Content-Type") != "application/json" || response.Header.Get("X-WAF-Match") != check.Rule || len(response.Header.Values("X-WAF-Match")) != 1 {
				return fmt.Errorf("missing denial headers: %v", response.Header)
			}
			if response.Header.Get("X-Request-Id") != "" {
				return fmt.Errorf("origin header escaped in denial")
			}
		} else if target != "/health" && !check.AnyBody {
			expected := test.OriginBody
			if expected == "" {
				expected = `{ "ok": true }`
			}
			if check.WantBody != "" {
				expected = check.WantBody
			}
			requestID := "origin-7"
			if test.Coursework {
				requestID = "course-origin"
			}
			if !bytes.Equal(body, []byte(expected)) || response.Header.Get("X-Request-Id") != requestID {
				return fmt.Errorf("origin body or request ID changed: %s", body)
			}
			if response.Header.Get("X-Origin-Hop") != "" || response.Header.Get("X-Second-Hop") != "" {
				return fmt.Errorf("hop header escaped: %v", response.Header)
			}
		}
		for key, value := range check.WantHeaders {
			if response.Header.Get(key) != value {
				return fmt.Errorf("expected %s=%q, got %q", key, value, response.Header.Get(key))
			}
		}
		if check.WantSignals != nil {
			actual := strings.Split(response.Header.Get("X-WAF-Signals"), ",")
			wanted := append([]string(nil), check.WantSignals...)
			sort.Strings(actual)
			sort.Strings(wanted)
			if !slices.Equal(actual, wanted) {
				return fmt.Errorf("expected signal IDs %q, got %q", wanted, actual)
			}
		}
		for _, key := range check.Absent {
			if response.Header.Get(key) != "" {
				return fmt.Errorf("unexpected %s: %q", key, response.Header.Get(key))
			}
		}
		time.Sleep(10 * time.Millisecond)
		lock.Lock()
		count := len(received) - before
		newInputs := append([][]string(nil), detectorInputs[detectorBefore:]...)
		var last *http.Request
		var lastBody []byte
		if count > 0 {
			last = received[len(received)-1]
			lastBody = bodies[len(bodies)-1]
		}
		lock.Unlock()
		expectedCount := 0
		if check.Forward {
			expectedCount = 1
		}
		if test.Coursework {
			log("Application requests through firewall: %d", count)
			if check.Rule == "response_leak" {
				log("Response withheld after application processing.")
			}
		}
		if count != expectedCount {
			return fmt.Errorf("expected %d origin requests, got %d", expectedCount, count)
		}
		if last != nil {
			if last.Method != method || last.URL.RequestURI() != target || string(lastBody) != check.Body {
				return fmt.Errorf("forwarded request changed")
			}
			if last.Host != strings.TrimPrefix(origin.URL, "http://") || last.Header.Get("Authorization") != "Bearer course-test-key" {
				return fmt.Errorf("upstream host or authentication changed")
			}
			if last.Header.Get("X-WAF-Match") != "" || last.Header.Get("X-Client-Hop") != "" {
				return fmt.Errorf("reserved or hop header forwarded")
			}
		}
		if check.Inputs != nil {
			if len(newInputs) != 1 {
				return fmt.Errorf("expected one detector call, got %d", len(newInputs))
			}
			actual := append([]string(nil), newInputs[0]...)
			wanted := append([]string(nil), check.Inputs...)
			sort.Strings(actual)
			sort.Strings(wanted)
			if !slices.Equal(actual, wanted) {
				return fmt.Errorf("inspection inputs: expected %q, got %q", wanted, actual)
			}
		}
		if check.Traffic != "" {
			outcome := "preserved legitimate"
			switch check.Traffic {
			case "attack":
				outcome = "blocked requests"
				if check.Rule == "response_leak" {
					outcome = "withheld responses"
				}
			case "probe":
				outcome = "unblocked probes"
			case "legitimate":
				if check.Rule != "" {
					outcome = "false positives"
				}
			}
			replayCounts[outcome]++
			log("Replay outcome: %s", outcome)
		}

		var policy map[string]json.RawMessage
		json.Unmarshal([]byte(test.Policy), &policy)
		if (policy["classifier"] == nil || target == "/health" || check.Status == 400 || check.Status == 413 || check.Status == 415) && len(newInputs) > 0 {
			return fmt.Errorf("detector called without classifier policy")
		}
	}
	if len(replayCounts) != 0 {
		log("Replay totals: blocked requests=%d, withheld responses=%d, unblocked probes=%d, preserved legitimate=%d, false positives=%d",
			replayCounts["blocked requests"], replayCounts["withheld responses"], replayCounts["unblocked probes"], replayCounts["preserved legitimate"], replayCounts["false positives"])
		log("An unblocked detection probe does not prove exploitation. Route thresholds do not override hard signatures.")
	}
	return nil
}
