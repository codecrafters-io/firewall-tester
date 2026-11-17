package waf

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"
)

func diagnosticProxyLaunch(mutateRequest func(*http.Request), mutateResponse func(*http.Response), originHost *string) launchFunc {
	return func(origin, _, _ string) (func(), error) {
		upstream, err := url.Parse(origin)
		if err != nil {
			return nil, err
		}
		*originHost = upstream.Host
		listener, err := net.Listen("tcp", "127.0.0.1:8080")
		if err != nil {
			return nil, err
		}
		transport := &http.Transport{}
		proxy := &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(request *httputil.ProxyRequest) {
				request.SetURL(upstream)
				request.Out.Header.Del("X-WAF-Match")
				request.Out.Header.Del("X-WAF-Injected")
				mutateRequest(request.Out)
			},
			ModifyResponse: func(response *http.Response) error {
				response.Header.Del("X-WAF-Match")
				response.Header.Del("X-WAF-Injected")
				mutateResponse(response)
				return nil
			},
		}
		server := &http.Server{Handler: proxy}
		go server.Serve(listener)
		return func() {
			server.Close()
			transport.CloseIdleConnections()
		}, nil
	}
}

// Each forwarding mismatch names the changed field and its expected and actual values.
func TestForwardingDiagnostics(t *testing.T) {
	for _, check := range []struct {
		name   string
		mutate func(*http.Request)
		want   string
	}{
		{"unchanged", func(r *http.Request) {}, ""},
		{"method", func(r *http.Request) { r.Method = "PUT" }, `forwarded request method: expected "POST", got "PUT"`},
		{"target", func(r *http.Request) { r.URL.RawQuery = "x=changed" }, `forwarded request target: expected "/echo?x=original", got "/echo?x=changed"`},
		{"body", func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader("changed"))
			r.ContentLength = int64(len("changed"))
		}, `forwarded request body: expected "original\n\xff", got "changed"`},
		{"Host", func(r *http.Request) { r.Host = "wrong.example" }, ""},
		{"Authorization", func(r *http.Request) { r.Header.Set("Authorization", "wrong-key") }, `forwarded request header Authorization: expected "Bearer course-test-key", got "wrong-key"`},
		{"missing Authorization", func(r *http.Request) { r.Header.Del("Authorization") }, `forwarded request header Authorization: expected "Bearer course-test-key", got ""`},
		{"X-WAF-Match", func(r *http.Request) { r.Header.Set("X-WAF-Match", "forged-client") }, `forwarded request header X-WAF-Match: expected absent, got ["forged-client"]`},
		{"X-WAF-Injected", func(r *http.Request) { r.Header.Set("X-WAF-Injected", "forged-client") }, `forwarded request header X-WAF-Injected: expected absent, got ["forged-client"]`},
		{"X-Client-Hop", func(r *http.Request) { r.Header.Set("X-Client-Hop", "remove-me") }, `forwarded request header X-Client-Hop: expected absent, got ["remove-me"]`},
	} {
		t.Run(check.name, func(t *testing.T) {
			// Arrange
			test := scenario{Policy: "{}", Probes: []probe{{
				Method: "POST", Target: "/echo?x=original", Body: "original\n\xff", Status: 200, Forward: true,
			}}}
			var originHost string
			// Act
			err := runScenario(test, diagnosticProxyLaunch(check.mutate, func(r *http.Response) {}, &originHost), t.Logf)
			// Assert
			want := check.want
			if check.name == "Host" {
				want = fmt.Sprintf("forwarded request Host: expected %q, got %q", originHost, "wrong.example")
			}
			if want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || err.Error() != want {
				t.Fatalf("expected diagnostic %q, got %v", want, err)
			}
		})
	}
}

// Each denial-header mismatch identifies the header, including missing or duplicate values.
func TestDenialHeaderDiagnostics(t *testing.T) {
	for _, check := range []struct {
		name   string
		mutate func(http.Header)
		want   string
	}{
		{"valid", func(h http.Header) {}, ""},
		{"missing Content-Type", func(h http.Header) { h.Del("Content-Type") }, `denial response header Content-Type: expected "application/json", got ""`},
		{"wrong Content-Type", func(h http.Header) { h.Set("Content-Type", "text/plain") }, `denial response header Content-Type: expected "application/json", got "text/plain"`},
		{"missing X-WAF-Match", func(h http.Header) { h.Del("X-WAF-Match") }, `denial response header X-WAF-Match: expected exactly one value "xss-script", got []`},
		{"wrong X-WAF-Match", func(h http.Header) { h.Set("X-WAF-Match", "wrong-rule") }, `denial response header X-WAF-Match: expected exactly one value "xss-script", got ["wrong-rule"]`},
		{"duplicate X-WAF-Match", func(h http.Header) { h.Add("X-WAF-Match", "xss-script") }, `denial response header X-WAF-Match: expected exactly one value "xss-script", got ["xss-script" "xss-script"]`},
	} {
		t.Run(check.name, func(t *testing.T) {
			// Arrange
			test := scenario{Policy: "{}", Probes: []probe{deny("/search", "xss-script")}}
			launch := func(_, _, _ string) (func(), error) {
				listener, err := net.Listen("tcp", "127.0.0.1:8080")
				if err != nil {
					return nil, err
				}
				server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					w.Header().Set("X-WAF-Match", "xss-script")
					check.mutate(w.Header())
					// Suppress automatic content sniffing when testing a missing header.
					if w.Header().Get("Content-Type") == "" {
						w.Header()["Content-Type"] = nil
					}
					w.WriteHeader(http.StatusForbidden)
					io.WriteString(w, `{"error":{"rule":"xss-script"}}`)
				})}
				go server.Serve(listener)
				return func() { server.Close() }, nil
			}
			// Act
			err := runScenario(test, launch, t.Logf)
			// Assert
			if check.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || err.Error() != check.want {
				t.Fatalf("expected diagnostic %q, got %v", check.want, err)
			}
		})
	}
}

// Origin response failures identify either the body or the request ID that changed.
func TestOriginResponseDiagnostics(t *testing.T) {
	for _, coursework := range []bool{false, true} {
		for _, check := range []struct {
			name   string
			mutate func(*http.Response)
		}{
			{"valid", func(r *http.Response) {}},
			{"body", func(r *http.Response) {
				r.Body.Close()
				r.Body = io.NopCloser(strings.NewReader("changed\n"))
				r.ContentLength = int64(len("changed\n"))
				r.Header.Set("Content-Length", fmt.Sprint(r.ContentLength))
			}},
			{"missing request ID", func(r *http.Response) { r.Header.Del("X-Request-Id") }},
			{"wrong request ID", func(r *http.Response) { r.Header.Set("X-Request-Id", "wrong-id") }},
		} {
			t.Run(fmt.Sprintf("coursework=%t/%s", coursework, check.name), func(t *testing.T) {
				// Arrange
				request := allow("/products")
				expectedBody, expectedID := `{ "ok": true }`, "origin-7"
				if coursework {
					request = productSearch()
					expectedBody, expectedID = productResults, "course-origin"
				}
				test := scenario{Coursework: coursework, Policy: "{}", Probes: []probe{request}}
				var originHost string
				// Act
				err := runScenario(test, diagnosticProxyLaunch(func(r *http.Request) {}, check.mutate, &originHost), t.Logf)
				// Assert
				var want string
				switch check.name {
				case "valid":
					if err != nil {
						t.Fatal(err)
					}
					return
				case "body":
					want = fmt.Sprintf("origin response body: expected %q, got %q", expectedBody, "changed\n")
				case "missing request ID":
					want = fmt.Sprintf("origin response header X-Request-Id: expected %q, got %q", expectedID, "")
				case "wrong request ID":
					want = fmt.Sprintf("origin response header X-Request-Id: expected %q, got %q", expectedID, "wrong-id")
				}
				if err == nil || err.Error() != want {
					t.Fatalf("expected diagnostic %q, got %v", want, err)
				}
			})
		}
	}
}
