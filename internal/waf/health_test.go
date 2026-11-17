package waf

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func startHealthServer(t *testing.T, handler http.HandlerFunc) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	t.Cleanup(func() { server.Close() })
	go server.Serve(listener)
}

// A health response slower than 200 ms can satisfy the five-second startup deadline.
func TestWaitHealthAcceptsSlowResponse(t *testing.T) {
	// Arrange
	startHealthServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(400 * time.Millisecond):
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	})
	// Act
	err := waitHealth(make(chan struct{}))
	// Assert
	if err != nil {
		t.Fatal(err)
	}
}

// A stalled health request reports its cause and is cancelled at the overall deadline.
func TestWaitHealthReportsResponseTimeout(t *testing.T) {
	// Arrange
	var requests atomic.Int32
	cancelled := make(chan struct{}, 1)
	startHealthServer(t, func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		<-r.Context().Done()
		select {
		case cancelled <- struct{}{}:
		default:
		}
	})
	// Act
	err := waitHealth(make(chan struct{}))
	// Assert
	if err == nil || !strings.Contains(err.Error(), "GET /health on port 8080 did not return HTTP 200 within five seconds; last request failed:") {
		t.Fatalf("expected a health request timeout diagnostic, got %v", err)
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("expected the underlying timeout, got %v", err)
	}
	if count := requests.Load(); count != 1 {
		t.Errorf("expected one request using the startup deadline, got %d", count)
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("timed-out health request was not cancelled")
	}
}

// Program exit cancels an in-flight health request instead of waiting for its deadline.
func TestWaitHealthCancelsOnProgramExit(t *testing.T) {
	// Arrange
	done := make(chan struct{})
	cancelled := make(chan struct{})
	startHealthServer(t, func(w http.ResponseWriter, r *http.Request) {
		close(done)
		<-r.Context().Done()
		close(cancelled)
	})
	result := make(chan error, 1)
	// Act
	go func() { result <- waitHealth(done) }()
	// Assert
	select {
	case err := <-result:
		if err == nil || err.Error() != "program exited before health checks completed" {
			t.Fatalf("expected program exit diagnostic, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("health request did not stop promptly after program exit")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("health request was not cancelled after program exit")
	}
}

// Non-200 health responses identify the status without following redirects.
func TestWaitHealthReportsHTTPStatus(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusMovedPermanently} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			// Arrange
			startHealthServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/ready" {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.Header().Set("Location", "/ready")
				w.WriteHeader(status)
			})
			// Act
			err := waitHealth(make(chan struct{}))
			// Assert
			want := fmt.Sprintf("GET /health: expected HTTP 200, got %d", status)
			if err == nil || err.Error() != want {
				t.Fatalf("expected status diagnostic %q, got %v", want, err)
			}
		})
	}
}
