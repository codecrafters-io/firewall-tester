package waf

import (
	"context"
	"fmt"
	testerutils "github.com/codecrafters-io/tester-utils"
	"github.com/codecrafters-io/tester-utils/test_case_harness"
	"github.com/codecrafters-io/tester-utils/tester_definition"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

var slugs = []string{"fi6", "tf0", "kg7", "wt4", "ro3", "xd5", "si3", "qe5", "as4", "mu9"}

func waitHealth(done <-chan struct{}) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		select {
		case <-done:
			cancel()
		case <-ctx.Done():
		}
	}()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	var lastErr error = context.DeadlineExceeded
	for ctx.Err() == nil {
		select {
		case <-done:
			return fmt.Errorf("program exited before health checks completed")
		default:
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:8080/health", nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				return fmt.Errorf("GET /health: expected HTTP 200, got %d", response.StatusCode)
			}
			return nil
		}
		lastErr = err
		select {
		case <-ctx.Done():
		case <-time.After(25 * time.Millisecond):
		}
	}
	select {
	case <-done:
		return fmt.Errorf("program exited before health checks completed")
	default:
	}
	return fmt.Errorf("GET /health on port 8080 did not return HTTP 200 within five seconds; last request failed: %w", lastErr)
}

func portAvailable() error {
	listener, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		return fmt.Errorf("tester setup: port 8080 is occupied")
	}
	listener.Close()
	if conn, err := net.DialTimeout("tcp", "127.0.0.1:8080", 100*time.Millisecond); err == nil {
		conn.Close()
		return fmt.Errorf("tester setup: port 8080 is occupied")
	}
	return nil
}

func runStage(h *test_case_harness.TestCaseHarness, stage int) error {
	launch := func(origin, detector, policy string) (func(), error) {
		if err := portAvailable(); err != nil {
			return nil, err
		}
		directory, err := os.MkdirTemp("", "waf-policy-")
		if err != nil {
			return nil, err
		}
		path := filepath.Join(directory, "policy.json")
		if err := os.WriteFile(path, []byte(policy), 0600); err != nil {
			os.RemoveAll(directory)
			return nil, err
		}
		h.Logger.Infof("Policy: %s", policy)
		program := h.Executable
		program.WorkingDir = directory
		program.TimeoutInMilliseconds = 120000
		if err := program.Start("--origin", origin, "--detector", detector, "--policy", path); err != nil {
			os.RemoveAll(directory)
			return nil, err
		}
		process := program.Process
		done := make(chan struct{})
		go func() { program.Wait(); close(done) }()
		var once sync.Once
		stop := func() {
			once.Do(func() {
				select {
				case <-done:
				default:
					syscall.Kill(-process.Pid, syscall.SIGTERM)
					select {
					case <-done:
					case <-time.After(time.Second):
						syscall.Kill(-process.Pid, syscall.SIGKILL)
						<-done
					}
				}
				os.RemoveAll(directory)
			})
		}
		h.RegisterTeardownFunc(stop)
		if err := waitHealth(done); err != nil {
			stop()
			return nil, err
		}
		return stop, nil
	}
	return verify(stage, launch, h.Logger.Infof)
}

func RunCLI(env map[string]string) int {
	definition := tester_definition.TesterDefinition{ExecutableFileName: "your_program.sh"}
	for i, slug := range slugs {
		stage := i + 1
		definition.TestCases = append(definition.TestCases, tester_definition.TestCase{Slug: slug, Timeout: 120 * time.Second, TestFunc: func(h *test_case_harness.TestCaseHarness) error { return runStage(h, stage) }})
	}
	return testerutils.RunCLI(env, definition)
}
