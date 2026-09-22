package tests

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	startTimeout        = 15 * time.Second
	gracefulStopTimeout = 10 * time.Second
	stateChangeTimeout  = 10 * time.Second
	startAttempts       = 3
)

// testBinary is a Go program that is built at most once per test run.
type testBinary struct {
	name     string // file name of the built binary
	buildDir string // directory, relative to the repository root, in which "go build" runs
	pkg      string // package to build, relative to buildDir
	once     sync.Once
	path     string
	err      error
}

var (
	wafBinary            = &testBinary{name: "synit-waf", buildDir: ".", pkg: "./cmd/synit-waf"}
	aiLogsReceiverBinary = &testBinary{name: "ai-logs-receiver", buildDir: filepath.Join("services", "ai-logs-receiver"), pkg: "."}

	// binDir holds every built binary. TestMain removes it.
	binDir     string
	binDirErr  error
	binDirOnce sync.Once
)

func TestMain(m *testing.M) {
	code := m.Run()
	if binDir != "" {
		_ = os.RemoveAll(binDir)
	}
	os.Exit(code)
}

// get builds the binary on first use and returns its path.
func (b *testBinary) get(t *testing.T) string {
	t.Helper()
	b.once.Do(func() {
		binDirOnce.Do(func() {
			binDir, binDirErr = os.MkdirTemp("", "synit-waf-e2e-bin-")
		})
		if binDirErr != nil {
			b.err = fmt.Errorf("failed to create temp dir for builds: %w", binDirErr)
			return
		}
		path := filepath.Join(binDir, b.name)
		if runtime.GOOS == "windows" {
			path += ".exe"
		}
		buildCmd := exec.Command("go", "build", "-o", path, b.pkg)
		buildCmd.Dir = filepath.Join(projectRootFromRuntime(t), b.buildDir)
		buildOutput, err := buildCmd.CombinedOutput()
		if err != nil {
			b.err = fmt.Errorf("failed to build %s: %v\noutput:\n%s", b.name, err, string(buildOutput))
			return
		}
		b.path = path
	})
	if b.err != nil {
		t.Fatalf("%v", b.err)
	}
	return b.path
}

// syncBuffer collects the output of a child process. The process writes while
// the test reads, so access is locked.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// childProcess is a running binary under test.
type childProcess struct {
	name    string
	cmd     *exec.Cmd
	output  *syncBuffer
	exited  chan struct{} // closed when the process has exited
	waitErr error         // valid once exited is closed
}

// startListeningProcess starts a binary that listens on freshly allocated
// local addresses and waits until its readiness URL answers 200. newCmd gets
// the addresses and returns the command and that URL.
//
// The ports are free when they are picked, but another process can take one
// before the child binds it. The child then exits with "address already in
// use", and the start is retried with new ports.
func startListeningProcess(t *testing.T, name string, addrCount int, newCmd func(addrs []string) (*exec.Cmd, string)) (*childProcess, []string) {
	t.Helper()

	for attempt := 1; ; attempt++ {
		addrs := freeLocalAddrs(t, addrCount)
		cmd, readyURL := newCmd(addrs)
		output := &syncBuffer{}
		cmd.Stdout = output
		cmd.Stderr = output
		if err := cmd.Start(); err != nil {
			t.Fatalf("failed to start %s process: %v", name, err)
		}
		proc := &childProcess{name: name, cmd: cmd, output: output, exited: make(chan struct{})}
		go func() {
			proc.waitErr = cmd.Wait()
			close(proc.exited)
		}()

		err := proc.waitReady(readyURL, startTimeout)
		if err == nil {
			t.Cleanup(func() { proc.stop(t) })
			return proc, addrs
		}
		_ = cmd.Process.Kill()
		<-proc.exited
		if attempt < startAttempts && strings.Contains(output.String(), "address already in use") {
			t.Logf("%s lost the race for a local port, retrying (attempt %d)", name, attempt)
			continue
		}
		t.Fatalf("%s did not become ready: %v\nlogs:\n%s", name, err, output.String())
	}
}

func (p *childProcess) waitReady(readyURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 2 * time.Second}

	for time.Now().Before(deadline) {
		select {
		case <-p.exited:
			return fmt.Errorf("process exited during startup: %v", p.waitErr)
		default:
		}
		resp, err := client.Get(readyURL)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for %s to return 200", readyURL)
}

// stop asks the process to shut down with SIGTERM and fails the test when it
// does not exit cleanly within gracefulStopTimeout. Only then is it killed.
func (p *childProcess) stop(t *testing.T) {
	t.Helper()
	defer func() {
		if t.Failed() {
			t.Logf("%s logs:\n%s", p.name, p.output.String())
		}
	}()

	select {
	case <-p.exited:
		t.Errorf("%s exited before the test stopped it: %v", p.name, p.waitErr)
		return
	default:
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		// SIGTERM cannot be sent on Windows.
		t.Logf("cannot send SIGTERM to %s, killing it: %v", p.name, err)
		_ = p.cmd.Process.Kill()
		<-p.exited
		return
	}
	select {
	case <-p.exited:
		if p.waitErr != nil {
			t.Errorf("%s did not exit cleanly after SIGTERM: %v", p.name, p.waitErr)
		}
	case <-time.After(gracefulStopTimeout):
		t.Errorf("%s did not exit within %s after SIGTERM, killing it", p.name, gracefulStopTimeout)
		_ = p.cmd.Process.Kill()
		<-p.exited
	}
}

// wafProcess is a running synit-waf binary.
type wafProcess struct {
	URL      string // public listener
	AdminURL string // admin listener: /livez, /healthz, /readyz, /metrics
	proc     *childProcess
}

// startWAF runs the synit-waf binary with the given config and waits until
// /readyz on the admin listener reports ready. The process is stopped when the
// test ends.
func startWAF(t *testing.T, configPath string) *wafProcess {
	t.Helper()

	repoRoot := projectRootFromRuntime(t)
	binaryPath := wafBinary.get(t)
	proc, addrs := startListeningProcess(t, "synit-waf", 2, func(addrs []string) (*exec.Cmd, string) {
		cmd := exec.Command(binaryPath, "-config", configPath)
		cmd.Dir = repoRoot
		cmd.Env = append(os.Environ(), "EDGE_WAF_ADDR="+addrs[0], "WAF_GLOBAL_ADMIN_ADDRESS="+addrs[1])
		return cmd, "http://" + addrs[1] + "/readyz"
	})
	return &wafProcess{URL: "http://" + addrs[0], AdminURL: "http://" + addrs[1], proc: proc}
}

// waitForLog waits until the WAF has written a log line that contains every
// given substring.
func (w *wafProcess) waitForLog(t *testing.T, substrings ...string) {
	t.Helper()

	waitFor(t, stateChangeTimeout, fmt.Sprintf("a synit-waf log line containing %q", substrings), func() error {
		for line := range strings.SplitSeq(w.proc.output.String(), "\n") {
			matches := true
			for _, substring := range substrings {
				matches = matches && strings.Contains(line, substring)
			}
			if matches {
				return nil
			}
		}
		return fmt.Errorf("no such line")
	})
}

// metricValue returns the value of one series on the admin /metrics endpoint,
// for example `synit_waf_audit_mode_events_total{tenant="a.example"}`. A series
// that was never incremented is not exported and counts as 0.
func (w *wafProcess) metricValue(t *testing.T, series string) float64 {
	t.Helper()

	_, body := sendRequest(t, newRequest(t, http.MethodGet, w.AdminURL+"/metrics", "", nil))
	for line := range strings.SplitSeq(body, "\n") {
		rest, ok := strings.CutPrefix(line, series+" ")
		if !ok {
			continue
		}
		value, err := strconv.ParseFloat(strings.TrimSpace(rest), 64)
		if err != nil {
			t.Fatalf("metric %s has unparsable value %q: %v", series, rest, err)
		}
		return value
	}
	return 0
}

// upstreamRequest is what an upstream saw of one proxied request.
type upstreamRequest struct {
	Host   string
	Path   string
	Header http.Header
}

// recordingUpstream is a mock upstream that remembers the requests the WAF
// sent to it, so a test can tell a proxied response from one the WAF wrote.
type recordingUpstream struct {
	*httptest.Server
	mu       sync.Mutex
	requests []upstreamRequest
}

func newRecordingUpstream(respond http.HandlerFunc) *recordingUpstream {
	upstream := &recordingUpstream{}
	upstream.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.mu.Lock()
		upstream.requests = append(upstream.requests, upstreamRequest{Host: r.Host, Path: r.URL.Path, Header: r.Header.Clone()})
		upstream.mu.Unlock()
		respond(w, r)
	}))
	return upstream
}

// hits returns how many requests for host reached the upstream.
func (u *recordingUpstream) hits(host string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	count := 0
	for _, request := range u.requests {
		if request.Host == host {
			count++
		}
	}
	return count
}

// last returns the most recent request that reached the upstream.
func (u *recordingUpstream) last(t *testing.T) upstreamRequest {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.requests) == 0 {
		t.Fatal("no request reached the upstream")
	}
	return u.requests[len(u.requests)-1]
}

// writeConfig writes a WAF config file and returns its path. Writing to the
// path of a running WAF triggers a reload.
func writeConfig(t *testing.T, path, content string) string {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("failed to create config directory: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("failed to write config file %s: %v", path, err)
	}
	return path
}

// newRequest builds a request. host overrides the Host header when not empty.
func newRequest(t *testing.T, method, url, host string, body io.Reader) *http.Request {
	t.Helper()

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("failed to create %s request for %s: %v", method, url, err)
	}
	if host != "" {
		req.Host = host
	}
	return req
}

// sendRequest fails the test on a transport error and returns the status code
// and the body.
func sendRequest(t *testing.T, req *http.Request) (int, string) {
	t.Helper()

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s (host=%s) failed: %v", req.Method, req.URL, req.Host, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s (host=%s): failed to read response body: %v", req.Method, req.URL, req.Host, err)
	}
	return resp.StatusCode, string(body)
}

func assertProxyResponse(t *testing.T, baseURL, host, path string, expectedStatus int, expectedBodySubstring string) {
	t.Helper()

	status, body := sendRequest(t, newRequest(t, http.MethodGet, baseURL+path, host, nil))
	if status != expectedStatus {
		t.Fatalf("request %s (host=%s) expected status %d, got %d (body=%q)", path, host, expectedStatus, status, body)
	}
	if expectedBodySubstring != "" && !strings.Contains(body, expectedBodySubstring) {
		t.Fatalf("request %s (host=%s) expected response containing %q, got %q", path, host, expectedBodySubstring, body)
	}
}

// waitForProxyStatus polls until a GET through the WAF answers with the
// expected status, for example after a config reload.
func waitForProxyStatus(t *testing.T, baseURL, host, path string, expectedStatus int) {
	t.Helper()

	waitFor(t, stateChangeTimeout, fmt.Sprintf("GET %s (host=%s) to return %d", path, host, expectedStatus), func() error {
		status, body := sendRequest(t, newRequest(t, http.MethodGet, baseURL+path, host, nil))
		if status != expectedStatus {
			return fmt.Errorf("last status %d (body=%q)", status, body)
		}
		return nil
	})
}

// waitFor polls check until it returns nil and fails the test when the
// timeout ends first.
func waitFor(t *testing.T, timeout time.Duration, what string, check func() error) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	for {
		err := check()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s: %v", timeout, what, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// freeLocalAddrs returns count distinct loopback addresses with free ports.
// The ports are released before the caller binds them; see
// startListeningProcess for how a lost race is handled.
func freeLocalAddrs(t *testing.T, count int) []string {
	t.Helper()

	addrs := make([]string, 0, count)
	for range count {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to allocate local port: %v", err)
		}
		// Closing only at the end keeps the addresses distinct.
		defer func() { _ = ln.Close() }()
		addrs = append(addrs, ln.Addr().String())
	}
	return addrs
}

func projectRootFromRuntime(t *testing.T) string {
	t.Helper()

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("failed to resolve test file path via runtime.Caller")
	}
	// file is test/e2e/shared_test.go
	// Dir(file) is test/e2e
	// Dir(Dir(file)) is test
	// Dir(Dir(Dir(file))) is the repo root
	return filepath.Dir(filepath.Dir(filepath.Dir(file)))
}
