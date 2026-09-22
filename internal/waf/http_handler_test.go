package waf

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

type mockReporter struct {
	report ReadinessReport
}

func (m *mockReporter) ReadinessReport() ReadinessReport {
	return m.report
}

func TestHealthzHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/healthz", nil)
	rr := httptest.NewRecorder()
	mockProxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler := NewPublicHTTPHandler(mockProxy)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	if body := rr.Body.String(); body != "ok" {
		t.Errorf("handler returned unexpected body: got %v want %v", body, "ok")
	}
}

func TestRootHandlerPassesThrough(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	rr := httptest.NewRecorder()

	// Create a mock proxy that records the request
	proxyCalled := false
	mockProxy := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyCalled = true
		w.WriteHeader(http.StatusOK)
	})

	handler := NewPublicHTTPHandler(mockProxy)
	handler.ServeHTTP(rr, req)

	if !proxyCalled {
		t.Error("expected proxy to be called for root path")
	}
}

func TestReadyzHandlerReady(t *testing.T) {
	reporter := &mockReporter{
		report: ReadinessReport{Ready: true},
	}
	req := httptest.NewRequest("GET", "/readyz", nil)
	rr := httptest.NewRecorder()
	handler := NewAdminHTTPHandler(reporter)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}
}

func TestReadyzHandlerNotReady(t *testing.T) {
	reporter := &mockReporter{
		report: ReadinessReport{Ready: false, Reasons: []string{"test reason"}},
	}
	req := httptest.NewRequest("GET", "/readyz", nil)
	rr := httptest.NewRecorder()
	handler := NewAdminHTTPHandler(reporter)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusServiceUnavailable {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusServiceUnavailable)
	}
}

func TestPublicMetricsPathPassesThrough(t *testing.T) {
	proxyCalled := false
	proxy := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyCalled = true
		w.WriteHeader(http.StatusNoContent)
	})
	handler := NewPublicHTTPHandler(proxy)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))

	if !proxyCalled {
		t.Fatal("expected public metrics path to pass to tenant proxy")
	}
}

func TestAdminUnknownPathNotProxied(t *testing.T) {
	handler := NewAdminHTTPHandler(&mockReporter{})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/application", nil))

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}
