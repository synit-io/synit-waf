package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGraphQLDepthIncludesFragmentExpansion(t *testing.T) {
	query := `query { root { ...Deep } } fragment Deep on Root { child { leaf } }`
	policy := GraphQLProtection{MaxQueryDepth: 2}

	if err := checkGraphQLRequest(query, policy); err == nil {
		t.Fatal("expected expanded fragment depth to exceed limit")
	}
}

func TestGraphQLOversizeBodyRejected(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	h.requestBodyLimit.Store(4)
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	if blocked := h.applyGraphQLProtection(w, req, GraphQLProtection{Enabled: true}); !blocked {
		t.Fatal("expected oversize GraphQL body to be rejected")
	}
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}

func TestGraphQLInvalidJSONRejected(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`{"query":`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	if blocked := h.applyGraphQLProtection(w, req, GraphQLProtection{Enabled: true}); !blocked {
		t.Fatal("expected invalid GraphQL JSON to be rejected")
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestGraphQLDocumentTransportInspected(t *testing.T) {
	h := NewProxyHandler(NewWAFRegistry())
	req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(`query { one { two } }`))
	req.Header.Set("Content-Type", "application/graphql")
	w := httptest.NewRecorder()

	policy := GraphQLProtection{Enabled: true, MaxQueryDepth: 1}
	if blocked := h.applyGraphQLProtection(w, req, policy); !blocked {
		t.Fatal("expected application/graphql body to be inspected")
	}
}

func TestGraphQLRejectsMissingQueries(t *testing.T) {
	for _, body := range []string{"{\"query\":\"\"}", "[{\"query\":\"query { ok }\"},{}]"} {
		h := NewProxyHandler(NewWAFRegistry())
		req := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		if blocked := h.applyGraphQLProtection(w, req, GraphQLProtection{Enabled: true}); !blocked {
			t.Fatalf("expected payload %s to be rejected", body)
		}
		if w.Code != http.StatusBadRequest {
			t.Fatalf("payload %s: expected 400, got %d", body, w.Code)
		}
	}
}
