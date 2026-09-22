package waf

import (
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"

	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/parser"
	"github.com/graphql-go/graphql/language/source"
)

type graphqlError struct {
	Message string `json:"message"`
}

type graphqlErrorResponse struct {
	Errors []graphqlError `json:"errors"`
}

func sendGraphQLError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	resp := graphqlErrorResponse{
		Errors: []graphqlError{{Message: msg}},
	}
	_ = json.NewEncoder(w).Encode(resp)
}

type graphqlDocument struct {
	fragments map[string]*ast.FragmentDefinition
}

func newGraphQLDocument(doc *ast.Document) *graphqlDocument {
	indexed := &graphqlDocument{fragments: make(map[string]*ast.FragmentDefinition)}
	for _, definition := range doc.Definitions {
		fragment, ok := definition.(*ast.FragmentDefinition)
		if ok && fragment.Name != nil {
			indexed.fragments[fragment.Name.Value] = fragment
		}
	}
	return indexed
}

func (d *graphqlDocument) selectionDepth(set *ast.SelectionSet, visiting map[string]bool) (int, error) {
	if set == nil {
		return 0, nil
	}
	maxDepth := 0
	for _, selection := range set.Selections {
		depth := 0
		switch node := selection.(type) {
		case *ast.Field:
			childDepth, err := d.selectionDepth(node.SelectionSet, visiting)
			if err != nil {
				return 0, err
			}
			depth = 1 + childDepth
		case *ast.InlineFragment:
			var err error
			depth, err = d.selectionDepth(node.SelectionSet, visiting)
			if err != nil {
				return 0, err
			}
		case *ast.FragmentSpread:
			if node.Name == nil {
				return 0, fmt.Errorf("invalid fragment spread")
			}
			name := node.Name.Value
			fragment, ok := d.fragments[name]
			if !ok {
				return 0, fmt.Errorf("unknown fragment %s", name)
			}
			if visiting[name] {
				return 0, fmt.Errorf("fragment cycle involving %s", name)
			}
			visiting[name] = true
			var err error
			depth, err = d.selectionDepth(fragment.SelectionSet, visiting)
			delete(visiting, name)
			if err != nil {
				return 0, err
			}
		}
		if depth > maxDepth {
			maxDepth = depth
		}
	}
	return maxDepth, nil
}

func (d *graphqlDocument) hasIntrospection(set *ast.SelectionSet, visiting map[string]bool) (bool, error) {
	if set == nil {
		return false, nil
	}
	for _, selection := range set.Selections {
		switch node := selection.(type) {
		case *ast.Field:
			if node.Name != nil && (node.Name.Value == "__schema" || node.Name.Value == "__type") {
				return true, nil
			}
			found, err := d.hasIntrospection(node.SelectionSet, visiting)
			if found || err != nil {
				return found, err
			}
		case *ast.InlineFragment:
			found, err := d.hasIntrospection(node.SelectionSet, visiting)
			if found || err != nil {
				return found, err
			}
		case *ast.FragmentSpread:
			if node.Name == nil {
				return false, fmt.Errorf("invalid fragment spread")
			}
			name := node.Name.Value
			fragment, ok := d.fragments[name]
			if !ok {
				return false, fmt.Errorf("unknown fragment %s", name)
			}
			if visiting[name] {
				return false, fmt.Errorf("fragment cycle involving %s", name)
			}
			visiting[name] = true
			found, err := d.hasIntrospection(fragment.SelectionSet, visiting)
			delete(visiting, name)
			if found || err != nil {
				return found, err
			}
		}
	}
	return false, nil
}

const (
	defaultGraphQLMaxQueryBytes = 100 << 10
	// minGraphQLNestingBudget is the structural nesting always allowed, so
	// input objects and lists in arguments do not trip the pre-parse check.
	minGraphQLNestingBudget = 64
)

// SetDefaults fills unset GraphQL protection options.
func (p *GraphQLProtection) SetDefaults() {
	if len(p.Paths) == 0 {
		p.Paths = []string{"/graphql"}
	}
	if p.MaxQueryBytes <= 0 {
		p.MaxQueryBytes = defaultGraphQLMaxQueryBytes
	}
}

// graphQLNestingDepth returns the deepest nesting of braces and brackets in
// query, ignoring strings and comments. The parser is recursive: without this
// linear pre-check a 1 MB query of nested selections costs hundreds of MB of
// goroutine stack before the depth limit can reject it.
func graphQLNestingDepth(query string) int {
	depth, deepest := 0, 0
	for i := 0; i < len(query); i++ {
		switch query[i] {
		case '#':
			for i < len(query) && query[i] != '\n' {
				i++
			}
		case '"':
			if strings.HasPrefix(query[i:], `"""`) {
				end := strings.Index(query[i+3:], `"""`)
				if end < 0 {
					return deepest
				}
				i += 3 + end + 2
				continue
			}
			for i++; i < len(query) && query[i] != '"' && query[i] != '\n'; i++ {
				if query[i] == '\\' {
					i++
				}
			}
		case '{', '[':
			depth++
			if depth > deepest {
				deepest = depth
			}
		case '}', ']':
			if depth > 0 {
				depth--
			}
		}
	}
	return deepest
}

func checkGraphQLRequest(query string, policy GraphQLProtection) error {
	if strings.TrimSpace(query) == "" {
		return fmt.Errorf("GraphQL query is required")
	}
	maxBytes := policy.MaxQueryBytes
	if maxBytes <= 0 {
		maxBytes = defaultGraphQLMaxQueryBytes
	}
	if len(query) > maxBytes {
		return fmt.Errorf("query size exceeds maximum allowed limit of %d bytes", maxBytes)
	}
	nestingBudget := max(minGraphQLNestingBudget, 2*policy.MaxQueryDepth+16)
	if graphQLNestingDepth(query) > nestingBudget {
		return fmt.Errorf("query nesting exceeds maximum allowed limit of %d", nestingBudget)
	}

	doc, err := parser.Parse(parser.ParseParams{
		Source: &source.Source{
			Body: []byte(query),
			Name: "GraphQL request",
		},
	})
	if err != nil {
		return fmt.Errorf("invalid GraphQL syntax")
	}

	indexed := newGraphQLDocument(doc)
	operations := 0
	for _, definition := range doc.Definitions {
		operation, ok := definition.(*ast.OperationDefinition)
		if !ok {
			continue
		}
		operations++
		if policy.BlockIntrospection {
			found, err := indexed.hasIntrospection(operation.SelectionSet, make(map[string]bool))
			if err != nil {
				return fmt.Errorf("invalid GraphQL document: %w", err)
			}
			if found {
				return fmt.Errorf("introspection queries are not allowed")
			}
		}
		depth, err := indexed.selectionDepth(operation.SelectionSet, make(map[string]bool))
		if err != nil {
			return fmt.Errorf("invalid GraphQL document: %w", err)
		}
		if policy.MaxQueryDepth > 0 && depth > policy.MaxQueryDepth {
			return fmt.Errorf("query depth exceeds maximum allowed limit of %d", policy.MaxQueryDepth)
		}
	}
	if operations == 0 {
		return fmt.Errorf("GraphQL document has no operation")
	}

	return nil
}

func (h *ProxyHandler) applyGraphQLProtection(w http.ResponseWriter, r *http.Request, policy GraphQLProtection) bool {
	if !policy.Enabled {
		return false
	}
	// Only the configured GraphQL endpoints are inspected; other paths of
	// the tenant keep serving REST, forms, and static content.
	paths := policy.Paths
	if len(paths) == 0 {
		paths = []string{"/graphql"}
	}
	if !pathMatchesAny(paths, r.URL.Path) {
		return false
	}

	if r.Method == http.MethodGet {
		query := r.URL.Query().Get("query")
		if query == "" {
			http.Error(w, "GraphQL query parameter is required", http.StatusBadRequest)
			return true
		}
		if err := checkGraphQLRequest(query, policy); err != nil {
			sendGraphQLError(w, err.Error())
			return true
		}
		return false
	}
	if r.Method != http.MethodPost {
		http.Error(w, "GraphQL transport method is not supported", http.StatusMethodNotAllowed)
		return true
	}

	if r.Body == nil {
		return false
	}
	if hasUnsupportedContentEncoding(r) {
		http.Error(w, "Compressed GraphQL request bodies cannot be inspected", http.StatusUnsupportedMediaType)
		return true
	}

	limit := h.requestBodyLimit.Load()
	if limit <= 0 {
		limit = defaultRequestBodyCap
	}
	bodyBytes, err := h.inspectionBody(r, limit)
	if errors.Is(err, errInspectionBodyTooLarge) {
		h.rejectInspectionOversize(w, r, "graphql")
		return true
	}
	if err != nil {
		sendGraphQLError(w, "Internal Server Error reading body")
		return true
	}

	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		http.Error(w, "Invalid Content-Type", http.StatusUnsupportedMediaType)
		return true
	}
	if mediaType == "application/graphql" {
		if err := checkGraphQLRequest(string(bodyBytes), policy); err != nil {
			sendGraphQLError(w, err.Error())
			return true
		}
		return false
	}
	if mediaType != "application/json" {
		http.Error(w, "GraphQL Content-Type is not supported", http.StatusUnsupportedMediaType)
		return true
	}

	var payload any
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		http.Error(w, "Invalid GraphQL JSON body", http.StatusBadRequest)
		return true
	}

	var queries []string

	switch v := payload.(type) {
	case map[string]any:
		q, ok := v["query"].(string)
		if !ok || strings.TrimSpace(q) == "" {
			http.Error(w, "GraphQL query is required", http.StatusBadRequest)
			return true
		}
		queries = append(queries, q)
	case []any:
		if policy.MaxBatchedQueries > 0 && len(v) > policy.MaxBatchedQueries {
			sendGraphQLError(w, fmt.Sprintf("GraphQL batch size exceeds maximum allowed limit of %d", policy.MaxBatchedQueries))
			return true
		}
		for _, item := range v {
			m, ok := item.(map[string]any)
			if !ok {
				http.Error(w, "Every GraphQL batch item must be an object with a query", http.StatusBadRequest)
				return true
			}
			q, ok := m["query"].(string)
			if !ok || q == "" {
				http.Error(w, "Every GraphQL batch item must contain a query", http.StatusBadRequest)
				return true
			}
			queries = append(queries, q)
		}
	}

	if len(queries) == 0 {
		http.Error(w, "GraphQL query is required", http.StatusBadRequest)
		return true
	}

	for _, query := range queries {
		if err := checkGraphQLRequest(query, policy); err != nil {
			sendGraphQLError(w, err.Error())
			return true
		}
	}

	return false
}
