package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// ══════════════════════════════════════════════════════════
//  Test Helpers
// ══════════════════════════════════════════════════════════

func setupMockDB(t *testing.T) sqlmock.Sqlmock {
	t.Helper()
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	db = mockDB
	t.Cleanup(func() { mockDB.Close() })
	return mock
}

// ══════════════════════════════════════════════════════════
//  CORS Middleware Tests
// ══════════════════════════════════════════════════════════

func TestCorsMiddleware_SetsHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := corsMiddleware(inner)

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("expected Access-Control-Allow-Origin: *")
	}
	if rec.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("expected Access-Control-Allow-Methods header")
	}
	if rec.Header().Get("Access-Control-Allow-Headers") == "" {
		t.Error("expected Access-Control-Allow-Headers header")
	}
}

func TestCorsMiddleware_OptionsReturns200(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("inner handler should not be called for OPTIONS")
	})
	handler := corsMiddleware(inner)

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

// ══════════════════════════════════════════════════════════
//  Health Endpoint Tests
// ══════════════════════════════════════════════════════════

func TestHandleHealth_OK(t *testing.T) {
	mock := setupMockDB(t)
	mock.ExpectPing()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handleHealth(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp HealthResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp.Status != "ok" {
		t.Errorf("expected status ok, got %s", resp.Status)
	}
	if resp.Database != "ok" {
		t.Errorf("expected database ok, got %s", resp.Database)
	}
	if resp.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}
}

// ══════════════════════════════════════════════════════════
//  CVE Routing Tests
// ══════════════════════════════════════════════════════════

func TestHandleCVERoot_MethodNotAllowed(t *testing.T) {
	_ = setupMockDB(t)

	for _, method := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		req := httptest.NewRequest(method, "/api/cves", nil)
		rec := httptest.NewRecorder()
		handleCVERoot(rec, req)

		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: expected 405, got %d", method, rec.Code)
		}
	}
}

func TestHandleCVEByID_MissingID(t *testing.T) {
	_ = setupMockDB(t)

	req := httptest.NewRequest(http.MethodGet, "/api/cves/", nil)
	rec := httptest.NewRecorder()
	handleCVEByID(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// ══════════════════════════════════════════════════════════
//  Stats Endpoint Tests
// ══════════════════════════════════════════════════════════

func TestHandleStats_MethodNotAllowed(t *testing.T) {
	_ = setupMockDB(t)

	req := httptest.NewRequest(http.MethodPost, "/api/stats", nil)
	rec := httptest.NewRecorder()
	handleStats(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rec.Code)
	}
}

func TestHandleStats_OK(t *testing.T) {
	mock := setupMockDB(t)

	// Total count
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(282000))

	// Severity distribution
	mock.ExpectQuery("SELECT COALESCE").
		WillReturnRows(sqlmock.NewRows([]string{"severity", "count"}).
			AddRow("HIGH", 100000).
			AddRow("MEDIUM", 143000).
			AddRow("LOW", 18000).
			AddRow("CRITICAL", 21000))

	// Top vendors
	mock.ExpectQuery("SELECT COALESCE\\(vendor").
		WillReturnRows(sqlmock.NewRows([]string{"vendor", "cve_count"}).
			AddRow("microsoft", 5000).
			AddRow("google", 3000))

	// Yearly distribution
	mock.ExpectQuery("EXTRACT\\(YEAR").
		WillReturnRows(sqlmock.NewRows([]string{"year", "count"}).
			AddRow(2024, 15000).
			AddRow(2023, 20000))

	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	rec := httptest.NewRecorder()
	handleStats(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp StatsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp.TotalCves != 282000 {
		t.Errorf("expected 282000 total CVEs, got %d", resp.TotalCves)
	}
	if len(resp.SeverityDistribution) != 4 {
		t.Errorf("expected 4 severity entries, got %d", len(resp.SeverityDistribution))
	}
	if len(resp.TopVendors) != 2 {
		t.Errorf("expected 2 top vendors, got %d", len(resp.TopVendors))
	}
}

// ══════════════════════════════════════════════════════════
//  CVE Create Validation Tests
// ══════════════════════════════════════════════════════════

func TestHandleCreateCve_InvalidJSON(t *testing.T) {
	_ = setupMockDB(t)

	req := httptest.NewRequest(http.MethodPost, "/api/cves", bytes.NewBufferString("not json"))
	rec := httptest.NewRecorder()
	handleCreateCve(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

func TestHandleCreateCve_EmptyCveID(t *testing.T) {
	_ = setupMockDB(t)

	body := `{"cve_id": "", "vendor": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/cves", bytes.NewBufferString(body))
	rec := httptest.NewRecorder()
	handleCreateCve(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}

// ══════════════════════════════════════════════════════════
//  CVE List Endpoint Tests
// ══════════════════════════════════════════════════════════

func TestHandleCVEList_Defaults(t *testing.T) {
	mock := setupMockDB(t)

	// Count query
	mock.ExpectQuery("SELECT COUNT").
		WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(5))

	// List query
	mock.ExpectQuery("SELECT cve_id").
		WillReturnRows(sqlmock.NewRows([]string{
			"cve_id", "description", "severity", "cvss_score", "vendor", "product", "version", "published_date",
		}).
			AddRow("CVE-2024-0001", "Test vuln", "HIGH", 7.5, "apache", "httpd", "2.4", nil).
			AddRow("CVE-2024-0002", "Another vuln", "MEDIUM", 5.0, "google", "chrome", "120", nil))

	req := httptest.NewRequest(http.MethodGet, "/api/cves", nil)
	rec := httptest.NewRecorder()
	handleCVEList(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	var resp CVEListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if resp.Total != 5 {
		t.Errorf("expected total 5, got %d", resp.Total)
	}
	if len(resp.Items) != 2 {
		t.Errorf("expected 2 items, got %d", len(resp.Items))
	}
	if resp.Page != 1 {
		t.Errorf("expected page 1, got %d", resp.Page)
	}
}

// ══════════════════════════════════════════════════════════
//  Response Type Tests
// ══════════════════════════════════════════════════════════

func TestHealthResponseJSON(t *testing.T) {
	resp := HealthResponse{
		Status:    "ok",
		Database:  "ok",
		Timestamp: "2024-01-01T00:00:00Z",
	}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded HealthResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.Status != "ok" {
		t.Errorf("expected ok, got %s", decoded.Status)
	}
}

func TestCVEItemJSON_OmitsNilFields(t *testing.T) {
	item := CVEItem{CVEID: "CVE-2024-0001"}
	data, err := json.Marshal(item)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var m map[string]interface{}
	json.Unmarshal(data, &m)

	if _, ok := m["description"]; ok {
		t.Error("expected description to be omitted when nil")
	}
	if m["cve_id"] != "CVE-2024-0001" {
		t.Errorf("expected CVE-2024-0001, got %v", m["cve_id"])
	}
}

func TestErrorResponseJSON(t *testing.T) {
	resp := ErrorResponse{Error: "something went wrong"}
	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded ErrorResponse
	json.Unmarshal(data, &decoded)
	if decoded.Error != "something went wrong" {
		t.Errorf("expected error message, got %s", decoded.Error)
	}
}
