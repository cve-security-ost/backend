package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq" // PostgreSQL driver
)

var db *sql.DB

// Response types
type HealthResponse struct {
	Status    string `json:"status"`
	Database  string `json:"database"`
	Timestamp string `json:"timestamp"`
}

type SeverityStat struct {
	Severity string `json:"severity"`
	Count    int    `json:"count"`
}

type YearlyStat struct {
	Year  int `json:"year"`
	Count int `json:"count"`
}

type VendorStat struct {
	Vendor   string `json:"vendor"`
	CveCount int    `json:"cve_count"`
}

type StatsResponse struct {
	TotalCves            int            `json:"total_cves"`
	SeverityDistribution []SeverityStat `json:"severity_distribution"`
	TopVendors           []VendorStat   `json:"top_vendors"`
	YearlyDistribution   []YearlyStat   `json:"yearly_distribution"`
}

type CVEItem struct {
	CVEID         string     `json:"cve_id"`
	Description   *string    `json:"description,omitempty"`
	Severity      *string    `json:"severity,omitempty"`
	CVSSScore     *float64   `json:"cvss_score,omitempty"`
	Vendor        *string    `json:"vendor,omitempty"`
	Product       *string    `json:"product,omitempty"`
	Version       *string    `json:"version,omitempty"`
	PublishedDate *time.Time `json:"published_date,omitempty"`
}

type CVEDetail struct {
	CVEID         string     `json:"cve_id"`
	Description   *string    `json:"description,omitempty"`
	Severity      *string    `json:"severity,omitempty"`
	CVSSScore     *float64   `json:"cvss_score,omitempty"`
	Vendor        *string    `json:"vendor,omitempty"`
	Product       *string    `json:"product,omitempty"`
	Version       *string    `json:"version,omitempty"`
	CWE           *string    `json:"cwe,omitempty"`
	PublishedDate *time.Time `json:"published_date,omitempty"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type CVEListResponse struct {
	Page     int       `json:"page"`
	PageSize int       `json:"page_size"`
	Total    int       `json:"total"`
	Items    []CVEItem `json:"items"`
}

// Matching types
type AlgorithmStats struct {
	MatchedApps   int `json:"matched_apps"`
	UnmatchedApps int `json:"unmatched_apps"`
	TotalMatches  int `json:"total_matches"`
}

type MatchingSummaryResponse struct {
	TotalApps int            `json:"total_apps"`
	Exact     AlgorithmStats `json:"exact"`
	Fuzzy     AlgorithmStats `json:"fuzzy"`
	Semantic  AlgorithmStats `json:"semantic"`
	Vendor    AlgorithmStats `json:"vendor"`
}

type AppMatchItem struct {
	AppID              string `json:"app_id"`
	AppName            string `json:"app_name"`
	ExactMatchCount    int    `json:"exact_match_count"`
	FuzzyMatchCount    int    `json:"fuzzy_match_count"`
	SemanticMatchCount int    `json:"semantic_match_count"`
	VendorMatchCount   int    `json:"vendor_match_count"`
	HasExactMatch      bool   `json:"has_exact_match"`
	HasFuzzyMatch      bool   `json:"has_fuzzy_match"`
	HasSemanticMatch   bool   `json:"has_semantic_match"`
	HasVendorMatch     bool   `json:"has_vendor_match"`
}

type MatchingAppsResponse struct {
	Page     int            `json:"page"`
	PageSize int            `json:"page_size"`
	Total    int            `json:"total"`
	Items    []AppMatchItem `json:"items"`
}

type MatchDetail struct {
	Algorithm string   `json:"algorithm"`
	CVEID     string   `json:"cve_id"`
	Score     float64  `json:"score"`
	Severity  *string  `json:"severity,omitempty"`
	CVSSScore *float64 `json:"cvss_score,omitempty"`
}

type AppMatchDetailResponse struct {
	AppID   string        `json:"app_id"`
	AppName string        `json:"app_name"`
	Matches []MatchDetail `json:"matches"`
}

type CveRecord struct {
	CveID       string   `json:"cve_id"`
	Vendor      string   `json:"vendor"`
	Product     string   `json:"product"`
	Severity    string   `json:"severity"`
	CvssScore   *float64 `json:"cvss_score,omitempty"`
	Description string   `json:"description,omitempty"`
}

func main() {
	// 1. DB bağlantısını aç
	initDB()
	defer db.Close()

	// 2. HTTP router
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/health", handleHealth)

	// API endpoints
	mux.HandleFunc("/api/stats", handleStats)
	mux.HandleFunc("/api/stats/severity", handleSeverityStats)

	// CVE endpoints (GET list/detail + POST/PUT/DELETE)
	mux.HandleFunc("/api/cves", handleCVERoot)
	mux.HandleFunc("/api/cves/", handleCVEByID) // path param: /api/cves/{id}

	// Matching endpoints
	mux.HandleFunc("/api/matching/summary", handleMatchingSummary)
	mux.HandleFunc("/api/matching/apps", handleMatchingApps)
	mux.HandleFunc("/api/matching/apps/", handleMatchingAppDetail)

	// Real-time matching endpoint
	mux.HandleFunc("/api/match", handleRealTimeMatch)

	// Applications CRUD with auto-matching
	mux.HandleFunc("/api/applications", handleApplicationsRoot)
	mux.HandleFunc("/api/applications/", handleApplicationByID)

	// ML proxy endpoints
	mux.HandleFunc("/api/ml/match", handleMLMatch)
	mux.HandleFunc("/api/ml/predict-severity", handleMLSeverity)
	mux.HandleFunc("/api/ml/health", handleMLHealth)
	mux.HandleFunc("/api/ml/scan/", handleMLScan)
	mux.HandleFunc("/api/ml/results", handleMLResults)

	// CORS middleware ile wrap et
	handler := corsMiddleware(mux)

	// 3. Server oluştur
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	server := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	// 4. Graceful shutdown için goroutine
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Server shutdown error: %v", err)
		}
	}()

	// 5. Sunucuyu başlat
	log.Printf("Backend starting on port %s...\n", port)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatal(err)
	}

	log.Println("Server stopped gracefully")
}

func initDB() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL environment variable is not set")
	}

	var err error
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("Could not open database: %v", err)
	}

	// Connection pool ayarları
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Bağlantıyı test et
	if err := db.Ping(); err != nil {
		log.Fatalf("Could not ping database: %v", err)
	}

	log.Println("Connected to PostgreSQL")
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	dbStatus := "ok"
	if err := db.Ping(); err != nil {
		dbStatus = fmt.Sprintf("error: %v", err)
	}

	resp := HealthResponse{
		Status:    "ok",
		Database:  dbStatus,
		Timestamp: time.Now().Format(time.RFC3339),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GET /api/stats - Tüm istatistikleri tek endpoint'te döner
func handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var resp StatsResponse

	// 1. Total CVE count
	if err := db.QueryRow("SELECT COUNT(*) FROM cve_records").Scan(&resp.TotalCves); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Printf("Total count error: %v", err)
		return
	}

	// 2. Severity distribution
	severityRows, err := db.Query(`
		SELECT COALESCE(severity, 'UNKNOWN') AS severity, COUNT(*)
		FROM cve_records
		GROUP BY severity
		ORDER BY COUNT(*) DESC
	`)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Printf("Severity query error: %v", err)
		return
	}
	defer severityRows.Close()

	resp.SeverityDistribution = []SeverityStat{}
	for severityRows.Next() {
		var s SeverityStat
		if err := severityRows.Scan(&s.Severity, &s.Count); err != nil {
			http.Error(w, "Scan error", http.StatusInternalServerError)
			log.Printf("Severity scan error: %v", err)
			return
		}
		resp.SeverityDistribution = append(resp.SeverityDistribution, s)
	}

	// 3. Top 10 vendors
	vendorRows, err := db.Query(`
		SELECT COALESCE(vendor, 'unknown') AS vendor, COUNT(*) as cve_count
		FROM cve_records
		WHERE vendor IS NOT NULL AND vendor != '' AND vendor != 'n/a'
		GROUP BY vendor
		ORDER BY cve_count DESC
		LIMIT 10
	`)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Printf("Vendor query error: %v", err)
		return
	}
	defer vendorRows.Close()

	resp.TopVendors = []VendorStat{}
	for vendorRows.Next() {
		var v VendorStat
		if err := vendorRows.Scan(&v.Vendor, &v.CveCount); err != nil {
			http.Error(w, "Scan error", http.StatusInternalServerError)
			log.Printf("Vendor scan error: %v", err)
			return
		}
		resp.TopVendors = append(resp.TopVendors, v)
	}

	// 4. Yearly distribution (sadece published_date olan kayıtlar)
	yearlyRows, err := db.Query(`
		SELECT EXTRACT(YEAR FROM published_date)::int AS year, COUNT(*)
		FROM cve_records
		WHERE published_date IS NOT NULL
		GROUP BY year
		ORDER BY year DESC
	`)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Printf("Yearly query error: %v", err)
		return
	}
	defer yearlyRows.Close()

	resp.YearlyDistribution = []YearlyStat{}
	for yearlyRows.Next() {
		var y YearlyStat
		if err := yearlyRows.Scan(&y.Year, &y.Count); err != nil {
			http.Error(w, "Scan error", http.StatusInternalServerError)
			log.Printf("Yearly scan error: %v", err)
			return
		}
		resp.YearlyDistribution = append(resp.YearlyDistribution, y)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GET only: severity dağılımı (sade)
func handleSeverityStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	rows, err := db.Query(`
		SELECT COALESCE(severity, 'UNKNOWN') AS severity, COUNT(*)
		FROM cve_records
		GROUP BY severity
		ORDER BY COUNT(*) DESC
	`)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Printf("Query error: %v", err)
		return
	}
	defer rows.Close()

	var stats []SeverityStat

	for rows.Next() {
		var s SeverityStat
		if err := rows.Scan(&s.Severity, &s.Count); err != nil {
			http.Error(w, "Scan error", http.StatusInternalServerError)
			log.Printf("Scan error: %v", err)
			return
		}
		stats = append(stats, s)
	}

	if err := rows.Err(); err != nil {
		http.Error(w, "Rows error", http.StatusInternalServerError)
		log.Printf("Rows error: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(stats); err != nil {
		log.Printf("Encode error: %v", err)
	}
}

// GET /api/cves?page=1&page_size=50&severity=HIGH&vendor=microsoft&search=remote
func handleCVEList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Pagination parametreleri (default: page=1, page_size=50, max=100)
	page := 1
	pageSize := 50

	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	// Filtreler
	severity := r.URL.Query().Get("severity")
	vendor := r.URL.Query().Get("vendor")
	search := r.URL.Query().Get("search")

	// Query oluştur
	whereClause := "WHERE 1=1"
	args := []interface{}{}
	argIndex := 1

	if severity != "" {
		whereClause += fmt.Sprintf(" AND severity = $%d", argIndex)
		args = append(args, strings.ToUpper(severity))
		argIndex++
	}
	if vendor != "" {
		whereClause += fmt.Sprintf(" AND vendor ILIKE $%d", argIndex)
		args = append(args, "%"+vendor+"%")
		argIndex++
	}
	if search != "" {
		whereClause += fmt.Sprintf(" AND (cve_id ILIKE $%d OR description ILIKE $%d OR product ILIKE $%d OR vendor ILIKE $%d)", argIndex, argIndex+1, argIndex+2, argIndex+3)
		searchPattern := "%" + search + "%"
		args = append(args, searchPattern, searchPattern, searchPattern, searchPattern)
		argIndex += 4
	}

	// Toplam kayıt sayısı
	var total int
	countQuery := "SELECT COUNT(*) FROM cve_records " + whereClause
	if err := db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Printf("Count error: %v", err)
		return
	}

	// Data çek
	offset := (page - 1) * pageSize
	args = append(args, pageSize, offset)

	dataQuery := fmt.Sprintf(`
		SELECT cve_id, description, severity, cvss_score, vendor, product, version, published_date
		FROM cve_records
		%s
		ORDER BY cvss_score DESC NULLS LAST, cve_id DESC
		LIMIT $%d OFFSET $%d
	`, whereClause, argIndex, argIndex+1)

	rows, err := db.Query(dataQuery, args...)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Printf("Query error: %v", err)
		return
	}
	defer rows.Close()

	items := []CVEItem{}
	for rows.Next() {
		var c CVEItem
		if err := rows.Scan(&c.CVEID, &c.Description, &c.Severity, &c.CVSSScore,
			&c.Vendor, &c.Product, &c.Version, &c.PublishedDate); err != nil {
			http.Error(w, "Scan error", http.StatusInternalServerError)
			log.Printf("Scan error: %v", err)
			return
		}
		items = append(items, c)
	}

	resp := CVEListResponse{
		Page:     page,
		PageSize: pageSize,
		Total:    total,
		Items:    items,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// GET /api/cves/{cve_id} - Tek CVE detayı
func handleCVEDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "method_not_allowed"})
		return
	}

	// URL'den CVE ID'yi çıkar: /api/cves/CVE-2024-1234
	path := strings.TrimPrefix(r.URL.Path, "/api/cves/")
	if path == "" || path == "/" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "cve_id_required"})
		return
	}
	cveID := strings.ToUpper(path)

	var c CVEDetail
	err := db.QueryRow(`
		SELECT cve_id, description, severity, cvss_score, vendor, product, version, cwe, published_date
		FROM cve_records
		WHERE cve_id = $1
	`, cveID).Scan(&c.CVEID, &c.Description, &c.Severity, &c.CVSSScore,
		&c.Vendor, &c.Product, &c.Version, &c.CWE, &c.PublishedDate)

	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "not_found"})
		return
	}
	if err != nil {
		log.Printf("Query error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "database_error"})
		return
	}

	json.NewEncoder(w).Encode(c)
}

// GET /api/matching/summary - Matching özet istatistikleri
func handleMatchingSummary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "method_not_allowed"})
		return
	}

	var resp MatchingSummaryResponse

	// Total apps
	if err := db.QueryRow("SELECT COUNT(*) FROM applications").Scan(&resp.TotalApps); err != nil {
		log.Printf("Total apps error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "database_error"})
		return
	}

	// Exact stats
	if err := db.QueryRow(`
		SELECT COUNT(DISTINCT app_id) FROM matching_results WHERE algorithm = 'exact'
	`).Scan(&resp.Exact.MatchedApps); err != nil {
		log.Printf("Exact matched error: %v", err)
	}
	resp.Exact.UnmatchedApps = resp.TotalApps - resp.Exact.MatchedApps

	if err := db.QueryRow(`
		SELECT COUNT(*) FROM matching_results WHERE algorithm = 'exact'
	`).Scan(&resp.Exact.TotalMatches); err != nil {
		log.Printf("Exact total error: %v", err)
	}

	// Fuzzy stats
	if err := db.QueryRow(`
		SELECT COUNT(DISTINCT app_id) FROM matching_results WHERE algorithm = 'fuzzy'
	`).Scan(&resp.Fuzzy.MatchedApps); err != nil {
		log.Printf("Fuzzy matched error: %v", err)
	}
	resp.Fuzzy.UnmatchedApps = resp.TotalApps - resp.Fuzzy.MatchedApps

	if err := db.QueryRow(`
		SELECT COUNT(*) FROM matching_results WHERE algorithm = 'fuzzy'
	`).Scan(&resp.Fuzzy.TotalMatches); err != nil {
		log.Printf("Fuzzy total error: %v", err)
	}

	// Semantic stats
	if err := db.QueryRow(`
		SELECT COUNT(DISTINCT app_id) FROM matching_results WHERE algorithm = 'semantic'
	`).Scan(&resp.Semantic.MatchedApps); err != nil {
		log.Printf("Semantic matched error: %v", err)
	}
	resp.Semantic.UnmatchedApps = resp.TotalApps - resp.Semantic.MatchedApps

	if err := db.QueryRow(`
		SELECT COUNT(*) FROM matching_results WHERE algorithm = 'semantic'
	`).Scan(&resp.Semantic.TotalMatches); err != nil {
		log.Printf("Semantic total error: %v", err)
	}

	// Vendor stats
	if err := db.QueryRow(`
		SELECT COUNT(DISTINCT app_id) FROM matching_results WHERE algorithm = 'vendor'
	`).Scan(&resp.Vendor.MatchedApps); err != nil {
		log.Printf("Vendor matched error: %v", err)
	}
	resp.Vendor.UnmatchedApps = resp.TotalApps - resp.Vendor.MatchedApps

	if err := db.QueryRow(`
		SELECT COUNT(*) FROM matching_results WHERE algorithm = 'vendor'
	`).Scan(&resp.Vendor.TotalMatches); err != nil {
		log.Printf("Vendor total error: %v", err)
	}

	json.NewEncoder(w).Encode(resp)
}

// GET /api/matching/apps?status=matched|unmatched&algorithm=exact|fuzzy&page=1&page_size=20
func handleMatchingApps(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "method_not_allowed"})
		return
	}

	// Pagination
	page := 1
	pageSize := 20
	if p := r.URL.Query().Get("page"); p != "" {
		if parsed, err := strconv.Atoi(p); err == nil && parsed > 0 {
			page = parsed
		}
	}
	if ps := r.URL.Query().Get("page_size"); ps != "" {
		if parsed, err := strconv.Atoi(ps); err == nil && parsed > 0 && parsed <= 100 {
			pageSize = parsed
		}
	}

	// Filters
	status := r.URL.Query().Get("status")
	algorithm := r.URL.Query().Get("algorithm")

	// Build query
	baseQuery := `
		SELECT
			a.app_id,
			a.app_name,
			COALESCE(SUM(CASE WHEN m.algorithm = 'exact' THEN 1 ELSE 0 END), 0) as exact_count,
			COALESCE(SUM(CASE WHEN m.algorithm = 'fuzzy' THEN 1 ELSE 0 END), 0) as fuzzy_count,
			COALESCE(SUM(CASE WHEN m.algorithm = 'semantic' THEN 1 ELSE 0 END), 0) as semantic_count,
			COALESCE(SUM(CASE WHEN m.algorithm = 'vendor' THEN 1 ELSE 0 END), 0) as vendor_count
		FROM applications a
		LEFT JOIN matching_results m ON a.app_id = m.app_id
	`

	havingClause := ""
	if status == "matched" {
		if algorithm == "exact" {
			havingClause = "HAVING SUM(CASE WHEN m.algorithm = 'exact' THEN 1 ELSE 0 END) > 0"
		} else if algorithm == "fuzzy" {
			havingClause = "HAVING SUM(CASE WHEN m.algorithm = 'fuzzy' THEN 1 ELSE 0 END) > 0"
		} else {
			havingClause = "HAVING COUNT(m.id) > 0"
		}
	} else if status == "unmatched" {
		if algorithm == "exact" {
			havingClause = "HAVING SUM(CASE WHEN m.algorithm = 'exact' THEN 1 ELSE 0 END) = 0"
		} else if algorithm == "fuzzy" {
			havingClause = "HAVING SUM(CASE WHEN m.algorithm = 'fuzzy' THEN 1 ELSE 0 END) = 0"
		} else {
			havingClause = "HAVING COUNT(m.id) = 0"
		}
	}

	// Count query
	countQuery := fmt.Sprintf(`
		SELECT COUNT(*) FROM (
			%s
			GROUP BY a.app_id, a.app_name
			%s
		) sub
	`, baseQuery, havingClause)

	var total int
	if err := db.QueryRow(countQuery).Scan(&total); err != nil {
		log.Printf("Count error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "database_error"})
		return
	}

	// Data query
	offset := (page - 1) * pageSize
	dataQuery := fmt.Sprintf(`
		%s
		GROUP BY a.app_id, a.app_name
		%s
		ORDER BY a.app_name
		LIMIT $1 OFFSET $2
	`, baseQuery, havingClause)

	rows, err := db.Query(dataQuery, pageSize, offset)
	if err != nil {
		log.Printf("Query error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "database_error"})
		return
	}
	defer rows.Close()

	items := []AppMatchItem{}
	for rows.Next() {
		var item AppMatchItem
		if err := rows.Scan(&item.AppID, &item.AppName, &item.ExactMatchCount, &item.FuzzyMatchCount, &item.SemanticMatchCount, &item.VendorMatchCount); err != nil {
			log.Printf("Scan error: %v", err)
			continue
		}
		item.HasExactMatch = item.ExactMatchCount > 0
		item.HasFuzzyMatch = item.FuzzyMatchCount > 0
		item.HasSemanticMatch = item.SemanticMatchCount > 0
		item.HasVendorMatch = item.VendorMatchCount > 0
		items = append(items, item)
	}

	resp := MatchingAppsResponse{
		Page:     page,
		PageSize: pageSize,
		Total:    total,
		Items:    items,
	}

	json.NewEncoder(w).Encode(resp)
}

// GET /api/matching/apps/{app_id} - Bir uygulamanın tüm eşleşmeleri
func handleMatchingAppDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "method_not_allowed"})
		return
	}

	// URL'den app_id'yi çıkar
	path := strings.TrimPrefix(r.URL.Path, "/api/matching/apps/")
	if path == "" || path == "/" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "app_id_required"})
		return
	}
	appID := path

	// App bilgisi
	var resp AppMatchDetailResponse
	err := db.QueryRow(`
		SELECT app_id, app_name FROM applications WHERE app_id = $1
	`, appID).Scan(&resp.AppID, &resp.AppName)

	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "not_found"})
		return
	}
	if err != nil {
		log.Printf("Query error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "database_error"})
		return
	}

	// Matching results with CVE details
	rows, err := db.Query(`
		SELECT
			m.algorithm,
			m.cve_id,
			m.score,
			c.severity,
			c.cvss_score
		FROM matching_results m
		LEFT JOIN cve_records c ON m.cve_id = c.cve_id
		WHERE m.app_id = $1
		ORDER BY m.algorithm, m.score DESC
	`, appID)

	if err != nil {
		log.Printf("Query error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "database_error"})
		return
	}
	defer rows.Close()

	resp.Matches = []MatchDetail{}
	for rows.Next() {
		var match MatchDetail
		if err := rows.Scan(&match.Algorithm, &match.CVEID, &match.Score, &match.Severity, &match.CVSSScore); err != nil {
			log.Printf("Scan error: %v", err)
			continue
		}
		resp.Matches = append(resp.Matches, match)
	}

	json.NewEncoder(w).Encode(resp)
}

// /api/cves -> GET list (mevcut handler), POST create
func handleCVERoot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleCVEList(w, r)
	case http.MethodPost:
		handleCreateCve(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// /api/cves/{id} -> GET one (detay handler), PUT update, DELETE remove
func handleCVEByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/cves/")
	if id == "" || id == "/api/cves" {
		http.Error(w, "Missing id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		handleCVEDetail(w, r)
	case http.MethodPut:
		handleUpdateCve(w, r, id)
	case http.MethodDelete:
		handleDeleteCve(w, r, id)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleCreateCve(w http.ResponseWriter, r *http.Request) {
	var payload CveRecord
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(payload.CveID) == "" {
		http.Error(w, "cve_id is required", http.StatusBadRequest)
		return
	}

	rec, err := insertCve(r.Context(), payload)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Printf("insert error: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(rec)
}

func handleUpdateCve(w http.ResponseWriter, r *http.Request, id string) {
	var payload CveRecord
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(payload.CveID) == "" {
		payload.CveID = id // path öncelikli olsun
	}

	updated, err := updateCve(r.Context(), id, payload)
	if err == sql.ErrNoRows {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Printf("update error: %v", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(updated)
}

func handleDeleteCve(w http.ResponseWriter, r *http.Request, id string) {
	rows, err := db.ExecContext(r.Context(), `DELETE FROM cve_records WHERE cve_id=$1`, id)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		log.Printf("delete error: %v", err)
		return
	}
	affected, _ := rows.RowsAffected()
	if affected == 0 {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func insertCve(ctx context.Context, payload CveRecord) (CveRecord, error) {
	row := db.QueryRowContext(ctx, `
		INSERT INTO cve_records (cve_id, vendor, product, severity, cvss_score, description)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING cve_id, vendor, product, severity, cvss_score, description
	`,
		payload.CveID,
		payload.Vendor,
		payload.Product,
		payload.Severity,
		payload.CvssScore,
		payload.Description,
	)
	return scanCve(row)
}

func updateCve(ctx context.Context, id string, payload CveRecord) (CveRecord, error) {
	row := db.QueryRowContext(ctx, `
		UPDATE cve_records
		SET vendor=$2, product=$3, severity=$4, cvss_score=$5, description=$6
		WHERE cve_id=$1
		RETURNING cve_id, vendor, product, severity, cvss_score, description
	`,
		id,
		payload.Vendor,
		payload.Product,
		payload.Severity,
		payload.CvssScore,
		payload.Description,
	)
	return scanCve(row)
}

// scanCve accepts both *sql.Row and *sql.Rows
type rowScanner interface {
	Scan(dest ...any) error
}

func scanCve(rs rowScanner) (CveRecord, error) {
	var rec CveRecord
	var cvss sql.NullFloat64
	var vendor, product, severity, description sql.NullString

	err := rs.Scan(
		&rec.CveID,
		&vendor,
		&product,
		&severity,
		&cvss,
		&description,
	)
	if err != nil {
		return rec, err
	}
	if vendor.Valid {
		rec.Vendor = vendor.String
	}
	if product.Valid {
		rec.Product = product.String
	}
	if severity.Valid {
		rec.Severity = severity.String
	}
	if description.Valid {
		rec.Description = description.String
	}
	if cvss.Valid {
		rec.CvssScore = &cvss.Float64
	}
	return rec, nil
}

// Real-time matching types
type MatchRequest struct {
	AppName string `json:"app_name"`
	Vendor  string `json:"vendor"`
}

type MatchResult struct {
	CveID       string   `json:"cve_id"`
	Score       float64  `json:"score"`
	Algorithm   string   `json:"algorithm"`
	Severity    *string  `json:"severity,omitempty"`
	CVSSScore   *float64 `json:"cvss_score,omitempty"`
	Vendor      *string  `json:"vendor,omitempty"`
	Product     *string  `json:"product,omitempty"`
	Description *string  `json:"description,omitempty"`
}

type MatchResponse struct {
	AppName    string        `json:"app_name"`
	Vendor     string        `json:"vendor"`
	TotalFound int           `json:"total_found"`
	Matches    []MatchResult `json:"matches"`
}

// POST /api/match - Real-time CVE matching (Gelişmiş Algoritma)
func handleRealTimeMatch(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "method_not_allowed"})
		return
	}

	var req MatchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid_json"})
		return
	}

	if req.AppName == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "app_name_required"})
		return
	}

	// runAutoMatching fonksiyonunu kullan (aynı algoritma)
	matches := runAutoMatching(req.AppName, req.Vendor)

	resp := MatchResponse{
		AppName:    req.AppName,
		Vendor:     req.Vendor,
		TotalFound: len(matches),
		Matches:    matches,
	}

	json.NewEncoder(w).Encode(resp)
}

// Application types
type Application struct {
	AppID     string  `json:"app_id"`
	AppName   string  `json:"app_name"`
	Vendor    string  `json:"vendor"`
	Version   *string `json:"version,omitempty"`
	Category  *string `json:"category,omitempty"`
	CpeID     *string `json:"cpe_id,omitempty"`
	CreatedAt *string `json:"created_at,omitempty"`
}

type ApplicationCreateRequest struct {
	AppName  string  `json:"app_name"`
	Vendor   string  `json:"vendor"`
	Version  *string `json:"version,omitempty"`
	Category *string `json:"category,omitempty"`
	CpeID    *string `json:"cpe_id,omitempty"`
}

type ApplicationCreateResponse struct {
	Application   Application   `json:"application"`
	MatchingCount int           `json:"matching_count"`
	Matches       []MatchResult `json:"matches"`
}

// GET /api/applications - List all applications
// POST /api/applications - Create new application with auto-matching
func handleApplicationsRoot(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		handleListApplications(w, r)
	case http.MethodPost:
		handleCreateApplication(w, r)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "method_not_allowed"})
	}
}

// GET/DELETE /api/applications/{app_id}
func handleApplicationByID(w http.ResponseWriter, r *http.Request) {
	appID := strings.TrimPrefix(r.URL.Path, "/api/applications/")
	if appID == "" || appID == "/" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "app_id_required"})
		return
	}

	switch r.Method {
	case http.MethodGet:
		handleGetApplication(w, r, appID)
	case http.MethodDelete:
		handleDeleteApplication(w, r, appID)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "method_not_allowed"})
	}
}

func handleListApplications(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := db.Query(`
		SELECT app_id, app_name, vendor, version, category, cpe_id
		FROM applications
		ORDER BY app_name
	`)
	if err != nil {
		log.Printf("List applications error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "database_error"})
		return
	}
	defer rows.Close()

	apps := []Application{}
	for rows.Next() {
		var app Application
		if err := rows.Scan(&app.AppID, &app.AppName, &app.Vendor, &app.Version, &app.Category, &app.CpeID); err != nil {
			log.Printf("Scan error: %v", err)
			continue
		}
		apps = append(apps, app)
	}

	json.NewEncoder(w).Encode(apps)
}

func handleGetApplication(w http.ResponseWriter, r *http.Request, appID string) {
	w.Header().Set("Content-Type", "application/json")

	var app Application
	err := db.QueryRow(`
		SELECT app_id, app_name, vendor, version, category, cpe_id
		FROM applications WHERE app_id = $1
	`, appID).Scan(&app.AppID, &app.AppName, &app.Vendor, &app.Version, &app.Category, &app.CpeID)

	if err == sql.ErrNoRows {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "not_found"})
		return
	}
	if err != nil {
		log.Printf("Get application error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "database_error"})
		return
	}

	json.NewEncoder(w).Encode(app)
}

func handleDeleteApplication(w http.ResponseWriter, r *http.Request, appID string) {
	w.Header().Set("Content-Type", "application/json")

	// Önce matching_results'tan sil
	_, _ = db.Exec("DELETE FROM matching_results WHERE app_id = $1", appID)

	// Sonra application'ı sil
	result, err := db.Exec("DELETE FROM applications WHERE app_id = $1", appID)
	if err != nil {
		log.Printf("Delete application error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "database_error"})
		return
	}

	affected, _ := result.RowsAffected()
	if affected == 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "not_found"})
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func handleCreateApplication(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var req ApplicationCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "invalid_json"})
		return
	}

	if req.AppName == "" || req.Vendor == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "app_name_and_vendor_required"})
		return
	}

	// Generate new app_id
	var maxID int
	err := db.QueryRow(`
		SELECT COALESCE(MAX(CAST(SUBSTRING(app_id FROM 5) AS INTEGER)), 0)
		FROM applications WHERE app_id LIKE 'APP-%'
	`).Scan(&maxID)
	if err != nil {
		log.Printf("Max ID query error: %v", err)
		maxID = 56 // fallback
	}
	newAppID := fmt.Sprintf("APP-%03d", maxID+1)

	// Insert application
	var app Application
	err = db.QueryRow(`
		INSERT INTO applications (app_id, app_name, vendor, version, category, cpe_id)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING app_id, app_name, vendor, version, category, cpe_id
	`, newAppID, req.AppName, req.Vendor, req.Version, req.Category, req.CpeID).Scan(
		&app.AppID, &app.AppName, &app.Vendor, &app.Version, &app.Category, &app.CpeID,
	)

	if err != nil {
		log.Printf("Insert application error: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Error: "database_error"})
		return
	}

	// Run auto-matching and save results
	matches := runAutoMatching(app.AppName, app.Vendor)
	saveMatchingResults(app.AppID, matches)

	resp := ApplicationCreateResponse{
		Application:   app,
		MatchingCount: len(matches),
		Matches:       matches,
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(resp)
}

// ==================== FUZZY MATCHING UTILITIES ====================

// levenshteinDistance - İki string arasındaki edit distance hesapla
func levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	// Create matrix
	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
	}

	// Initialize first column
	for i := 0; i <= len(s1); i++ {
		matrix[i][0] = i
	}
	// Initialize first row
	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}

	// Fill matrix
	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 1
			if s1[i-1] == s2[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

// min - 3 sayının minimumunu bul
func min(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// fuzzyScore - Levenshtein distance'a dayalı benzerlik skoru (0-100)
func fuzzyScore(s1, s2 string) float64 {
	s1 = strings.ToLower(s1)
	s2 = strings.ToLower(s2)

	if s1 == s2 {
		return 100.0
	}

	maxLen := len(s1)
	if len(s2) > maxLen {
		maxLen = len(s2)
	}

	if maxLen == 0 {
		return 0.0
	}

	distance := levenshteinDistance(s1, s2)
	similarity := 1.0 - float64(distance)/float64(maxLen)

	return similarity * 100
}

// tokenSetRatio - Python'daki fuzz.token_set_ratio benzeri
// Kelimeleri sete dönüştürüp ortak kelimeleri karşılaştırır
func tokenSetRatio(s1, s2 string) float64 {
	s1 = strings.ToLower(strings.TrimSpace(s1))
	s2 = strings.ToLower(strings.TrimSpace(s2))

	words1 := strings.Fields(s1)
	words2 := strings.Fields(s2)

	set1 := make(map[string]bool)
	set2 := make(map[string]bool)

	for _, w := range words1 {
		if len(w) >= 2 {
			set1[w] = true
		}
	}
	for _, w := range words2 {
		if len(w) >= 2 {
			set2[w] = true
		}
	}

	if len(set1) == 0 || len(set2) == 0 {
		return 0.0
	}

	// Ortak kelimeleri bul
	intersection := 0
	for w := range set1 {
		if set2[w] {
			intersection++
		}
	}

	// Jaccard similarity
	union := len(set1) + len(set2) - intersection
	if union == 0 {
		return 0.0
	}

	return float64(intersection) / float64(union) * 100
}

// getNgrams - String'den n-gram'lar çıkar
func getNgrams(s string, n int) map[string]int {
	s = strings.ToLower(s)
	ngrams := make(map[string]int)

	if len(s) < n {
		ngrams[s] = 1
		return ngrams
	}

	for i := 0; i <= len(s)-n; i++ {
		ngram := s[i : i+n]
		ngrams[ngram]++
	}

	return ngrams
}

// ngramSimilarity - N-gram tabanlı benzerlik (TF-IDF benzeri)
func ngramSimilarity(s1, s2 string, n int) float64 {
	ngrams1 := getNgrams(s1, n)
	ngrams2 := getNgrams(s2, n)

	if len(ngrams1) == 0 || len(ngrams2) == 0 {
		return 0.0
	}

	// Cosine similarity hesapla
	dotProduct := 0
	for ng, count1 := range ngrams1 {
		if count2, ok := ngrams2[ng]; ok {
			dotProduct += count1 * count2
		}
	}

	// Magnitude hesapla
	mag1 := 0
	for _, count := range ngrams1 {
		mag1 += count * count
	}
	mag2 := 0
	for _, count := range ngrams2 {
		mag2 += count * count
	}

	if mag1 == 0 || mag2 == 0 {
		return 0.0
	}

	return float64(dotProduct) / (float64(mag1)*float64(mag2)) * 100
}

// trigramSimilarity - Trigram benzerliği (pg_trgm benzeri)
func trigramSimilarity(s1, s2 string) float64 {
	return ngramSimilarity(s1, s2, 3)
}

// ==================== CASCADE HYBRID MATCHING ALGORITHM ====================

// runAutoMatching - 4 Katmanlı CASCADE (Sıralı) CVE Eşleştirme Algoritması
// Mantık: Üst katmanda eşleşme bulunursa alt katmanlara GEÇİLMEZ
// Layer 1: Exact Match (Score: 90-100) - Vendor VE Product tam eşleşme
// Layer 2: Fuzzy Match (Score: 70-89) - Levenshtein + Token Set Ratio
// Layer 3: Semantic Match (Score: 55-69) - N-gram/Trigram benzerliği
// Layer 4: Vendor Only (Score: 40-54) - Sadece vendor eşleşmesi
func runAutoMatching(appName, vendor string) []MatchResult {
	appNameLower := strings.ToLower(strings.TrimSpace(appName))
	vendorLower := strings.ToLower(strings.TrimSpace(vendor))
	appWords := strings.Fields(appNameLower)

	var matches []MatchResult
	existingCves := make(map[string]bool)

	// ========== LAYER 1: EXACT MATCH (Score: 90-100) ==========
	// Vendor VE Product SQL LIKE ile eşleşiyor
	log.Printf("[CASCADE Layer 1] Exact matching for: %s / %s", vendor, appName)

	exactQuery := `
		SELECT cve_id, severity, cvss_score, vendor, product, description
		FROM cve_records
		WHERE LOWER(vendor) LIKE $1 AND LOWER(product) LIKE $2
		ORDER BY cvss_score DESC NULLS LAST
		LIMIT 50
	`
	exactRows, err := db.Query(exactQuery, "%"+vendorLower+"%", "%"+appNameLower+"%")
	if err == nil {
		defer exactRows.Close()
		for exactRows.Next() {
			var m MatchResult
			if err := exactRows.Scan(&m.CveID, &m.Severity, &m.CVSSScore, &m.Vendor, &m.Product, &m.Description); err == nil {
				if !existingCves[m.CveID] {
					m.Score = calculateHybridScore(appNameLower, vendorLower, appWords, m.Vendor, m.Product, "exact")
					m.Algorithm = "exact"
					matches = append(matches, m)
					existingCves[m.CveID] = true
				}
			}
		}
	}
	log.Printf("[CASCADE Layer 1] Found %d exact matches", len(matches))

	// CASCADE: Exact bulunduysa STOP - alt katmanlara geçme
	if len(matches) > 0 {
		log.Printf("[CASCADE] Exact matches found, STOPPING at Layer 1")
		sortMatchesByScore(matches)
		if len(matches) > 50 {
			matches = matches[:50]
		}
		return matches
	}

	// ========== LAYER 2: FUZZY MATCH (Score: 70-89) ==========
	// Exact bulunamadı, Fuzzy dene
	log.Printf("[CASCADE Layer 2] No exact matches, trying Fuzzy...")

	if len(appWords) > 0 {
		for _, word := range appWords {
			if len(word) < 3 {
				continue
			}

			fuzzyQuery := `
				SELECT cve_id, severity, cvss_score, vendor, product, description
				FROM cve_records
				WHERE LOWER(vendor) LIKE $1 AND LOWER(product) LIKE $2
				ORDER BY cvss_score DESC NULLS LAST
				LIMIT 30
			`
			fuzzyRows, err := db.Query(fuzzyQuery, "%"+vendorLower+"%", "%"+word+"%")
			if err == nil {
				defer fuzzyRows.Close()
				for fuzzyRows.Next() {
					var m MatchResult
					if err := fuzzyRows.Scan(&m.CveID, &m.Severity, &m.CVSSScore, &m.Vendor, &m.Product, &m.Description); err == nil {
						if !existingCves[m.CveID] {
							m.Score = calculateHybridScore(appNameLower, vendorLower, appWords, m.Vendor, m.Product, "fuzzy")
							m.Algorithm = "fuzzy"
							matches = append(matches, m)
							existingCves[m.CveID] = true
						}
					}
				}
			}
		}
	}
	log.Printf("[CASCADE Layer 2] Found %d fuzzy matches", len(matches))

	// CASCADE: Fuzzy bulunduysa STOP
	if len(matches) > 0 {
		log.Printf("[CASCADE] Fuzzy matches found, STOPPING at Layer 2")
		sortMatchesByScore(matches)
		if len(matches) > 50 {
			matches = matches[:50]
		}
		return matches
	}

	// ========== LAYER 3: SEMANTIC MATCH (Score: 55-69) ==========
	// Fuzzy bulunamadı, Semantic dene
	log.Printf("[CASCADE Layer 3] No fuzzy matches, trying Semantic...")

	semanticQuery := `
		SELECT cve_id, severity, cvss_score, vendor, product, description
		FROM cve_records
		WHERE LOWER(description) LIKE $1 OR LOWER(description) LIKE $2
		ORDER BY cvss_score DESC NULLS LAST
		LIMIT 50
	`
	semanticRows, err := db.Query(semanticQuery, "%"+vendorLower+"%", "%"+appNameLower+"%")
	if err == nil {
		defer semanticRows.Close()
		for semanticRows.Next() {
			var m MatchResult
			if err := semanticRows.Scan(&m.CveID, &m.Severity, &m.CVSSScore, &m.Vendor, &m.Product, &m.Description); err == nil {
				if !existingCves[m.CveID] {
					m.Score = calculateHybridScore(appNameLower, vendorLower, appWords, m.Vendor, m.Product, "semantic")
					m.Algorithm = "semantic"
					matches = append(matches, m)
					existingCves[m.CveID] = true
				}
			}
		}
	}
	log.Printf("[CASCADE Layer 3] Found %d semantic matches", len(matches))

	// CASCADE: Semantic bulunduysa STOP
	if len(matches) > 0 {
		log.Printf("[CASCADE] Semantic matches found, STOPPING at Layer 3")
		sortMatchesByScore(matches)
		if len(matches) > 50 {
			matches = matches[:50]
		}
		return matches
	}

	// ========== LAYER 4: VENDOR ONLY (Score: 40-54) ==========
	// Semantic bulunamadı, son şans: Vendor Only
	log.Printf("[CASCADE Layer 4] No semantic matches, trying Vendor-only (last resort)...")

	vendorQuery := `
		SELECT cve_id, severity, cvss_score, vendor, product, description
		FROM cve_records
		WHERE LOWER(vendor) LIKE $1
		ORDER BY cvss_score DESC NULLS LAST
		LIMIT 50
	`
	vendorRows, err := db.Query(vendorQuery, "%"+vendorLower+"%")
	if err == nil {
		defer vendorRows.Close()
		for vendorRows.Next() {
			var m MatchResult
			if err := vendorRows.Scan(&m.CveID, &m.Severity, &m.CVSSScore, &m.Vendor, &m.Product, &m.Description); err == nil {
				if !existingCves[m.CveID] {
					m.Score = calculateHybridScore(appNameLower, vendorLower, appWords, m.Vendor, m.Product, "vendor_only")
					m.Algorithm = "vendor"
					matches = append(matches, m)
					existingCves[m.CveID] = true
				}
			}
		}
	}
	log.Printf("[CASCADE Layer 4] Found %d vendor-only matches", len(matches))

	// Skorlara göre sırala
	sortMatchesByScore(matches)

	// En iyi 50'yi al
	if len(matches) > 50 {
		matches = matches[:50]
	}

	if len(matches) == 0 {
		log.Printf("[CASCADE] NO MATCHES FOUND for %s/%s", vendor, appName)
	} else {
		log.Printf("[CASCADE DONE] Returning %d matches (Layer 4) for %s/%s", len(matches), vendor, appName)
	}

	return matches
}

// calculateHybridScore - Gelişmiş Hybrid Skor Hesaplama
// Fuzzy matching algoritmalarını kullanarak dinamik skor hesaplar
func calculateHybridScore(appName, vendor string, appWords []string, cveVendor, cveProduct *string, matchType string) float64 {
	cveVendorLower := ""
	cveProductLower := ""
	if cveVendor != nil {
		cveVendorLower = strings.ToLower(*cveVendor)
	}
	if cveProduct != nil {
		cveProductLower = strings.ToLower(*cveProduct)
	}

	// Match type'a göre base score belirle
	var baseScore float64
	switch matchType {
	case "exact":
		baseScore = 90.0 // 90-100 aralığı
	case "fuzzy":
		baseScore = 70.0 // 70-89 aralığı
	case "semantic":
		baseScore = 55.0 // 55-69 aralığı
	case "vendor_only":
		baseScore = 40.0 // 40-54 aralığı
	default:
		baseScore = 50.0
	}

	// ===== VENDOR SCORING =====
	vendorScore := 0.0
	if cveVendorLower != "" && vendor != "" {
		// Tam eşleşme
		if cveVendorLower == vendor {
			vendorScore = 10.0
		} else {
			// Fuzzy score hesapla
			fuzzy := fuzzyScore(vendor, cveVendorLower)
			tokenSet := tokenSetRatio(vendor, cveVendorLower)
			vendorScore = (fuzzy + tokenSet) / 2 / 10 // Max 10 puan
		}
	}

	// ===== PRODUCT SCORING =====
	productScore := 0.0
	if cveProductLower != "" && appName != "" {
		// Tam eşleşme
		if cveProductLower == appName {
			productScore = 15.0
		} else {
			// Fuzzy score hesapla
			fuzzy := fuzzyScore(appName, cveProductLower)
			tokenSet := tokenSetRatio(appName, cveProductLower)
			trigram := trigramSimilarity(appName, cveProductLower)

			// En iyi skoru al
			bestScore := fuzzy
			if tokenSet > bestScore {
				bestScore = tokenSet
			}
			if trigram > bestScore {
				bestScore = trigram
			}

			productScore = bestScore / 100 * 15 // Max 15 puan
		}
	}

	// ===== WORD MATCHING BONUS =====
	wordBonus := 0.0
	if len(appWords) > 0 && cveProductLower != "" {
		matchedWords := 0
		for _, word := range appWords {
			if len(word) >= 3 {
				// Exact word match
				if strings.Contains(cveProductLower, word) {
					matchedWords++
				} else {
					// Fuzzy word match
					productWords := strings.Fields(cveProductLower)
					for _, pw := range productWords {
						if fuzzyScore(word, pw) > 80 {
							matchedWords++
							break
						}
					}
				}
			}
		}
		wordMatchRatio := float64(matchedWords) / float64(len(appWords))
		wordBonus = wordMatchRatio * 5 // Max 5 puan
	}

	// ===== FINAL SCORE =====
	finalScore := baseScore + vendorScore + productScore + wordBonus

	// Match type'a göre skor sınırlarını uygula
	switch matchType {
	case "exact":
		if finalScore > 100 {
			finalScore = 100
		}
		if finalScore < 90 {
			finalScore = 90
		}
	case "fuzzy":
		if finalScore > 89 {
			finalScore = 89
		}
		if finalScore < 70 {
			finalScore = 70
		}
	case "semantic":
		if finalScore > 69 {
			finalScore = 69
		}
		if finalScore < 55 {
			finalScore = 55
		}
	case "vendor_only":
		if finalScore > 54 {
			finalScore = 54
		}
		if finalScore < 40 {
			finalScore = 40
		}
	}

	return finalScore
}

// sortMatchesByScore - Skorlara göre sırala
func sortMatchesByScore(matches []MatchResult) {
	for i := 0; i < len(matches)-1; i++ {
		for j := i + 1; j < len(matches); j++ {
			if matches[j].Score > matches[i].Score {
				matches[i], matches[j] = matches[j], matches[i]
			}
		}
	}
}

// saveMatchingResults - Eşleşme sonuçlarını veritabanına kaydet
func saveMatchingResults(appID string, matches []MatchResult) {
	for _, match := range matches {
		_, err := db.Exec(`
			INSERT INTO matching_results (app_id, cve_id, algorithm, score)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT DO NOTHING
		`, appID, match.CveID, match.Algorithm, match.Score)
		if err != nil {
			log.Printf("Save matching result error: %v", err)
		}
	}
	log.Printf("Saved %d matching results for app %s", len(matches), appID)
}
