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
}

type AppMatchItem struct {
	AppID           string `json:"app_id"`
	AppName         string `json:"app_name"`
	ExactMatchCount int    `json:"exact_match_count"`
	FuzzyMatchCount int    `json:"fuzzy_match_count"`
	HasExactMatch   bool   `json:"has_exact_match"`
	HasFuzzyMatch   bool   `json:"has_fuzzy_match"`
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
			COALESCE(SUM(CASE WHEN m.algorithm = 'fuzzy' THEN 1 ELSE 0 END), 0) as fuzzy_count
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
		if err := rows.Scan(&item.AppID, &item.AppName, &item.ExactMatchCount, &item.FuzzyMatchCount); err != nil {
			log.Printf("Scan error: %v", err)
			continue
		}
		item.HasExactMatch = item.ExactMatchCount > 0
		item.HasFuzzyMatch = item.FuzzyMatchCount > 0
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
