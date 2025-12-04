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

func main() {
	// 1. DB bağlantısını aç
	initDB()
	defer db.Close()

	// 2. HTTP router
	mux := http.NewServeMux()

	// Health check
	mux.HandleFunc("/health", handleHealth)

	// API endpoints
	mux.HandleFunc("/api/stats/severity", handleSeverityStats)

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
		WriteTimeout: 10 * time.Second,
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
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
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
