package main

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// ML servisinin adresi — Docker Compose'da "ml_service" container adıyla çalışır
func getMLServiceURL() string {
	url := os.Getenv("ML_SERVICE_URL")
	if url == "" {
		url = "http://ml_service:8001"
	}
	return url
}

// proxyToML — gelen isteği FastAPI'ye iletir, cevabı olduğu gibi döner
func proxyToML(w http.ResponseWriter, r *http.Request, targetPath string) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// İstek gövdesini oku
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// FastAPI'ye ilet
	mlURL := getMLServiceURL() + targetPath
	req, err := http.NewRequest(r.Method, mlURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("[ML Proxy] Failed to create request: %v", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ML Proxy] ML service unreachable: %v", err)
		http.Error(w, `{"error":"ML service unavailable"}`, http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()

	// Cevabı frontend'e ilet
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, "Failed to read ML response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// POST /api/ml/match — CASCADE hybrid matching
func handleMLMatch(w http.ResponseWriter, r *http.Request) {
	log.Printf("[ML] Match request from %s", r.RemoteAddr)
	proxyToML(w, r, "/ml/match")
}

// POST /api/ml/predict-severity — severity prediction
func handleMLSeverity(w http.ResponseWriter, r *http.Request) {
	log.Printf("[ML] Severity request from %s", r.RemoteAddr)
	proxyToML(w, r, "/ml/predict-severity")
}

// GET /api/ml/health — ML servis sağlık kontrolü
func handleMLHealth(w http.ResponseWriter, r *http.Request) {
	proxyToML(w, r, "/health")
}
