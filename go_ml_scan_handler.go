package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// ── Tip tanımları ──────────────────────────────────────────────

type MLMatchResult struct {
	CveID       string  `json:"cve_id"`
	Description string  `json:"description"`
	Score       float64 `json:"score"`
	MatchType   string  `json:"match_type"`
	Layer       int     `json:"layer"`
	SbertScore  float64 `json:"sbert_score"`
	TfidfScore  float64 `json:"tfidf_score"`
	FuzzyScore  float64 `json:"fuzzy_score"`
}

type MLMatchResponse struct {
	Query       string          `json:"query"`
	Total       int             `json:"total"`
	QueryTimeMs float64         `json:"query_time_ms"`
	Results     []MLMatchResult `json:"results"`
	Error       string          `json:"error,omitempty"`
}

type SSEEvent struct {
	Stage   string `json:"stage"`   // "sbert" | "tfidf" | "rerank" | "save" | "done" | "error"
	Status  string `json:"status"`  // "running" | "done" | "error"
	Count   int    `json:"count"`   // bulunan sonuç sayısı
	Message string `json:"message"` // kullanıcıya gösterilecek metin
}

// ── POST /api/ml/scan/{appId}  ─────────────────────────────────
// Server-Sent Events ile canlı progress döner.
// Frontend EventSource ile dinler.
func handleMLScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// app_id path'ten al: /api/ml/scan/{appId}
	appID := strings.TrimPrefix(r.URL.Path, "/api/ml/scan/")
	appID = strings.TrimSuffix(appID, "/")
	if appID == "" {
		http.Error(w, `{"error":"app_id required"}`, http.StatusBadRequest)
		return
	}

	// Uygulamayı DB'den çek
	var appName, vendor string
	err := db.QueryRow(
		`SELECT app_name, COALESCE(vendor, '') FROM applications WHERE app_id = $1`, appID,
	).Scan(&appName, &vendor)
	if err != nil {
		http.Error(w, `{"error":"application not found"}`, http.StatusNotFound)
		return
	}

	// SSE header'larını ayarla
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	// SSE yardımcı fonksiyonları
	sendEvent := func(stage, status, message string, count int) {
		evt := SSEEvent{Stage: stage, Status: status, Count: count, Message: message}
		data, _ := json.Marshal(evt)
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	sendLog := func(message string) {
		ts := time.Now().Format("15:04:05.000")
		logData, _ := json.Marshal(map[string]string{
			"stage":   "log",
			"status":  "info",
			"message": fmt.Sprintf("[%s] %s", ts, message),
		})
		fmt.Fprintf(w, "data: %s\n\n", logData)
		flusher.Flush()
	}

	// ── 1. SBERT + CASCADE ML çalıştır ────────────────────────
	query := appName
	if vendor != "" {
		query = vendor + " " + appName
	}

	sendEvent("sbert", "running", "SBERT modeli yükleniyor…", 0)
	sendLog(fmt.Sprintf("Sorgu oluşturuldu: \"%s\"", query))
	sendLog("ML Service'e bağlanılıyor → " + getMLServiceURL() + "/ml/match")
	sendLog(fmt.Sprintf("Parametreler: top_k=20, query_len=%d karakter", len(query)))

	mlURL := getMLServiceURL() + "/ml/match"
	reqBody, _ := json.Marshal(map[string]interface{}{
		"query":  query,
		"top_k":  20,
	})

	sendLog("SBERT embedding hesaplanıyor (all-MiniLM-L6-v2)…")
	startTime := time.Now()

	client := &http.Client{Timeout: 120 * time.Second}
	resp, err := client.Post(mlURL, "application/json", bytes.NewReader(reqBody))
	if err != nil {
		sendEvent("error", "error", "ML servisi yanıt vermedi: "+err.Error(), 0)
		sendLog("HATA: " + err.Error())
		return
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	elapsed := time.Since(startTime)
	sendLog(fmt.Sprintf("ML Service yanıtı alındı (%dms, %d bytes)", elapsed.Milliseconds(), len(respBody)))

	var mlResp MLMatchResponse
	if err := json.Unmarshal(respBody, &mlResp); err != nil {
		sendEvent("error", "error", "ML yanıtı parse edilemedi", 0)
		sendLog("HATA: JSON parse başarısız — " + err.Error())
		return
	}

	if mlResp.Error != "" {
		sendEvent("error", "error", mlResp.Error, 0)
		sendLog("ML HATA: " + mlResp.Error)
		return
	}

	sendLog(fmt.Sprintf("SBERT tamamlandı: %d CVE bulundu (%.0fms)", len(mlResp.Results), mlResp.QueryTimeMs))
	sendEvent("sbert", "done", "SBERT tamamlandı", len(mlResp.Results))

	// Top 3 sonucu logla
	for i, r := range mlResp.Results {
		if i >= 3 {
			break
		}
		sendLog(fmt.Sprintf("  #%d %s → cascade=%.3f sbert=%.3f tfidf=%.3f [%s]",
			i+1, r.CveID, r.Score, r.SbertScore, r.TfidfScore, r.MatchType))
	}
	if len(mlResp.Results) > 3 {
		sendLog(fmt.Sprintf("  ... ve %d sonuç daha", len(mlResp.Results)-3))
	}

	// ── 2. TF-IDF + Reranking bilgisi (CASCADE içinde zaten yapıldı) ──
	sendLog("TF-IDF skorları hesaplandı (sude_tfidf_vectorizer.pkl)")
	sendEvent("tfidf", "done", "TF-IDF reranking tamamlandı", len(mlResp.Results))

	sendEvent("rerank", "running", "CASCADE skorları hesaplanıyor…", 0)
	sendLog("CASCADE Rerank: 0.85×SBERT + 0.15×TF-IDF hibrit skor")
	time.Sleep(200 * time.Millisecond)

	// Skor dağılımını logla
	if len(mlResp.Results) > 0 {
		minScore := mlResp.Results[len(mlResp.Results)-1].Score
		maxScore := mlResp.Results[0].Score
		sendLog(fmt.Sprintf("Skor aralığı: %.3f – %.3f", minScore, maxScore))
	}
	sendEvent("rerank", "done", "Reranking tamamlandı", len(mlResp.Results))

	// ── 3. Severity Prediction (batch — 3 model ayrı ayrı) ──────────
	sendEvent("severity", "running", "3 model ile severity tahmin ediliyor…", 0)
	sendLog("Batch severity: 20 CVE × 3 model (LightGBM + XGBoost + DistilBERT)")

	type SeverityPrediction struct {
		Severity   string  `json:"predicted_severity"`
		Confidence float64 `json:"confidence"`
		ModelUsed  string  `json:"model_used"`
	}

	type ThreeModelSev struct {
		LightGBM   SeverityPrediction
		XGBoost    SeverityPrediction
		DistilBERT SeverityPrediction
	}

	// Tüm description'ları topla
	descriptions := make([]string, len(mlResp.Results))
	for i, r := range mlResp.Results {
		descriptions[i] = r.Description
	}

	sevMap := make(map[string]ThreeModelSev)
	batchURL := getMLServiceURL() + "/ml/predict-severity/batch"
	modelTypes := []string{"lightgbm", "xgboost", "distilbert"}

	// Her model için tek batch çağrı (60 çağrı → 3 çağrı)
	batchResults := make(map[string][]SeverityPrediction)
	for _, mt := range modelTypes {
		batchReqBody, _ := json.Marshal(map[string]interface{}{
			"descriptions": descriptions,
			"model_type":   mt,
		})
		sendLog(fmt.Sprintf("  %s batch çağrılıyor (%d CVE)…", mt, len(descriptions)))
		batchResp, err := client.Post(batchURL, "application/json", bytes.NewReader(batchReqBody))
		if err != nil {
			sendLog(fmt.Sprintf("  HATA: %s batch başarısız: %v", mt, err))
			continue
		}
		batchBody, _ := io.ReadAll(batchResp.Body)
		batchResp.Body.Close()

		// Batch endpoint direkt array dönüyor: [...]
		var preds []SeverityPrediction
		if err := json.Unmarshal(batchBody, &preds); err != nil {
			errSnip := string(batchBody)
			if len(errSnip) > 100 {
				errSnip = errSnip[:100]
			}
			sendLog(fmt.Sprintf("  HATA: %s parse başarısız: %s", mt, errSnip))
			continue
		}
		batchResults[mt] = preds
		sendLog(fmt.Sprintf("  %s tamamlandı (%d sonuç)", mt, len(preds)))
	}

	// Sonuçları birleştir
	for i, r := range mlResp.Results {
		var three ThreeModelSev
		if preds, ok := batchResults["lightgbm"]; ok && i < len(preds) {
			three.LightGBM = preds[i]
		}
		if preds, ok := batchResults["xgboost"]; ok && i < len(preds) {
			three.XGBoost = preds[i]
		}
		if preds, ok := batchResults["distilbert"]; ok && i < len(preds) {
			three.DistilBERT = preds[i]
		}
		sevMap[r.CveID] = three

		if i < 3 {
			sendLog(fmt.Sprintf("  %s → LGBM=%s(%.0f%%) XGB=%s(%.0f%%) BERT=%s(%.0f%%)",
				r.CveID,
				three.LightGBM.Severity, three.LightGBM.Confidence*100,
				three.XGBoost.Severity, three.XGBoost.Confidence*100,
				three.DistilBERT.Severity, three.DistilBERT.Confidence*100))
		}
	}

	sendLog(fmt.Sprintf("Severity tahmin tamamlandı: %d CVE × 3 model", len(sevMap)))
	sendEvent("severity", "done", fmt.Sprintf("%d × 3 model", len(sevMap)), len(sevMap))

	// ── 4. Sonuçları DB'ye yaz ────────────────────────────────
	sendEvent("save", "running", "Sonuçlar veritabanına kaydediliyor…", 0)
	sendLog(fmt.Sprintf("PostgreSQL'e yazılıyor: %d kayıt → matching_results tablosu", len(mlResp.Results)))

	saved := 0
	for _, r := range mlResp.Results {
		three := sevMap[r.CveID]
		_, err := db.Exec(`
			INSERT INTO matching_results
				(app_id, cve_id, algorithm, score, sbert_score, tfidf_score, cascade_score, match_type, source,
				 sev_lightgbm, sev_lightgbm_conf, sev_xgboost, sev_xgboost_conf, sev_distilbert, sev_distilbert_conf,
				 predicted_severity, severity_confidence)
			VALUES ($1, $2, 'ml_cascade', $3, $4, $5, $6, $7, 'ml_cascade',
				$8, $9, $10, $11, $12, $13, $14, $15)
			ON CONFLICT (app_id, cve_id, algorithm) DO UPDATE SET
				score                = EXCLUDED.score,
				sbert_score          = EXCLUDED.sbert_score,
				tfidf_score          = EXCLUDED.tfidf_score,
				cascade_score        = EXCLUDED.cascade_score,
				match_type           = EXCLUDED.match_type,
				source               = 'ml_cascade',
				sev_lightgbm         = EXCLUDED.sev_lightgbm,
				sev_lightgbm_conf    = EXCLUDED.sev_lightgbm_conf,
				sev_xgboost          = EXCLUDED.sev_xgboost,
				sev_xgboost_conf     = EXCLUDED.sev_xgboost_conf,
				sev_distilbert       = EXCLUDED.sev_distilbert,
				sev_distilbert_conf  = EXCLUDED.sev_distilbert_conf,
				predicted_severity   = EXCLUDED.predicted_severity,
				severity_confidence  = EXCLUDED.severity_confidence
		`, appID, r.CveID, r.Score, r.SbertScore, r.TfidfScore, r.Score, r.MatchType,
			three.LightGBM.Severity, three.LightGBM.Confidence,
			three.XGBoost.Severity, three.XGBoost.Confidence,
			three.DistilBERT.Severity, three.DistilBERT.Confidence,
			three.DistilBERT.Severity, three.DistilBERT.Confidence)
		if err != nil {
			log.Printf("[ML Scan] DB write error for %s: %v", r.CveID, err)
			sendLog(fmt.Sprintf("DB HATA: %s → %v", r.CveID, err))
			continue
		}
		saved++
	}

	sendLog(fmt.Sprintf("DB kayıt tamamlandı: %d/%d başarılı", saved, len(mlResp.Results)))
	sendEvent("save", "done", fmt.Sprintf("%d sonuç kaydedildi", saved), saved)
	sendEvent("done", "done", "Tarama tamamlandı", saved)
}

// ── GET /api/ml/results?app_id=APP-001  ────────────────────────
// ML tarafından bulunan eşleşmeleri döner (source='ml_cascade')
func handleMLResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	appID := r.URL.Query().Get("app_id")
	minScore := r.URL.Query().Get("min_score")  // opsiyonel filtre
	matchType := r.URL.Query().Get("match_type") // opsiyonel filtre

	query := `
		SELECT
			mr.app_id, mr.cve_id, mr.algorithm, mr.score,
			COALESCE(mr.sbert_score, 0)   AS sbert_score,
			COALESCE(mr.tfidf_score, 0)   AS tfidf_score,
			COALESCE(mr.cascade_score, 0) AS cascade_score,
			COALESCE(mr.match_type, '')   AS match_type,
			COALESCE(mr.source, 'go_builtin') AS source,
			COALESCE(mr.predicted_severity, COALESCE(cr.severity, 'UNKNOWN')) AS severity,
			COALESCE(cr.cvss_score, 0)        AS cvss_score,
			COALESCE(cr.vendor, '')           AS vendor,
			COALESCE(cr.product, '')          AS product,
			COALESCE(mr.sev_lightgbm, '')     AS sev_lightgbm,
			COALESCE(mr.sev_lightgbm_conf, 0) AS sev_lightgbm_conf,
			COALESCE(mr.sev_xgboost, '')      AS sev_xgboost,
			COALESCE(mr.sev_xgboost_conf, 0)  AS sev_xgboost_conf,
			COALESCE(mr.sev_distilbert, '')   AS sev_distilbert,
			COALESCE(mr.sev_distilbert_conf, 0) AS sev_distilbert_conf
		FROM matching_results mr
		LEFT JOIN cve_records cr ON mr.cve_id = cr.cve_id
		WHERE mr.source = 'ml_cascade'
	`

	args := []interface{}{}
	argIdx := 1

	if appID != "" {
		query += fmt.Sprintf(" AND mr.app_id = $%d", argIdx)
		args = append(args, appID)
		argIdx++
	}
	if minScore != "" {
		query += fmt.Sprintf(" AND mr.cascade_score >= $%d", argIdx)
		args = append(args, minScore)
		argIdx++
	}
	if matchType != "" {
		query += fmt.Sprintf(" AND mr.match_type = $%d", argIdx)
		args = append(args, matchType)
		argIdx++
	}

	query += " ORDER BY mr.cascade_score DESC NULLS LAST LIMIT 100"

	rows, err := db.Query(query, args...)
	if err != nil {
		log.Printf("[ML Results] DB error: %v", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type MLResultRow struct {
		AppID            string  `json:"app_id"`
		CveID            string  `json:"cve_id"`
		Algorithm        string  `json:"algorithm"`
		Score            float64 `json:"score"`
		SbertScore       float64 `json:"sbert_score"`
		TfidfScore       float64 `json:"tfidf_score"`
		CascadeScore     float64 `json:"cascade_score"`
		MatchType        string  `json:"match_type"`
		Source           string  `json:"source"`
		Severity         string  `json:"severity"`
		CVSSScore        float64 `json:"cvss_score"`
		Vendor           string  `json:"vendor"`
		Product          string  `json:"product"`
		SevLightGBM      string  `json:"sev_lightgbm"`
		SevLightGBMConf  float64 `json:"sev_lightgbm_conf"`
		SevXGBoost       string  `json:"sev_xgboost"`
		SevXGBoostConf   float64 `json:"sev_xgboost_conf"`
		SevDistilBERT    string  `json:"sev_distilbert"`
		SevDistilBERTConf float64 `json:"sev_distilbert_conf"`
	}

	var results []MLResultRow
	for rows.Next() {
		var row MLResultRow
		err := rows.Scan(
			&row.AppID, &row.CveID, &row.Algorithm, &row.Score,
			&row.SbertScore, &row.TfidfScore, &row.CascadeScore,
			&row.MatchType, &row.Source, &row.Severity,
			&row.CVSSScore, &row.Vendor, &row.Product,
			&row.SevLightGBM, &row.SevLightGBMConf,
			&row.SevXGBoost, &row.SevXGBoostConf,
			&row.SevDistilBERT, &row.SevDistilBERTConf,
		)
		if err != nil {
			log.Printf("[ML Results] Row scan error: %v", err)
			continue
		}
		results = append(results, row)
	}

	if results == nil {
		results = []MLResultRow{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"total":   len(results),
		"results": results,
	})
}

