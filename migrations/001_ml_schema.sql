-- ══════════════════════════════════════════════════════════════
--  001_ml_schema.sql
--  Konum: repo kökünde migrations/ klasörüne koy
--  Çalıştır: psql $DATABASE_URL -f migrations/001_ml_schema.sql
-- ══════════════════════════════════════════════════════════════

-- ── applications tablosu (yoksa oluştur) ──────────────────────
CREATE TABLE IF NOT EXISTS applications (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    vendor     TEXT,
    version    TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ── matching_results tablosu (yoksa oluştur) ──────────────────
CREATE TABLE IF NOT EXISTS matching_results (
    app_id    TEXT    NOT NULL,
    cve_id    TEXT    NOT NULL,
    algorithm TEXT    NOT NULL,
    score     FLOAT,
    UNIQUE (app_id, cve_id, algorithm)
);

-- ── ML kolonlarını ekle (varsa atla) ──────────────────────────
ALTER TABLE matching_results
    ADD COLUMN IF NOT EXISTS sbert_score   FLOAT,
    ADD COLUMN IF NOT EXISTS tfidf_score   FLOAT,
    ADD COLUMN IF NOT EXISTS cascade_score FLOAT,
    ADD COLUMN IF NOT EXISTS match_type    TEXT,
    ADD COLUMN IF NOT EXISTS source        TEXT DEFAULT 'go_builtin';

-- ── source kolonunu mevcut satırlarda doldur ──────────────────
UPDATE matching_results
SET source = 'go_builtin'
WHERE source IS NULL;

-- ── İndeksler ─────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_mr_app_id  ON matching_results(app_id);
CREATE INDEX IF NOT EXISTS idx_mr_source  ON matching_results(source);
CREATE INDEX IF NOT EXISTS idx_mr_cascade ON matching_results(cascade_score DESC NULLS LAST);
