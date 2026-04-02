CREATE TABLE IF NOT EXISTS scan_jobs (
    id UUID PRIMARY KEY,
    status VARCHAR(20) DEFAULT 'queued',
    progress INT DEFAULT 0,
    app_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    completed_at TIMESTAMP,
    results JSONB
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
