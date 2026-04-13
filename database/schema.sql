-- ================================================
-- CSPM Database Schema
-- Run against: cspm_db
-- ================================================

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      VARCHAR(100) UNIQUE  NOT NULL,
    email         VARCHAR(150) UNIQUE  NOT NULL,
    password_hash VARCHAR(255)         NOT NULL,
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Scan history
CREATE TABLE IF NOT EXISTS scan_history (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER REFERENCES users(id) ON DELETE CASCADE,
    scan_type  VARCHAR(100),
    result     TEXT,
    status     VARCHAR(50) DEFAULT 'pending',
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_scan_history_user     ON scan_history (user_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_scanned  ON scan_history (scanned_at DESC);