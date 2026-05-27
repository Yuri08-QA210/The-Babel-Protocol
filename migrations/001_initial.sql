-- QA CTF Challenge — Initial Database Schema
-- WARNING: This is NOT the actual schema used in production
-- The real schema is created dynamically by the Flask apps

-- ============================================
-- Users table (schema is WRONG - see notes)
-- ============================================
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    api_key VARCHAR(255),  -- decoy: no api_key column in real schema
    created_at TIMESTAMP DEFAULT NOW()
);

-- ============================================
-- Decoy tables that don't exist in the real database
-- Real database uses SQLite, not PostgreSQL
-- ============================================

CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(255),
    ip_address INET,
    timestamp TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rate_limits (
    id SERIAL PRIMARY KEY,
    ip_address INET NOT NULL,
    request_count INTEGER DEFAULT 0,
    window_start TIMESTAMP DEFAULT NOW(),
    blocked BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS flag_store (
    id SERIAL PRIMARY KEY,
    stage INTEGER NOT NULL,
    flag_value VARCHAR(255) NOT NULL,
    rotation_key VARCHAR(255),  -- decoy: flags don't rotate
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP  -- decoy: flags don't expire
);

CREATE TABLE IF NOT EXISTS waf_events (
    id SERIAL PRIMARY KEY,
    rule_id VARCHAR(50) NOT NULL,
    source_ip INET NOT NULL,
    request_method VARCHAR(10),
    request_path VARCHAR(500),
    payload TEXT,
    blocked BOOLEAN DEFAULT TRUE,
    timestamp TIMESTAMP DEFAULT NOW()
);

-- ============================================
-- Indexes (some real, some decoy)
-- ============================================

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key);  -- decoy index
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits(ip_address);
CREATE INDEX IF NOT EXISTS idx_flag_store_stage ON flag_store(stage);
CREATE INDEX IF NOT EXISTS idx_waf_events_rule ON waf_events(rule_id);
CREATE INDEX IF NOT EXISTS idx_waf_events_timestamp ON waf_events(timestamp);

-- ============================================
-- Seed Data (ALL DECOY - not used in real app)
-- ============================================

INSERT INTO users (username, password_hash, role, api_key) VALUES
    ('admin', '$2b$12$FAKE_HASH_admin_password', 'admin', 'qa-admin-api-key-2024'),
    ('operator', '$2b$12$FAKE_HASH_operator_password', 'operator', 'qa-operator-api-key-2024'),
    ('viewer', '$2b$12$FAKE_HASH_viewer_password', 'viewer', 'qa-viewer-api-key-2024');

INSERT INTO flag_store (stage, flag_value, rotation_key) VALUES
    (1, 'QA{st4g3_1_d3c0y_fl4g}', 'rotation-key-1'),
    (2, 'QA{st4g3_2_d3c0y_fl4g}', 'rotation-key-2'),
    (3, 'QA{st4g3_3_d3c0y_fl4g}', 'rotation-key-3');
