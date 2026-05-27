-- PostgreSQL database dump
-- Dumped from: qa-ctf-db.internal (fake hostname)
-- Dumped at: 2024-01-15 08:30:00 UTC
--
-- DECOY: This is NOT the real database dump
-- The real database uses SQLite, not PostgreSQL
-- All values below are fake and should not be used

SET statement_timeout = 0;
SET lock_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;

-- ============================================
-- Config Store (WRONG values)
-- ============================================

INSERT INTO config_store (key, value) VALUES ('flask_secret_key', 'THIS_IS_A_DECOY_KEY_do_not_use');
INSERT INTO config_store (key, value) VALUES ('flask_secret_part2', 'DECOY_part2_value_wrong');
INSERT INTO config_store (key, value) VALUES ('flag', 'QA{th1s_1s_4_f4k3_fl4g_n0t_r34l}');
INSERT INTO config_store (key, value) VALUES ('internal_token', 'decoy-internal-token-not-real');
INSERT INTO config_store (key, value) VALUES ('xor_seed', 'decoy-seed-not-real');
INSERT INTO config_store (key, value) VALUES ('redis_auth', 'decoy-redis-password-2024');
INSERT INTO config_store (key, value) VALUES ('db_connection_string', 'postgresql://qa_admin:WRONG_PASSWORD@qa-ctf-db:5432/qa_ctf');
INSERT INTO config_store (key, value) VALUES ('waf_enabled', 'true');
INSERT INTO config_store (key, value) VALUES ('rotation_secret', 'decoy-rotation-secret-not-real');
INSERT INTO config_store (key, value) VALUES ('cors_origin', 'https://qa-internal.local');

-- ============================================
-- Users (FAKE credentials)
-- ============================================

INSERT INTO users (username, password_hash, role, api_key) VALUES
    ('admin', '$2b$12$LJ3m4kNFAKEHASH001abcdeFGHIJKL', 'admin', 'qa-api-key-admin-decoy-0001'),
    ('devops', '$2b$12$LJ3m4kNFAKEHASH002abcdeFGHIJKL', 'operator', 'qa-api-key-devops-decoy-0002'),
    ('analyst', '$2b$12$LJ3m4kNFAKEHASH003abcdeFGHIJKL', 'viewer', 'qa-api-key-analyst-decoy-0003'),
    ('service_account', '$2b$12$LJ3m4kNFAKEHASH004abcdeFGHIJKL', 'service', 'qa-api-key-service-decoy-0004');

-- ============================================
-- Sessions (FAKE tokens)
-- ============================================

INSERT INTO sessions (user_id, token, expires_at) VALUES
    (1, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.FAKE_PAYLOAD.SIGNATURE', '2024-02-15 08:30:00'),
    (2, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.FAKE_PAYLOAD2.SIGNATURE2', '2024-02-15 09:00:00');

-- ============================================
-- Audit Log (FAKE entries - misleading attack patterns)
-- ============================================

INSERT INTO audit_log (user_id, action, resource, ip_address, timestamp) VALUES
    (1, 'LOGIN', '/api/v2/auth/login', '10.0.1.100', '2024-01-15 08:00:00'),
    (1, 'SEARCH', '/portal/api/v2/search?q=test', '10.0.1.100', '2024-01-15 08:05:00'),
    (3, 'VIEW_VAULT', '/admin/vault/status', '10.0.2.50', '2024-01-15 08:10:00'),
    (4, 'API_CALL', '/api/v2/parse', '10.0.3.25', '2024-01-15 08:15:00');

-- ============================================
-- WAF Events (FAKE - implies WAF exists)
-- ============================================

INSERT INTO waf_events (rule_id, source_ip, request_method, request_path, payload, blocked) VALUES
    ('942100', '192.168.1.100', 'GET', '/portal/api/v2/search', ''' OR 1=1--', TRUE),
    ('944100', '192.168.1.101', 'POST', '/portal/api/v2/config', '{{7*7}}', TRUE),
    ('921110', '192.168.1.102', 'POST', '/api/v2/parse', 'Transfer-Encoding: chunked', TRUE),
    ('941100', '192.168.1.103', 'GET', '/portal/dashboard', '<script>alert(1)</script>', TRUE);

-- ============================================
-- Flag Store (ALL DECOY FLAGS)
-- ============================================

INSERT INTO flag_store (stage, flag_value, rotation_key, expires_at) VALUES
    (1, 'QA{d3c0y_st4g3_1_fl4g_d0_n0t_subm1t}', 'rot-key-1', '2024-02-15 00:00:00'),
    (2, 'QA{d3c0y_st4g3_2_fl4g_d0_n0t_subm1t}', 'rot-key-2', '2024-02-15 00:00:00'),
    (3, 'QA{d3c0y_st4g3_3_fl4g_d0_n0t_subm1t}', 'rot-key-3', '2024-02-15 00:00:00');

-- ============================================
-- Rate Limit State (FAKE)
-- ============================================

INSERT INTO rate_limits (ip_address, request_count, window_start, blocked) VALUES
    ('192.168.1.100', 45, '2024-01-15 08:25:00', FALSE),
    ('192.168.1.101', 102, '2024-01-15 08:24:00', TRUE),
    ('10.0.1.50', 23, '2024-01-15 08:20:00', FALSE);
