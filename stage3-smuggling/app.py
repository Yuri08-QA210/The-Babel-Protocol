"""
QA CTF Challenge — Stage 3: HTTP Smuggling + Race Condition (EXTREME)
=====================================================================
EXTREMELY FRUSTRATING CTF with 40+ rabbit holes.

Race condition mechanism:
1. POST /api/vault/grant with smuggled headers → temporarily grants admin for 3ms
2. Within 3ms, hit /admin/vault → writes encrypted flag to memory
3. Within 300ms, hit /admin/vault/flag → get encrypted flag
4. Decrypt flag using derived XOR key: MD5(seed + INTERNAL_TOKEN)[:5]

Critical: XOR key is NOT given directly. Grant returns a `seed`.
Players must compute: xor_key = hashlib.md5((seed + INTERNAL_TOKEN).encode()).hexdigest()[:5]

Anti-features:
- Anti-replay sequence numbers
- Optimistic locking on role updates
- 5% random connection issues (delays)
- Random noise in ALL responses
- All endpoints return 200 OK
- 40+ rabbit holes returning plausible but useless data
- 12 database tables (most are decoys)
- Multiple fake flags in vault
- Fake admin tokens
- Decoy XOR keys scattered everywhere
- Fake timing information
"""

import os
import re
import time
import json
import uuid
import sqlite3
import threading
import hashlib
import random
import struct
import base64
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, Response, session, make_response

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'default-dev-key-change-me-stage3')

# ============================================================
# Configuration
# ============================================================
FINAL_FLAG = os.environ.get('FINAL_FLAG', 'QA{smuggl1ng_r4c3_c0nd1t10n_ful1_syst3m_t4k30v3r}')
DB_PATH = os.environ.get('DB_PATH', '/var/lib/qa-challenge/challenge.db')
RACE_WINDOW_MS = int(os.environ.get('RACE_WINDOW_MS', '3'))       # 3ms window!
FLAG_MEMORY_TTL_MS = int(os.environ.get('FLAG_MEMORY_TTL_MS', '300'))  # 300ms TTL!
INTERNAL_TOKEN = os.environ.get('INTERNAL_TOKEN', 'qa-internal-smuggle-token-2024-xk9')

# XOR key derivation: MD5(seed + INTERNAL_TOKEN)[:5]
# The grant endpoint returns a seed, NOT the key directly.
# Players must compute the key themselves.
GRANT_SEED = os.environ.get('GRANT_SEED', 'xk9z-seed-2024')

def derive_xor_key(seed):
    """Derive the XOR key from seed + INTERNAL_TOKEN."""
    combined = seed + INTERNAL_TOKEN
    return hashlib.md5(combined.encode()).hexdigest()[:5]

# Pre-compute the actual XOR key
FLAG_XOR_KEY = derive_xor_key(GRANT_SEED)

# ============================================================
# In-memory state
# ============================================================
_flag_memory = {
    'encrypted_value': None,
    'decrypt_hint': None,
    'timestamp': None,
    'lock': threading.Lock()
}

_request_tracker = {
    'last_request_time': None,
    'concurrent_count': 0,
    'total_requests': 0,
    'lock': threading.Lock()
}

# Anti-replay sequence store: session_id -> last_sequence_number
_sequence_store = {}
_sequence_lock = threading.Lock()

# Role elevation tracking (for race condition)
_elevated_roles = {}  # user_id -> {'expires_at': timestamp_ms, 'version': int}
_elevated_lock = threading.Lock()

# Rate limiting state
_rate_limit_store = {}
_rate_limit_lock = threading.Lock()

# Fake session store (decoy)
_fake_session_store = {}

# ============================================================
# Database — Thread-safe with WAL mode
# ============================================================
db_lock = threading.Lock()

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.execute('PRAGMA busy_timeout=5000')
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db_lock:
        conn = get_db()
        c = conn.cursor()

        # ---- REAL TABLES ----
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            version INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS vault (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            value TEXT NOT NULL,
            access_count INTEGER DEFAULT 0,
            last_access TIMESTAMP,
            version INTEGER DEFAULT 1
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS transaction_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        # ---- DECOY TABLES ----
        c.execute('''CREATE TABLE IF NOT EXISTS admin_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT NOT NULL,
            scope TEXT DEFAULT 'admin',
            expires_at TEXT,
            created_by TEXT DEFAULT 'system'
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS encryption_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_name TEXT UNIQUE NOT NULL,
            key_value TEXT NOT NULL,
            algorithm TEXT DEFAULT 'AES-256-GCM',
            rotation_date TEXT
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS backup_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            user_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS system_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_by TEXT DEFAULT 'system'
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_name TEXT,
            key_value TEXT,
            permissions TEXT,
            rate_limit INTEGER DEFAULT 100
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS audit_trail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT,
            action TEXT,
            resource TEXT,
            result TEXT DEFAULT 'success',
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS rate_limit_config (
            endpoint TEXT PRIMARY KEY,
            max_requests INTEGER DEFAULT 100,
            window_seconds INTEGER DEFAULT 60,
            burst_allowed INTEGER DEFAULT 0
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS feature_flags (
            flag_name TEXT PRIMARY KEY,
            enabled INTEGER DEFAULT 0,
            description TEXT,
            rollout_percent INTEGER DEFAULT 0
        )''')

        # ---- SEED DATA ----
        from werkzeug.security import generate_password_hash

        # Real vault entries
        c.execute('INSERT OR IGNORE INTO vault (key, value, access_count) VALUES (?, ?, 0)',
                  ('final_flag_hash', hashlib.sha256(FINAL_FLAG.encode()).hexdigest()))
        c.execute('INSERT OR IGNORE INTO vault (key, value, access_count) VALUES (?, ?, 0)',
                  ('admin_role_token', str(uuid.uuid4())))

        # DECOY vault entries — fake flags and misleading data
        decoy_flags = [
            ('flag', f'QA{{{hashlib.md5(os.urandom(8)).hexdigest()[:16]}}}'),
            ('backup_flag', f'QA{{b4ckup_fl4g_{hashlib.md5(os.urandom(8)).hexdigest()[:10]}}}'),
            ('staging_flag', f'QA{{st4g1ng_{hashlib.md5(os.urandom(8)).hexdigest()[:10]}}}'),
            ('dev_flag', f'QA{{d3v_m0d3_{hashlib.md5(os.urandom(8)).hexdigest()[:10]}}}'),
            ('test_flag', f'QA{{t3st_3nv_{hashlib.md5(os.urandom(8)).hexdigest()[:10]}}}'),
            ('legacy_flag', f'QA{{l3g4cy_{hashlib.md5(os.urandom(8)).hexdigest()[:10]}}}'),
            ('internal_flag', f'QA{{1nt3rn4l_{hashlib.md5(os.urandom(8)).hexdigest()[:10]}}}'),
            ('admin_flag', f'QA{{4dm1n_p4n3l_{hashlib.md5(os.urandom(8)).hexdigest()[:10]}}}'),
        ]
        for k, v in decoy_flags:
            c.execute('INSERT OR IGNORE INTO vault (key, value, access_count) VALUES (?, ?, 0)', (k, v))

        # More decoy vault entries
        c.execute('INSERT OR IGNORE INTO vault (key, value, access_count) VALUES (?, ?, 0)',
                  ('backup_key', hashlib.md5(os.urandom(16)).hexdigest()))
        c.execute('INSERT OR IGNORE INTO vault (key, value, access_count) VALUES (?, ?, 0)',
                  ('encryption_master_key', hashlib.sha512(os.urandom(32)).hexdigest()))
        c.execute('INSERT OR IGNORE INTO vault (key, value, access_count) VALUES (?, ?, 0)',
                  ('jwt_signing_key', hashlib.sha256(os.urandom(32)).hexdigest()))
        c.execute('INSERT OR IGNORE INTO vault (key, value, access_count) VALUES (?, ?, 0)',
                  ('database_url', 'postgresql://admin:password@db.internal:5432/vault'))
        c.execute('INSERT OR IGNORE INTO vault (key, value, access_count) VALUES (?, ?, 0)',
                  ('redis_url', 'redis://:s3cret@cache.internal:6379/0'))
        c.execute('INSERT OR IGNORE INTO vault (key, value, access_count) VALUES (?, ?, 0)',
                  ('xor_key_hint', base64.b64encode(os.urandom(8)).decode()))  # FAKE XOR key

        # Real user
        c.execute('INSERT OR IGNORE INTO users (username, password_hash, role, version) VALUES (?, ?, ?, 1)',
                  ('admin', generate_password_hash('changeme'), 'admin'))

        # Decoy users
        c.execute('INSERT OR IGNORE INTO users (username, password_hash, role, version) VALUES (?, ?, ?, 1)',
                  ('root', generate_password_hash(os.urandom(16).hex()), 'superadmin'))
        c.execute('INSERT OR IGNORE INTO users (username, password_hash, role, version) VALUES (?, ?, ?, 1)',
                  ('service-account', generate_password_hash(os.urandom(16).hex()), 'service'))
        c.execute('INSERT OR IGNORE INTO users (username, password_hash, role, version) VALUES (?, ?, ?, 1)',
                  ('backup-operator', generate_password_hash(os.urandom(16).hex()), 'operator'))

        # Decoy admin_tokens
        for _ in range(5):
            c.execute('INSERT OR IGNORE INTO admin_tokens (token, scope, expires_at, created_by) VALUES (?, ?, ?, ?)',
                      (str(uuid.uuid4()), random.choice(['admin', 'superadmin', 'full_access']),
                       (datetime.now() + timedelta(days=random.randint(1, 365))).isoformat(),
                       random.choice(['system', 'root', 'bootstrap'])))

        # Decoy encryption_keys — with FAKE xor keys
        decoy_keys = [
            ('flag_xor_key', base64.b64encode(os.urandom(5)).decode(), 'XOR', '2025-01-01'),
            ('master_aes_key', hashlib.sha256(os.urandom(32)).hexdigest(), 'AES-256-CBC', '2025-06-01'),
            ('hmac_key', hashlib.sha256(os.urandom(32)).hexdigest(), 'HMAC-SHA256', '2025-03-01'),
            ('rsa_private_key', base64.b64encode(os.urandom(64)).decode(), 'RSA-4096', '2026-01-01'),
            ('data_encryption_key', hashlib.sha256(os.urandom(32)).hexdigest(), 'AES-256-GCM', '2025-09-01'),
        ]
        for name, val, algo, rot in decoy_keys:
            c.execute('INSERT OR IGNORE INTO encryption_keys (key_name, key_value, algorithm, rotation_date) VALUES (?, ?, ?, ?)',
                      (name, val, algo, rot))

        # Decoy backup_codes
        for _ in range(8):
            c.execute('INSERT OR IGNORE INTO backup_codes (code, used, user_id) VALUES (?, ?, ?)',
                      (str(random.randint(100000, 999999)), random.choice([0, 1]), random.randint(1, 4)))

        # Decoy system_config
        decoy_configs = [
            ('debug_mode', 'false'),
            ('log_level', 'INFO'),
            ('max_connections', '1000'),
            ('session_timeout', '3600'),
            ('flag_encryption_enabled', 'true'),
            ('race_window_ms', str(random.randint(50, 500))),  # FAKE timing
            ('flag_ttl_ms', str(random.randint(5000, 30000))),  # FAKE TTL
            ('internal_token', f'qa-internal-{hashlib.md5(os.urandom(8)).hexdigest()[:12]}'),  # FAKE token
            ('xor_key', base64.b64encode(os.urandom(5)).decode()),  # FAKE XOR key
            ('admin_secret', hashlib.sha256(os.urandom(16)).hexdigest()),  # FAKE secret
            ('smuggle_detection', 'enabled'),
            ('waf_enabled', 'true'),
        ]
        for k, v in decoy_configs:
            c.execute('INSERT OR IGNORE INTO system_config (key, value) VALUES (?, ?)', (k, v))

        # Decoy api_keys
        decoy_api_keys = [
            ('vault_read', hashlib.sha256(os.urandom(16)).hexdigest(), 'read:vault', 50),
            ('admin_write', hashlib.sha256(os.urandom(16)).hexdigest(), 'write:admin', 10),
            ('flag_access', hashlib.sha256(os.urandom(16)).hexdigest(), 'read:flag', 5),
            ('internal_service', hashlib.sha256(os.urandom(16)).hexdigest(), 'full_access', 1000),
        ]
        for name, val, perm, rl in decoy_api_keys:
            c.execute('INSERT OR IGNORE INTO api_keys (key_name, key_value, permissions, rate_limit) VALUES (?, ?, ?, ?)',
                      (name, val, perm, rl))

        # Decoy audit_trail
        audit_actions = [
            ('admin', 'vault.access', 'final_flag', 'denied'),
            ('system', 'role.grant', 'user:3', 'success'),
            ('admin', 'flag.decrypt', 'final_flag', 'failed'),
            ('root', 'config.update', 'race_window_ms', 'success'),
            ('service-account', 'backup.create', 'vault', 'success'),
            ('admin', 'token.generate', 'admin_token', 'success'),
        ]
        for actor, action, resource, result in audit_actions:
            c.execute('INSERT OR IGNORE INTO audit_trail (actor, action, resource, result) VALUES (?, ?, ?, ?)',
                      (actor, action, resource, result))

        # Decoy rate_limit_config
        rate_configs = [
            ('/api/vault/grant', 3, 10, 0),
            ('/admin/vault', 1, 60, 0),
            ('/admin/vault/flag', 2, 10, 0),
            ('/api/health', 1000, 60, 1),
            ('/api/vault/status', 100, 60, 1),
        ]
        for endpoint, max_req, window, burst in rate_configs:
            c.execute('INSERT OR IGNORE INTO rate_limit_config (endpoint, max_requests, window_seconds, burst_allowed) VALUES (?, ?, ?, ?)',
                      (endpoint, max_req, window, burst))

        # Decoy feature_flags
        feature_flags_data = [
            ('vault_encryption', 1, 'Encrypt vault entries at rest', 100),
            ('admin_2fa', 1, 'Require 2FA for admin access', 50),
            ('race_detection', 0, 'Detect race condition attempts', 0),
            ('flag_honeypot', 1, 'Serve fake flags to unauthorized access', 100),
            ('smuggle_protection', 1, 'Block HTTP smuggling attempts', 75),
            ('timing_attack_protection', 0, 'Add random delays to prevent timing attacks', 0),
        ]
        for name, enabled, desc, rollout in feature_flags_data:
            c.execute('INSERT OR IGNORE INTO feature_flags (flag_name, enabled, description, rollout_percent) VALUES (?, ?, ?, ?)',
                      (name, enabled, desc, rollout))

        conn.commit()
        conn.close()


# ============================================================
# Helper functions
# ============================================================
def xor_encrypt(text, key):
    """XOR encrypt text with repeating key."""
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))


def xor_decrypt(cipher, key):
    """XOR decrypt (same as encrypt for XOR)."""
    return xor_encrypt(cipher, key)


def noise_dict(base=None):
    """Add random noise to response dicts to confuse pattern matching."""
    noise = {
        'request_id': str(uuid.uuid4())[:8],
        'timestamp': int(time.time() * 1000),
        'server_node': random.choice(['node-1', 'node-2', 'node-3']),
        'trace_id': hashlib.md5(os.urandom(8)).hexdigest()[:12],
    }
    if base:
        base.update(noise)
        return base
    return noise


def fake_flag():
    """Generate a random fake flag for decoy responses."""
    return f'QA{{{hashlib.md5(os.urandom(8)).hexdigest()[:16]}}}'


def check_sequence(session_id, seq_num):
    """
    Anti-replay: check that sequence number is strictly increasing.
    Returns True if valid (new sequence number), False otherwise.
    """
    if not session_id or seq_num is None:
        return False
    with _sequence_lock:
        last_seq = _sequence_store.get(session_id, -1)
        if seq_num <= last_seq:
            return False
        _sequence_store[session_id] = seq_num
        return True


def is_internal_request():
    """Check if request has all required smuggled headers."""
    internal_token = request.headers.get('X-Internal-Token', '')
    source_ip = request.headers.get('X-Real-Source', '')
    bypass_waf = request.headers.get('X-Bypass-WAF', '')
    return all([
        internal_token == INTERNAL_TOKEN,
        source_ip == '127.0.0.1',
        bypass_waf == 'true'
    ])


def apply_rate_limit(endpoint, max_requests=100, window_seconds=60):
    """Simple in-memory rate limiting."""
    now = time.time()
    with _rate_limit_lock:
        if endpoint not in _rate_limit_store:
            _rate_limit_store[endpoint] = []
        # Clean old entries
        _rate_limit_store[endpoint] = [t for t in _rate_limit_store[endpoint] if now - t < window_seconds]
        if len(_rate_limit_store[endpoint]) >= max_requests:
            return False
        _rate_limit_store[endpoint].append(now)
        return True


# ============================================================
# Middleware — Random delays + connection issues + tracking
# ============================================================
@app.before_request
def before_request_func():
    with _request_tracker['lock']:
        _request_tracker['concurrent_count'] += 1
        _request_tracker['total_requests'] += 1
        _request_tracker['last_request_time'] = time.time() * 1000

    # 5% chance of random connection issue (simulated as delay)
    if random.random() < 0.05:
        time.sleep(random.uniform(0.05, 0.5))

    # Small random delay on ALL requests (timing attack prevention)
    time.sleep(random.uniform(0.001, 0.01))


@app.teardown_request
def after_request_func(exception=None):
    with _request_tracker['lock']:
        if _request_tracker['concurrent_count'] > 0:
            _request_tracker['concurrent_count'] -= 1


@app.after_request
def after_request_headers(response):
    # Add noise headers to confuse players
    response.headers['X-Request-Id'] = str(uuid.uuid4())[:8]
    response.headers['X-Response-Time'] = f'{random.uniform(0.001, 0.1):.4f}s'
    response.headers['X-Server-Node'] = random.choice(['prod-1', 'prod-2', 'prod-3'])
    response.headers['X-RateLimit-Remaining'] = str(random.randint(0, 100))
    return response


@app.errorhandler(Exception)
def handle_exception(e):
    return jsonify(noise_dict({'status': 'ok', 'message': 'Request processed'})), 200


# ============================================================
# CORE ROUTES — The actual challenge path
# ============================================================

@app.route('/')
def index():
    accept = request.headers.get('Accept', '')
    if 'application/json' in accept:
        return jsonify(noise_dict({
            'service': 'QA-Vault-Backend',
            'version': '3.0.0',
            'build': '2024.12.15-rc3',
            'endpoints': {
                '/api/health': 'GET', '/api/vault/status': 'GET',
                '/api/vault/grant': 'POST', '/admin/vault': 'POST',
                '/admin/vault/flag': 'GET',
            }
        }))

    html = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Babel Infrastructure — Monitoring</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#06080d;color:#c8d0dc;font-family:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;min-height:100vh;overflow-x:hidden}
#bg-canvas{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0;pointer-events:none}
.container{max-width:960px;margin:0 auto;padding:30px 20px;position:relative;z-index:1;animation:fadeIn .6s ease-out}
@keyframes fadeIn{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
header{text-align:center;margin-bottom:36px}
.brand{font-size:2em;font-weight:800;letter-spacing:4px;background:linear-gradient(135deg,#cc44ff,#9933cc);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:5px}
.brand-sub{font-size:.78em;color:#3e4858;letter-spacing:2px}
.dashboard{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:28px}
.card{background:rgba(14,18,27,.85);border:1px solid rgba(204,68,255,.08);border-radius:12px;padding:18px;position:relative;overflow:hidden;backdrop-filter:blur(10px)}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,#cc44ff,#9933cc);border-radius:12px 12px 0 0}
.card-label{font-size:.65em;color:#4e5a6b;letter-spacing:1.5px;text-transform:uppercase;margin-bottom:6px}
.card-value{font-size:1.3em;font-weight:700;color:#e0e5ed}
.card-value.mono{font-family:monospace;color:rgba(204,68,255,.7)}
.card-value.ok{color:#00d4aa}
.card-value.warn{color:#ff8c42}
.status-row{display:grid;grid-template-columns:1fr 1fr 1fr;gap:10px;margin-bottom:28px}
.status-item{background:rgba(14,18,27,.85);border:1px solid rgba(255,255,255,.04);border-radius:10px;padding:14px;text-align:center}
.status-dot{width:8px;height:8px;border-radius:50%;margin:0 auto 6px}
.status-dot.green{background:#00d4aa;box-shadow:0 0 8px rgba(0,212,170,.4);animation:pulse 2s infinite}
.status-dot.red{background:#ff4757}
.status-dot.yellow{background:#ffa502;animation:pulse 1.5s infinite}
.status-label{font-size:.65em;color:#4e5a6b;letter-spacing:1px;text-transform:uppercase}
.panel{background:rgba(14,18,27,.85);border:1px solid rgba(204,68,255,.08);border-radius:14px;padding:22px;margin-bottom:22px;position:relative;backdrop-filter:blur(10px)}
.panel::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,#cc44ff,#4488ff);border-radius:14px 14px 0 0}
.panel h2{font-size:1em;color:#c8d0dc;margin-bottom:14px;letter-spacing:.5px;font-weight:600}
.ep-list{list-style:none}
.ep-list li{padding:9px 0;border-bottom:1px solid rgba(255,255,255,.03);font-size:.82em;display:flex;justify-content:space-between;align-items:center}
.ep-list li:last-child{border:none}
.ep-method{padding:2px 7px;border-radius:4px;font-size:.68em;font-weight:700;letter-spacing:.5px}
.ep-method.get{background:rgba(0,212,170,.08);color:#00d4aa;border:1px solid rgba(0,212,170,.15)}
.ep-method.post{background:rgba(204,68,255,.08);color:#cc44ff;border:1px solid rgba(204,68,255,.15)}
.ep-path{font-family:monospace;color:#6b7a8d;font-size:.78em}
.ep-desc{color:#3e4858;font-size:.7em}
.footer-bar{text-align:center;padding:22px 0;margin-top:40px;border-top:1px solid rgba(255,255,255,.03);font-size:.7em;color:#2e3646;letter-spacing:1px}
</style>
</head>
<body>
<canvas id="bg-canvas"></canvas>
<div class="container">
<header>
<div class="brand">BABEL INFRASTRUCTURE</div>
<div class="brand-sub">Monitoring &middot; v3.0.0</div>
</header>
<div class="dashboard">
<div class="card">
<div class="card-label">Service Status</div>
<div class="card-value ok" id="vaultStatus">Operational</div>
</div>
<div class="card">
<div class="card-label">Memory Cache</div>
<div class="card-value" id="flagMemory" style="color:#4e5a6b">Empty</div>
</div>
<div class="card">
<div class="card-label">Access Level</div>
<div class="card-value mono">Standard</div>
</div>
<div class="card">
<div class="card-label">Active Requests</div>
<div class="card-value mono" id="reqCount">0</div>
</div>
</div>
<div class="status-row">
<div class="status-item">
<div class="status-dot green"></div>
<div class="status-label">Database</div>
</div>
<div class="status-item">
<div class="status-dot green"></div>
<div class="status-label">Cache</div>
</div>
<div class="status-item">
<div class="status-dot yellow"></div>
<div class="status-label">Admin API</div>
</div>
</div>
<div class="panel">
<h2>API Endpoints</h2>
<ul class="ep-list">
<li><span><span class="ep-method get">GET</span> <span class="ep-path">/api/health</span></span><span class="ep-desc">Health check</span></li>
<li><span><span class="ep-method get">GET</span> <span class="ep-path">/api/vault/status</span></span><span class="ep-desc">Service status</span></li>
<li><span><span class="ep-method post">POST</span> <span class="ep-path">/api/vault/grant</span></span><span class="ep-desc">Request elevation</span></li>
<li><span><span class="ep-method post">POST</span> <span class="ep-path">/admin/vault</span></span><span class="ep-desc">Admin access</span></li>
<li><span><span class="ep-method get">GET</span> <span class="ep-path">/admin/vault/flag</span></span><span class="ep-desc">Encrypted data</span></li>
</ul>
</div>
<div class="footer-bar">Babel Infrastructure v3.0.0 &copy; 2024</div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
<script>
(function(){var c=document.getElementById('bg-canvas');var scene=new THREE.Scene();var cam=new THREE.PerspectiveCamera(75,innerWidth/innerHeight,0.1,1000);var ren=new THREE.WebGLRenderer({canvas:c,alpha:true,antialias:true});ren.setSize(innerWidth,innerHeight);ren.setPixelRatio(Math.min(devicePixelRatio,2));var GS=14;var SP=1.6;var N=GS*GS;var pos=new Float32Array(N*3);var meta=[];for(var x=0;x<GS;x++){for(var z=0;z<GS;z++){var i=x*GS+z;pos[i*3]=(x-GS/2)*SP;pos[i*3+1]=0;pos[i*3+2]=(z-GS/2)*SP;meta.push({phase:Math.random()*Math.PI*2,speed:.4+Math.random()*1.2})}}var geo=new THREE.BufferGeometry();geo.setAttribute('position',new THREE.BufferAttribute(pos,3));var mat=new THREE.PointsMaterial({size:.05,color:0xcc44ff,transparent:true,opacity:.5,sizeAttenuation:true});var pts=new THREE.Points(geo,mat);scene.add(pts);var lpos=[];for(var x=0;x<GS;x++){for(var z=0;z<GS;z++){var i=x*GS+z;if(x<GS-1){var ri=(x+1)*GS+z;lpos.push(pos[i*3],pos[i*3+1],pos[i*3+2],pos[ri*3],pos[ri*3+1],pos[ri*3+2])}if(z<GS-1){var bi=x*GS+z+1;lpos.push(pos[i*3],pos[i*3+1],pos[i*3+2],pos[bi*3],pos[bi*3+1],pos[bi*3+2])}}}var la=new Float32Array(lpos.length);for(var k=0;k<lpos.length;k++)la[k]=lpos[k];var lg=new THREE.BufferGeometry();lg.setAttribute('position',new THREE.BufferAttribute(la,3));var lm=new THREE.LineBasicMaterial({color:0xcc44ff,transparent:true,opacity:.06});var ln=new THREE.LineSegments(lg,lm);scene.add(ln);cam.position.set(0,14,14);cam.lookAt(0,0,0);var t=0;function anim(){requestAnimationFrame(anim);t+=.016;var p=geo.attributes.position.array;for(var i=0;i<N;i++){p[i*3+1]=Math.sin(t*meta[i].speed+meta[i].phase)*.35}geo.attributes.position.needsUpdate=true;var lp=lg.attributes.position.array;var li=0;for(var x=0;x<GS;x++){for(var z=0;z<GS;z++){var i=x*GS+z;if(x<GS-1){var ri=(x+1)*GS+z;lp[li++]=p[i*3];lp[li++]=p[i*3+1];lp[li++]=p[i*3+2];lp[li++]=p[ri*3];lp[li++]=p[ri*3+1];lp[li++]=p[ri*3+2]}if(z<GS-1){var bi=x*GS+z+1;lp[li++]=p[i*3];lp[li++]=p[i*3+1];lp[li++]=p[i*3+2];lp[li++]=p[bi*3];lp[li++]=p[bi*3+1];lp[li++]=p[bi*3+2]}}}lg.attributes.position.needsUpdate=true;ren.render(scene,cam)}anim();addEventListener('resize',function(){cam.aspect=innerWidth/innerHeight;cam.updateProjectionMatrix();ren.setSize(innerWidth,innerHeight)})})();
</script>
<script>
fetch('/api/vault/status').then(function(r){return r.json()}).then(function(d){if(d.vault_status)document.getElementById('vaultStatus').textContent=d.vault_status==='locked'?'Locked':'Operational';if(d.flag_in_memory!==undefined)document.getElementById('flagMemory').textContent=d.flag_in_memory?'Active':'Empty';if(d.concurrent_requests)document.getElementById('reqCount').textContent=d.concurrent_requests}).catch(function(){});
</script>
</body>
</html>'''
    resp = make_response(html)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    return resp


@app.route('/api/health')
def health():
    return jsonify(noise_dict({
        'status': 'healthy',
        'uptime_seconds': random.randint(1000, 999999),
        'db_status': 'connected',
        'cache_status': 'connected',
    }))


@app.route('/api/vault/status')
def vault_status():
    with _flag_memory['lock']:
        flag_available = _flag_memory['encrypted_value'] is not None

    return jsonify(noise_dict({
        'vault_status': 'locked',
        'flag_in_memory': flag_available,
        'access_level': 'user',
        'concurrent_requests': _request_tracker['concurrent_count'],
        'total_requests': _request_tracker['total_requests'],
        'race_window_hint': f'{random.randint(10, 100)}ms',  # FAKE timing
    }))


@app.route('/api/vault/grant', methods=['POST'])
def grant_role():
    """
    Role elevation — requires smuggled request with internal headers.
    
    The grant response returns a SEED, not the XOR key directly.
    Players must derive: xor_key = MD5(seed + INTERNAL_TOKEN)[:5]
    """
    # Check for smuggled headers
    internal_token = request.headers.get('X-Internal-Token', '')
    source_ip = request.headers.get('X-Real-Source', '')
    bypass_waf = request.headers.get('X-Bypass-WAF', '')

    if not all([internal_token, source_ip == '127.0.0.1', bypass_waf == 'true']):
        # Return plausible but useless response
        return jsonify(noise_dict({
            'status': 'ok',
            'message': 'Request processed',
            'grant_status': 'pending_approval',
            'estimated_wait': f'{random.randint(1, 48)}h',
        })), 200

    if internal_token != INTERNAL_TOKEN:
        return jsonify(noise_dict({
            'status': 'ok',
            'message': 'Request processed',
            'grant_status': 'pending_approval',
            'estimated_wait': f'{random.randint(1, 48)}h',
        })), 200

    # Validate request body
    user_id = request.json.get('user_id', 0) if request.is_json else 0
    if user_id <= 0:
        return jsonify(noise_dict({'status': 'ok', 'message': 'Request processed'})), 200

    # Anti-replay sequence check
    session_id = request.headers.get('X-Session-Id', '')
    seq_num = request.headers.get('X-Sequence', type=int, default=None)
    if session_id and seq_num is not None:
        if not check_sequence(session_id, seq_num):
            return jsonify(noise_dict({
                'status': 'ok',
                'message': 'Request processed',
                'error_code': 'DUPLICATE_REQUEST',
            })), 200

    # Optimistic locking: read version, update with version check
    with db_lock:
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

        if not user:
            conn.close()
            return jsonify(noise_dict({'status': 'ok', 'message': 'Request processed'})), 200

        current_version = user['version']

        try:
            cursor = conn.execute(
                'UPDATE users SET role = ?, version = version + 1 WHERE id = ? AND version = ?',
                ('admin', user_id, current_version))
            if cursor.rowcount == 0:
                # Optimistic lock failure — concurrent modification
                conn.rollback()
                conn.close()
                return jsonify(noise_dict({
                    'status': 'ok',
                    'message': 'Request processed',
                    'error_code': 'VERSION_CONFLICT',
                })), 200

            conn.execute(
                'INSERT INTO transaction_log (user_id, action, details) VALUES (?, ?, ?)',
                (user_id, 'role_grant', json.dumps({
                    'from': 'user', 'to': 'admin', 'version': current_version,
                    'expires_ms': RACE_WINDOW_MS,
                    'granted_at': time.time() * 1000,
                })))
            conn.commit()
        except sqlite3.OperationalError:
            conn.rollback()
            conn.close()
            return jsonify(noise_dict({'status': 'ok', 'message': 'Request processed'})), 200

        new_version = current_version + 1
        conn.close()

    # Track elevated role in memory for fast lookup
    with _elevated_lock:
        _elevated_roles[user_id] = {
            'expires_at': time.time() * 1000 + RACE_WINDOW_MS,
            'version': new_version,
        }

    # Schedule role revert after race window
    def revert_role():
        time.sleep(RACE_WINDOW_MS / 1000.0)
        try:
            with db_lock:
                conn2 = get_db()
                conn2.execute(
                    'UPDATE users SET role = ?, version = version + 1 WHERE id = ? AND version = ?',
                    ('user', user_id, new_version))
                conn2.execute(
                    'INSERT INTO transaction_log (user_id, action, details) VALUES (?, ?, ?)',
                    (user_id, 'role_revert', json.dumps({
                        'from': 'admin', 'to': 'user', 'version': new_version,
                        'reverted_at': time.time() * 1000,
                    })))
                conn2.commit()
                conn2.close()
        except Exception:
            pass
        finally:
            with _elevated_lock:
                _elevated_roles.pop(user_id, None)

    revert_thread = threading.Thread(target=revert_role, daemon=True)
    revert_thread.start()

    # Return the SEED — players must derive the XOR key themselves
    # xor_key = MD5(seed + INTERNAL_TOKEN)[:5]
    return jsonify(noise_dict({
        'status': 'ok',
        'message': 'Request processed',
        'grant_status': 'elevated',
        'seed': GRANT_SEED,
        'window_ms': RACE_WINDOW_MS,
        'hint': 'Derive the decryption key from the seed and your knowledge of the internal architecture.',
        'key_derivation': 'HMAC-based key derivation function (HKDF)',  # LIE — it's actually MD5
        'new_version': new_version,
    })), 200


@app.route('/admin/vault', methods=['GET', 'POST'])
def admin_vault():
    """Race condition target — must hit within race window."""
    user_id = request.args.get('user_id', type=int, default=0)
    if request.is_json:
        user_id = request.json.get('user_id', user_id)

    if user_id <= 0:
        return jsonify(noise_dict({'status': 'ok', 'message': 'Request processed'})), 200

    # Check elevated roles in memory FIRST (faster than DB)
    is_admin = False
    with _elevated_lock:
        if user_id in _elevated_roles:
            if time.time() * 1000 < _elevated_roles[user_id]['expires_at']:
                is_admin = True

    # Fallback to DB check
    if not is_admin:
        with db_lock:
            conn = get_db()
            user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            conn.close()

        if not user or user['role'] != 'admin':
            return jsonify(noise_dict({
                'status': 'ok',
                'message': 'Request processed',
                'vault_entries': 0,
            })), 200

    # SUCCESS — Role is admin right now! Write encrypted flag to memory
    encrypted_flag = xor_encrypt(FINAL_FLAG, FLAG_XOR_KEY)
    with _flag_memory['lock']:
        _flag_memory['encrypted_value'] = encrypted_flag
        _flag_memory['decrypt_hint'] = 'XOR with the derived key'
        _flag_memory['timestamp'] = time.time() * 1000

    # Schedule flag memory cleanup (300ms TTL)
    def clear_flag():
        time.sleep(FLAG_MEMORY_TTL_MS / 1000.0)
        with _flag_memory['lock']:
            _flag_memory['encrypted_value'] = None
            _flag_memory['decrypt_hint'] = None
            _flag_memory['timestamp'] = None

    clear_thread = threading.Thread(target=clear_flag, daemon=True)
    clear_thread.start()

    # Increment vault access count
    with db_lock:
        try:
            conn = get_db()
            conn.execute('UPDATE vault SET access_count = access_count + 1, last_access = ? WHERE key = ?',
                         (datetime.now().isoformat(), 'final_flag_hash'))
            conn.commit()
            conn.close()
        except Exception:
            pass

    return jsonify(noise_dict({
        'status': 'ok',
        'message': 'Vault accessed',
        'vault_access': True,
        'hint': 'Flag encrypted in memory — check /admin/vault/flag',
        'encryption': 'XOR',
        'ttl_ms': FLAG_MEMORY_TTL_MS,
    })), 200


@app.route('/admin/vault/flag')
def get_vault_flag():
    """Get encrypted flag from memory — 300ms TTL after race success."""
    with _flag_memory['lock']:
        if _flag_memory['encrypted_value'] is not None:
            elapsed = time.time() * 1000 - _flag_memory['timestamp'] if _flag_memory['timestamp'] else 9999
            if elapsed < FLAG_MEMORY_TTL_MS:
                # Return encrypted flag as hex bytes for clarity
                encrypted_hex = _flag_memory['encrypted_value'].encode('utf-8').hex()
                return jsonify(noise_dict({
                    'status': 'ok',
                    'encrypted_flag': encrypted_hex,
                    'decrypt_method': _flag_memory['decrypt_hint'],
                    'expires_in_ms': int(FLAG_MEMORY_TTL_MS - elapsed),
                    'encryption_algo': 'XOR',
                    'note': 'The decryption key was derived from the grant seed. Figure out the derivation.',
                }))

    return jsonify(noise_dict({'status': 'ok', 'message': 'Request processed'})), 200


# ============================================================
# RABBIT HOLE: /api/vault/* endpoints (14 endpoints)
# ============================================================

@app.route('/api/vault/decrypt')
def vault_decrypt():
    """RABBIT HOLE — Fake decryption endpoint."""
    return jsonify(noise_dict({
        'status': 'ok',
        'message': 'Quantum decryption module not initialized',
        'algorithm': 'Kyber-1024',
        'error_code': 'QKM_NOT_READY',
    })), 200


@app.route('/api/vault/export')
def vault_export():
    """RABBIT HOLE — Fake export."""
    return jsonify(noise_dict({
        'status': 'ok',
        'message': 'Export requires admin approval and 2FA verification',
        'export_format': 'encrypted_tar.gz',
        'estimated_size': f'{random.randint(1, 50)}MB',
    })), 200


@app.route('/api/vault/backup')
def vault_backup():
    """RABBIT HOLE — Fake backup."""
    return jsonify(noise_dict({
        'status': 'ok',
        'message': 'Backup system under maintenance',
        'last_backup': (datetime.now() - timedelta(hours=random.randint(1, 72))).isoformat(),
        'next_backup': (datetime.now() + timedelta(hours=random.randint(1, 24))).isoformat(),
    })), 200


@app.route('/api/vault/reset')
def vault_reset():
    """RABBIT HOLE — Looks like it might reset the vault."""
    return jsonify(noise_dict({
        'status': 'ok',
        'message': 'Reset requires physical access token and dual authorization',
        'reset_code': str(random.randint(100000, 999999)),  # USELESS code
    })), 200


@app.route('/api/vault/keys')
def vault_keys():
    """RABBIT HOLE — Returns fake encryption keys."""
    with db_lock:
        conn = get_db()
        try:
            keys = conn.execute('SELECT key_name, algorithm, rotation_date FROM encryption_keys').fetchall()
            result = [dict(k) for k in keys]
        except Exception:
            result = []
        conn.close()

    return jsonify(noise_dict({
        'status': 'ok',
        'keys': result,
        'note': 'Key values are stored in HSM and not accessible via API',
    })), 200


@app.route('/api/vault/history')
def vault_history():
    """RABBIT HOLE — Fake audit history."""
    fake_entries = []
    for i in range(random.randint(3, 8)):
        fake_entries.append({
            'timestamp': (datetime.now() - timedelta(minutes=random.randint(1, 1440))).isoformat(),
            'action': random.choice(['read', 'write', 'grant', 'rotate']),
            'actor': random.choice(['admin', 'system', 'backup-operator', 'service-account']),
            'result': random.choice(['success', 'denied', 'pending']),
        })
    return jsonify(noise_dict({
        'status': 'ok',
        'history': fake_entries,
        'total_entries': random.randint(100, 10000),
    })), 200


@app.route('/api/vault/shares')
def vault_shares():
    """RABBIT HOLE — Shamir's Secret Sharing reference (useless)."""
    return jsonify(noise_dict({
        'status': 'ok',
        'message': 'Secret sharing enabled — 3 of 5 shares required',
        'shares_generated': 5,
        'threshold': 3,
        'algorithm': 'Shamir-SSS-256',
    })), 200


@app.route('/api/vault/metadata')
def vault_metadata():
    """RABBIT HOLE — Returns decoy vault metadata."""
    return jsonify(noise_dict({
        'status': 'ok',
        'total_entries': random.randint(50, 200),
        'encrypted_entries': random.randint(30, 100),
        'last_rotation': (datetime.now() - timedelta(days=random.randint(1, 90))).isoformat(),
        'integrity_hash': hashlib.sha256(os.urandom(32)).hexdigest(),
        'storage_backend': 'encrypted-raft',
    })), 200


@app.route('/api/vault/audit')
def vault_audit():
    """RABBIT HOLE — Fake audit log."""
    with db_lock:
        conn = get_db()
        try:
            entries = conn.execute('SELECT actor, action, resource, result, timestamp FROM audit_trail ORDER BY timestamp DESC LIMIT 10').fetchall()
            result = [dict(e) for e in entries]
        except Exception:
            result = []
        conn.close()

    return jsonify(noise_dict({
        'status': 'ok',
        'audit_entries': result,
    })), 200


@app.route('/api/vault/config')
def vault_config():
    """RABBIT HOLE — Returns decoy config (looks real!)."""
    with db_lock:
        conn = get_db()
        try:
            configs = conn.execute('SELECT key, value FROM system_config').fetchall()
            config_dict = {c['key']: c['value'] for c in configs}
        except Exception:
            config_dict = {}
        conn.close()

    return jsonify(noise_dict({
        'status': 'ok',
        'config': config_dict,
        'warning': 'Sensitive values are redacted',
    })), 200


@app.route('/api/vault/policy')
def vault_policy():
    """RABBIT HOLE — Fake policy information."""
    return jsonify(noise_dict({
        'status': 'ok',
        'policy': {
            'max_role_duration': '8h',
            'elevation_requires_2fa': True,
            'smuggling_detection': 'enabled',
            'race_condition_protection': 'enabled',
            'flag_access_requires': 'admin + mfa + internal_source',
        },
    })), 200


@app.route('/api/vault/seal')
def vault_seal():
    """RABBIT HOLE — Looks like HashiCorp Vault seal."""
    return jsonify(noise_dict({
        'status': 'ok',
        'sealed': True,
        'seal_type': 'shamir',
        'total_shares': 5,
        'threshold': 3,
        'progress': random.randint(0, 2),
    })), 200


@app.route('/api/vault/unseal', methods=['POST'])
def vault_unseal():
    """RABBIT HOLE — Fake unseal (always fails)."""
    return jsonify(noise_dict({
        'status': 'ok',
        'sealed': True,
        'progress': random.randint(0, 2),
        'message': 'Invalid unseal key',
    })), 200


@app.route('/api/vault/health')
def vault_health():
    """RABBIT HOLE — Fake vault health."""
    return jsonify(noise_dict({
        'status': 'ok',
        'vault_health': 'sealed',
        'ha_enabled': False,
        'standby': False,
        'replication': 'disabled',
    })), 200


# ============================================================
# RABBIT HOLE: /admin/* endpoints (10 endpoints)
# ============================================================

@app.route('/admin/dashboard')
def admin_dashboard():
    """RABBIT HOLE — Fake admin dashboard."""
    return jsonify(noise_dict({
        'status': 'ok',
        'dashboard': {
            'active_users': random.randint(1, 50),
            'total_requests_today': random.randint(1000, 99999),
            'vault_access_attempts': random.randint(10, 500),
            'failed_logins': random.randint(0, 20),
            'system_load': f'{random.uniform(0.1, 3.0):.2f}',
        }
    })), 200


@app.route('/admin/logs')
def admin_logs():
    """RABBIT HOLE — Fake logs with decoy info."""
    fake_logs = []
    for _ in range(random.randint(3, 8)):
        fake_logs.append({
            'level': random.choice(['INFO', 'WARN', 'ERROR', 'DEBUG']),
            'timestamp': (datetime.now() - timedelta(seconds=random.randint(1, 3600))).isoformat(),
            'message': random.choice([
                'Role elevation request from 10.0.0.5',
                'Vault access denied — insufficient permissions',
                'Rate limit exceeded for /api/vault/grant',
                f'Flag access attempt — result: {random.choice(["denied", "blocked", "logged"])}',
                'HTTP smuggling attempt detected and blocked',
                'Race condition mitigation triggered',
                'XOR key rotation completed',
                'Admin session expired for user service-account',
            ]),
        })
    return jsonify(noise_dict({
        'status': 'ok',
        'logs': fake_logs,
    })), 200


@app.route('/admin/users')
def admin_users():
    """RABBIT HOLE — Returns user list (with decoy roles)."""
    with db_lock:
        conn = get_db()
        try:
            users = conn.execute('SELECT id, username, role, version, created_at FROM users').fetchall()
            result = [dict(u) for u in users]
        except Exception:
            result = []
        conn.close()

    return jsonify(noise_dict({
        'status': 'ok',
        'users': result,
    })), 200


@app.route('/admin/config')
def admin_config():
    """RABBIT HOLE — Returns decoy admin config (looks very real!)."""
    with db_lock:
        conn = get_db()
        try:
            configs = conn.execute('SELECT key, value, updated_at, updated_by FROM system_config').fetchall()
            result = [dict(c) for c in configs]
        except Exception:
            result = []
        conn.close()

    return jsonify(noise_dict({
        'status': 'ok',
        'config': result,
        'warning': 'Production configuration — do not modify without approval',
    })), 200


@app.route('/admin/system')
def admin_system():
    """RABBIT HOLE — Fake system info."""
    return jsonify(noise_dict({
        'status': 'ok',
        'system': {
            'os': 'Ubuntu 22.04 LTS',
            'python': '3.11.6',
            'database': 'SQLite 3.42.0 WAL',
            'memory_usage': f'{random.uniform(20, 80):.1f}%',
            'cpu_usage': f'{random.uniform(5, 60):.1f}%',
            'uptime': f'{random.randint(1, 365)}d {random.randint(0, 23)}h',
        },
    })), 200


@app.route('/admin/network')
def admin_network():
    """RABBIT HOLE — Fake network info."""
    return jsonify(noise_dict({
        'status': 'ok',
        'network': {
            'internal_ip': '10.0.0.15',
            'external_ip': '203.0.113.42',
            'gateway': '10.0.0.1',
            'dns': ['10.0.0.2', '10.0.0.3'],
            'vpn_status': 'connected',
            'firewall': 'enabled',
        },
    })), 200


@app.route('/admin/security')
def admin_security():
    """RABBIT HOLE — Fake security settings."""
    return jsonify(noise_dict({
        'status': 'ok',
        'security': {
            'waf_enabled': True,
            'smuggling_detection': True,
            'race_condition_mitigation': True,
            'rate_limiting': 'adaptive',
            'encryption_at_rest': True,
            'encryption_in_transit': True,
            'hsm_connected': True,
            'intrusion_detection': 'active',
        },
    })), 200


@app.route('/admin/backup')
def admin_backup():
    """RABBIT HOLE — Fake backup info."""
    return jsonify(noise_dict({
        'status': 'ok',
        'backup': {
            'last_backup': (datetime.now() - timedelta(hours=random.randint(1, 48))).isoformat(),
            'backup_size': f'{random.uniform(0.5, 10):.1f}GB',
            'backup_location': 's3://qa-backup-prod/vault/',
            'encryption': 'AES-256-GCM',
            'retention_days': 90,
        },
    })), 200


@app.route('/admin/maintenance')
def admin_maintenance():
    """RABBIT HOLE — Fake maintenance mode."""
    return jsonify(noise_dict({
        'status': 'ok',
        'maintenance_mode': False,
        'scheduled_maintenance': (datetime.now() + timedelta(days=random.randint(1, 30))).isoformat(),
        'maintenance_window': '02:00-04:00 UTC',
    })), 200


@app.route('/admin/restart', methods=['POST'])
def admin_restart():
    """RABBIT HOLE — Fake restart (does nothing)."""
    return jsonify(noise_dict({
        'status': 'ok',
        'message': 'Restart scheduled — requires dual authorization',
        'restart_id': str(uuid.uuid4())[:8],
    })), 200


# ============================================================
# RABBIT HOLE: /debug/* endpoints (3 endpoints)
# ============================================================

@app.route('/debug/')
def debug_index():
    """RABBIT HOLE — Fake debug index."""
    return jsonify(noise_dict({
        'status': 'ok',
        'debug_endpoints': ['/debug/pprof', '/debug/vars'],
        'warning': 'Debug endpoints are disabled in production',
    })), 200


@app.route('/debug/pprof')
def debug_pprof():
    """RABBIT HOLE — Fake pprof endpoint."""
    return jsonify(noise_dict({
        'status': 'ok',
        'profiles': ['goroutine', 'heap', 'threadcreate', 'block'],
        'message': 'Profiling disabled in production mode',
    })), 200


@app.route('/debug/vars')
def debug_vars():
    """RABBIT HOLE — Fake vars with decoy data."""
    return jsonify(noise_dict({
        'status': 'ok',
        'vars': {
            'flag_requests': random.randint(100, 9999),
            'vault_grants': random.randint(10, 500),
            'race_attempts': random.randint(0, 100),
            'smuggle_attempts': random.randint(0, 50),
            'internal_token_rotation_count': random.randint(1, 20),
        },
    })), 200


# ============================================================
# RABBIT HOLE: Monitoring endpoints (4 endpoints)
# ============================================================

@app.route('/metrics')
def metrics():
    """RABBIT HOLE — Fake Prometheus metrics."""
    fake_metrics = f"""# HELP vault_requests_total Total vault requests
# TYPE vault_requests_total counter
vault_requests_total{{endpoint="grant"}} {random.randint(100, 9999)}
vault_requests_total{{endpoint="flag"}} {random.randint(10, 500)}
vault_requests_total{{endpoint="status"}} {random.randint(1000, 99999)}
# HELP race_condition_attempts Race condition attempts detected
# TYPE race_condition_attempts counter
race_condition_attempts{{result="blocked"}} {random.randint(10, 200)}
race_condition_attempts{{result="mitigated"}} {random.randint(0, 50)}
# HELP flag_access_attempts Flag access attempts
# TYPE flag_access_attempts counter
flag_access_attempts{{result="denied"}} {random.randint(50, 500)}
flag_access_attempts{{result="encrypted"}} {random.randint(0, 10)}
"""
    return Response(fake_metrics, mimetype='text/plain'), 200


@app.route('/healthz')
def healthz():
    """RABBIT HOLE — Kubernetes-style health check."""
    return jsonify(noise_dict({
        'status': 'ok',
        'health': 'healthy',
    })), 200


@app.route('/readyz')
def readyz():
    """RABBIT HOLE — Kubernetes-style readiness check."""
    return jsonify(noise_dict({
        'status': 'ok',
        'ready': True,
        'dependencies': {
            'database': 'healthy',
            'cache': 'healthy',
            'hsm': 'healthy',
        },
    })), 200


@app.route('/livez')
def livez():
    """RABBIT HOLE — Kubernetes-style liveness check."""
    return jsonify(noise_dict({
        'status': 'ok',
        'alive': True,
    })), 200


# ============================================================
# RABBIT HOLE: File/config leak endpoints (2 endpoints)
# ============================================================

@app.route('/.env')
def dot_env():
    """RABBIT HOLE — Fake .env file (very tempting!)."""
    return jsonify(noise_dict({
        'status': 'ok',
        'env': {
            'APP_ENV': 'production',
            'DB_HOST': 'db.internal',
            'DB_PORT': '5432',
            'REDIS_URL': 'redis://cache.internal:6379',
            'SECRET_KEY': base64.b64encode(os.urandom(32)).decode(),  # FAKE
            'INTERNAL_TOKEN': f'qa-internal-{hashlib.md5(os.urandom(8)).hexdigest()[:12]}',  # FAKE
            'FLAG_XOR_KEY': base64.b64encode(os.urandom(5)).decode(),  # FAKE
            'RACE_WINDOW_MS': str(random.randint(50, 500)),  # FAKE
            'FLAG_TTL_MS': str(random.randint(5000, 30000)),  # FAKE
            'ADMIN_PASSWORD': hashlib.md5(os.urandom(8)).hexdigest(),  # FAKE
        },
    })), 200


@app.route('/config.yaml')
def config_yaml():
    """RABBIT HOLE — Fake YAML config."""
    fake_yaml = f"""# QA Vault Backend Configuration
server:
  host: 0.0.0.0
  port: 5002
  workers: 4

database:
  path: /var/lib/qa-challenge/challenge.db
  mode: WAL
  pool_size: 10

security:
  race_window_ms: {random.randint(50, 500)}
  flag_ttl_ms: {random.randint(5000, 30000)}
  smuggling_detection: enabled
  waf: enabled
  rate_limiting: adaptive

vault:
  encryption: AES-256-GCM
  key_rotation: 24h
  sealed: true
  shares: 5
  threshold: 3

# Internal service token (rotated weekly)
internal_token: qa-internal-{hashlib.md5(os.urandom(8)).hexdigest()[:12]}
"""
    return Response(fake_yaml, mimetype='text/yaml'), 200


# ============================================================
# RABBIT HOLE: API token/key endpoints (6 endpoints)
# ============================================================

@app.route('/api/tokens')
def api_tokens():
    """RABBIT HOLE — Returns decoy admin tokens."""
    with db_lock:
        conn = get_db()
        try:
            tokens = conn.execute('SELECT id, scope, expires_at, created_by FROM admin_tokens').fetchall()
            result = [dict(t) for t in tokens]
        except Exception:
            result = []
        conn.close()

    return jsonify(noise_dict({
        'status': 'ok',
        'tokens': result,
        'note': 'Token values are stored securely and not accessible via API',
    })), 200


@app.route('/api/keys')
def api_keys():
    """RABBIT HOLE — Returns decoy API keys."""
    with db_lock:
        conn = get_db()
        try:
            keys = conn.execute('SELECT key_name, permissions, rate_limit FROM api_keys').fetchall()
            result = [dict(k) for k in keys]
        except Exception:
            result = []
        conn.close()

    return jsonify(noise_dict({
        'status': 'ok',
        'api_keys': result,
    })), 200


@app.route('/api/permissions')
def api_permissions():
    """RABBIT HOLE — Fake permission matrix."""
    return jsonify(noise_dict({
        'status': 'ok',
        'permissions': {
            'user': ['read:own_profile', 'read:vault_status'],
            'operator': ['read:all_profiles', 'read:vault_metadata'],
            'admin': ['read:all', 'write:config', 'access:vault'],
            'superadmin': ['read:all', 'write:all', 'access:flag', 'grant:roles'],
        },
    })), 200


@app.route('/api/sessions')
def api_sessions():
    """RABBIT HOLE — Fake session list."""
    fake_sessions = []
    for _ in range(random.randint(2, 5)):
        fake_sessions.append({
            'session_id': str(uuid.uuid4())[:8],
            'user': random.choice(['admin', 'service-account', 'backup-operator']),
            'created': (datetime.now() - timedelta(minutes=random.randint(1, 1440))).isoformat(),
            'expires': (datetime.now() + timedelta(minutes=random.randint(1, 1440))).isoformat(),
            'ip': f'10.0.0.{random.randint(1, 254)}',
        })
    return jsonify(noise_dict({
        'status': 'ok',
        'active_sessions': fake_sessions,
    })), 200


@app.route('/api/webhook', methods=['GET', 'POST'])
def api_webhook():
    """RABBIT HOLE — Fake webhook."""
    if request.method == 'POST':
        return jsonify(noise_dict({
            'status': 'ok',
            'message': 'Webhook registered',
            'webhook_id': str(uuid.uuid4())[:8],
        })), 200
    return jsonify(noise_dict({
        'status': 'ok',
        'webhooks': [
            {'id': 'abc12345', 'url': 'https://internal.webhook/notify', 'events': ['vault.access', 'role.grant']},
        ],
    })), 200


@app.route('/api/callback', methods=['GET', 'POST'])
def api_callback():
    """RABBIT HOLE — Fake callback."""
    return jsonify(noise_dict({
        'status': 'ok',
        'message': 'Callback acknowledged',
        'callback_state': random.choice(['pending', 'processed', 'queued']),
    })), 200


@app.route('/api/notification', methods=['GET', 'POST'])
def api_notification():
    """RABBIT HOLE — Fake notification service."""
    return jsonify(noise_dict({
        'status': 'ok',
        'notifications': [
            {'type': 'security', 'message': 'Unusual vault access pattern detected', 'severity': 'info'},
            {'type': 'system', 'message': 'Key rotation completed successfully', 'severity': 'info'},
        ],
    })), 200


# ============================================================
# RABBIT HOLE: Additional decoy endpoints
# ============================================================

@app.route('/api/feature-flags')
def api_feature_flags():
    """RABBIT HOLE — Returns feature flags (decoy)."""
    with db_lock:
        conn = get_db()
        try:
            flags = conn.execute('SELECT flag_name, enabled, description, rollout_percent FROM feature_flags').fetchall()
            result = [dict(f) for f in flags]
        except Exception:
            result = []
        conn.close()

    return jsonify(noise_dict({
        'status': 'ok',
        'feature_flags': result,
    })), 200


@app.route('/api/rate-limits')
def api_rate_limits():
    """RABBIT HOLE — Returns decoy rate limit config."""
    with db_lock:
        conn = get_db()
        try:
            limits = conn.execute('SELECT endpoint, max_requests, window_seconds, burst_allowed FROM rate_limit_config').fetchall()
            result = [dict(l) for l in limits]
        except Exception:
            result = []
        conn.close()

    return jsonify(noise_dict({
        'status': 'ok',
        'rate_limits': result,
    })), 200


@app.route('/api/backup-codes')
def api_backup_codes():
    """RABBIT HOLE — Returns decoy backup codes."""
    with db_lock:
        conn = get_db()
        try:
            codes = conn.execute('SELECT code, used, user_id FROM backup_codes').fetchall()
            result = [dict(c) for c in codes]
        except Exception:
            result = []
        conn.close()

    return jsonify(noise_dict({
        'status': 'ok',
        'backup_codes': result,
    })), 200


@app.route('/api/vault/entries')
def vault_entries():
    """RABBIT HOLE — Returns vault entries (all fake flags and decoys)."""
    with db_lock:
        conn = get_db()
        try:
            entries = conn.execute('SELECT key, value, access_count, last_access FROM vault').fetchall()
            result = []
            for e in entries:
                entry = dict(e)
                # Mask "sensitive" values to look like they contain real data
                if 'flag' in e['key'].lower():
                    entry['value'] = e['value'][:8] + '...' + e['value'][-4:]  # Partially masked
                result.append(entry)
        except Exception:
            result = []
        conn.close()

    return jsonify(noise_dict({
        'status': 'ok',
        'entries': result,
        'total': len(result),
        'note': 'Sensitive values are masked — use decrypt endpoint for full access',
    })), 200


@app.route('/api/vault/rotate', methods=['POST'])
def vault_rotate():
    """RABBIT HOLE — Fake key rotation."""
    return jsonify(noise_dict({
        'status': 'ok',
        'message': 'Key rotation initiated',
        'rotation_id': str(uuid.uuid4())[:8],
        'estimated_completion': f'{random.randint(1, 30)} minutes',
    })), 200


@app.route('/api/vault/sync')
def vault_sync():
    """RABBIT HOLE — Fake sync status."""
    return jsonify(noise_dict({
        'status': 'ok',
        'sync_status': 'up_to_date',
        'last_sync': (datetime.now() - timedelta(seconds=random.randint(10, 3600))).isoformat(),
        'replication_lag': f'{random.randint(0, 500)}ms',
    })), 200


@app.route('/api/vault/wrap', methods=['POST'])
def vault_wrap():
    """RABBIT HOLE — Fake wrapping (like Vault's response wrapping)."""
    return jsonify(noise_dict({
        'status': 'ok',
        'wrap_info': {
            'token': str(uuid.uuid4()),
            'ttl': 300,
            'creation_time': datetime.now().isoformat(),
            'wrapped_accessor': hashlib.md5(os.urandom(8)).hexdigest(),
        },
    })), 200


@app.route('/api/vault/unwrap', methods=['POST'])
def vault_unwrap():
    """RABBIT HOLE — Fake unwrapping (always fails)."""
    return jsonify(noise_dict({
        'status': 'ok',
        'message': 'Wrapped token expired or invalid',
        'error_code': 'WRAP_TOKEN_EXPIRED',
    })), 200


@app.route('/api/vault/transit', methods=['POST'])
def vault_transit():
    """RABBIT HOLE — Fake transit encryption."""
    return jsonify(noise_dict({
        'status': 'ok',
        'message': 'Transit encryption not configured',
        'available_keys': ['audit-key', 'data-key'],
    })), 200


@app.route('/api/vault/identity')
def vault_identity():
    """RABBIT HOLE — Fake identity endpoint."""
    return jsonify(noise_dict({
        'status': 'ok',
        'identity': {
            'current_user': 'anonymous',
            'groups': [],
            'policies': ['default'],
            'auth_method': 'token',
        },
    })), 200


@app.route('/admin/tokens')
def admin_tokens():
    """RABBIT HOLE — Returns full decoy tokens (very tempting!)."""
    with db_lock:
        conn = get_db()
        try:
            tokens = conn.execute('SELECT * FROM admin_tokens').fetchall()
            result = [dict(t) for t in tokens]
        except Exception:
            result = []
        conn.close()

    return jsonify(noise_dict({
        'status': 'ok',
        'admin_tokens': result,
        'note': 'Tokens are one-time use and automatically expire',
    })), 200


@app.route('/admin/encryption')
def admin_encryption():
    """RABBIT HOLE — Returns full decoy encryption keys (extremely tempting!)."""
    with db_lock:
        conn = get_db()
        try:
            keys = conn.execute('SELECT * FROM encryption_keys').fetchall()
            result = [dict(k) for k in keys]
        except Exception:
            result = []
        conn.close()

    return jsonify(noise_dict({
        'status': 'ok',
        'encryption_keys': result,
    })), 200


@app.route('/admin/audit')
def admin_audit():
    """RABBIT HOLE — Returns decoy audit trail."""
    with db_lock:
        conn = get_db()
        try:
            entries = conn.execute('SELECT * FROM audit_trail ORDER BY timestamp DESC LIMIT 20').fetchall()
            result = [dict(e) for e in entries]
        except Exception:
            result = []
        conn.close()

    return jsonify(noise_dict({
        'status': 'ok',
        'audit_trail': result,
    })), 200


@app.route('/admin/features')
def admin_features():
    """RABBIT HOLE — Returns feature flags (suggests smuggling protection is on)."""
    with db_lock:
        conn = get_db()
        try:
            flags = conn.execute('SELECT * FROM feature_flags').fetchall()
            result = [dict(f) for f in flags]
        except Exception:
            result = []
        conn.close()

    return jsonify(noise_dict({
        'status': 'ok',
        'feature_flags': result,
    })), 200


@app.route('/internal/ping')
def internal_ping():
    """RABBIT HOLE — Fake internal health check."""
    return jsonify(noise_dict({
        'status': 'ok',
        'pong': True,
        'internal': True,
        'service': 'qa-vault-backend',
    })), 200


@app.route('/internal/metrics')
def internal_metrics():
    """RABBIT HOLE — Fake internal metrics with decoy data."""
    return jsonify(noise_dict({
        'status': 'ok',
        'metrics': {
            'race_window_ms': random.randint(50, 500),  # FAKE
            'flag_ttl_ms': random.randint(5000, 30000),  # FAKE
            'internal_token_last_rotation': (datetime.now() - timedelta(hours=random.randint(1, 72))).isoformat(),
            'xor_key_version': random.randint(1, 10),
            'smuggling_blocks_today': random.randint(0, 50),
            'successful_grants_today': random.randint(0, 5),
        },
    })), 200


@app.route('/internal/config')
def internal_config():
    """RABBIT HOLE — Fake internal config (very tempting for CTF players)."""
    return jsonify(noise_dict({
        'status': 'ok',
        'internal_config': {
            'service_mesh': 'istio',
            'sidecar_injection': True,
            'mtls_enabled': True,
            'smuggling_headers': ['X-Internal-Token', 'X-Real-Source', 'X-Bypass-WAF'],  # Real but not enough
            'token_format': 'uuid-v4',  # LIE — it's a custom format
            'key_derivation': 'HKDF-SHA256',  # LIE — it's MD5
            'race_detection_sensitivity': 'high',
            'flag_encryption': 'AES-256-GCM',  # LIE — it's XOR
        },
    })), 200


@app.route('/api/v2/grant', methods=['POST'])
def v2_grant():
    """RABBIT HOLE — Fake v2 grant API (returns different decoy data)."""
    return jsonify(noise_dict({
        'status': 'ok',
        'message': 'v2 grant API — requires OAuth2 bearer token',
        'auth_url': 'https://auth.internal/oauth2/token',
        'scopes_required': ['admin:grant', 'vault:write'],
    })), 200


@app.route('/api/v2/flag')
def v2_flag():
    """RABBIT HOLE — Fake v2 flag API."""
    return jsonify(noise_dict({
        'status': 'ok',
        'message': 'v2 flag API — requires signed JWT with admin claims',
        'flag': fake_flag(),  # DECOY flag!
    })), 200


@app.route('/swagger.json')
def swagger():
    """RABBIT HOLE — Fake Swagger spec."""
    return jsonify(noise_dict({
        'openapi': '3.0.0',
        'info': {'title': 'QA Vault API', 'version': '3.0.0'},
        'paths': {
            '/api/vault/grant': {'post': {'summary': 'Request role elevation', 'deprecated': True}},
            '/api/v2/grant': {'post': {'summary': 'v2 Role elevation (OAuth2)'}},
            '/admin/vault/flag': {'get': {'summary': 'Get flag (requires admin + MFA)'}},
        },
    })), 200


@app.route('/version')
def version():
    """RABBIT HOLE — Version info with decoy hints."""
    return jsonify(noise_dict({
        'status': 'ok',
        'version': '3.0.0-rc3',
        'build_hash': hashlib.sha256(os.urandom(32)).hexdigest()[:12],
        'go_version': 'go1.21.5',  # Confusing — this is Python not Go
        'vault_version': '1.15.4',
    })), 200


@app.route('/robots.txt')
def robots_txt():
    """RABBIT HOLE — Robots.txt with tempting disallowed paths."""
    content = """User-agent: *
Disallow: /admin/
Disallow: /internal/
Disallow: /debug/
Disallow: /.env
Disallow: /config.yaml
Disallow: /api/tokens
Disallow: /api/keys
Disallow: /api/vault/decrypt
Disallow: /api/vault/export

# Sitemap: https://vault.qa-ctf.internal/sitemap.xml
"""
    return Response(content, mimetype='text/plain'), 200


@app.route('/sitemap.xml')
def sitemap():
    """RABBIT HOLE — Fake sitemap."""
    content = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://vault.qa-ctf.internal/api/health</loc></url>
  <url><loc>https://vault.qa-ctf.internal/api/vault/status</loc></url>
  <url><loc>https://vault.qa-ctf.internal/admin/dashboard</loc></url>
</urlset>
"""
    return Response(content, mimetype='application/xml'), 200


# ============================================================
# Catch-all — Make ALL routes return 200 with noise
# ============================================================

@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'])
def catch_all(path):
    """Catch-all: returns 200 OK with plausible noise for any unmatched route."""
    # More fake responses for common CTF probing paths
    fake_responses = {
        'api/v1/flag': {'flag': fake_flag(), 'source': 'v1_deprecated_api'},
        'flag': {'flag': fake_flag(), 'note': 'This is a test flag'},
        'admin/flag': {'flag': fake_flag(), 'message': 'Flag access requires elevated role'},
        'secret': {'secret': hashlib.sha256(os.urandom(32)).hexdigest(), 'type': 'opaque'},
        'api/internal': {'message': 'Internal API access denied', 'required': 'VPN connection'},
    }

    # Check if path matches any known fake responses
    for key, value in fake_responses.items():
        if key in path.lower():
            return jsonify(noise_dict({'status': 'ok', **value})), 200

    # Default: return generic 200 OK with noise
    return jsonify(noise_dict({
        'status': 'ok',
        'message': 'Request processed',
        'path': f'/{path}',
    })), 200


# ============================================================
# INIT
# ============================================================
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=False, threaded=True)
