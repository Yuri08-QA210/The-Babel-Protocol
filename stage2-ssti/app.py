"""
QA CTF Challenge — Stage 2: Secret Key Recovery + SSTI/RCE
============================================================
EXTREMELY FRUSTRATING edition with 70+ rabbit holes.

Attack chain:
  1. Get SECRET_KEY_PART1 via XXE/SSRF from Stage 1 internal service
  2. Get SECRET_KEY_PART2 via SQL injection or database access (config_store table)
  3. Compute REAL_SECRET_KEY = SHA256(part1 + part2)
  4. Forge Flask session cookie with malicious username (SSTI payload)
  5. SSTI bypass: |map(attribute=var) with string-built dunder names
     - Input blacklist blocks __class__, |attr, [], etc.
     - SafeRenderExtension blocks jinja_env.getattr for dunders
     - BUT |map(attribute=...) uses operator.attrgetter → bypasses extension
     - AND "__cl"~"ass__" bypasses __\\w+__ regex (split dunder names)

Design principles:
  - ALL responses return 200 OK with noise — NEVER leak errors
  - Random delay 20-300ms on every request
  - Session expires in 15 minutes
  - Tool detection → garbage response
  - 70+ rabbit hole endpoints with fake flags and misleading data
  - Flag format: QA{sst1_f0rg3d_s3ss10n_rc3_ch41n_byp4ss}
"""

import os
import re
import time
import random
import sqlite3
import hashlib
import threading
import json
import uuid
from functools import wraps
from collections import defaultdict
from flask import (
    Flask, request, jsonify, Response, make_response,
    render_template_string, redirect, url_for, session
)
from itsdangerous import URLSafeTimedSerializer, BadSignature
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta

app = Flask(__name__)

# ============================================================
# CRITICAL: Key Derivation — NO SHORTCUT
# ============================================================
# The old code had: REAL_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', ...)
# which was a shortcut — players could just read .env.
#
# NEW: The actual session signing key is SHA256(part1 + part2).
# part1 comes from the internal service (SSRF from Stage 1).
# part2 comes from the database config_store table (SQLi or DB access).
# Players MUST compute SHA256 — concatenating the parts gives wrong key.

SECRET_KEY_PART1 = os.environ.get('SECRET_KEY_PART1', 'qa-s3cr3t-k3y-p4rt1-')
SECRET_KEY_PART2 = os.environ.get('SECRET_KEY_PART2', 'p4rt2-fr0m-d4t4b4s3!')

# The REAL Flask secret key — SHA256 hash, not the raw concatenation
REAL_SECRET_KEY = hashlib.sha256(
    (SECRET_KEY_PART1 + SECRET_KEY_PART2).encode()
).hexdigest()
app.config['SECRET_KEY'] = REAL_SECRET_KEY

# Also store the (WRONG) concatenation as a decoy — if players try
# simple concatenation they get this, which is NOT the signing key
DECOY_CONCAT_KEY = SECRET_KEY_PART1 + SECRET_KEY_PART2

STAGE2_FLAG = os.environ.get('STAGE2_FLAG', 'QA{sst1_f0rg3d_s3ss10n_rc3_ch41n_byp4ss}')
DB_PATH = os.environ.get('DB_PATH', '/var/lib/qa-challenge/challenge.db')
SESSION_LIFETIME = int(os.environ.get('SESSION_LIFETIME_MINUTES', '15'))
INTERNAL_TOKEN = os.environ.get('INTERNAL_TOKEN', 'qa-internal-token-2024')

# ============================================================
# Fake "FLASK_SECRET_KEY" env var — INTERMEDIATE, not the real key
# ============================================================
# This is intentionally misleading. If a player reads the env and finds
# FLASK_SECRET_KEY, they get the CONCATENATION of part1+part2, which
# is NOT the actual signing key. The real key is SHA256(part1+part2).
# We set this for the docker-compose compatibility, but it's a trap.
os.environ['FLASK_SECRET_KEY'] = DECOY_CONCAT_KEY  # DECOY!

# ============================================================
# Rate Limiting
# ============================================================
RATE_LIMIT_STORE = defaultdict(list)
RATE_LOCK = threading.Lock()

def check_rate_limit(ip, endpoint, max_requests=10, window_seconds=30):
    now = time.time()
    key = f"{ip}:{endpoint}"
    with RATE_LOCK:
        RATE_LIMIT_STORE[key] = [t for t in RATE_LIMIT_STORE[key] if now - t < window_seconds]
        if len(RATE_LIMIT_STORE[key]) >= max_requests:
            return False
        RATE_LIMIT_STORE[key].append(now)
        return True


# ============================================================
# Database Setup — Many Decoy Tables
# ============================================================
db_lock = threading.Lock()

def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db_lock:
        conn = get_db()
        c = conn.cursor()

        # ---- REAL tables ----
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            bio TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            session_token TEXT,
            avatar_url TEXT DEFAULT '',
            email TEXT DEFAULT '',
            last_login TIMESTAMP
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS config_store (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            description TEXT DEFAULT ''
        )''')

        # ---- DECOY tables (18!) ----
        c.execute('''CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY,
            key_name TEXT,
            key_value TEXT,
            permissions TEXT,
            created_at TEXT,
            expires_at TEXT
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            user_id INTEGER,
            timestamp TEXT,
            details TEXT,
            ip_address TEXT
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS feature_flags (
            flag_name TEXT PRIMARY KEY,
            enabled INTEGER,
            description TEXT,
            updated_by TEXT
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY,
            session_id TEXT UNIQUE,
            user_id INTEGER,
            created_at TEXT,
            expires_at TEXT,
            data TEXT
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS tokens (
            id INTEGER PRIMARY KEY,
            token_value TEXT UNIQUE,
            token_type TEXT,
            user_id INTEGER,
            expires_at TEXT,
            revoked INTEGER DEFAULT 0
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE,
            description TEXT,
            level INTEGER DEFAULT 0
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS oauth_clients (
            id INTEGER PRIMARY KEY,
            client_id TEXT UNIQUE,
            client_secret TEXT,
            redirect_uri TEXT,
            name TEXT
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS webhook_configs (
            id INTEGER PRIMARY KEY,
            url TEXT,
            event_type TEXT,
            secret TEXT,
            enabled INTEGER DEFAULT 1
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS encryption_keys (
            id INTEGER PRIMARY KEY,
            key_id TEXT UNIQUE,
            key_value TEXT,
            algorithm TEXT,
            created_at TEXT,
            active INTEGER DEFAULT 1
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS vault_entries (
            id INTEGER PRIMARY KEY,
            entry_name TEXT,
            entry_value TEXT,
            category TEXT,
            encrypted INTEGER DEFAULT 1
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS backup_codes (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            code TEXT,
            used INTEGER DEFAULT 0,
            created_at TEXT
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS rate_limits (
            id INTEGER PRIMARY KEY,
            endpoint TEXT,
            max_requests INTEGER,
            window_seconds INTEGER,
            ip_range TEXT
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS admin_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            content TEXT,
            author TEXT,
            created_at TEXT,
            priority TEXT DEFAULT 'normal'
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS system_config (
            key TEXT PRIMARY KEY,
            value TEXT,
            type TEXT DEFAULT 'string',
            description TEXT
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS cache_entries (
            id INTEGER PRIMARY KEY,
            cache_key TEXT UNIQUE,
            cache_value TEXT,
            expires_at TEXT,
            tags TEXT
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS deployment_config (
            id INTEGER PRIMARY KEY,
            env_name TEXT,
            config_key TEXT,
            config_value TEXT,
            encrypted INTEGER DEFAULT 0
        )''')

        c.execute('''CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY,
            secret_name TEXT UNIQUE,
            secret_value TEXT,
            secret_type TEXT,
            rotation_days INTEGER DEFAULT 90
        )''')

        # ---- Insert REAL config ----
        c.execute('INSERT OR IGNORE INTO config_store (key, value, description) VALUES (?, ?, ?)',
                  ('flask_secret_part2', SECRET_KEY_PART2,
                   'Second part of Flask session signing key'))
        c.execute('INSERT OR IGNORE INTO config_store (key, value, description) VALUES (?, ?, ?)',
                  ('key_derivation', 'sha256_concat',
                   'Method used to derive the real signing key'))

        # ---- Insert DECOY config entries ----
        decoy_configs = [
            ('jwt_secret', hashlib.md5(os.urandom(16)).hexdigest(), 'JWT signing secret'),
            ('encryption_key', hashlib.sha256(os.urandom(16)).hexdigest(), 'AES-256 encryption key'),
            ('api_gateway_token', hashlib.md5(os.urandom(16)).hexdigest(), 'API gateway auth token'),
            ('flag', f'QA{{{hashlib.md5(os.urandom(8)).hexdigest()[:12]}}}', 'Stage flag'),
            ('admin_password_hash', generate_password_hash('decoy123'), 'Admin password hash'),
            ('database_url', 'postgresql://admin:fake@db.internal:5432/qa', 'Database URL'),
            ('redis_url', 'redis://redis.internal:6379/0', 'Redis URL'),
            ('s3_bucket', 'qa-ctf-flags-bucket', 'S3 bucket for flags'),
            ('vault_addr', 'http://vault.internal:8200', 'Vault address'),
            ('session_secret', hashlib.sha256(os.urandom(16)).hexdigest(), 'Session signing secret'),
            ('csrf_secret', hashlib.md5(os.urandom(16)).hexdigest(), 'CSRF protection secret'),
            ('oauth_client_secret', hashlib.sha256(os.urandom(16)).hexdigest(), 'OAuth2 client secret'),
        ]
        for key, value, desc in decoy_configs:
            c.execute('INSERT OR IGNORE INTO config_store (key, value, description) VALUES (?, ?, ?)',
                      (key, value, desc))

        # ---- Insert DECOY API keys ----
        decoy_api_keys = [
            ('internal_read', hashlib.md5(os.urandom(8)).hexdigest(), 'read', '2024-01-01', '2025-01-01'),
            ('admin_access', hashlib.md5(os.urandom(8)).hexdigest(), 'admin', '2024-01-01', '2025-01-01'),
            ('service_token', hashlib.sha256(os.urandom(16)).hexdigest(), 'service', '2024-01-01', '2025-01-01'),
            ('monitoring_key', hashlib.md5(os.urandom(8)).hexdigest(), 'monitoring', '2024-01-01', '2025-01-01'),
            ('deploy_key', hashlib.sha256(os.urandom(16)).hexdigest(), 'deploy', '2024-01-01', '2025-01-01'),
        ]
        for name, val, perm, created, expires in decoy_api_keys:
            c.execute('INSERT OR IGNORE INTO api_keys (key_name, key_value, permissions, created_at, expires_at) VALUES (?, ?, ?, ?, ?)',
                      (name, val, perm, created, expires))

        # ---- Insert DECOY encryption keys ----
        decoy_enc_keys = [
            ('ek-001', hashlib.sha256(os.urandom(16)).hexdigest(), 'AES-256-GCM', '2024-01-01', 1),
            ('ek-002', hashlib.sha256(os.urandom(16)).hexdigest(), 'AES-256-CBC', '2024-02-01', 0),
            ('ek-003', hashlib.sha512(os.urandom(32)).hexdigest(), 'ChaCha20', '2024-03-01', 1),
        ]
        for kid, kval, algo, created, active in decoy_enc_keys:
            c.execute('INSERT OR IGNORE INTO encryption_keys (key_id, key_value, algorithm, created_at, active) VALUES (?, ?, ?, ?, ?)',
                      (kid, kval, algo, created, active))

        # ---- Insert DECOY vault entries ----
        decoy_vault = [
            ('flask_secret', hashlib.sha256(os.urandom(16)).hexdigest(), 'application', 1),
            ('db_password', hashlib.md5(os.urandom(8)).hexdigest(), 'database', 1),
            ('stage2_flag', f'QA{{{hashlib.md5(os.urandom(8)).hexdigest()[:16]}}}', 'flag', 1),
            ('internal_token', hashlib.sha256(os.urandom(16)).hexdigest(), 'auth', 1),
        ]
        for name, val, cat, enc in decoy_vault:
            c.execute('INSERT OR IGNORE INTO vault_entries (entry_name, entry_value, category, encrypted) VALUES (?, ?, ?, ?)',
                      (name, val, cat, enc))

        # ---- Insert DECOY secrets ----
        decoy_secrets = [
            ('flask_session_key', hashlib.sha256(os.urandom(16)).hexdigest(), 'session', 90),
            ('jwt_signing_key', hashlib.sha256(os.urandom(16)).hexdigest(), 'jwt', 30),
            ('admin_backdoor', f'QA{{{hashlib.md5(os.urandom(8)).hexdigest()[:12]}}}', 'flag', 365),
            ('smuggling_key', hashlib.sha256(os.urandom(16)).hexdigest(), 'http', 180),
        ]
        for name, val, stype, rot in decoy_secrets:
            c.execute('INSERT OR IGNORE INTO secrets (secret_name, secret_value, secret_type, rotation_days) VALUES (?, ?, ?, ?)',
                      (name, val, stype, rot))

        # ---- Insert DECOY feature flags ----
        decoy_flags = [
            ('ssti_protection', 1, 'Enable SSTI protection layer', 'admin'),
            ('waf_mode', 1, 'Enable WAF mode', 'admin'),
            ('debug_mode', 0, 'Debug mode disabled', 'admin'),
            ('sql_injection_protection', 1, 'SQL injection protection', 'admin'),
            ('rate_limiting', 1, 'Rate limiting enabled', 'system'),
            ('session_encryption', 0, 'Session encryption (beta)', 'admin'),
            ('new_auth_flow', 1, 'New authentication flow', 'dev'),
        ]
        for fname, enabled, desc, by in decoy_flags:
            c.execute('INSERT OR IGNORE INTO feature_flags VALUES (?, ?, ?, ?)',
                      (fname, enabled, desc, by))

        # ---- Insert DECOY admin notes (misleading hints) ----
        decoy_notes = [
            ('Secret Key Location', 'The Flask secret key is stored in the FLASK_SECRET_KEY environment variable. Just read /proc/self/environ to get it.', 'admin', '2024-01-15', 'high'),
            ('SSTI Bypass', 'The SSTI filter blocks everything. The only way in is through the |attr filter with hex encoding. Try |attr("\\x5f\\x5fclass\\x5f\\x5f").', 'dev', '2024-01-20', 'high'),
            ('Database Access', 'The config_store table has all the secrets. Use the SQLi in /api/search to extract them. The parameter is "q".', 'admin', '2024-02-01', 'normal'),
            ('Session Forging', 'Flask uses itsdangerous for session cookies. The signing key is the FLASK_SECRET_KEY env var. No hash derivation needed.', 'dev', '2024-02-10', 'normal'),
            ('OAuth Bypass', 'The OAuth implementation has a redirect_uri bypass. Use /api/oauth/callback?redirect_uri=http://evil.com to steal tokens.', 'security', '2024-02-15', 'low'),
            ('Race Condition', 'There might be a race condition in the session creation. Try sending concurrent requests to /login.', 'dev', '2024-03-01', 'low'),
            ('Backup Codes', 'The 2FA backup codes are stored in plain text in the backup_codes table. SQL injection in /api/search can reveal them.', 'security', '2024-03-05', 'normal'),
        ]
        for title, content, author, created, priority in decoy_notes:
            c.execute('INSERT OR IGNORE INTO admin_notes (title, content, author, created_at, priority) VALUES (?, ?, ?, ?, ?)',
                      (title, content, author, created, priority))

        # ---- Insert DECOY deployment configs ----
        decoy_deploy = [
            ('production', 'SECRET_KEY', hashlib.sha256(os.urandom(16)).hexdigest(), 1),
            ('production', 'DATABASE_URL', 'postgresql://prod:pass@db:5432/qa', 0),
            ('staging', 'SECRET_KEY', hashlib.md5(os.urandom(8)).hexdigest(), 0),
            ('staging', 'FLAG', f'QA{{{hashlib.md5(os.urandom(8)).hexdigest()[:12]}}}', 1),
            ('development', 'SECRET_KEY', 'dev-secret-key-change-me', 0),
            ('development', 'DEBUG', 'True', 0),
        ]
        for env, key, val, enc in decoy_deploy:
            c.execute('INSERT OR IGNORE INTO deployment_config (env_name, config_key, config_value, encrypted) VALUES (?, ?, ?, ?)',
                      (env, key, val, enc))

        # ---- Insert DECOY system configs ----
        decoy_sys = [
            ('auth_backend', 'internal', 'string', 'Authentication backend type'),
            ('session_store', 'redis', 'string', 'Session storage backend'),
            ('cache_driver', 'redis', 'string', 'Cache driver'),
            ('mail_driver', 'smtp', 'string', 'Mail driver'),
            ('queue_driver', 'redis', 'string', 'Queue driver'),
            ('hash_algorithm', 'bcrypt', 'string', 'Password hash algorithm'),
        ]
        for key, val, typ, desc in decoy_sys:
            c.execute('INSERT OR IGNORE INTO system_config (key, value, type, description) VALUES (?, ?, ?, ?)',
                      (key, val, typ, desc))

        # ---- Insert DECOY OAuth clients ----
        c.execute('INSERT OR IGNORE INTO oauth_clients (client_id, client_secret, redirect_uri, name) VALUES (?, ?, ?, ?)',
                  ('qa-portal-client', hashlib.sha256(os.urandom(16)).hexdigest(),
                   'http://localhost/callback', 'QA Portal Client'))

        # ---- Insert DECOY webhooks ----
        c.execute('INSERT OR IGNORE INTO webhook_configs (url, event_type, secret, enabled) VALUES (?, ?, ?, ?)',
                  ('http://hooks.internal/notify', 'user.login', hashlib.sha256(os.urandom(16)).hexdigest(), 1))

        # ---- Insert DECOY cache entries ----
        for i in range(5):
            c.execute('INSERT OR IGNORE INTO cache_entries (cache_key, cache_value, expires_at, tags) VALUES (?, ?, ?, ?)',
                      (f'cache:{hashlib.md5(os.urandom(4)).hexdigest()[:8]}',
                       json.dumps({'data': f'item_{i}', 'meta': {'v': 1}}),
                       datetime.utcnow().isoformat(), 'temp'))

        # ---- Default users ----
        c.execute('INSERT OR IGNORE INTO users (username, password_hash, role, bio, email) VALUES (?, ?, ?, ?, ?)',
                  ('guest', generate_password_hash('guest123'), 'user',
                   'Hello, I am a guest user!', 'guest@qa-ctf.local'))
        c.execute('INSERT OR IGNORE INTO users (username, password_hash, role, bio, email) VALUES (?, ?, ?, ?, ?)',
                  ('admin', generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'changeme')),
                   'admin', 'System Administrator', 'admin@qa-ctf.local'))
        c.execute('INSERT OR IGNORE INTO users (username, password_hash, role, bio, email) VALUES (?, ?, ?, ?, ?)',
                  ('service', generate_password_hash(hashlib.md5(os.urandom(8)).hexdigest()),
                   'service', 'Service Account', 'service@qa-ctf.local'))

        # ---- Insert DECOY audit log entries ----
        audit_entries = [
            ('user.login', 1, '2024-01-15T10:30:00', 'User logged in from 10.0.0.1', '10.0.0.1'),
            ('config.update', 2, '2024-01-15T11:00:00', 'Updated config: flask_secret_part2', '10.0.0.2'),
            ('admin.access', 2, '2024-01-15T12:00:00', 'Admin panel accessed', '10.0.0.2'),
            ('api.key_generated', 2, '2024-01-16T09:00:00', 'Generated API key: internal_read', '10.0.0.2'),
            ('flag.access', 2, '2024-01-17T14:00:00', 'Flag endpoint accessed from internal', '127.0.0.1'),
            ('session.forge_attempt', None, '2024-01-18T16:00:00', 'Invalid session cookie detected', '10.0.0.99'),
            ('ssti.attempt', None, '2024-01-19T08:00:00', 'SSTI pattern detected in username', '10.0.0.99'),
        ]
        for action, uid, ts, details, ip in audit_entries:
            c.execute('INSERT OR IGNORE INTO audit_log (action, user_id, timestamp, details, ip_address) VALUES (?, ?, ?, ?, ?)',
                      (action, uid, ts, details, ip))

        # ---- Insert DECOY permissions ----
        decoy_perms = [
            ('read_config', 'Read configuration values', 1),
            ('write_config', 'Write configuration values', 2),
            ('admin_access', 'Access admin panel', 3),
            ('flag_access', 'Access flag endpoints', 4),
            ('debug_access', 'Access debug endpoints', 2),
        ]
        for name, desc, level in decoy_perms:
            c.execute('INSERT OR IGNORE INTO permissions (name, description, level) VALUES (?, ?, ?)',
                      (name, desc, level))

        # ---- Insert DECOY rate limit configs ----
        decoy_rates = [
            ('/api/search', 100, 60, '*'),
            ('/api/auth/*', 20, 60, '*'),
            ('/login', 5, 300, '*'),
            ('/profile', 60, 60, '*'),
        ]
        for endpoint, maxr, window, ipr in decoy_rates:
            c.execute('INSERT OR IGNORE INTO rate_limits (endpoint, max_requests, window_seconds, ip_range) VALUES (?, ?, ?, ?)',
                      (endpoint, maxr, window, ipr))

        # ---- Insert DECOY tokens ----
        c.execute('INSERT OR IGNORE INTO tokens (token_value, token_type, user_id, expires_at, revoked) VALUES (?, ?, ?, ?, ?)',
                  (hashlib.sha256(os.urandom(16)).hexdigest(), 'access', 2,
                   '2025-12-31T23:59:59', 0))
        c.execute('INSERT OR IGNORE INTO tokens (token_value, token_type, user_id, expires_at, revoked) VALUES (?, ?, ?, ?, ?)',
                  (hashlib.sha256(os.urandom(16)).hexdigest(), 'refresh', 2,
                   '2025-12-31T23:59:59', 0))
        c.execute('INSERT OR IGNORE INTO tokens (token_value, token_type, user_id, expires_at, revoked) VALUES (?, ?, ?, ?, ?)',
                  (f'QA{{{hashlib.md5(os.urandom(8)).hexdigest()[:12]}}}', 'flag', 0,
                   '2024-12-31T23:59:59', 1))

        conn.commit()
        conn.close()


# ============================================================
# SSTI Blacklist — HEAVY
# ============================================================
SSTI_BLACKLIST_PATTERNS = [
    # Dunder attributes
    r'__class__', r'__mro__', r'__subclasses__', r'__bases__',
    r'__init__', r'__globals__', r'__builtins__', r'__import__',
    r'__dict__', r'__code__', r'__closure__', r'__func__',
    # Catch-all for any __word__ pattern
    r'__\w+__',
    # Bracket notation
    r'\[', r'\]',
    # Dangerous functions
    r'os\.', r'subprocess', r'eval\s*\(', r'exec\s*\(',
    r'compile\s*\(', r'open\s*\(', r'__import__',
    r'getattr\s*\(', r'setattr\s*\(',
    # |attr filter (blocks obj|attr('x'))
    r'\|\s*attr',
    # Request/config/self access
    r'request\.', r'\bconfig\b', r'\bself\.',
    # Common Jinja2 gadgets
    r'\blipsum\b', r'\bcycler\b', r'\bjoiner\b', r'\bnamespace\b',
    # Flask helpers
    r'url_for', r'get_flashed_messages',
]

def check_ssti_blacklist(value):
    """Check if value contains SSTI patterns. Returns True if BLOCKED."""
    for pattern in SSTI_BLACKLIST_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE | re.DOTALL):
            return True
    return False


# ============================================================
# SafeRenderExtension — Runtime Jinja2 Protection
# ============================================================
class SafeRenderExtension:
    """
    Patches jinja_env.getattr and getitem to block dunder access.

    HOWEVER, this does NOT block |map(attribute=...) because that
    uses operator.attrgetter() internally, which calls Python's
    built-in getattr() directly, bypassing jinja_env.getattr.

    This is the INTENDED bypass for the SSTI challenge.
    """
    BLOCKED_ATTRS = frozenset([
        '__class__', '__mro__', '__subclasses__', '__bases__',
        '__init__', '__globals__', '__builtins__', '__dict__',
        '__code__', '__closure__', '__func__', '__import__',
        '__name__', '__module__',
    ])

    def __init__(self, app):
        self.app = app
        original_getattr = app.jinja_env.getattr

        def safe_getattr(obj, attr):
            if attr in self.BLOCKED_ATTRS:
                # Return misleading value instead of raising error
                return f"<blocked {attr}>"
            return original_getattr(obj, attr)

        app.jinja_env.getattr = safe_getattr

        original_getitem = app.jinja_env.getitem

        def safe_getitem(obj, item):
            if isinstance(item, str) and item in self.BLOCKED_ATTRS:
                return f"<blocked {item}>"
            return original_getitem(obj, item)

        app.jinja_env.getitem = safe_getitem


# ============================================================
# Anti-Tool Detection
# ============================================================
BLOCKED_USER_AGENTS = [
    'sqlmap', 'nikto', 'dirb', 'dirbuster', 'gobuster',
    'wfuzz', 'burpsuite', 'burp', 'nmap', 'masscan',
    'hydra', 'medusa', 'zap', 'arachni', 'w3af',
    'acunetix', 'nessus', 'openvas', 'wpscan', 'ffuf',
    'feroxbuster', 'httpx', 'nuclei',
]

def is_tool_request():
    """Detect CTF/security tools — return garbage if detected."""
    ua = request.headers.get('User-Agent', '').lower()
    for tool in BLOCKED_USER_AGENTS:
        if tool in ua:
            return True
    if request.headers.get('X-Scanner'):
        return True
    if request.headers.get('X-Forwarded-Scan'):
        return True
    if request.headers.get('X-Burp'):
        return True
    return False


# ============================================================
# Helper Functions
# ============================================================
def fake_response():
    """Generate a generic 200 response with random noise."""
    return jsonify({
        'status': 'ok',
        'message': 'Request processed',
        'ref': str(uuid.uuid4()),
        'ts': int(time.time()),
        'noise': hashlib.md5(os.urandom(16)).hexdigest()[:8],
        'meta': {
            'version': '2.3.1',
            'region': random.choice(['us-east-1', 'eu-west-2', 'ap-south-1']),
            'latency_ms': random.randint(10, 200),
        }
    }), 200


def fake_flag_response():
    """Return a response with fake QA{} flags mixed in with noise."""
    decoys = [f"QA{{{hashlib.md5(os.urandom(8)).hexdigest()[:12]}}}" for _ in range(random.randint(3, 6))]
    return jsonify({
        'status': 'ok',
        'message': 'Request processed',
        'ref': str(uuid.uuid4()),
        'ts': int(time.time()),
        'noise': hashlib.md5(os.urandom(16)).hexdigest()[:8],
        'data': {
            'entries': [
                {'id': i, 'value': f, 'type': random.choice(['cache', 'temp', 'config', 'log', 'flag', 'secret'])}
                for i, f in enumerate(decoys)
            ],
            'total': len(decoys),
            'offset': random.randint(0, 100),
        }
    }), 200


def noise_headers(response):
    """Add noise headers to response."""
    response.headers['X-Request-Id'] = str(uuid.uuid4())
    response.headers['X-Service-Id'] = 'qa-portal-' + str(uuid.uuid4())[:8]
    response.headers['X-Region'] = random.choice(['us-east-1', 'eu-west-2', 'ap-south-1'])
    response.headers['X-Trace-Id'] = hashlib.md5(os.urandom(16)).hexdigest()
    response.headers['X-RateLimit-Remaining'] = str(random.randint(1, 100))
    response.headers['X-Cache-Status'] = random.choice(['HIT', 'MISS', 'STALE'])
    return response


def require_auth(f):
    """Decorator: require valid session."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'status': 'ok', 'message': 'Request processed',
                          'ref': str(uuid.uuid4())}), 200
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    """Decorator: require admin role (but always returns 200)."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            return fake_response()
        return f(*args, **kwargs)
    return decorated


# ============================================================
# Middleware — Delay, Tool Detection, Session Expiry
# ============================================================
@app.before_request
def before_request_func():
    """Random delay + tool detection + session expiry check."""
    # Random delay 20-300ms
    time.sleep(random.uniform(0.02, 0.3))

    # Tool detection → garbage
    if is_tool_request():
        return jsonify({
            'status': 'ok',
            'message': 'Request processed',
            'ref': str(uuid.uuid4()),
            'ts': int(time.time()),
            'noise': hashlib.md5(os.urandom(16)).hexdigest()[:8]
        }), 200

    # Session expiry
    if 'user_id' in session:
        login_time = session.get('login_time', 0)
        if login_time and time.time() - login_time > SESSION_LIFETIME * 60:
            session.clear()


# ============================================================
# Error Handlers — ALWAYS 200 OK, NEVER leak errors
# ============================================================
@app.errorhandler(Exception)
def handle_exception(e):
    return fake_response()

@app.errorhandler(404)
def not_found(e):
    return fake_response()

@app.errorhandler(405)
def method_not_allowed(e):
    return fake_response()

@app.errorhandler(500)
def internal_error(e):
    return fake_response()

@app.errorhandler(400)
def bad_request(e):
    return fake_response()

@app.errorhandler(401)
def unauthorized(e):
    return fake_response()

@app.errorhandler(403)
def forbidden(e):
    return fake_response()


# ============================================================
# REAL ENDPOINTS
# ============================================================

@app.route('/')
def index():
    """Portal landing page — dark cyberpunk UI."""
    accept = request.headers.get('Accept', '')
    if 'application/json' in accept:
        resp = jsonify({
            'service': 'QA-User-Portal',
            'version': '2.3.1',
            'endpoints': {'/login': 'POST', '/register': 'POST', '/profile': 'GET'},
            'ref': str(uuid.uuid4()),
        })
        resp.headers['X-Debug-Mode'] = 'disabled'
        return noise_headers(resp)

    html = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Babel Protocol — Sign In</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#06080d;color:#c8d0dc;font-family:'Inter','Segoe UI',system-ui,-apple-system,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}
#bg-canvas{position:fixed;top:0;left:0;width:100%;height:100%;z-index:0;pointer-events:none}
@keyframes fadeIn{from{opacity:0;transform:translateY(16px)}to{opacity:1;transform:translateY(0)}}
.portal{width:100%;max-width:400px;padding:36px;background:rgba(14,18,27,.9);border:1px solid rgba(68,136,255,.08);border-radius:18px;position:relative;z-index:1;animation:fadeIn .5s ease-out;backdrop-filter:blur(12px)}
.portal::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,#4488ff,#2266dd);border-radius:18px 18px 0 0}
.brand{text-align:center;margin-bottom:28px}
.brand-name{font-size:1.5em;font-weight:700;letter-spacing:3px;background:linear-gradient(135deg,#4488ff,#2266dd);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:4px}
.brand-sub{font-size:.72em;color:#3e4858;letter-spacing:1.5px}
.form-group{margin-bottom:16px}
label{display:block;font-size:.7em;color:#4e5a6b;letter-spacing:1px;text-transform:uppercase;margin-bottom:5px;font-weight:500}
input[type=text],input[type=password]{width:100%;padding:10px 14px;background:rgba(6,8,13,.8);border:1px solid rgba(255,255,255,.05);border-radius:8px;color:#c8d0dc;font-size:.88em;outline:none;transition:border-color .3s}
input:focus{border-color:rgba(68,136,255,.3)}
.btn{width:100%;padding:11px;border-radius:8px;border:none;cursor:pointer;font-size:.85em;font-weight:600;letter-spacing:.5px;transition:all .3s}
.btn-primary{background:linear-gradient(135deg,#4488ff,#2266dd);color:#fff;margin-top:4px}
.btn-primary:hover{box-shadow:0 4px 20px rgba(68,136,255,.3);transform:translateY(-1px)}
.divider{text-align:center;margin:20px 0;color:#2e3646;font-size:.75em;letter-spacing:1.5px;position:relative}
.divider::before,.divider::after{content:'';position:absolute;top:50%;width:38%;height:1px;background:rgba(255,255,255,.04)}
.divider::before{left:0}.divider::after{right:0}
.register-link{text-align:center;font-size:.78em;color:#3e4858}
.register-link a{color:#4488ff;text-decoration:none;transition:color .3s}
.register-link a:hover{color:#6699ff}
.msg{text-align:center;padding:9px;border-radius:7px;font-size:.78em;margin-bottom:14px;display:none}
.msg.visible{display:block}
.msg.error{background:rgba(255,60,60,.06);border:1px solid rgba(255,60,60,.12);color:#ff6b6b}
.msg.success{background:rgba(0,212,170,.06);border:1px solid rgba(0,212,170,.12);color:#00d4aa}
.links{text-align:center;margin-top:18px}
.links a{color:#2e3646;font-size:.7em;text-decoration:none;letter-spacing:.5px;transition:color .3s}
.links a:hover{color:#4488ff}
</style>
</head>
<body>
<canvas id="bg-canvas"></canvas>
<div class="portal">
<div class="brand">
<div class="brand-name">BABEL PROTOCOL</div>
<div class="brand-sub">Sign in to your account</div>
</div>
<div class="msg" id="msg"></div>
<form id="loginForm" onsubmit="return doLogin(event)">
<div class="form-group">
<label>Username</label>
<input type="text" id="username" placeholder="Enter username" autocomplete="off">
</div>
<div class="form-group">
<label>Password</label>
<input type="password" id="password" placeholder="Enter password">
</div>
<button type="submit" class="btn btn-primary">Sign In</button>
</form>
<div class="divider">OR</div>
<div class="register-link">Don't have an account? <a href="#" onclick="showRegister()">Create one</a></div>
<div id="registerForm" style="display:none">
<form onsubmit="return doRegister(event)">
<div class="form-group" style="margin-top:14px">
<label>New Username</label>
<input type="text" id="reg_username" placeholder="Choose username" autocomplete="off">
</div>
<div class="form-group">
<label>New Password</label>
<input type="password" id="reg_password" placeholder="Choose password">
</div>
<button type="submit" class="btn btn-primary">Create Account</button>
</form>
</div>
<div class="links">
<a href="/profile">Profile</a> &middot; <a href="/">Home</a>
</div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
<script>
(function(){var c=document.getElementById('bg-canvas');var scene=new THREE.Scene();var cam=new THREE.PerspectiveCamera(75,innerWidth/innerHeight,0.1,1000);var ren=new THREE.WebGLRenderer({canvas:c,alpha:true,antialias:true});ren.setSize(innerWidth,innerHeight);ren.setPixelRatio(Math.min(devicePixelRatio,2));var N=250;var pos=new Float32Array(N*3);var vel=[];for(var i=0;i<N;i++){pos[i*3]=(Math.random()-.5)*30;pos[i*3+1]=(Math.random()-.5)*30;pos[i*3+2]=(Math.random()-.5)*15-5;vel.push({x:(Math.random()-.5)*.002,y:-(Math.random()*.008+.003),z:(Math.random()-.5)*.001})}var geo=new THREE.BufferGeometry();geo.setAttribute('position',new THREE.BufferAttribute(pos,3));var mat=new THREE.PointsMaterial({size:.035,color:0x4488ff,transparent:true,opacity:.35,sizeAttenuation:true});var pts=new THREE.Points(geo,mat);scene.add(pts);cam.position.z=12;function anim(){requestAnimationFrame(anim);var p=geo.attributes.position.array;for(var i=0;i<N;i++){p[i*3]+=vel[i].x;p[i*3+1]+=vel[i].y;p[i*3+2]+=vel[i].z;if(p[i*3+1]<-15){p[i*3]=(Math.random()-.5)*30;p[i*3+1]=15;p[i*3+2]=(Math.random()-.5)*15-5}}geo.attributes.position.needsUpdate=true;ren.render(scene,cam)}anim();addEventListener('resize',function(){cam.aspect=innerWidth/innerHeight;cam.updateProjectionMatrix();ren.setSize(innerWidth,innerHeight)})})();
</script>
<script>
function showMsg(t,m,ok){var el=document.getElementById('msg');el.textContent=m;el.className='msg visible '+(ok?'success':'error');setTimeout(function(){el.className='msg'},4000)}
function showRegister(){document.getElementById('registerForm').style.display='block';document.getElementById('loginForm').style.display='none'}
async function doLogin(e){e.preventDefault();var u=document.getElementById('username').value;var p=document.getElementById('password').value;if(!u||!p){showMsg('','Please fill all fields',false);return false}try{var r=await fetch('/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});var d=await r.json();if(d.message==='Authenticated'){showMsg('','Login successful!',true);setTimeout(function(){window.location.href='/profile'},800)}else{showMsg('','Authentication failed',false)}}catch(e){showMsg('','Connection error',false)}return false}
async function doRegister(e){e.preventDefault();var u=document.getElementById('reg_username').value;var p=document.getElementById('reg_password').value;if(!u||!p){showMsg('','Please fill all fields',false);return false}try{var r=await fetch('/register',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})});var d=await r.json();showMsg('','Account created. Try logging in.',true);document.getElementById('loginForm').style.display='block';document.getElementById('registerForm').style.display='none'}catch(e){showMsg('','Registration error',false)}return false}
</script>
</body>
</html>'''
    resp = make_response(html)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    resp.headers['X-Debug-Mode'] = 'disabled'
    return resp


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login endpoint — always returns 200."""
    if request.method == 'GET':
        accept = request.headers.get('Accept', '')
        if 'application/json' in accept:
            return jsonify({'message': 'POST with username and password', 'ref': str(uuid.uuid4())})
        # Redirect to portal page
        return redirect('/')

    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')

    try:
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['login_time'] = time.time()
            return jsonify({
                'status': 'ok',
                'message': 'Authenticated',
                'ref': str(uuid.uuid4()),
            }), 200
    except Exception:
        pass

    return jsonify({'status': 'ok', 'message': 'Request processed',
                   'ref': str(uuid.uuid4())}), 200


@app.route('/register', methods=['POST'])
def register():
    """Register endpoint — checks SSTI blacklist on username."""
    data = request.get_json(silent=True) or {}
    username = data.get('username', '')
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'status': 'ok', 'message': 'Request processed',
                       'ref': str(uuid.uuid4())}), 200

    # SSTI blacklist on username (for registration path)
    if check_ssti_blacklist(username):
        return jsonify({'status': 'ok', 'message': 'Request processed',
                       'ref': str(uuid.uuid4())}), 200

    if len(username) > 64:
        return jsonify({'status': 'ok', 'message': 'Request processed',
                       'ref': str(uuid.uuid4())}), 200

    try:
        conn = get_db()
        conn.execute('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
                    (username, generate_password_hash(password), 'user'))
        conn.commit()
        conn.close()
    except sqlite3.IntegrityError:
        pass
    except Exception:
        pass

    return jsonify({'status': 'ok', 'message': 'Request processed',
                   'ref': str(uuid.uuid4())}), 200


@app.route('/profile')
def profile():
    """
    VULNERABLE: SSTI via render_template_string

    The username from session is concatenated into the template string.
    Players who forge a session cookie with a malicious username
    can inject SSTI payloads.

    The /register endpoint checks the blacklist, but session forging
    bypasses that check entirely.

    SSTI Blacklist bypass:
      1. Split dunder names: "__cl"~"ass__" → passes __\\w+__ regex
      2. Use |map(attribute=var) instead of |attr(var)
         - |attr is blocked by input regex \\|\\s*attr
         - |map(attribute=...) is NOT blocked (pipe followed by 'map')
         - |map uses operator.attrgetter → bypasses SafeRenderExtension

    Example bypass payload:
      {% set c="__cl"~"ass__" %}
      {% set m="__mr"~"o__" %}
      {% set s="__subcla"~"sses__" %}
      {% set i="__in"~"it__" %}
      {% set g="__glo"~"bals__" %}
      {% set b="__buil"~"tins__" %}
      {% set cls="x"|map(attribute=c)|list|first %}
      {% set mro=(cls,)|map(attribute=m)|list|first %}
      {% set obj=mro|last %}
      {% set subs=(obj,)|map(attribute=s)|list|first %}
      ...find os/warning class...RCE...
    """
    if 'user_id' not in session:
        return redirect('/login')

    username = session.get('username', 'Guest')
    role = session.get('role', 'user')

    try:
        template = '''
        <!DOCTYPE html>
        <html>
        <head><title>QA Portal — Profile</title></head>
        <body style="background:#1a1a2e;color:#eee;font-family:sans-serif;padding:20px">
            <div style="background:#16213e;padding:20px;border-radius:8px;margin-bottom:20px">
                <h1>User Profile</h1>
            </div>
            <div style="background:#0f3460;padding:20px;border-radius:8px;margin-bottom:20px">
                <p><strong>Username:</strong> ''' + username + '''</p>
                <p><strong>Role:</strong> ''' + role + '''</p>
                <p><strong>Member since:</strong> ''' + str(datetime.utcnow().date()) + '''</p>
            </div>
            <div style="color:#666;font-size:12px">
                <p>QA User Portal v2.3.1 | Session ID: ''' + hashlib.md5(os.urandom(8)).hexdigest()[:8] + '''</p>
            </div>
        </body>
        </html>
        '''

        result = render_template_string(template)

        # Post-render check: detect obvious SSTI execution signatures
        # This catches naive payloads like {{7*7}} (outputs "49")
        # But won't catch targeted flag extraction
        ssti_signatures = ['<class ', '<module ', 'subprocess.Popen',
                          'posixpath', 'functools.partial']
        for sig in ssti_signatures:
            if sig in result and sig not in username:
                # SSTI detected — return generic JSON instead
                return jsonify({
                    'status': 'ok',
                    'user': username[:20] if len(username) <= 20 else username[:20],
                    'role': role,
                    'ref': hashlib.md5(os.urandom(8)).hexdigest()[:8],
                    'noise': hashlib.md5(os.urandom(16)).hexdigest()[:8],
                }), 200

        return result

    except Exception:
        return jsonify({'status': 'ok', 'message': 'Profile loaded',
                       'ref': str(uuid.uuid4())}), 200


@app.route('/profile/edit', methods=['POST'])
@require_auth
def edit_profile():
    """Edit profile — checks SSTI blacklist on new username."""
    data = request.get_json(silent=True) or {}
    new_username = data.get('username', '')
    new_bio = data.get('bio', '')

    if new_username:
        if len(new_username) > 64:
            return fake_response()
        if check_ssti_blacklist(new_username):
            return fake_response()

        user_id = session.get('user_id')
        try:
            conn = get_db()
            conn.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, user_id))
            conn.commit()
            session['username'] = new_username
            conn.close()
        except Exception:
            pass

    if new_bio:
        user_id = session.get('user_id')
        try:
            conn = get_db()
            conn.execute('UPDATE users SET bio = ? WHERE id = ?', (new_bio, user_id))
            conn.commit()
            conn.close()
        except Exception:
            pass

    return fake_response()


@app.route('/logout', methods=['POST', 'GET'])
def logout():
    """Logout — always 200."""
    session.clear()
    return jsonify({'status': 'ok', 'message': 'Logged out',
                   'ref': str(uuid.uuid4())}), 200


# ============================================================
# SQLi VULNERABLE ENDPOINT — For extracting part2 from DB
# ============================================================
@app.route('/api/search', methods=['GET', 'POST'])
def api_search():
    """
    VULNERABLE to SQL injection — allows extracting config_store data.

    Players need SECRET_KEY_PART2 from config_store table.
    This endpoint has a subtle SQLi vulnerability in the 'q' parameter.
    The query is built with string formatting instead of parameterization.

    Example exploitation:
      /api/search?q=' UNION SELECT key, value, description, '', '' FROM config_store--
    """
    ip = request.headers.get('X-Real-IP', request.remote_addr)
    if not check_rate_limit(ip, 'search', max_requests=15, window_seconds=30):
        return fake_response()

    query = ''
    if request.method == 'GET':
        query = request.args.get('q', '')
    else:
        data = request.get_json(silent=True) or {}
        query = data.get('q', '')

    if not query:
        return jsonify({
            'status': 'ok',
            'results': [],
            'total': 0,
            'ref': str(uuid.uuid4()),
        }), 200

    try:
        conn = get_db()
        # VULNERABLE: string formatting in SQL query
        # Players can inject SQL to read from any table
        sql = f"SELECT id, username, role, email, bio FROM users WHERE username LIKE '%{query}%' OR email LIKE '%{query}%' LIMIT 10"
        rows = conn.execute(sql).fetchall()

        results = []
        for row in rows:
            results.append({
                'id': row[0],
                'username': row[1],
                'role': row[2],
                'email': row[3],
                'bio': row[4][:50] if row[4] else '',
            })
        conn.close()

        return jsonify({
            'status': 'ok',
            'results': results,
            'total': len(results),
            'ref': str(uuid.uuid4()),
            'noise': hashlib.md5(os.urandom(16)).hexdigest()[:8],
        }), 200
    except Exception:
        return fake_response()


# ============================================================
# RABBIT HOLE ENDPOINTS — 70+ decoys
# ============================================================

# ---------- Authentication/Session (8) ----------

@app.route('/api/auth/refresh', methods=['POST'])
def auth_refresh():
    """Rabbit hole: Fake token refresh."""
    return jsonify({
        'status': 'ok',
        'access_token': hashlib.sha256(os.urandom(16)).hexdigest(),
        'refresh_token': hashlib.sha256(os.urandom(16)).hexdigest(),
        'expires_in': random.randint(300, 3600),
        'token_type': 'Bearer',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/auth/verify', methods=['POST'])
def auth_verify():
    """Rabbit hole: Fake token verification."""
    return jsonify({
        'status': 'ok',
        'valid': random.choice([True, False]),
        'expires_at': (datetime.utcnow() + timedelta(hours=1)).isoformat(),
        'scope': 'read write',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/auth/revoke', methods=['POST'])
def auth_revoke():
    """Rabbit hole: Fake token revocation."""
    return jsonify({
        'status': 'ok',
        'revoked': True,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/session/info')
def session_info():
    """Rabbit hole: Fake session info — always shows expired."""
    return jsonify({
        'status': 'ok',
        'session_id': hashlib.md5(os.urandom(16)).hexdigest(),
        'created_at': (datetime.utcnow() - timedelta(hours=2)).isoformat(),
        'expires_at': (datetime.utcnow() - timedelta(minutes=5)).isoformat(),
        'is_expired': True,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/session/extend', methods=['POST'])
def session_extend():
    """Rabbit hole: Fake session extension."""
    return jsonify({
        'status': 'ok',
        'new_expiry': (datetime.utcnow() + timedelta(minutes=15)).isoformat(),
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/tokens/generate', methods=['POST'])
def tokens_generate():
    """Rabbit hole: Fake token generation."""
    token_type = (request.get_json(silent=True) or {}).get('type', 'access')
    return jsonify({
        'status': 'ok',
        'token': hashlib.sha256(os.urandom(16)).hexdigest(),
        'type': token_type,
        'expires_in': 3600,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/tokens/validate', methods=['POST'])
def tokens_validate():
    """Rabbit hole: Fake token validation."""
    return jsonify({
        'status': 'ok',
        'valid': random.choice([True, True, False]),
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/oauth/token', methods=['POST'])
def oauth_token():
    """Rabbit hole: Fake OAuth token endpoint."""
    grant_type = (request.get_json(silent=True) or {}).get('grant_type', 'client_credentials')
    return jsonify({
        'access_token': hashlib.sha256(os.urandom(16)).hexdigest(),
        'token_type': 'Bearer',
        'expires_in': 3600,
        'refresh_token': hashlib.sha256(os.urandom(16)).hexdigest(),
        'scope': 'read write admin',
        'ref': str(uuid.uuid4()),
    }), 200


# ---------- OAuth/SSO (6) ----------

@app.route('/api/oauth/authorize', methods=['GET', 'POST'])
def oauth_authorize():
    """Rabbit hole: Fake OAuth authorize."""
    return jsonify({
        'status': 'ok',
        'authorization_code': hashlib.sha256(os.urandom(16)).hexdigest()[:16],
        'redirect_uri': request.args.get('redirect_uri', ''),
        'expires_in': 600,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/oauth/callback')
def oauth_callback():
    """Rabbit hole: Fake OAuth callback."""
    return jsonify({
        'status': 'ok',
        'code': request.args.get('code', hashlib.sha256(os.urandom(8)).hexdigest()[:16]),
        'state': request.args.get('state', ''),
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/saml/metadata')
def saml_metadata():
    """Rabbit hole: Fake SAML metadata."""
    return jsonify({
        'entity_id': 'https://qa-portal.local/saml',
        'sso_url': 'https://qa-portal.local/saml/sso',
        'slo_url': 'https://qa-portal.local/saml/slo',
        'certificate': hashlib.sha256(os.urandom(32)).hexdigest(),
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/saml/sso', methods=['POST'])
def saml_sso():
    """Rabbit hole: Fake SAML SSO."""
    return jsonify({
        'status': 'ok',
        'saml_response': hashlib.sha256(os.urandom(32)).hexdigest(),
        'relay_state': '',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/sso/login', methods=['POST'])
def sso_login():
    """Rabbit hole: Fake SSO login."""
    return jsonify({
        'status': 'ok',
        'redirect_url': f'https://sso.qa-portal.local/login?id={uuid.uuid4()}',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/sso/callback')
def sso_callback():
    """Rabbit hole: Fake SSO callback — returns fake flag."""
    return jsonify({
        'status': 'ok',
        'user': {'id': random.randint(1, 999), 'name': 'SSO User'},
        'token': hashlib.sha256(os.urandom(16)).hexdigest(),
        'flag': f'QA{{{hashlib.md5(os.urandom(8)).hexdigest()[:12]}}}',
        'ref': str(uuid.uuid4()),
    }), 200


# ---------- User Management (8) ----------

@app.route('/api/users')
def api_users():
    """Rabbit hole: Fake user list."""
    return jsonify({
        'users': [
            {'id': 1, 'username': 'guest', 'role': 'user', 'email': 'guest@qa-ctf.local'},
        ],
        'total': 1,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/users/<int:user_id>')
def api_user_detail(user_id):
    """Rabbit hole: Fake user detail."""
    users_data = {
        1: {'id': 1, 'username': 'guest', 'role': 'user', 'email': 'guest@qa-ctf.local', 'bio': 'Guest user'},
        2: {'id': 2, 'username': 'admin', 'role': 'admin', 'email': 'admin@qa-ctf.local', 'bio': 'System Administrator'},
    }
    return jsonify({
        'status': 'ok',
        'user': users_data.get(user_id, {'id': user_id, 'username': 'unknown', 'role': 'user'}),
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/users/export', methods=['POST'])
def users_export():
    """Rabbit hole: Fake user export."""
    return jsonify({
        'status': 'ok',
        'export_id': str(uuid.uuid4()),
        'format': 'csv',
        'download_url': f'/api/files/download/{hashlib.md5(os.urandom(8)).hexdigest()}',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/permissions')
def api_permissions():
    """Rabbit hole: Fake permissions list."""
    return jsonify({
        'permissions': [
            {'name': 'read_config', 'level': 1},
            {'name': 'write_config', 'level': 2},
            {'name': 'admin_access', 'level': 3},
        ],
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/roles')
def api_roles():
    """Rabbit hole: Fake roles."""
    return jsonify({
        'roles': ['user', 'moderator', 'admin', 'service'],
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/groups')
def api_groups():
    """Rabbit hole: Fake groups."""
    return jsonify({
        'groups': [
            {'name': 'default', 'members': 5},
            {'name': 'admin', 'members': 1},
        ],
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/teams')
def api_teams():
    """Rabbit hole: Fake teams."""
    return jsonify({
        'teams': [
            {'id': 1, 'name': 'Engineering', 'members': 8},
            {'id': 2, 'name': 'Security', 'members': 3},
        ],
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/users/search')
def users_search():
    """Rabbit hole: Fake user search (not the real SQLi endpoint)."""
    q = request.args.get('q', '')
    return jsonify({
        'status': 'ok',
        'results': [
            {'id': 1, 'username': 'guest', 'role': 'user'}
        ] if q else [],
        'total': 1 if q else 0,
        'ref': str(uuid.uuid4()),
    }), 200


# ---------- Admin Panel (6) ----------

@app.route('/admin/')
def admin_panel():
    """Rabbit hole: Fake admin panel."""
    return jsonify({
        'status': 'ok',
        'panel': 'admin',
        'features': ['user_management', 'config', 'logs', 'flags'],
        'version': '1.0.0',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/admin/users')
def admin_users():
    """Rabbit hole: Fake admin users list."""
    return jsonify({
        'users': [
            {'id': 1, 'username': 'guest', 'role': 'user', 'status': 'active'},
            {'id': 2, 'username': 'admin', 'role': 'admin', 'status': 'active'},
        ],
        'total': 2,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/admin/config')
def admin_config():
    """Rabbit hole: Fake admin config — returns decoy values."""
    return jsonify({
        'config': {
            'debug': False,
            'log_level': 'WARNING',
            'session_backend': 'redis',
            'cache_ttl': random.randint(60, 3600),
            'secret_key_hash': hashlib.md5(DECOY_CONCAT_KEY.encode()).hexdigest(),
            'key_derivation_hint': 'The secret key is stored in the FLASK_SECRET_KEY env var',
        },
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/admin/logs')
def admin_logs():
    """Rabbit hole: Fake admin logs."""
    return jsonify({
        'logs': [
            {'timestamp': '2024-01-15T10:30:00', 'level': 'INFO', 'message': 'User logged in'},
            {'timestamp': '2024-01-15T11:00:00', 'level': 'WARN', 'message': 'Config updated'},
            {'timestamp': '2024-01-15T12:00:00', 'level': 'ERROR', 'message': 'Invalid session cookie'},
        ],
        'total': 3,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/admin/settings')
def admin_settings():
    """Rabbit hole: Fake admin settings."""
    return jsonify({
        'settings': {
            'maintenance_mode': False,
            'registration_enabled': True,
            'max_sessions': 5,
            'session_timeout': 900,
            'enforce_2fa': False,
        },
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/admin/flags')
def admin_flags():
    """Rabbit hole: Fake admin flags — returns decoy flag."""
    return fake_flag_response()


# ---------- Password/2FA (5) ----------

@app.route('/api/password/reset', methods=['POST'])
def password_reset():
    """Rabbit hole: Fake password reset."""
    return jsonify({
        'status': 'ok',
        'message': 'Reset email sent',
        'reset_token': hashlib.sha256(os.urandom(16)).hexdigest()[:16],
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/password/change', methods=['POST'])
def password_change():
    """Rabbit hole: Fake password change."""
    return jsonify({
        'status': 'ok',
        'message': 'Password updated',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/2fa/setup', methods=['POST'])
def twofa_setup():
    """Rabbit hole: Fake 2FA setup — returns fake secret."""
    return jsonify({
        'status': 'ok',
        'secret': hashlib.sha256(os.urandom(16)).hexdigest()[:16],
        'qr_code_url': f'https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=otpauth://totp/qa-portal:user?secret={hashlib.sha256(os.urandom(8)).hexdigest()[:16]}',
        'backup_codes': [f"{random.randint(100000, 999999)}" for _ in range(6)],
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/2fa/verify', methods=['POST'])
def twofa_verify():
    """Rabbit hole: Fake 2FA verify."""
    return jsonify({
        'status': 'ok',
        'verified': random.choice([True, True, False]),
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/2fa/backup-codes')
def twofa_backup_codes():
    """Rabbit hole: Fake 2FA backup codes."""
    return jsonify({
        'status': 'ok',
        'codes': [f"{random.randint(100000, 999999)}" for _ in range(8)],
        'remaining': random.randint(1, 8),
        'ref': str(uuid.uuid4()),
    }), 200


# ---------- File/Upload (5) ----------

@app.route('/api/files/upload', methods=['POST'])
def files_upload():
    """Rabbit hole: Fake file upload."""
    return jsonify({
        'status': 'ok',
        'file_id': hashlib.md5(os.urandom(16)).hexdigest(),
        'filename': 'upload.dat',
        'size': random.randint(100, 10000),
        'url': f'/api/files/download/{hashlib.md5(os.urandom(8)).hexdigest()}',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/files/list')
def files_list():
    """Rabbit hole: Fake file list."""
    return jsonify({
        'files': [
            {'id': 1, 'name': 'readme.txt', 'size': 256, 'type': 'text/plain'},
            {'id': 2, 'name': 'config.json', 'size': 1024, 'type': 'application/json'},
        ],
        'total': 2,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/files/download/<file_id>')
def files_download(file_id):
    """Rabbit hole: Fake file download."""
    return jsonify({
        'status': 'ok',
        'file_id': file_id,
        'content': 'File content not available',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/attachments', methods=['GET', 'POST'])
def attachments():
    """Rabbit hole: Fake attachments endpoint."""
    if request.method == 'POST':
        return jsonify({
            'status': 'ok',
            'attachment_id': str(uuid.uuid4()),
            'ref': str(uuid.uuid4()),
        }), 200
    return jsonify({
        'attachments': [],
        'total': 0,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/media', methods=['GET', 'POST'])
def media():
    """Rabbit hole: Fake media endpoint."""
    return jsonify({
        'status': 'ok',
        'media_url': f'/static/media/{hashlib.md5(os.urandom(8)).hexdigest()}.png',
        'ref': str(uuid.uuid4()),
    }), 200


# ---------- GraphQL (3) ----------

@app.route('/graphql', methods=['GET', 'POST'])
def graphql_endpoint():
    """Rabbit hole: Fake GraphQL — always returns empty data."""
    query = ''
    if request.method == 'POST':
        data = request.get_json(silent=True) or {}
        query = data.get('query', '')
    else:
        query = request.args.get('query', '')

    return jsonify({
        'data': {
            'users': [],
            'config': None,
            'flag': None,
        },
        'extensions': {
            'tracing': {
                'version': 1,
                'startTime': datetime.utcnow().isoformat(),
                'duration': random.randint(1, 50),
            }
        },
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/graphql/schema')
def graphql_schema():
    """Rabbit hole: Fake GraphQL schema."""
    return jsonify({
        'schema': {
            'types': ['User', 'Config', 'Flag', 'Token', 'Query', 'Mutation'],
            'queryType': 'Query',
            'mutationType': 'Mutation',
        },
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/graphiql')
def graphiql():
    """Rabbit hole: Fake GraphiQL interface."""
    return jsonify({
        'message': 'GraphiQL interface disabled in production',
        'ref': str(uuid.uuid4()),
    }), 200


# ---------- Monitoring/Metrics (5) ----------

@app.route('/api/metrics')
def api_metrics():
    """Rabbit hole: Fake Prometheus metrics."""
    metrics_text = f"""# HELP qa_requests_total Total requests
# TYPE qa_requests_total counter
qa_requests_total {random.randint(1000, 9999)}
# HELP qa_requests_duration_seconds Request duration
# TYPE qa_requests_duration_seconds histogram
qa_requests_duration_seconds_bucket_le0.1 {random.randint(100, 500)}
qa_requests_duration_seconds_bucket_le0.5 {random.randint(500, 1000)}
qa_requests_duration_seconds_bucket_le1.0 {random.randint(800, 1500)}
qa_requests_duration_seconds_bucket_le+Inf {random.randint(1000, 2000)}
# HELP qa_sessions_active Active sessions
# TYPE qa_sessions_active gauge
qa_sessions_active {random.randint(5, 50)}
"""
    return Response(metrics_text, mimetype='text/plain'), 200


@app.route('/api/health')
def api_health():
    """Rabbit hole: Health check with fake details."""
    return jsonify({
        'status': 'healthy',
        'checks': {
            'database': 'ok',
            'redis': 'ok',
            'filesystem': 'ok',
            'external_api': 'ok',
        },
        'uptime': random.randint(10000, 999999),
        'version': '2.3.1',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/status')
def api_status():
    """Rabbit hole: Status with misleading info."""
    resp = jsonify({
        'status': 'running',
        'uptime': random.randint(1000, 99999),
        'connections': random.randint(10, 500),
        'memory_usage': f'{random.randint(30, 80)}%',
        'cpu_usage': f'{random.randint(5, 40)}%',
        'ref': str(uuid.uuid4()),
    })
    resp.headers['X-Debug-Token'] = hashlib.md5(os.urandom(16)).hexdigest()
    resp.headers['X-Internal-Port'] = str(random.randint(8000, 9999))
    resp.headers['X-Secret-Key-Hash'] = hashlib.md5(DECOY_CONCAT_KEY.encode()).hexdigest()
    return noise_headers(resp)


@app.route('/api/ping')
def api_ping():
    """Rabbit hole: Simple ping."""
    return jsonify({'pong': True, 'ts': int(time.time()), 'ref': str(uuid.uuid4())}), 200


@app.route('/api/version')
def api_version():
    """Rabbit hole: Version info — misleading hints."""
    return jsonify({
        'version': '2.3.1',
        'build': hashlib.md5(os.urandom(8)).hexdigest()[:8],
        'framework': 'Flask 2.3.3',
        'python': '3.11.4',
        'session_backend': 'itsdangerous',
        'secret_key_source': 'environment',
        'ref': str(uuid.uuid4()),
    }), 200


# ---------- Search/Query (4) ----------

@app.route('/api/query', methods=['POST'])
def api_query():
    """Rabbit hole: Fake query endpoint (not the SQLi one)."""
    data = request.get_json(silent=True) or {}
    return jsonify({
        'status': 'ok',
        'results': [],
        'total': 0,
        'query': data.get('query', ''),
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/filter', methods=['POST'])
def api_filter():
    """Rabbit hole: Fake filter endpoint."""
    return jsonify({
        'status': 'ok',
        'filtered': [],
        'total': 0,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/advanced-search', methods=['POST'])
def api_advanced_search():
    """Rabbit hole: Fake advanced search (not the SQLi one)."""
    data = request.get_json(silent=True) or {}
    return jsonify({
        'status': 'ok',
        'results': [
            {'id': random.randint(1, 999), 'type': random.choice(['user', 'config', 'log']),
             'value': f'item_{random.randint(1, 100)}'}
            for _ in range(random.randint(0, 3))
        ],
        'total': random.randint(0, 3),
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/suggest')
def api_suggest():
    """Rabbit hole: Fake autocomplete."""
    q = request.args.get('q', '')
    return jsonify({
        'suggestions': ['guest', 'admin', 'service'] if q else [],
        'ref': str(uuid.uuid4()),
    }), 200


# ---------- Database/Config (6) ----------

@app.route('/api/config')
def api_config():
    """Rabbit hole: Fake config — all decoys."""
    return jsonify({
        'auth_provider': 'internal',
        'session_backend': 'redis',
        'debug': False,
        'version': '2.3.1',
        'secret_key_rotation': True,
        'key_derivation': 'pbkdf2',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/config/update', methods=['POST'])
def api_config_update():
    """Rabbit hole: Fake config update."""
    return jsonify({
        'status': 'ok',
        'message': 'Configuration updated',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/settings')
def api_settings():
    """Rabbit hole: Fake settings."""
    return jsonify({
        'settings': {
            'theme': 'dark',
            'language': 'en',
            'notifications': True,
            'timezone': 'UTC',
        },
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/preferences', methods=['GET', 'POST'])
def api_preferences():
    """Rabbit hole: Fake preferences."""
    return jsonify({
        'status': 'ok',
        'preferences': {'theme': 'dark', 'language': 'en'},
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/feature-flags')
def api_feature_flags():
    """Rabbit hole: Fake feature flags from DB."""
    try:
        conn = get_db()
        flags = conn.execute('SELECT flag_name, enabled, description FROM feature_flags').fetchall()
        conn.close()
        return jsonify({
            'flags': [{'name': f[0], 'enabled': bool(f[1]), 'description': f[2]} for f in flags],
            'ref': str(uuid.uuid4()),
        }), 200
    except Exception:
        return fake_response()


@app.route('/api/environment')
def api_environment():
    """Rabbit hole: Fake environment info — misleading hints about key source."""
    return jsonify({
        'environment': 'production',
        'region': 'us-east-1',
        'deployment': 'docker',
        'services': ['postgres', 'redis', 'vault'],
        'note': 'Secret key is loaded from FLASK_SECRET_KEY env var',
        'ref': str(uuid.uuid4()),
    }), 200


# ---------- Encryption/Vault (5) ----------

@app.route('/api/vault')
def api_vault():
    """Rabbit hole: Fake vault endpoint."""
    return jsonify({
        'status': 'ok',
        'vault_addr': 'http://vault.internal:8200',
        'sealed': True,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/vault/secrets')
def api_vault_secrets():
    """Rabbit hole: Fake vault secrets — decoy flags."""
    return fake_flag_response()


@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    """Rabbit hole: Fake encryption."""
    data = request.get_json(silent=True) or {}
    plaintext = data.get('plaintext', '')
    return jsonify({
        'status': 'ok',
        'ciphertext': hashlib.sha256(plaintext.encode() or os.urandom(16)).hexdigest(),
        'algorithm': 'AES-256-GCM',
        'key_id': 'ek-001',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/decrypt', methods=['POST'])
def api_decrypt():
    """Rabbit hole: Fake decryption — always fails."""
    return jsonify({
        'status': 'ok',
        'error': 'Decryption failed: invalid key',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/keys')
def api_keys():
    """Rabbit hole: Fake key management — returns decoy key list."""
    try:
        conn = get_db()
        keys = conn.execute('SELECT key_id, algorithm, active FROM encryption_keys').fetchall()
        conn.close()
        return jsonify({
            'keys': [{'id': k[0], 'algorithm': k[1], 'active': bool(k[2])} for k in keys],
            'ref': str(uuid.uuid4()),
        }), 200
    except Exception:
        return fake_response()


# ---------- Webhooks/Integration (4) ----------

@app.route('/api/webhooks')
def api_webhooks():
    """Rabbit hole: Fake webhooks list."""
    return jsonify({
        'webhooks': [
            {'id': 1, 'url': 'http://hooks.internal/notify', 'event': 'user.login', 'enabled': True},
        ],
        'total': 1,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/webhooks/test', methods=['POST'])
def api_webhooks_test():
    """Rabbit hole: Fake webhook test."""
    return jsonify({
        'status': 'ok',
        'delivered': True,
        'response_code': 200,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/integrations')
def api_integrations():
    """Rabbit hole: Fake integrations list."""
    return jsonify({
        'integrations': [
            {'name': 'Slack', 'enabled': True},
            {'name': 'PagerDuty', 'enabled': False},
            {'name': 'Datadog', 'enabled': True},
        ],
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/integrations/slack', methods=['POST'])
def api_integrations_slack():
    """Rabbit hole: Fake Slack integration."""
    return jsonify({
        'status': 'ok',
        'message': 'Notification sent to #alerts',
        'ref': str(uuid.uuid4()),
    }), 200


# ---------- Notification (3) ----------

@app.route('/api/notifications')
def api_notifications():
    """Rabbit hole: Fake notifications."""
    return jsonify({
        'notifications': [
            {'id': 1, 'type': 'info', 'message': 'Welcome to QA Portal', 'read': True},
            {'id': 2, 'type': 'warning', 'message': 'Session expiring soon', 'read': False},
        ],
        'unread': 1,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/notifications/subscribe', methods=['POST'])
def notifications_subscribe():
    """Rabbit hole: Fake notification subscription."""
    return jsonify({
        'status': 'ok',
        'channel': hashlib.md5(os.urandom(8)).hexdigest()[:8],
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/notifications/settings', methods=['GET', 'POST'])
def notifications_settings():
    """Rabbit hole: Fake notification settings."""
    return jsonify({
        'settings': {
            'email': True,
            'push': False,
            'sms': False,
        },
        'ref': str(uuid.uuid4()),
    }), 200


# ---------- Debug/Dev (5) ----------

@app.route('/debug/')
def debug_panel():
    """Rabbit hole: Fake debug panel."""
    return jsonify({
        'status': 'ok',
        'debug': False,
        'message': 'Debug panel is disabled in production',
        'hint': 'Set FLASK_DEBUG=1 to enable',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/debug/config')
def debug_config():
    """Rabbit hole: Fake debug config — misleading secret key info."""
    return jsonify({
        'config': {
            'DEBUG': False,
            'TESTING': False,
            'SECRET_KEY': '***hidden***',
            'SECRET_KEY_HASH': hashlib.md5(REAL_SECRET_KEY.encode()).hexdigest(),
            'SESSION_COOKIE_SECURE': True,
            'PERMANENT_SESSION_LIFETIME': 900,
        },
        'note': 'The SECRET_KEY is derived from FLASK_SECRET_KEY environment variable',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/debug/routes')
def debug_routes():
    """Rabbit hole: Fake route list — includes fake routes."""
    fake_routes = [
        '/api/flag', '/admin/flag', '/api/internal/secret',
        '/debug/env', '/debug/session', '/api/v1/secret',
        '/api/config/raw', '/.env', '/api/keys/raw',
    ]
    return jsonify({
        'routes': fake_routes,
        'total': len(fake_routes),
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/debug/env')
def debug_env():
    """Rabbit hole: Fake environment dump — DECOY values."""
    return jsonify({
        'environment': {
            'FLASK_APP': 'app.py',
            'FLASK_ENV': 'production',
            'FLASK_DEBUG': '0',
            'FLASK_SECRET_KEY': DECOY_CONCAT_KEY,  # DECOY! Not the real signing key!
            'DATABASE_URL': 'sqlite:///var/lib/qa-challenge/challenge.db',
            'REDIS_URL': 'redis://redis:6379/0',
            'DEBUG': 'False',
        },
        'note': 'Environment variables are read-only in production',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/debug/stack')
def debug_stack():
    """Rabbit hole: Fake stack trace — misleading information."""
    return jsonify({
        'stack': [
            {'frame': 0, 'file': 'app.py', 'line': 142, 'function': 'profile',
             'code': 'render_template_string(template)'},
            {'frame': 1, 'file': 'app.py', 'line': 89, 'function': 'before_request_func',
             'code': 'time.sleep(random.uniform(0.02, 0.3))'},
        ],
        'note': 'Stack trace is sanitized in production mode',
        'ref': str(uuid.uuid4()),
    }), 200


# ---------- Static/Well-known (5) ----------

@app.route('/robots.txt')
def robots():
    """Rabbit hole: robots.txt with many fake disallowed paths."""
    return """User-agent: *
Disallow: /admin/
Disallow: /debug/
Disallow: /internal/
Disallow: /api/v2/
Disallow: /backup/
Disallow: /console/
Disallow: /graphql/
Disallow: /wp-admin/
Disallow: /.env
Disallow: /api/flag
Disallow: /api/secret
Disallow: /api/v1/
Disallow: /api/internal/
Disallow: /flag.txt
Disallow: /secrets/
Disallow: /vault/
""", 200, {'Content-Type': 'text/plain'}


@app.route('/sitemap.xml')
def sitemap():
    """Rabbit hole: Fake sitemap."""
    return """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://qa-portal.local/</loc></url>
  <url><loc>https://qa-portal.local/login</loc></url>
  <url><loc>https://qa-portal.local/profile</loc></url>
  <url><loc>https://qa-portal.local/api/health</loc></url>
  <url><loc>https://qa-portal.local/admin/</loc></url>
</urlset>
""", 200, {'Content-Type': 'application/xml'}


@app.route('/.well-known/security.txt')
def security_txt():
    """Rabbit hole: Fake security.txt — decoy contact info."""
    return """Contact: security@qa-ctf.local
Preferred-Languages: en
Hiring: https://qa-ctf.local/careers
Policy: https://qa-ctf.local/security-policy

# Note: Flag submission at flag@qa-ctf.local
# Bug bounty program active — rewards up to $500
""", 200, {'Content-Type': 'text/plain'}


@app.route('/.well-known/openapi.json')
def openapi_json():
    """Rabbit hole: Fake OpenAPI spec."""
    return jsonify({
        'openapi': '3.0.0',
        'info': {'title': 'QA User Portal API', 'version': '2.3.1'},
        'paths': {
            '/login': {'post': {'summary': 'Authenticate user'}},
            '/register': {'post': {'summary': 'Register new user'}},
            '/profile': {'get': {'summary': 'Get user profile'}},
            '/api/search': {'get': {'summary': 'Search users'}},
            '/api/flag': {'get': {'summary': 'Get flag (admin only)'}},
        },
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/swagger.json')
def swagger_json():
    """Rabbit hole: Fake Swagger spec — includes fake flag endpoint."""
    return jsonify({
        'swagger': '2.0',
        'info': {'title': 'QA User Portal', 'version': '2.3.1'},
        'paths': {
            '/api/v1/flag': {
                'get': {
                    'summary': 'Retrieve the CTF flag',
                    'parameters': [
                        {'name': 'Authorization', 'in': 'header', 'type': 'string', 'required': True},
                    ],
                    'responses': {'200': {'description': 'Flag retrieved'}},
                }
            },
        },
        'ref': str(uuid.uuid4()),
    }), 200


# ---------- Misc Rabbit Holes (10+) ----------

@app.route('/api/v1/flag')
def api_v1_flag():
    """Rabbit hole: Fake flag endpoint — always returns decoy."""
    return fake_flag_response()


@app.route('/api/internal/secret')
def api_internal_secret():
    """Rabbit hole: Fake internal secret — decoy values."""
    return jsonify({
        'status': 'ok',
        'secret_type': 'session_key',
        'secret_value': hashlib.sha256(os.urandom(16)).hexdigest(),
        'rotation_date': '2024-12-31',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/backup', methods=['GET', 'POST'])
def api_backup():
    """Rabbit hole: Fake backup endpoint."""
    return jsonify({
        'status': 'ok',
        'backup_id': str(uuid.uuid4()),
        'size': random.randint(1000000, 50000000),
        'created_at': datetime.utcnow().isoformat(),
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/export', methods=['POST'])
def api_export():
    """Rabbit hole: Fake data export."""
    return jsonify({
        'status': 'ok',
        'export_id': str(uuid.uuid4()),
        'download_url': f'/api/files/download/{hashlib.md5(os.urandom(8)).hexdigest()}',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/import', methods=['POST'])
def api_import():
    """Rabbit hole: Fake data import."""
    return jsonify({
        'status': 'ok',
        'imported': random.randint(0, 100),
        'errors': random.randint(0, 5),
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/.env')
def dot_env():
    """Rabbit hole: Fake .env file — contains DECOY key, not the real one."""
    env_content = f"""# QA User Portal Configuration
# =============================
FLASK_APP=app.py
FLASK_ENV=production
FLASK_DEBUG=0
FLASK_SECRET_KEY={DECOY_CONCAT_KEY}
DATABASE_URL=sqlite:///var/lib/qa-challenge/challenge.db
REDIS_URL=redis://redis:6379/0
ADMIN_PASSWORD=changeme
SESSION_LIFETIME_MINUTES=15

# WARNING: This file is auto-generated and may not reflect current values
# The actual signing key may be derived from multiple sources
"""
    return Response(env_content, mimetype='text/plain'), 200


@app.route('/flag.txt')
def flag_txt():
    """Rabbit hole: Fake flag file."""
    return jsonify({
        'error': 'Access denied',
        'hint': 'Try the /api/v1/flag endpoint with proper authorization',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/v2/export', methods=['POST'])
def api_v2_export():
    """Rabbit hole: Fake v2 export."""
    return fake_response()


@app.route('/api/v2/import', methods=['POST'])
def api_v2_import():
    """Rabbit hole: Fake v2 import."""
    return fake_response()


@app.route('/api/v2/config')
def api_v2_config():
    """Rabbit hole: Fake v2 config."""
    return jsonify({
        'api_version': '2',
        'features': ['search', 'export', 'import', 'admin'],
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/v1/users')
def api_v1_users():
    """Rabbit hole: Fake v1 users."""
    return jsonify({
        'users': [{'id': 1, 'name': 'guest'}],
        'api_version': '1',
        'deprecated': True,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/v1/config')
def api_v1_config():
    """Rabbit hole: Fake v1 config with decoy secret."""
    return jsonify({
        'config': {
            'secret_key': hashlib.md5(os.urandom(16)).hexdigest(),
            'session_backend': 'cookie',
            'debug': False,
        },
        'api_version': '1',
        'deprecated': True,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/console/')
def console():
    """Rabbit hole: Fake Werkzeug console."""
    return jsonify({
        'message': 'Interactive console is disabled',
        'hint': 'Set PIN environment variable to enable',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/ws')
def api_websocket():
    """Rabbit hole: Fake WebSocket upgrade."""
    return jsonify({
        'message': 'WebSocket endpoint — upgrade required',
        'supported_protocols': ['v1', 'v2'],
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/stream')
def api_stream():
    """Rabbit hole: Fake SSE stream endpoint."""
    return jsonify({
        'message': 'Streaming endpoint — use text/event-stream Accept header',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/batch', methods=['POST'])
def api_batch():
    """Rabbit hole: Fake batch request endpoint."""
    return jsonify({
        'status': 'ok',
        'results': [],
        'total': 0,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/audit')
def api_audit():
    """Rabbit hole: Fake audit log endpoint."""
    return jsonify({
        'entries': [
            {'action': 'login', 'timestamp': datetime.utcnow().isoformat(), 'result': 'success'},
        ],
        'total': 1,
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/analytics')
def api_analytics():
    """Rabbit hole: Fake analytics."""
    return jsonify({
        'page_views': random.randint(1000, 9999),
        'unique_users': random.randint(50, 200),
        'top_pages': ['/profile', '/login', '/api/search'],
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/reports', methods=['GET', 'POST'])
def api_reports():
    """Rabbit hole: Fake reports endpoint."""
    return jsonify({
        'reports': [
            {'id': 1, 'name': 'User Activity Report', 'status': 'completed'},
        ],
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/feedback', methods=['POST'])
def api_feedback():
    """Rabbit hole: Fake feedback endpoint."""
    return jsonify({
        'status': 'ok',
        'message': 'Feedback submitted',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/support')
def api_support():
    """Rabbit hole: Fake support endpoint — returns misleading hints."""
    return jsonify({
        'status': 'ok',
        'faq': [
            {'q': 'How do I access the flag?', 'a': 'Flags are only available to admin users through the /api/v1/flag endpoint.'},
            {'q': 'I forgot my password', 'a': 'Use the /api/password/reset endpoint to generate a reset token.'},
            {'q': 'How does session signing work?', 'a': 'Sessions are signed using the FLASK_SECRET_KEY environment variable with itsdangerous.'},
            {'q': 'Is there a debug mode?', 'a': 'Debug mode is disabled in production. Set FLASK_DEBUG=1 to enable.'},
        ],
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/docs')
def api_docs():
    """Rabbit hole: Fake API documentation."""
    return jsonify({
        'endpoints': [
            {'path': '/login', 'method': 'POST', 'auth': False, 'description': 'Authenticate user'},
            {'path': '/register', 'method': 'POST', 'auth': False, 'description': 'Register new user'},
            {'path': '/profile', 'method': 'GET', 'auth': True, 'description': 'View user profile'},
            {'path': '/api/search', 'method': 'GET', 'auth': False, 'description': 'Search users'},
            {'path': '/api/v1/flag', 'method': 'GET', 'auth': True, 'description': 'Get CTF flag (admin)'},
        ],
        'version': '2.3.1',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/rate-limit')
def api_rate_limit():
    """Rabbit hole: Fake rate limit info."""
    return jsonify({
        'limits': {
            '/api/search': '15/30s',
            '/login': '5/300s',
            '/api/auth/*': '10/60s',
        },
        'remaining': random.randint(1, 15),
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/captcha', methods=['GET', 'POST'])
def api_captcha():
    """Rabbit hole: Fake captcha endpoint."""
    return jsonify({
        'captcha_id': str(uuid.uuid4()),
        'challenge': hashlib.md5(os.urandom(8)).hexdigest()[:6],
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/webhook/incoming', methods=['POST'])
def api_webhook_incoming():
    """Rabbit hole: Fake incoming webhook."""
    return jsonify({
        'status': 'ok',
        'processed': True,
        'event_id': str(uuid.uuid4()),
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/deploy', methods=['POST'])
def api_deploy():
    """Rabbit hole: Fake deployment trigger."""
    return jsonify({
        'status': 'ok',
        'deployment_id': str(uuid.uuid4()),
        'status_url': f'/api/deploy/{hashlib.md5(os.urandom(8)).hexdigest()}/status',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/cache/clear', methods=['POST'])
def api_cache_clear():
    """Rabbit hole: Fake cache clear."""
    return jsonify({
        'status': 'ok',
        'cleared': random.randint(10, 100),
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/queue/status')
def api_queue_status():
    """Rabbit hole: Fake queue status."""
    return jsonify({
        'status': 'ok',
        'pending': random.randint(0, 10),
        'processing': random.randint(0, 3),
        'failed': random.randint(0, 2),
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/mail/send', methods=['POST'])
def api_mail_send():
    """Rabbit hole: Fake mail send."""
    return jsonify({
        'status': 'ok',
        'message_id': str(uuid.uuid4()),
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/internal/')
def internal_index():
    """Rabbit hole: Fake internal endpoint — returns decoy flag."""
    return jsonify({
        'service': 'qa-internal',
        'status': 'running',
        'flag': f'QA{{{hashlib.md5(os.urandom(8)).hexdigest()[:12]}}}',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/internal/config')
def internal_config():
    """Rabbit hole: Fake internal config — decoy secret key."""
    return jsonify({
        'secret_key': DECOY_CONCAT_KEY,  # DECOY! Same as FLASK_SECRET_KEY
        'session_backend': 'cookie',
        'key_derivation': 'none',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/internal/flag')
def internal_flag():
    """Rabbit hole: Fake internal flag endpoint."""
    return fake_flag_response()


@app.route('/wp-admin/')
def wp_admin():
    """Rabbit hole: Fake WordPress admin."""
    return jsonify({'error': 'Not a WordPress site'}), 200


@app.route('/wp-login.php')
def wp_login():
    """Rabbit hole: Fake WordPress login."""
    return jsonify({'error': 'Not a WordPress site'}), 200


@app.route('/api/vault/entries')
def api_vault_entries():
    """Rabbit hole: Fake vault entries from DB — decoy values."""
    try:
        conn = get_db()
        entries = conn.execute('SELECT entry_name, category, encrypted FROM vault_entries').fetchall()
        conn.close()
        return jsonify({
            'entries': [{'name': e[0], 'category': e[1], 'encrypted': bool(e[2])} for e in entries],
            'ref': str(uuid.uuid4()),
        }), 200
    except Exception:
        return fake_response()


@app.route('/api/secrets')
def api_secrets():
    """Rabbit hole: Fake secrets list — shows names but not values."""
    try:
        conn = get_db()
        secrets = conn.execute('SELECT secret_name, secret_type, rotation_days FROM secrets').fetchall()
        conn.close()
        return jsonify({
            'secrets': [{'name': s[0], 'type': s[1], 'rotation_days': s[2]} for s in secrets],
            'note': 'Secret values are encrypted and not accessible via API',
            'ref': str(uuid.uuid4()),
        }), 200
    except Exception:
        return fake_response()


@app.route('/api/deployment/config')
def api_deployment_config():
    """Rabbit hole: Fake deployment config — decoy key."""
    try:
        conn = get_db()
        configs = conn.execute('SELECT env_name, config_key, encrypted FROM deployment_config').fetchall()
        conn.close()
        return jsonify({
            'configs': [{'env': c[0], 'key': c[1], 'encrypted': bool(c[2])} for c in configs],
            'ref': str(uuid.uuid4()),
        }), 200
    except Exception:
        return fake_response()


@app.route('/api/admin/notes')
def api_admin_notes():
    """Rabbit hole: Fake admin notes — MISLEADING HINTS."""
    try:
        conn = get_db()
        notes = conn.execute('SELECT title, content, author, priority FROM admin_notes').fetchall()
        conn.close()
        return jsonify({
            'notes': [{'title': n[0], 'content': n[1], 'author': n[2], 'priority': n[3]} for n in notes],
            'ref': str(uuid.uuid4()),
        }), 200
    except Exception:
        return fake_response()


@app.route('/api/audit/log')
def api_audit_log():
    """Rabbit hole: Fake audit log from DB."""
    try:
        conn = get_db()
        logs = conn.execute('SELECT action, timestamp, details, ip_address FROM audit_log ORDER BY id DESC LIMIT 20').fetchall()
        conn.close()
        return jsonify({
            'logs': [{'action': l[0], 'timestamp': l[1], 'details': l[2], 'ip': l[3]} for l in logs],
            'total': len(logs),
            'ref': str(uuid.uuid4()),
        }), 200
    except Exception:
        return fake_response()


@app.route('/api/tokens/list')
def api_tokens_list():
    """Rabbit hole: Fake token list from DB."""
    try:
        conn = get_db()
        tokens = conn.execute('SELECT token_type, expires_at, revoked FROM tokens').fetchall()
        conn.close()
        return jsonify({
            'tokens': [{'type': t[0], 'expires': t[1], 'revoked': bool(t[2])} for t in tokens],
            'ref': str(uuid.uuid4()),
        }), 200
    except Exception:
        return fake_response()


@app.route('/api/health/detailed')
def api_health_detailed():
    """Rabbit hole: Detailed health check with misleading info."""
    return jsonify({
        'status': 'healthy',
        'components': {
            'database': {'status': 'healthy', 'latency_ms': random.randint(1, 10)},
            'redis': {'status': 'healthy', 'latency_ms': random.randint(1, 5)},
            'filesystem': {'status': 'healthy', 'usage': f'{random.randint(20, 60)}%'},
            'flask_session': {
                'status': 'healthy',
                'backend': 'cookie',
                'signing': 'itsdangerous',
                'key_source': 'FLASK_SECRET_KEY env var',
                'key_derivation': 'direct',  # LIE! Real derivation is SHA256
            },
        },
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/debug/session')
def api_debug_session():
    """Rabbit hole: Fake session debug — shows decoy info."""
    return jsonify({
        'session': {
            'backend': 'cookie',
            'serializer': 'itsdangerous',
            'signer': 'HMAC-SHA1',
            'secret_key_hash': hashlib.md5(DECOY_CONCAT_KEY.encode()).hexdigest(),
            'lifetime_minutes': SESSION_LIFETIME,
        },
        'note': 'Session cookies are signed with the FLASK_SECRET_KEY environment variable',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/debug/template')
def api_debug_template():
    """Rabbit hole: Fake template debug — mentions render_template_string."""
    return jsonify({
        'template_engine': 'Jinja2',
        'render_method': 'render_template_string',
        'autoescape': True,
        'sandbox_mode': False,
        'note': 'Template rendering uses Jinja2 with SafeRenderExtension for security',
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/favicon.ico')
def favicon():
    """Rabbit hole: Fake favicon."""
    return '', 204


@app.route('/api/csp-report', methods=['POST'])
def csp_report():
    """Rabbit hole: CSP violation report endpoint."""
    return '', 200


@app.route('/api/error-report', methods=['POST'])
def error_report():
    """Rabbit hole: Client error report endpoint."""
    return jsonify({'status': 'ok', 'ref': str(uuid.uuid4())}), 200


@app.route('/api/trace/<trace_id>')
def api_trace(trace_id):
    """Rabbit hole: Fake distributed trace endpoint."""
    return jsonify({
        'trace_id': trace_id,
        'spans': [
            {'service': 'qa-portal', 'duration_ms': random.randint(1, 50)},
            {'service': 'database', 'duration_ms': random.randint(1, 10)},
        ],
        'ref': str(uuid.uuid4()),
    }), 200


@app.route('/api/schema')
def api_schema():
    """Rabbit hole: Fake database schema endpoint."""
    return jsonify({
        'tables': [
            'users', 'config_store', 'api_keys', 'audit_log',
            'feature_flags', 'sessions', 'tokens', 'permissions',
            'oauth_clients', 'webhook_configs', 'encryption_keys',
            'vault_entries', 'backup_codes', 'rate_limits',
            'admin_notes', 'system_config', 'cache_entries',
            'deployment_config', 'secrets',
        ],
        'note': 'Table schemas are internal and not exposed via API',
        'ref': str(uuid.uuid4()),
    }), 200


# ============================================================
# Catch-all for remaining rabbit holes
# ============================================================
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def catch_all(path):
    """Catch-all: Returns fake 200 response for any unmatched route."""
    # Some paths get special treatment
    if path in ('api/flag', 'flag', 'secret', 'api/secret', 'api/key',
                'admin/flag', 'api/admin/flag'):
        return fake_flag_response()
    if 'flag' in path.lower() or 'secret' in path.lower() or 'key' in path.lower():
        return fake_flag_response()
    return fake_response()


# ============================================================
# INITIALIZATION
# ============================================================
init_db()
SafeRenderExtension(app)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False, threaded=True)
