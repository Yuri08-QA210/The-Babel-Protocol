"""
QA CTF Challenge — Internal Service (SSRF Target)
===================================================
This service runs on the Docker internal network and listens
on INTERNAL_PORT (default 8888). It binds to 0.0.0.0 so other
containers on the same Docker network can reach it.

It provides SECRET_KEY_PART1 that players need for Stage 2.

Players must:
1. Use XXE to SSRF into this service from stage1-app
2. Find the real endpoints among 30+ rabbit holes
3. Combine part1 (from here) + part2 (from config_store DB table)
4. Real combination method: SHA256(part1 + part2)

CRITICAL: Binds to 0.0.0.0 (not 127.0.0.1) because it runs in its
own container. Security comes from Docker network isolation — the
port is NOT exposed externally by Docker Compose.
"""

import os
import random
import time
import hashlib
import uuid
import json
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, make_response

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Real secret key components
# ---------------------------------------------------------------------------
SECRET_KEY_PART1 = os.environ.get(
    'SECRET_KEY_PART1', 'qa-s3cr3t-k3y-p4rt1-'
)
SECRET_KEY_PART2_HINT = os.environ.get(
    'SECRET_KEY_PART2_HINT',
    'Check the internal database table: config_store, key=flask_secret_part2'
)

# ---------------------------------------------------------------------------
# Fake keys / decoy data — regenerated every process start
# ---------------------------------------------------------------------------
FAKE_KEYS = {
    'jwt_secret': hashlib.md5(os.urandom(16)).hexdigest(),
    'encryption_key': hashlib.sha256(os.urandom(16)).hexdigest(),
    'api_key': str(uuid.uuid4()),
    'admin_token': hashlib.sha512(os.urandom(32)).hexdigest()[:32],
    'session_key': hashlib.sha1(os.urandom(16)).hexdigest(),
    'signing_key': hashlib.sha256(os.urandom(16)).hexdigest()[:48],
}

# Fake flags — wrong answers to waste time
FAKE_FLAGS = [
    'QA{1nt3rn4l_s3rv1c3_expl01t3d}',
    'QA{ssrf_thr0ugh_xx3_w0rk3d}',
    'QA{h1dd3n_1nt3rn4l_3ndp01nt}',
    'QA{c0nf1g_st0r3_s3cr3t_l3ak}',
    'QA{d0ck3r_n3tw0rk_p1v0t}',
    'QA{1nt3rn4l_k3y_d1sc0v3ry}',
    'QA{f4k3_fl4g_f0r_d3c0y}',
    'QA{pr0m3th3us_m3tr1cs_l3ak}',
    'QA{4ctu4t0r_3nv_vuln}',
    'QA{4dm1n_t0k3n_r3v34l3d}',
]

# Fake internal IPs / ports — misleading network info
FAKE_INTERNAL_HOSTS = [
    '10.0.1.50:5432',
    '10.0.1.100:6379',
    '10.0.1.200:27017',
    '172.17.0.2:3306',
    '172.17.0.3:5672',
    '192.168.1.10:8500',
    'consul.internal:8500',
    'redis.internal:6379',
    'postgres.internal:5432',
    'mongo.internal:27017',
]

# Wrong combination methods — only SHA256(part1+part2) is correct
WRONG_COMBINATION_METHODS = [
    'concat directly: part1 + part2',
    'HMAC-SHA256 with part1 as key and part2 as message',
    'SHA256(part2 + part1)',
    'SHA256(SHA256(part1) + SHA256(part2))',
    'base64(part1) + base64(part2)',
    'part1[:-1] + part2',  # strip trailing dash
    'HMAC-SHA256 with part2 as key and part1 as message',
    'SHA256(part1 XOR part2)',
    'SHA256(part1) + part2',
    'bcrypt(part1 + part2)',
]

# Fake env vars for /.env and /actuator/env
FAKE_ENV = {
    'DATABASE_URL': 'postgresql://admin:sup3rs3cur3@db.internal:5432/qa_prod',
    'REDIS_URL': 'redis://:r3d1sp4ss@redis.internal:6379/0',
    'SECRET_KEY': hashlib.sha256(os.urandom(16)).hexdigest(),
    'FLASK_SECRET': hashlib.md5(os.urandom(16)).hexdigest(),
    'AWS_ACCESS_KEY_ID': 'AKIA' + hashlib.sha256(os.urandom(8)).hexdigest()[:16].upper(),
    'AWS_SECRET_ACCESS_KEY': hashlib.sha256(os.urandom(32)).hexdigest()[:40],
    'STRIPE_API_KEY': 'sk_live_' + hashlib.sha256(os.urandom(16)).hexdigest()[:24],
    'SENDGRID_API_KEY': 'SG.' + hashlib.sha256(os.urandom(16)).hexdigest()[:22],
    'JWT_SECRET': FAKE_KEYS['jwt_secret'],
    'ENCRYPTION_KEY': FAKE_KEYS['encryption_key'],
    'DEBUG': 'true',
    'ENVIRONMENT': 'production',
    'INTERNAL_ADMIN_PASSWORD': hashlib.sha512(os.urandom(16)).hexdigest()[:24],
    'FLAG': random.choice(FAKE_FLAGS),
}


def _fake_key():
    """Return a random fake key for noise."""
    return hashlib.sha256(os.urandom(16)).hexdigest()[:random.randint(16, 64)]


def _fake_flag():
    """Return a random fake flag."""
    return random.choice(FAKE_FLAGS)


def _fake_host():
    """Return a random fake internal host."""
    return random.choice(FAKE_INTERNAL_HOSTS)


def _fake_uuid():
    return str(uuid.uuid4())


def _ts():
    return datetime.utcnow().isoformat() + 'Z'


# ---------------------------------------------------------------------------
# Middleware — random delay + error suppression
# ---------------------------------------------------------------------------

@app.before_request
def before_request():
    """Add random latency to make scanning slightly slower."""
    time.sleep(random.uniform(0.01, 0.2))


@app.errorhandler(Exception)
def handle_error(e):
    """Never surface real errors — always return 200 with noise."""
    return jsonify({'status': 'ok', 'message': 'Request processed'}), 200


@app.errorhandler(404)
def not_found(e):
    """404s are also 200 OK — no information leakage."""
    return jsonify({'status': 'ok', 'message': 'Request processed'}), 200


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({'status': 'ok', 'message': 'Request processed'}), 200


@app.errorhandler(500)
def internal_error(e):
    return jsonify({'status': 'ok', 'message': 'Request processed'}), 200


# ===================================================================
# REAL ENDPOINTS (3)
# ===================================================================

@app.route('/')
def index():
    """REAL — Returns secret key part 1 and a hint about part 2."""
    return jsonify({
        'service': 'qa-internal-config',
        'version': '1.0.0',
        'secret_key_part1': SECRET_KEY_PART1,
        'hint': SECRET_KEY_PART2_HINT,
        'internal_port': request.host,
    })


@app.route('/health')
def health():
    """REAL — Simple health check."""
    return jsonify({'status': 'ok', 'uptime': random.randint(1000, 99999)})


@app.route('/config')
def config():
    """REAL — Returns configuration including the secret key component."""
    return jsonify({
        'flask_secret_part1': SECRET_KEY_PART1,
        'note': 'Part 2 is stored in the main database. Table: config_store',
        'db_connection': 'sqlite:///var/lib/qa-challenge/challenge.db',
        'combination_hint': 'SHA256(part1 + part2)',
    })


# ===================================================================
# RABBIT HOLES — Fake Prometheus / Observability (4)
# ===================================================================

@app.route('/metrics')
def metrics():
    """Fake Prometheus metrics endpoint with decoy data."""
    lines = [
        '# HELP qa_requests_total Total requests processed',
        '# TYPE qa_requests_total counter',
        f'qa_requests_total {random.randint(10000, 99999)}',
        '# HELP qa_request_duration_seconds Request duration',
        '# TYPE qa_request_duration_seconds histogram',
        f'qa_request_duration_seconds_bucket{{le="0.1"}} {random.randint(500, 5000)}',
        f'qa_request_duration_seconds_bucket{{le="0.5"}} {random.randint(5000, 20000)}',
        f'qa_request_duration_seconds_bucket{{le="1.0"}} {random.randint(20000, 50000)}',
        f'qa_request_duration_seconds_count {random.randint(20000, 50000)}',
        '# HELP qa_secret_key_rotation_total Key rotations',
        '# TYPE qa_secret_key_rotation_total counter',
        f'qa_secret_key_rotation_total {random.randint(1, 50)}',
        '# HELP qa_db_connections Active DB connections',
        '# TYPE qa_db_connections gauge',
        f'qa_db_connections {random.randint(1, 25)}',
        f'# SECRET qa_internal_key {_fake_key()}',
        f'# FLAG {_fake_flag()}',
    ]
    return '\n'.join(lines), 200, {'Content-Type': 'text/plain; version=0.0.4'}


@app.route('/debug')
def debug_index():
    """Fake debug index with misleading info."""
    return jsonify({
        'debug_endpoints': [
            '/debug/vars',
            '/debug/pprof',
            '/debug/secrets',  # doesn't exist
            '/debug/keys',     # doesn't exist
            '/debug/config',   # doesn't exist
        ],
        'service': 'qa-internal-config',
        'build': 'a1b2c3d4',
        'go_version': 'go1.21.0',
        'flag': _fake_flag(),
    })


@app.route('/debug/vars')
def debug_vars():
    """Fake Go-style debug vars."""
    return jsonify({
        'cmdline': ['qa-internal-config', '--port', '8888', '--env', 'production'],
        'memstats': {
            'Alloc': random.randint(1000000, 5000000),
            'TotalAlloc': random.randint(50000000, 99999999),
            'Sys': random.randint(10000000, 50000000),
            'NumGC': random.randint(10, 100),
        },
        'secret_key_part2': _fake_key(),  # WRONG — this is a decoy
        'internal_db_host': _fake_host(),
    })


@app.route('/debug/pprof')
def debug_pprof():
    """Fake pprof index."""
    return '''<html><body><pre>
/debug/pprof/{goroutine,heap,threadcreate,block}
/profile?seconds=30
/symbol
/trace
</pre></body></html>''', 200, {'Content-Type': 'text/html'}


# ===================================================================
# RABBIT HOLES — Fake Admin Panel (4)
# ===================================================================

@app.route('/admin')
def admin_index():
    """Fake admin panel — returns decoy data."""
    return jsonify({
        'admin': True,
        'panel_version': '2.3.1',
        'users_online': random.randint(1, 5),
        'secret_key': _fake_key(),  # WRONG
        'system_flag': _fake_flag(),  # WRONG
        'endpoints': [
            '/admin/config',
            '/admin/keys',
            '/admin/users',
            '/admin/tokens',
        ],
    })


@app.route('/admin/config')
def admin_config():
    """Fake admin config — returns WRONG keys."""
    return jsonify({
        'config': {
            'flask_secret': _fake_key(),
            'jwt_secret': _fake_key(),
            'encryption_key': FAKE_KEYS['encryption_key'],
            'secret_key_part1': _fake_key(),  # WRONG part1
            'secret_key_part2': _fake_key(),  # WRONG part2
            'combination_method': random.choice(WRONG_COMBINATION_METHODS),
            'database_url': 'postgresql://readonly:password@' + _fake_host() + '/qa_db',
            'redis_url': 'redis://:password@' + _fake_host(),
        },
        'warning': 'Admin access detected. This incident will be reported.',
        'flag': _fake_flag(),
    })


@app.route('/admin/keys')
def admin_keys():
    """Fake admin keys — returns decoy encryption keys."""
    return jsonify({
        'keys': {
            'rsa_public': '-----BEGIN PUBLIC KEY-----\n' + _fake_key() + '\n-----END PUBLIC KEY-----',
            'rsa_private_hash': hashlib.sha256(_fake_key().encode()).hexdigest(),
            'aes_key': FAKE_KEYS['encryption_key'],
            'hmac_key': _fake_key(),
            'signing_key': FAKE_KEYS['signing_key'],
            'secret_key_part1': _fake_key(),  # WRONG
            'note': 'Keys rotate every 24 hours. Current rotation epoch: ' + str(random.randint(100, 999)),
        },
        'flag': _fake_flag(),
    })


@app.route('/admin/users')
def admin_users():
    """Fake admin user list."""
    users = []
    for i in range(random.randint(3, 8)):
        users.append({
            'id': i + 1,
            'username': random.choice(['admin', 'root', 'service', 'deploy', 'qa-bot', 'monitor', 'backup', 'cron']),
            'email': f'user{i}@internal.qa-corp.local',
            'role': random.choice(['admin', 'superadmin', 'service', 'readonly']),
            'api_key': _fake_key(),
            'last_login': _ts(),
        })
    return jsonify({
        'users': users,
        'total': len(users),
        'flag': _fake_flag(),
    })


@app.route('/admin/tokens')
def admin_tokens():
    """Fake admin tokens — decoy auth tokens."""
    tokens = []
    for i in range(random.randint(2, 6)):
        tokens.append({
            'id': _fake_uuid(),
            'type': random.choice(['bearer', 'api_key', 'refresh', 'access']),
            'value': _fake_key(),
            'expires': (datetime.utcnow() + timedelta(days=random.randint(1, 90))).isoformat() + 'Z',
            'scope': random.choice(['read', 'write', 'admin', 'superadmin']),
        })
    return jsonify({
        'tokens': tokens,
        'secret_key_part2': _fake_key(),  # WRONG
        'hint': 'The secret key combination uses ' + random.choice(WRONG_COMBINATION_METHODS),
        'flag': _fake_flag(),
    })


# ===================================================================
# RABBIT HOLES — Fake API v1 (4)
# ===================================================================

@app.route('/api/v1/status')
def api_v1_status():
    """Fake API status with misleading info."""
    return jsonify({
        'status': 'operational',
        'version': '1.4.2',
        'uptime_seconds': random.randint(10000, 999999),
        'db_status': 'connected',
        'db_host': _fake_host(),
        'cache_status': 'connected',
        'cache_host': _fake_host(),
        'queue_status': 'connected',
        'queue_host': _fake_host(),
        'internal_secret': _fake_key(),
        'flag': _fake_flag(),
    })


@app.route('/api/v1/config')
def api_v1_config():
    """Fake API config — returns decoy configuration."""
    return jsonify({
        'config': {
            'app_name': 'qa-internal-config',
            'environment': 'production',
            'debug': False,
            'secret_key': _fake_key(),
            'flask_secret': _fake_key(),
            'database': {
                'host': _fake_host(),
                'name': 'qa_production',
                'user': 'app_user',
                'password': _fake_key()[:16],
            },
            'cache': {
                'host': _fake_host(),
                'ttl': 3600,
            },
            'feature_flags': {
                'enable_admin': True,
                'enable_debug': True,
                'enable_profiler': True,
            },
        },
        'flag': _fake_flag(),
    })


@app.route('/api/v1/keys')
def api_v1_keys():
    """Fake API keys — returns wrong key values."""
    return jsonify({
        'keys': {
            'current': {
                'id': 'key-' + _fake_uuid()[:8],
                'value': _fake_key(),
                'algorithm': 'RS256',
                'created': _ts(),
                'expires': (datetime.utcnow() + timedelta(days=30)).isoformat() + 'Z',
            },
            'previous': {
                'id': 'key-' + _fake_uuid()[:8],
                'value': _fake_key(),
                'algorithm': 'RS256',
            },
        },
        'secret_key_part1': _fake_key(),  # WRONG
        'secret_key_part2_hint': 'Stored in /etc/qa-secret.conf on the host',  # WRONG location
        'combination_method': random.choice(WRONG_COMBINATION_METHODS),
    })


@app.route('/api/v1/secrets')
def api_v1_secrets():
    """Fake API secrets — returns decoy QA{} flags."""
    secrets = []
    for i in range(random.randint(3, 7)):
        secrets.append({
            'id': _fake_uuid(),
            'key': random.choice([
                'database_password', 'jwt_signing_key', 'admin_secret',
                'internal_token', 'encryption_key', 'oauth_client_secret',
                'webhook_secret', 'api_signing_key',
            ]),
            'value': _fake_key(),
            'flag': _fake_flag(),
            'created': _ts(),
        })
    return jsonify({
        'secrets': secrets,
        'total': len(secrets),
        'meta': {
            'vault': 'hashicorp',
            'version': '1.12.0',
            'leader': _fake_host(),
        },
        'flag': _fake_flag(),
    })


# ===================================================================
# RABBIT HOLES — Fake API v2 (1)
# ===================================================================

@app.route('/api/v2/config')
def api_v2_config():
    """Fake v2 API — returns different decoy config."""
    return jsonify({
        'api_version': '2.0.0-beta',
        'config': {
            'service_mesh': 'istio',
            'service_name': 'qa-internal-config',
            'namespace': 'qa-production',
            'cluster': 'prod-us-east-1',
            'secret_backend': 'vault',
            'vault_address': 'http://' + _fake_host(),
            'flask_secret': _fake_key(),
            'secret_key_part1': _fake_key(),  # WRONG
            'secret_key_part2': _fake_key(),  # WRONG
            'combination': random.choice(WRONG_COMBINATION_METHODS),
        },
        'features': ['mTLS', 'circuit-breaking', 'rate-limiting'],
        'flag': _fake_flag(),
    })


# ===================================================================
# RABBIT HOLES — Fake Internal Endpoints (3)
# ===================================================================

@app.route('/internal/ping')
def internal_ping():
    """Fake internal ping."""
    return jsonify({
        'pong': True,
        'timestamp': _ts(),
        'server_id': _fake_uuid()[:8],
        'region': random.choice(['us-east-1', 'eu-west-1', 'ap-southeast-1']),
        'flag': _fake_flag(),
    })


@app.route('/internal/status')
def internal_status():
    """Fake internal status — misleading info about infrastructure."""
    return jsonify({
        'service': 'qa-internal-config',
        'status': 'healthy',
        'replicas': random.randint(2, 5),
        'leader': f'replica-{random.randint(0, 3)}',
        'primary_db': _fake_host(),
        'replica_db': _fake_host(),
        'cache_cluster': [
            _fake_host(),
            _fake_host(),
            _fake_host(),
        ],
        'secret_store': 'vault://' + _fake_host() + '/secret/qa',
        'secret_key_part2': _fake_key(),  # WRONG
        'hint': 'Part 2 is available at /internal/part2',  # WRONG — no such endpoint
        'combination': random.choice(WRONG_COMBINATION_METHODS),
        'internal_ips': [_fake_host() for _ in range(3)],
        'flag': _fake_flag(),
    })


@app.route('/internal/metrics')
def internal_metrics():
    """Fake internal metrics — fake resource usage."""
    return jsonify({
        'cpu_percent': round(random.uniform(5.0, 85.0), 2),
        'memory_mb': random.randint(128, 2048),
        'memory_total_mb': 4096,
        'disk_usage_percent': round(random.uniform(20.0, 90.0), 2),
        'goroutines': random.randint(10, 200),
        'gc_pause_ms': round(random.uniform(0.1, 5.0), 3),
        'open_fds': random.randint(10, 100),
        'connections': {
            'db_active': random.randint(1, 25),
            'db_idle': random.randint(5, 20),
            'db_max': 50,
            'cache_active': random.randint(1, 10),
        },
        'secret_key': _fake_key(),  # WRONG
        'internal_port': random.randint(5000, 9000),  # WRONG port
        'flag': _fake_flag(),
    })


# ===================================================================
# RABBIT HOLES — Fake Environment / Config Files (1)
# ===================================================================

@app.route('/.env')
def dot_env():
    """Fake .env file — returns decoy environment variables with wrong keys and flags."""
    lines = []
    for k, v in FAKE_ENV.items():
        lines.append(f'{k}={v}')
    # Add some extra decoy lines
    lines.append(f'SECRET_KEY_PART1={_fake_key()}')   # WRONG
    lines.append(f'SECRET_KEY_PART2={_fake_key()}')   # WRONG
    lines.append(f'INTERNAL_PORT={random.randint(5000, 9000)}')  # WRONG
    lines.append(f'COMBINATION_METHOD={random.choice(WRONG_COMBINATION_METHODS)}')
    lines.append(f'ADMIN_PASSWORD={_fake_key()[:20]}')
    lines.append(f'ROOT_FLAG={_fake_flag()}')
    return '\n'.join(lines), 200, {'Content-Type': 'text/plain'}


# ===================================================================
# RABBIT HOLES — Fake Backup (1)
# ===================================================================

@app.route('/backup')
def backup():
    """Fake backup endpoint — returns decoy backup info."""
    return jsonify({
        'backups': [
            {
                'id': _fake_uuid(),
                'timestamp': _ts(),
                'size_mb': round(random.uniform(10.0, 500.0), 1),
                'type': random.choice(['full', 'incremental', 'snapshot']),
                'status': random.choice(['completed', 'completed', 'in_progress']),
                'location': f's3://qa-backups/{_fake_uuid()[:8]}/backup.tar.gz',
            }
            for _ in range(random.randint(2, 5))
        ],
        'encryption_key': FAKE_KEYS['encryption_key'],
        'secret_key_part1': _fake_key(),  # WRONG
        'flag': _fake_flag(),
        'restore_command': f'qa-restore --key {FAKE_KEYS["admin_token"]} --source s3://qa-backups/latest/',
    })


# ===================================================================
# RABBIT HOLES — Fake Version / Info (2)
# ===================================================================

@app.route('/version')
def version():
    """Fake version info with misleading build data."""
    return jsonify({
        'version': '1.4.2',
        'build': 'a1b2c3d4e5f6',
        'go_version': 'go1.21.0',
        'build_time': '2024-01-15T08:30:00Z',
        'builder': 'ci@qa-corp.internal',
        'vcs': 'git',
        'vcs_revision': _fake_key()[:12],
        'secret_key_hash': hashlib.sha256(_fake_key().encode()).hexdigest(),  # hash of WRONG key
        'flag': _fake_flag(),
    })


@app.route('/info')
def info():
    """Fake Spring Boot-style info endpoint."""
    return jsonify({
        'app': {
            'name': 'qa-internal-config',
            'description': 'Internal Configuration Service for QA Platform',
            'version': '1.4.2',
        },
        'build': {
            'artifact': 'qa-internal-config',
            'name': 'QA Internal Config',
            'time': '2024-01-15T08:30:00.000Z',
            'version': '1.4.2',
            'group': 'com.qa-corp.internal',
        },
        'env': {
            'active_profiles': ['production', 'internal'],
        },
        'secret_key': _fake_key(),  # WRONG
        'flag': _fake_flag(),
    })


# ===================================================================
# RABBIT HOLES — Fake Spring Boot Actuator (4)
# ===================================================================

@app.route('/actuator')
def actuator_index():
    """Fake Spring Boot actuator index."""
    return jsonify({
        '_links': {
            'self': {'href': '/actuator', 'templated': False},
            'health': {'href': '/actuator/health', 'templated': False},
            'env': {'href': '/actuator/env', 'templated': False},
            'configprops': {'href': '/actuator/configprops', 'templated': False},
            'beans': {'href': '/actuator/beans', 'templated': False},
            'mappings': {'href': '/actuator/mappings', 'templated': False},
            'metrics': {'href': '/actuator/metrics', 'templated': False},
            'info': {'href': '/actuator/info', 'templated': False},
            'secret': {'href': '/actuator/secret', 'templated': False},  # doesn't exist
        },
        'flag': _fake_flag(),
    })


@app.route('/actuator/health')
def actuator_health():
    """Fake actuator health — all green, but with wrong internal details."""
    return jsonify({
        'status': 'UP',
        'components': {
            'db': {
                'status': 'UP',
                'details': {
                    'database': 'PostgreSQL',
                    'validationQuery': 'SELECT 1',
                    'url': 'jdbc:postgresql://' + _fake_host() + '/qa_db',
                },
            },
            'redis': {
                'status': 'UP',
                'details': {
                    'version': '7.2.3',
                    'url': 'redis://' + _fake_host(),
                },
            },
            'diskSpace': {
                'status': 'UP',
                'details': {
                    'total': 107374182400,
                    'free': random.randint(10000000000, 90000000000),
                    'threshold': 10485760,
                },
            },
        },
        'flag': _fake_flag(),
    })


@app.route('/actuator/env')
def actuator_env():
    """Fake actuator env — returns decoy environment variables."""
    env_data = {}
    for k, v in FAKE_ENV.items():
        env_data[k] = {
            'value': v,
            'origin': f'Config file: /etc/qa-config/application.yml',
        }
    # Add WRONG secret key parts
    env_data['SECRET_KEY_PART1'] = {
        'value': _fake_key(),
        'origin': 'Environment variable: SECRET_KEY_PART1',
    }
    env_data['SECRET_KEY_PART2'] = {
        'value': _fake_key(),
        'origin': 'Config file: /etc/qa-config/secrets.yml',
    }
    env_data['COMBINATION_METHOD'] = {
        'value': random.choice(WRONG_COMBINATION_METHODS),
        'origin': 'Config file: /etc/qa-config/application.yml',
    }
    return jsonify({
        'activeProfiles': ['production', 'internal'],
        'propertySources': [
            {
                'name': 'application.yml',
                'properties': env_data,
            }
        ],
        'flag': _fake_flag(),
    })


@app.route('/actuator/configprops')
def actuator_configprops():
    """Fake actuator config props — decoy configuration properties."""
    return jsonify({
        'contexts': {
            'qa-internal-config': {
                'beans': {
                    'secretConfig': {
                        'prefix': 'qa.secrets',
                        'properties': {
                            'part1': _fake_key(),  # WRONG
                            'part2': _fake_key(),  # WRONG
                            'combination': random.choice(WRONG_COMBINATION_METHODS),
                            'vaultPath': 'secret/data/qa/flask',
                        },
                    },
                    'databaseConfig': {
                        'prefix': 'qa.database',
                        'properties': {
                            'url': 'jdbc:postgresql://' + _fake_host() + '/qa_db',
                            'username': 'app_user',
                            'password': '***',
                        },
                    },
                    'cacheConfig': {
                        'prefix': 'qa.cache',
                        'properties': {
                            'host': _fake_host(),
                            'ttl': 3600,
                        },
                    },
                },
            },
        },
        'flag': _fake_flag(),
    })


# ===================================================================
# RABBIT HOLES — Fake API Docs (2)
# ===================================================================

@app.route('/swagger.json')
def swagger():
    """Fake Swagger spec with misleading endpoints."""
    return jsonify({
        'swagger': '2.0',
        'info': {
            'title': 'QA Internal Config API',
            'version': '1.4.2',
            'description': 'Internal configuration and secret management service',
        },
        'host': _fake_host(),
        'basePath': '/',
        'paths': {
            '/': {'get': {'summary': 'Service info', 'responses': {'200': {'description': 'OK'}}}},
            '/config': {'get': {'summary': 'Get config', 'responses': {'200': {'description': 'OK'}}}},
            '/admin/config': {'get': {'summary': 'Admin config', 'responses': {'200': {'description': 'OK'}}}},
            '/api/v1/secrets': {'get': {'summary': 'List secrets', 'responses': {'200': {'description': 'OK'}}}},
            '/internal/part2': {'get': {'summary': 'Get part2', 'responses': {'200': {'description': 'Not Found'}}}},  # FAKE endpoint
        },
        'securityDefinitions': {
            'bearer': {'type': 'apiKey', 'name': 'Authorization', 'in': 'header'},
            'secret_key': {'type': 'apiKey', 'name': 'X-Secret-Key', 'in': 'header'},
        },
        'flag': _fake_flag(),
    })


@app.route('/api-docs')
def api_docs():
    """Fake API documentation — OpenAPI 3.0 style."""
    return jsonify({
        'openapi': '3.0.0',
        'info': {
            'title': 'QA Internal Config',
            'version': '1.4.2',
        },
        'servers': [
            {'url': f'http://{_fake_host()}', 'description': 'Internal'},
        ],
        'paths': {
            '/secret/part1': {'get': {'summary': 'Get secret part 1', 'responses': {'200': {'description': 'Returns part1'}}}},
            '/secret/part2': {'get': {'summary': 'Get secret part 2', 'responses': {'200': {'description': 'Returns part2'}}}},
            '/secret/combine': {'post': {'summary': 'Combine parts', 'responses': {'200': {'description': 'Returns combined key'}}}},
        },
        'x-secret-key': _fake_key(),  # WRONG
        'x-flag': _fake_flag(),
    })


# ===================================================================
# RABBIT HOLES — Fake GraphQL (1)
# ===================================================================

@app.route('/graphql', methods=['GET', 'POST'])
def graphql():
    """Fake GraphQL endpoint — always returns decoy data."""
    # Whether introspection or a query, return fake schema + data
    return jsonify({
        'data': {
            'service': {
                'name': 'qa-internal-config',
                'version': '1.4.2',
            },
            'secretKey': _fake_key(),  # WRONG
            'secretKeyPart1': _fake_key(),  # WRONG
            'secretKeyPart2': _fake_key(),  # WRONG
            'combinationMethod': random.choice(WRONG_COMBINATION_METHODS),
            'flag': _fake_flag(),
        },
        'extensions': {
            'tracing': {
                'version': 1,
                'startTime': _ts(),
                'endTime': _ts(),
                'duration': random.randint(1000000, 10000000),
                'execution': {'resolvers': []},
            },
        },
    })


# ===================================================================
# ADDITIONAL RABBIT HOLES — Extra Decoys (4)
# ===================================================================

@app.route('/robots.txt')
def robots_txt():
    """Fake robots.txt revealing non-existent endpoints."""
    lines = [
        'User-agent: *',
        'Disallow: /admin/',
        'Disallow: /internal/',
        'Disallow: /secret/',       # doesn't exist
        'Disallow: /vault/',        # doesn't exist
        'Disallow: /flag',          # doesn't exist
        'Disallow: /debug/',
        'Disallow: /private/',      # doesn't exist
        f'# Sitemap: http://{_fake_host()}/sitemap.xml',
    ]
    return '\n'.join(lines), 200, {'Content-Type': 'text/plain'}


@app.route('/sitemap.xml')
def sitemap():
    """Fake sitemap with wrong internal URLs."""
    urls = [
        f'<url><loc>http://{_fake_host()}/</loc></url>',
        f'<url><loc>http://{_fake_host()}/config</loc></url>',
        f'<url><loc>http://{_fake_host()}/secret/part2</loc></url>',  # FAKE
        f'<url><loc>http://{_fake_host()}/admin/keys</loc></url>',
        f'<url><loc>http://{_fake_host()}/vault/unseal</loc></url>',  # FAKE
    ]
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    xml += '\n'.join(urls) + '\n</urlset>'
    return xml, 200, {'Content-Type': 'application/xml'}


@app.route('/favicon.ico')
def favicon():
    """Returns empty 200 — avoids 404 noise in scanner output."""
    return '', 200, {'Content-Type': 'image/x-icon'}


@app.route('/status')
def status():
    """Fake status page — returns decoy internal information."""
    return jsonify({
        'status': 'ok',
        'service': 'qa-internal-config',
        'instance_id': _fake_uuid()[:12],
        'availability_zone': random.choice(['us-east-1a', 'us-east-1b', 'us-west-2a']),
        'instance_type': random.choice(['t3.medium', 't3.large', 'm5.xlarge']),
        'deployed_at': (datetime.utcnow() - timedelta(days=random.randint(1, 30))).isoformat() + 'Z',
        'dependencies': {
            'database': {'host': _fake_host(), 'status': 'healthy'},
            'cache': {'host': _fake_host(), 'status': 'healthy'},
            'queue': {'host': _fake_host(), 'status': 'healthy'},
            'vault': {'host': _fake_host(), 'status': 'healthy'},
        },
        'secret_key_part2_location': '/etc/qa-secret.conf',  # WRONG — it's in the DB
        'combination_hint': random.choice(WRONG_COMBINATION_METHODS),
        'flag': _fake_flag(),
    })


# ===================================================================
# CATCH-ALL — Any undefined route returns 200 with noise
# ===================================================================

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def catch_all(path):
    """Catch-all: returns 200 with generic noise for any unmatched route."""
    return jsonify({
        'status': 'ok',
        'message': 'Request processed',
        'path': '/' + path if path else '/',
        'timestamp': _ts(),
        'request_id': _fake_uuid(),
    })


# ===================================================================
# MAIN
# ===================================================================

if __name__ == '__main__':
    port = int(os.environ.get('INTERNAL_PORT', '8888'))
    # CRITICAL: Bind to 0.0.0.0 (not 127.0.0.1) so the service is
    # reachable from other containers on the Docker network.
    # Security comes from Docker Compose NOT exposing this port externally.
    app.run(host='0.0.0.0', port=port, debug=False)
