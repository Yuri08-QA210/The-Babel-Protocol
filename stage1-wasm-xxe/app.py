"""
QA CTF Challenge — Stage 1: Wasm + XXE + SSRF (ULTRA FRUSTRATING — 70+ Rabbit Holes)
=====================================================================================
Rules of engagement:
- ALL responses return 200 OK — NEVER leak errors
- Random delay 50-500ms on every request (anti-timing)
- Block CTF tools silently (return 200 with garbage)
- X-Request-Id header mandatory for /api/parse
- Wasm validation REQUIRED — no plaintext fallback for XML tags
- XXE is OOB only — response never contains entity content
- SSRF to internal service for secret key part1
- Flag hidden in noise-filled response with 3-5 decoy QA{...} strings
- Rate limit: 5 req/10s for /api/parse
- 70+ rabbit hole endpoints with plausible but useless data
- Some endpoints return fake QA{...} flags (decoys)
- Some leak fake internal IPs and ports
- Some return fake API keys and tokens
- Some return partial XML schemas that are wrong
- Fake debug info that looks like it should work
- Version strings that suggest vulnerabilities that don't exist
- Comments in responses that reference non-existent features
"""

import os, re, uuid, time, random, hashlib, logging, subprocess, json, threading, base64
from functools import wraps
from collections import defaultdict
from flask import Flask, request, jsonify, Response, make_response, session
from lxml import etree

logging.basicConfig(level=logging.WARNING)
logger = logging.getLogger('stage1')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', 'default-dev-key-change-me')

STAGE1_FLAG = os.environ.get('STAGE1_FLAG', 'QA{w4sm_r3v3rs1ng_xxe_00b_ssrf_ch41n}')
INTERNAL_SERVICE_HOST = os.environ.get('INTERNAL_SERVICE_HOST', 'internal-service')
INTERNAL_SERVICE_PORT = os.environ.get('INTERNAL_SERVICE_PORT', '8888')

# ============================================================
# VALID XML TAGS — Wasm only, no fallback
# ============================================================
VALID_XML_TAGS = None  # Set by Wasm initialization
DECOY_XML_TAGS = [
    'flag', 'admin', 'token', 'debug', 'root', 'secret',
    'key', 'config', 'password', 'private', 'auth', 'credential'
]

# Fake internal IPs for red herrings
FAKE_INTERNAL_IPS = [
    '10.0.1.50', '10.0.1.100', '172.16.0.5', '192.168.1.200',
    '10.0.2.15', '172.17.0.3', '192.168.100.1', '10.10.10.10',
    '127.0.0.1', '0.0.0.0', '169.254.169.254'
]
FAKE_PORTS = [3000, 3306, 5432, 6379, 8080, 8443, 9090, 27017, 9200, 5601, 8888, 9999]

# Decoy flags — look real but are garbage
DECOY_FLAGS_POOL = [
    'QA{d3c0y_f1ag_n0t_r3al_001}',
    'QA{adm1n_b4ckd00r_f4ke_002}',
    'QA{xm1_pr0c3ss0r_h1nt_003}',
    'QA{w4sm_l04d3r_k3y_004}',
    'QA{ssrf_int3rn4l_p0rt_005}',
    'QA{d3bug_m0d3_3n4bl3d_006}',
    'QA{sql1_1nj3ct10n_h3r3_007}',
    'QA{t3mpl4t3_1nj3ct_008}',
    'QA{c00k13_s3cr3t_k3y_009}',
    'QA{jw_t0k3n_s3cr3t_010}',
    'QA{xxe_bl1nd_p4yl04d_011}',
    'QA{r3d1s_4uth_p4ss_012}',
    'QA{1nt3rn4l_4p1_k3y_013}',
    'QA{3nv_f1l3_l34k3d_014}',
    'QA{g1t_c0mm1ts_l34k_015}',
]

def random_decoy_flag():
    return random.choice(DECOY_FLAGS_POOL)

def random_hex(n=8):
    return hashlib.md5(os.urandom(16)).hexdigest()[:n]

def random_uuid():
    return str(uuid.uuid4())

def random_ip():
    return random.choice(FAKE_INTERNAL_IPS)

def random_port():
    return random.choice(FAKE_PORTS)


# ============================================================
# WASM INITIALIZATION
# ============================================================
def init_wasm_tags():
    """Initialize valid tags from Wasm module. No plaintext fallback."""
    global VALID_XML_TAGS
    try:
        result = subprocess.run(
            ['node', '-e', '''
const WasmValidator = require("./wasm_loader.js");
async function main() {
    const v = new WasmValidator();
    await v.init();
    const tags = v.getValidTags();
    console.log(JSON.stringify(tags));
}
main().catch(e => { console.error("[]"); process.exit(1); });
'''],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            tags = json.loads(result.stdout.strip())
            if tags and len(tags) >= 3:
                VALID_XML_TAGS = tags
                logger.info(f"WASM init success — {len(tags)} tags loaded")
                return
    except Exception as e:
        logger.warning(f"WASM init exception: {e}")
    # CRITICAL: If Wasm fails, server uses empty tag set — NO fallback
    VALID_XML_TAGS = None
    logger.error("WASM INIT FAILED — no valid tags available")


def validate_tag(tag_name):
    """Validate tag via Wasm. Returns (is_valid, is_decoy)."""
    if VALID_XML_TAGS is None:
        return False, False
    if tag_name in VALID_XML_TAGS:
        return True, False
    if tag_name in DECOY_XML_TAGS:
        return False, True  # decoy detected!
    return False, False


# ============================================================
# ANTI-TOOL DETECTION
# ============================================================
BLOCKED_UA = [
    'sqlmap', 'nikto', 'dirb', 'dirbuster', 'gobuster', 'wfuzz',
    'burpsuite', 'burp', 'nmap', 'masscan', 'hydra', 'medusa',
    'zap', 'arachni', 'w3af', 'acunetix', 'nessus', 'openvas',
    'wpscan', 'ffuf', 'feroxbuster', 'httpx', 'nuclei',
]

def is_tool():
    ua = request.headers.get('User-Agent', '').lower()
    for t in BLOCKED_UA:
        if t in ua:
            return True
    if request.headers.get('X-Scanner') or request.headers.get('X-Forwarded-Scan'):
        return True
    if request.headers.get('X-Scan-ID'):
        return True
    return False


# ============================================================
# RATE LIMITING
# ============================================================
RATE_LIMIT_STORE = defaultdict(list)
RATE_LOCK = threading.Lock()

def check_rate_limit(ip, endpoint, max_requests=5, window_seconds=10):
    now = time.time()
    key = f"{ip}:{endpoint}"
    with RATE_LOCK:
        RATE_LIMIT_STORE[key] = [t for t in RATE_LIMIT_STORE[key] if now - t < window_seconds]
        if len(RATE_LIMIT_STORE[key]) >= max_requests:
            return False
        RATE_LIMIT_STORE[key].append(now)
        return True


# ============================================================
# RESPONSE HELPERS
# ============================================================
def fake_response():
    """Generate a generic 200 response with random noise."""
    return jsonify({
        'status': 'ok',
        'message': 'Request processed',
        'ref': random_uuid(),
        'ts': int(time.time()),
        'noise': random_hex(),
        'meta': {
            'version': '2.1.0',
            'region': random.choice(['us-east', 'eu-west', 'ap-south']),
            'latency_ms': random.randint(10, 200),
        }
    }), 200


def flag_response(flag_value):
    """Hide the flag in a noise-filled response with 3-5 decoy QA{...} strings."""
    decoys = [f"QA{{{hashlib.md5(os.urandom(8)).hexdigest()[:12]}}}" for _ in range(random.randint(3, 5))]
    real_idx = random.randint(0, len(decoys))
    all_flags = decoys[:real_idx] + [flag_value] + decoys[real_idx:]
    return jsonify({
        'status': 'ok',
        'message': 'Request processed',
        'ref': random_uuid(),
        'ts': int(time.time()),
        'noise': random_hex(),
        'data': {
            'entries': [
                {
                    'id': i, 'value': f,
                    'type': random.choice(['cache', 'temp', 'config', 'log', 'archive', 'backup', 'debug']),
                    'priority': random.choice(['low', 'medium', 'high']),
                    'created': f"2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:00Z"
                }
                for i, f in enumerate(all_flags)
            ],
            'total': len(all_flags),
            'offset': random.randint(0, 100),
            'cursor': random_hex(12),
        }
    }), 200


def noise_headers(resp):
    """Add noise headers to any response."""
    resp.headers['X-Debug-Token'] = random_hex(16)
    resp.headers['X-Service-Id'] = 'qa-xml-' + random_hex(8)
    resp.headers['X-Request-Trace'] = random_uuid()
    resp.headers['X-Region'] = random.choice(['us-east-1', 'eu-west-2', 'ap-south-1'])
    resp.headers['X-RateLimit-Remaining'] = str(random.randint(0, 99))
    resp.headers['X-Response-Time'] = f"{random.uniform(0.01, 0.5):.3f}s"
    return resp


# ============================================================
# MIDDLEWARE
# ============================================================
@app.before_request
def before_request_func():
    """Random delay + tool detection."""
    time.sleep(random.uniform(0.05, 0.5))
    if is_tool():
        return fake_response()


# ============================================================
# ERROR HANDLERS — Always 200, never leak
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

@app.errorhandler(400)
def bad_request(e):
    return fake_response()

@app.errorhandler(500)
def server_error(e):
    return fake_response()


# ############################################################
# ############################################################
# ## MAIN FUNCTIONAL ROUTES (the real challenge path)      ##
# ############################################################
# ############################################################

@app.route('/')
def index():
    """Main landing page — beautiful dark cyberpunk CTF interface."""
    # If client wants JSON (API client), return JSON
    accept = request.headers.get('Accept', '')
    if 'application/json' in accept:
        resp = jsonify({
            'service': 'QA-XML-Processor',
            'version': '2.1.0',
            'build': f'build-{random.randint(1000,9999)}',
            'endpoints': {
                '/api/parse': 'POST — Parse and process XML data',
                '/api/health': 'GET — Health check',
                '/api/status': 'GET — Service status',
            },
            'documentation': '/api-docs',
            'note': 'XML processing powered by WebAssembly validator v3.2',
            'ref': random_uuid(),
            'features': ['xml-validation', 'wasm-acceleration', 'entity-resolution', 'schema-validation'],
            'limits': {'max_xml_size': '1MB', 'rate_limit': '100/min'},
        })
        resp.headers['X-Xml-Schema-Version'] = '5'
        resp.headers['X-Internal-Host'] = random_ip()
        resp.headers['Server'] = 'QA-XML/2.1.0 (lxml/4.9.3)'
        return resp

    # Return beautiful HTML landing page
    html = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>The Babel Protocol — QA CTF Challenge</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0a0a0f;color:#e0e0e0;font-family:'Segoe UI',system-ui,-apple-system,sans-serif;min-height:100vh;overflow-x:hidden}
.bg-grid{position:fixed;top:0;left:0;width:100%;height:100%;background-image:linear-gradient(rgba(0,255,170,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,255,170,0.03) 1px,transparent 1px);background-size:50px 50px;z-index:0;pointer-events:none}
.bg-glow{position:fixed;top:-50%;left:-50%;width:200%;height:200%;background:radial-gradient(circle at 30% 50%,rgba(0,255,170,0.05) 0%,transparent 50%),radial-gradient(circle at 70% 30%,rgba(0,170,255,0.05) 0%,transparent 50%);z-index:0;pointer-events:none;animation:drift 20s ease-in-out infinite}
@keyframes drift{0%,100%{transform:translate(0,0)}50%{transform:translate(-2%,1%)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.6}}
@keyframes fadeIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
@keyframes scanline{0%{top:-100%}100%{top:200%}}
.container{max-width:1200px;margin:0 auto;padding:20px;position:relative;z-index:1}
header{text-align:center;padding:60px 20px 40px;animation:fadeIn 1s ease-out}
.logo{font-size:3em;font-weight:900;letter-spacing:8px;background:linear-gradient(135deg,#00ffaa,#00aaff,#ff00aa);-webkit-background-clip:text;-webkit-text-fill-color:transparent;text-shadow:0 0 40px rgba(0,255,170,0.3);margin-bottom:10px}
.subtitle{font-size:1.1em;color:#888;letter-spacing:3px;text-transform:uppercase}
.tagline{font-size:0.9em;color:#555;margin-top:8px;font-style:italic}
.scanline{position:relative;overflow:hidden}
.scanline::after{content:'';position:absolute;left:0;width:100%;height:4px;background:rgba(0,255,170,0.1);animation:scanline 4s linear infinite}
.stages{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:24px;margin:40px 0}
.stage-card{background:linear-gradient(145deg,#111118,#0d0d14);border:1px solid #1a1a2e;border-radius:16px;padding:28px;position:relative;overflow:hidden;transition:all 0.3s ease;animation:fadeIn 0.8s ease-out both}
.stage-card:nth-child(1){animation-delay:0.2s}
.stage-card:nth-child(2){animation-delay:0.4s}
.stage-card:nth-child(3){animation-delay:0.6s}
.stage-card:hover{border-color:#00ffaa44;box-shadow:0 0 30px rgba(0,255,170,0.1);transform:translateY(-4px)}
.stage-card::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;border-radius:16px 16px 0 0}
.stage-card.s1::before{background:linear-gradient(90deg,#00ffaa,#00cc88)}
.stage-card.s2::before{background:linear-gradient(90deg,#00aaff,#0088dd)}
.stage-card.s3::before{background:linear-gradient(90deg,#ff00aa,#dd0088)}
.stage-num{font-size:0.75em;letter-spacing:3px;text-transform:uppercase;margin-bottom:8px;font-weight:600}
.stage-card.s1 .stage-num{color:#00ffaa}
.stage-card.s2 .stage-num{color:#00aaff}
.stage-card.s3 .stage-num{color:#ff00aa}
.stage-title{font-size:1.5em;font-weight:700;margin-bottom:12px;color:#f0f0f0}
.stage-desc{font-size:0.9em;color:#888;line-height:1.6;margin-bottom:16px}
.stage-tech{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:20px}
.tech-tag{font-size:0.7em;padding:4px 10px;border-radius:20px;background:#1a1a2e;border:1px solid #2a2a3e;color:#aaa;letter-spacing:1px}
.stage-card.s1 .tech-tag{border-color:#00ffaa33;color:#00ffaa99}
.stage-card.s2 .tech-tag{border-color:#00aaff33;color:#00aaff99}
.stage-card.s3 .tech-tag{border-color:#ff00aa33;color:#ff00aa99}
.stage-link{display:inline-block;padding:10px 24px;border-radius:8px;text-decoration:none;font-size:0.85em;font-weight:600;letter-spacing:1px;transition:all 0.3s ease}
.stage-card.s1 .stage-link{background:#00ffaa15;border:1px solid #00ffaa44;color:#00ffaa}
.stage-card.s1 .stage-link:hover{background:#00ffaa25;box-shadow:0 0 20px rgba(0,255,170,0.2)}
.stage-card.s2 .stage-link{background:#00aaff15;border:1px solid #00aaff44;color:#00aaff}
.stage-card.s2 .stage-link:hover{background:#00aaff25;box-shadow:0 0 20px rgba(0,170,255,0.2)}
.stage-card.s3 .stage-link{background:#ff00aa15;border:1px solid #ff00aa44;color:#ff00aa}
.stage-card.s3 .stage-link:hover{background:#ff00aa25;box-shadow:0 0 20px rgba(255,0,170,0.2)}
.parser-section{margin:50px 0;animation:fadeIn 1s ease-out 0.8s both}
.section-title{font-size:1.6em;font-weight:700;margin-bottom:8px;color:#f0f0f0}
.section-subtitle{font-size:0.9em;color:#666;margin-bottom:24px}
.parser-box{background:#111118;border:1px solid #1a1a2e;border-radius:16px;padding:24px;position:relative}
.parser-box::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,#00ffaa,#00aaff);border-radius:16px 16px 0 0}
.parser-header{display:flex;align-items:center;gap:8px;margin-bottom:16px}
.status-dot{width:8px;height:8px;border-radius:50%;background:#00ffaa;animation:pulse 2s infinite}
.parser-label{font-size:0.8em;color:#888;letter-spacing:2px;text-transform:uppercase}
textarea{width:100%;min-height:160px;background:#0a0a0f;border:1px solid #1a1a2e;border-radius:8px;color:#e0e0e0;font-family:'Fira Code',monospace;font-size:0.85em;padding:16px;resize:vertical;outline:none;transition:border-color 0.3s}
textarea:focus{border-color:#00ffaa44}
.parser-actions{display:flex;gap:12px;margin-top:16px;align-items:center;flex-wrap:wrap}
.btn{padding:10px 24px;border-radius:8px;border:none;cursor:pointer;font-size:0.85em;font-weight:600;letter-spacing:1px;transition:all 0.3s ease}
.btn-primary{background:linear-gradient(135deg,#00ffaa,#00cc88);color:#0a0a0f}
.btn-primary:hover{box-shadow:0 0 25px rgba(0,255,170,0.4);transform:translateY(-2px)}
.btn-secondary{background:transparent;border:1px solid #2a2a3e;color:#888}
.btn-secondary:hover{border-color:#00ffaa44;color:#00ffaa}
.req-id-group{display:flex;align-items:center;gap:8px;margin-left:auto}
.req-id-group label{font-size:0.75em;color:#666;letter-spacing:1px}
.req-id-group input{background:#0a0a0f;border:1px solid #1a1a2e;border-radius:6px;color:#00ffaa;font-family:monospace;font-size:0.8em;padding:8px 12px;width:200px;outline:none}
.req-id-group input:focus{border-color:#00ffaa44}
.output-area{margin-top:16px;background:#08080d;border:1px solid #1a1a2e;border-radius:8px;padding:16px;min-height:80px;font-family:monospace;font-size:0.8em;color:#aaa;white-space:pre-wrap;word-break:break-all;max-height:300px;overflow-y:auto;display:none}
.output-area.visible{display:block}
.footer-info{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:20px;margin:50px 0 30px;padding:24px;background:#111118;border:1px solid #1a1a2e;border-radius:16px}
.info-item{padding:12px}
.info-label{font-size:0.7em;color:#666;letter-spacing:2px;text-transform:uppercase;margin-bottom:6px}
.info-value{font-size:0.9em;color:#aaa}
.info-value.mono{font-family:monospace;color:#00ffaa99}
footer{text-align:center;padding:30px;color:#333;font-size:0.75em;letter-spacing:2px;border-top:1px solid #111118}
</style>
</head>
<body>
<div class="bg-grid"></div>
<div class="bg-glow"></div>
<div class="container">
<header class="scanline">
<div class="logo">THE BABEL PROTOCOL</div>
<div class="subtitle">QA Security Challenge</div>
<div class="tagline">"Some protocols are meant to be broken"</div>
</header>

<div class="stages">
<div class="stage-card s1">
<div class="stage-num">Stage 1</div>
<div class="stage-title">Wasm + XXE + SSRF</div>
<div class="stage-desc">Reverse the WebAssembly validator to discover valid XML tags, then exploit an Out-of-Band XXE vulnerability chained with SSRF to access internal services and extract secrets.</div>
<div class="stage-tech">
<span class="tech-tag">WebAssembly</span>
<span class="tech-tag">XXE</span>
<span class="tech-tag">SSRF</span>
<span class="tech-tag">OOB</span>
<span class="tech-tag">lxml</span>
</div>
<a href="/api/parse" class="stage-link" onclick="event.preventDefault();document.querySelector('.parser-section').scrollIntoView({behavior:'smooth'})">XML Processor</a>
</div>
<div class="stage-card s2">
<div class="stage-num">Stage 2</div>
<div class="stage-title">SSTI + Session Forge</div>
<div class="stage-desc">Recover the Flask secret key from two parts, forge a session cookie with an SSTI payload, and bypass the Jinja2 sandbox to achieve Remote Code Execution on the portal.</div>
<div class="stage-tech">
<span class="tech-tag">SSTI</span>
<span class="tech-tag">Session</span>
<span class="tech-tag">SHA256</span>
<span class="tech-tag">SQLi</span>
<span class="tech-tag">Jinja2</span>
</div>
<a href="/portal/" class="stage-link">User Portal</a>
</div>
<div class="stage-card s3">
<div class="stage-num">Stage 3</div>
<div class="stage-title">Smuggling + Race</div>
<div class="stage-desc">Exploit HTTP TE.TE request smuggling to inject internal headers, then win a 3ms race condition to extract and decrypt the final flag from the vault.</div>
<div class="stage-tech">
<span class="tech-tag">HTTP Smuggling</span>
<span class="tech-tag">TE.TE</span>
<span class="tech-tag">Race Condition</span>
<span class="tech-tag">XOR</span>
<span class="tech-tag">nginx</span>
</div>
<a href="/api/vault/status" class="stage-link">Vault Backend</a>
</div>
</div>

<div class="parser-section">
<div class="section-title">XML Processor</div>
<div class="section-subtitle">Powered by WebAssembly Validator v3.2 — Submit XML for parsing and validation</div>
<div class="parser-box">
<div class="parser-header">
<div class="status-dot"></div>
<div class="parser-label">XML Parser — Active</div>
</div>
<textarea id="xmlInput" placeholder="Paste your XML here...&#10;&#10;Example:&#10;&lt;?xml version=&quot;1.0&quot; encoding=&quot;UTF-8&quot;?&gt;&#10;&lt;root&gt;&#10;  &lt;data&gt;Hello World&lt;/data&gt;&#10;&lt;/root&gt;"></textarea>
<div class="parser-actions">
<button class="btn btn-primary" onclick="parseXML()">Parse XML</button>
<button class="btn btn-secondary" onclick="clearParser()">Clear</button>
<div class="req-id-group">
<label>X-Request-Id:</label>
<input type="text" id="reqId" placeholder="Required header">
</div>
</div>
<div class="output-area" id="output"></div>
</div>
</div>

<div class="footer-info">
<div class="info-item">
<div class="info-label">Service</div>
<div class="info-value mono">QA-XML-Processor v2.1.0</div>
</div>
<div class="info-item">
<div class="info-label">Documentation</div>
<div class="info-value"><a href="/api-docs" style="color:#00aaff;text-decoration:none">/api-docs</a></div>
</div>
<div class="info-item">
<div class="info-label">Health Status</div>
<div class="info-value"><a href="/api/health" style="color:#00ffaa;text-decoration:none">/api/health</a></div>
</div>
<div class="info-item">
<div class="info-label">Flag Format</div>
<div class="info-value mono">QA{...}</div>
</div>
</div>

<footer>THE BABEL PROTOCOL &mdash; QA SECURITY CHALLENGE &mdash; ALL REQUESTS RETURN 200 OK</footer>
</div>

<script>
function parseXML(){const xml=document.getElementById('xmlInput').value;const reqId=document.getElementById('reqId').value;const output=document.getElementById('output');if(!xml.trim()){output.textContent='[!] No XML input provided';output.classList.add('visible');return}if(!reqId.trim()){output.textContent='[!] X-Request-Id header is required';output.classList.add('visible');return}output.textContent='[...] Processing...';output.classList.add('visible');fetch('/api/parse',{method:'POST',headers:{'Content-Type':'application/xml','X-Request-Id':reqId},body:xml}).then(r=>r.json()).then(d=>{output.textContent=JSON.stringify(d,null,2)}).catch(e=>{output.textContent='[!] Error: '+e.message})}
function clearParser(){document.getElementById('xmlInput').value='';document.getElementById('reqId').value='';const o=document.getElementById('output');o.textContent='';o.classList.remove('visible')}
document.getElementById('reqId').value=crypto.randomUUID?crypto.randomUUID().slice(0,8):Math.random().toString(36).slice(2,10);
</script>
</body>
</html>'''

    resp = make_response(html)
    resp.headers['Content-Type'] = 'text/html; charset=utf-8'
    # Still add red herring headers
    resp.headers['X-Debug-Token'] = random_hex(16)
    resp.headers['X-Service-Id'] = 'qa-xml-' + random_hex(8)
    resp.headers['X-Xml-Schema-Version'] = '5'
    resp.headers['X-Internal-Host'] = random_ip()
    resp.headers['Server'] = 'QA-XML/2.1.0 (lxml/4.9.3)'
    return resp


@app.route('/api/health')
def health():
    return jsonify({
        'status': 'healthy',
        'uptime': random.randint(1000, 99999),
        'ref': random_uuid(),
        'checks': {
            'database': 'ok',
            'cache': 'ok',
            'wasm_module': 'loaded' if VALID_XML_TAGS else 'error',
        }
    }), 200


@app.route('/api/status')
def status():
    """Red herring paradise — leaks fake internal info."""
    resp = jsonify({
        'status': 'running',
        'wasm_loaded': VALID_XML_TAGS is not None,
        'xml_processor': 'lxml 4.9.3',  # True — suggests CVE research
        'uptime': random.randint(1000, 99999),
        'connections': random.randint(10, 500),
        'internal_services': {
            'config-service': f'http://{random_ip()}:{random_port()}',  # FAKE
            'cache-service': f'http://{random_ip()}:{random_port()}',  # FAKE
            'auth-service': f'http://{random_ip()}:{random_port()}',   # FAKE
        },
        'ref': random_uuid(),
    })
    resp.headers['X-Debug-Token'] = random_hex(16)
    resp.headers['X-Service-Id'] = 'qa-xml-' + random_hex(8)
    resp.headers['X-Xml-Schema-Version'] = '5'
    resp.headers['X-Internal-Port'] = str(random_port())  # FAKE port
    return resp


@app.route('/api/parse', methods=['POST'])
def parse_xml():
    """
    XXE-vulnerable XML parsing endpoint.
    Requires: X-Request-Id header, valid Wasm tag as root element.
    ALWAYS returns 200 regardless of success/failure.
    XXE is OOB only — response never contains entity content.
    """
    # Rate limit: 5 requests per 10 seconds
    ip = request.headers.get('X-Real-IP', request.remote_addr)
    if not check_rate_limit(ip, 'parse', max_requests=5, window_seconds=10):
        return fake_response()

    # Require X-Request-Id header
    req_id = request.headers.get('X-Request-Id', '')
    if not req_id:
        return fake_response()

    try:
        xml_data = request.data.decode('utf-8', errors='replace')
        if not xml_data.strip():
            return fake_response()

        # Parse XML — VULNERABLE (resolve_entities + no_network=False)
        try:
            parser = etree.XMLParser(
                resolve_entities=True,
                no_network=False,  # Allow SSRF via XXE
                load_dtd=True,
                dtd_validation=False,
            )
            tree = etree.fromstring(xml_data.encode('utf-8'), parser)
        except etree.XMLSyntaxError:
            return fake_response()

        # Validate root tag via Wasm
        root_tag = tree.tag
        is_valid, is_decoy = validate_tag(root_tag)

        if is_decoy:
            # Player used a decoy tag — return extra garbage
            extra_noise = {
                'hint': f'Tag <{root_tag}> is not supported. See documentation at /api-docs',  # RED HERRING
                'supported_tags': random.sample(DECOY_XML_TAGS, min(4, len(DECOY_XML_TAGS))),
                'ref': random_uuid(),
            }
            return jsonify({
                'status': 'ok',
                'message': 'Request processed',
                'processed': False,
                'ref': random_uuid(),
                'ts': int(time.time()),
                'noise': random_hex(),
                'data': extra_noise,
            }), 200

        if not is_valid:
            return fake_response()

        # Process XML — extract child elements
        # XXE-exfiltrated data lands in child.text via OOB
        # But we only return MD5 hash — NEVER the actual content
        result_data = {}
        for child in tree:
            child_valid, child_decoy = validate_tag(child.tag)
            if child_valid:
                # OOB only! Response contains hash, not content
                result_data[child.tag] = hashlib.md5(
                    (child.text or '').encode()
                ).hexdigest()[:8]

        # Check if the child text contains the flag pattern from SSRF
        # If any child text matches the internal service response pattern,
        # embed the flag in the response (hidden in noise)
        has_flag_trigger = False
        for child in tree:
            child_valid, _ = validate_tag(child.tag)
            if child_valid and child.text:
                # If XXE+SSRF was successful, the child text will contain
                # data from the internal service. We check for the secret_key_part1 pattern.
                if 'secret_key_part1' in (child.text or '') or 'qa-s3cr3t' in (child.text or ''):
                    has_flag_trigger = True
                    break

        if has_flag_trigger:
            return flag_response(STAGE1_FLAG)

        return jsonify({
            'status': 'ok',
            'message': 'Request processed',
            'processed': True,
            'data': result_data,
            'ref': random_uuid(),
            'ts': int(time.time()),
            'noise': random_hex(),
        }), 200

    except Exception:
        return fake_response()


# ############################################################
# ############################################################
# ## RABBIT HOLES — 70+ endpoints of pure frustration      ##
# ############################################################
# ############################################################

# ============================================================
# GROUP 1: Fake API Discovery & Documentation
# ============================================================

@app.route('/swagger.json')
def swagger_json():
    """Fake Swagger spec — references non-existent endpoints."""
    return jsonify({
        'openapi': '3.0.1',
        'info': {'title': 'QA XML Processor API', 'version': '2.1.0', 'description': 'XML processing service with Wasm validation'},
        'servers': [
            {'url': f'http://{random_ip()}:{random_port()}', 'description': 'production'},  # FAKE
            {'url': f'http://{random_ip()}:{random_port()}', 'description': 'staging'},      # FAKE
        ],
        'paths': {
            '/api/parse': {
                'post': {
                    'summary': 'Parse XML document',
                    'requestBody': {
                        'required': True,
                        'content': {
                            'application/xml': {
                                'schema': {
                                    'type': 'object',
                                    'xml': {'name': 'document'},  # WRONG — this is not a valid tag
                                    'properties': {
                                        'content': {'type': 'string', 'xml': {'name': 'content'}},  # WRONG
                                    }
                                }
                            }
                        }
                    },
                    'responses': {
                        '200': {'description': 'Processed'},
                        '400': {'description': 'Invalid XML'},  # NEVER returned
                        '429': {'description': 'Rate limited'},  # NEVER returned
                    }
                }
            },
            '/api/search': {'get': {'summary': 'Search documents', 'deprecated': True}},
            '/api/debug/config': {'get': {'summary': 'Get configuration', 'deprecated': True}},
            '/api/v2/export': {'post': {'summary': 'Export data'}},
            '/admin/dashboard': {'get': {'summary': 'Admin panel'}},  # FAKE
            '/internal/metrics': {'get': {'summary': 'Internal metrics'}},  # FAKE
        },
        'components': {
            'securitySchemes': {
                'bearerAuth': {'type': 'http', 'scheme': 'bearer', 'bearerFormat': 'JWT'},
                'apiKey': {'type': 'apiKey', 'in': 'header', 'name': 'X-API-Key'},
            }
        },
        'security': [{'bearerAuth': []}],  # Suggests auth is needed — it's not
    }), 200


@app.route('/api-docs')
def api_docs():
    """Fake API documentation page."""
    return jsonify({
        'title': 'QA XML Processor — API Documentation',
        'version': '2.1.0',
        'endpoints': [
            {'path': '/api/parse', 'method': 'POST', 'description': 'Parse XML with Wasm validation', 'auth': 'required'},  # auth is NOT required
            {'path': '/api/search', 'method': 'GET', 'description': 'Search documents', 'params': ['q', 'filter', 'sort']},
            {'path': '/api/debug/config', 'method': 'GET', 'description': 'Get runtime configuration'},
            {'path': '/api/v2/export', 'method': 'POST', 'description': 'Export processed data'},
            {'path': '/api/auth/login', 'method': 'POST', 'description': 'Authenticate user'},
            {'path': '/admin/dashboard', 'method': 'GET', 'description': 'Admin dashboard'},
        ],
        'note': 'All endpoints require X-API-Key header for authentication',  # LIE
        'ref': random_uuid(),
    }), 200


@app.route('/openapi.json')
def openapi_json():
    """Another fake spec — slightly different from swagger."""
    return jsonify({
        'openapi': '3.0.0',
        'info': {'title': 'QA XML Service', 'version': '1.5.0'},  # Different version
        'paths': {
            '/api/parse': {'post': {'summary': 'Parse XML', 'deprecated': False}},
            '/api/v1/validate': {'post': {'summary': 'Validate XML (legacy)', 'deprecated': True}},
            '/api/v2/validate': {'post': {'summary': 'Validate XML v2', 'deprecated': False}},
        },
        'x-internal-endpoints': {  # FAKE "internal" section
            '/internal/config': {'get': {'summary': 'Internal configuration'}},
            '/internal/keys': {'get': {'summary': 'Service keys'}},
        }
    }), 200


@app.route('/api/schema')
def api_schema():
    """Fake XML schema — wrong root element names."""
    return jsonify({
        'type': 'xml-schema',
        'version': '5',
        'root_elements': [
            'document', 'xml', 'payload', 'message', 'envelope',  # ALL WRONG
        ],
        'namespace': 'http://qa-xml.internal/v5',
        'entities_enabled': False,  # LIE — entities ARE enabled
        'external_dtd': False,      # LIE — external DTD IS loaded
        'ref': random_uuid(),
    }), 200


# ============================================================
# GROUP 2: Fake SQLi & Search
# ============================================================

@app.route('/api/search', methods=['GET', 'POST'])
def search():
    """Fake SQLi endpoint — always returns garbage results."""
    query = request.args.get('q', '') or (request.json or {}).get('q', '')
    results = [
        {
            'id': random.randint(1, 9999),
            'name': f'record_{random.randint(100,999)}',
            'category': random.choice(['general', 'internal', 'archive', 'classified', 'deleted']),
            'created': f'2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}',
        }
        for _ in range(random.randint(1, 5))
    ]
    # If query contains SQL-like patterns, still return same garbage
    # but add a fake "hint" that wastes time
    resp_data = {
        'status': 'ok',
        'results': results,
        'total': random.randint(1, 50),
        'page': random.randint(1, 10),
        'ref': random_uuid(),
        'noise': random_hex(),
    }
    if any(kw in query.lower() for kw in ["'", 'union', 'select', 'or 1=1', '--', ';', 'drop']):
        # Fake SQL error hint — but we still return 200
        resp_data['hint'] = 'Query syntax may contain special characters'
        resp_data['error_code'] = f'ERR_SQL_{random.randint(100,999)}'  # FAKE error code
    return jsonify(resp_data), 200


# ============================================================
# GROUP 3: Fake Debug Endpoints
# ============================================================

@app.route('/api/debug/config')
def fake_debug_config():
    """Fake config dump — all values are meaningless."""
    return jsonify({
        'debug': False,
        'log_level': 'WARNING',
        'cache_ttl': random.randint(60, 3600),
        'max_connections': random.randint(50, 200),
        'db_pool_size': random.randint(5, 20),
        'wasm_module': 'xml_validator.wasm',
        'wasm_version': '3.2.1',
        'xml_parser': 'lxml',
        'entity_resolution': False,  # LIE — entities ARE resolved
        'network_access': False,     # LIE — network IS accessible
        'internal_port': random_port(),  # FAKE
        'admin_key': f'adm-{random_hex(16)}',  # FAKE
        'ref': random_uuid(),
    }), 200


@app.route('/api/debug/logs')
def fake_debug_logs():
    """Fake log entries — plausible but useless."""
    levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR']
    messages = [
        'XML parsing request received',
        'Wasm validator loaded successfully',
        'Entity resolution completed',
        'Cache miss for key: ' + random_hex(),
        'Connection pool exhausted, waiting',
        'Rate limit reached for IP: ' + random_ip(),
        'Internal service health check: OK',
        'DTD validation skipped (not configured)',  # LIE
        'External entity blocked (security policy)',  # LIE
        'SSRF protection active',  # LIE
        f'Config reloaded from /etc/qa/config.yml',  # FAKE path
        f'Database query took {random.uniform(0.01, 0.5):.3f}s',
        'Session token expired, regenerating',
        'X-Request-Id header missing, generated: ' + random_uuid(),
    ]
    logs = [
        {
            'timestamp': f'2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}Z',
            'level': random.choice(levels),
            'message': random.choice(messages),
            'source': random.choice(['api.parse', 'wasm.loader', 'xml.parser', 'auth.middleware']),
            'trace_id': random_uuid(),
        }
        for _ in range(random.randint(5, 15))
    ]
    return jsonify({
        'logs': logs,
        'total': random.randint(100, 5000),
        'ref': random_uuid(),
    }), 200


@app.route('/api/debug/env')
def fake_debug_env():
    """Fake environment variables — ALL wrong/decoy."""
    return jsonify({
        'ENVIRONMENT': 'production',
        'DEBUG': 'false',
        'LOG_LEVEL': 'warning',
        'DATABASE_URL': f'postgresql://admin:password123@{random_ip()}:{random_port()}/qa_db',  # FAKE
        'REDIS_URL': f'redis://{random_ip()}:{random_port()}/0',  # FAKE
        'SECRET_KEY': random_hex(32),  # FAKE — not the real secret key
        'FLASK_SECRET_KEY': random_hex(32),  # FAKE
        'STAGE1_FLAG': random_decoy_flag(),  # DECOY
        'INTERNAL_SERVICE_HOST': random_ip(),  # FAKE
        'INTERNAL_SERVICE_PORT': str(random_port()),  # FAKE
        'WASM_MODULE_PATH': '/opt/qa/xml_validator.wasm',  # FAKE
        'AWS_ACCESS_KEY_ID': f'AKIA{random_hex(16).upper()}',  # FAKE
        'AWS_SECRET_ACCESS_KEY': random_hex(40),  # FAKE
        'API_KEY': f'qa-{random_hex(24)}',  # FAKE
        'ADMIN_PASSWORD': random_hex(16),  # FAKE
        'JWT_SECRET': random_hex(32),  # FAKE
        'SMTP_HOST': f'smtp.{random.choice(["gmail","outlook","internal"])}.com',  # FAKE
        'SENTRY_DSN': f'https://{random_hex(32)}@sentry.io/{random.randint(100000,999999)}',  # FAKE
        'ref': random_uuid(),
    }), 200


# ============================================================
# GROUP 4: Fake Internal Endpoints
# ============================================================

@app.route('/api/internal/ping')
def fake_internal_ping():
    """Fake internal service ping."""
    return jsonify({
        'status': 'pong',
        'service': 'qa-internal-config',
        'host': random_ip(),  # FAKE
        'port': random_port(),  # FAKE
        'latency_ms': random.uniform(0.1, 5.0),
        'ref': random_uuid(),
    }), 200


@app.route('/api/internal/status')
def fake_internal_status():
    """Fake internal service status."""
    return jsonify({
        'status': 'running',
        'service': 'qa-internal-config',
        'version': '1.0.0',
        'endpoints': ['/', '/health', '/config', '/metrics'],
        'host': random_ip(),  # FAKE
        'port': random_port(),  # FAKE — NOT the real internal port
        'secret_key_part1': f'qa-fake-{random_hex(8)}-',  # FAKE
        'ref': random_uuid(),
    }), 200


# ============================================================
# GROUP 5: Fake Validation Endpoints
# ============================================================

@app.route('/api/v1/validate', methods=['GET', 'POST'])
def fake_validate_v1():
    """Old API — always rejects with plausible error."""
    return jsonify({
        'status': 'error',
        'message': 'API v1 is deprecated. Please use /api/v3/validate',  # Sends to another rabbit hole
        'migration_guide': '/api-docs#v1-to-v3',
        'ref': random_uuid(),
        'noise': random_hex(),
    }), 200


@app.route('/api/v2/validate', methods=['GET', 'POST'])
def fake_validate_v2():
    """Same — always rejects."""
    return jsonify({
        'status': 'error',
        'message': 'API v2 requires authentication. See /api/auth/login',  # Sends to auth rabbit hole
        'ref': random_uuid(),
        'noise': random_hex(),
    }), 200


@app.route('/api/v3/validate', methods=['GET', 'POST'])
def fake_validate_v3():
    """Same — always rejects but with different message."""
    return jsonify({
        'status': 'error',
        'message': 'Validation requires X-Api-Version header set to 3',  # Even if you set it, still fails
        'supported_versions': [1, 2, 3],
        'ref': random_uuid(),
        'noise': random_hex(),
    }), 200


# ============================================================
# GROUP 6: Fake Admin Endpoints
# ============================================================

@app.route('/admin/')
def admin_panel():
    """Fake admin panel."""
    return jsonify({
        'panel': 'admin',
        'status': 'locked',
        'message': 'Authentication required. Use /admin/login',
        'ref': random_uuid(),
    }), 200


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    """Fake admin login — always fails with plausible reasons."""
    if request.method == 'POST':
        data = request.json or {}
        username = data.get('username', '')
        password = data.get('password', '')
        # Always fail but with different messages to waste time
        messages = [
            'Invalid credentials',
            'Account locked. Contact administrator',
            '2FA required. Use /api/2fa',
            'IP not whitelisted',
            'Authentication service unavailable',
        ]
        return jsonify({
            'status': 'error',
            'message': random.choice(messages),
            'attempts_remaining': random.randint(1, 5),
            'ref': random_uuid(),
            'noise': random_hex(),
        }), 200
    return jsonify({
        'endpoint': '/admin/login',
        'method': 'POST',
        'required_fields': ['username', 'password'],
        'hint': 'Default credentials may be admin:admin',  # LIE
        'ref': random_uuid(),
    }), 200


@app.route('/admin/dashboard')
def admin_dashboard():
    """Fake dashboard — returns plausible but fake data."""
    return jsonify({
        'dashboard': 'admin',
        'stats': {
            'total_requests': random.randint(10000, 99999),
            'active_users': random.randint(5, 50),
            'errors_24h': random.randint(0, 100),
            'uptime_days': round(random.uniform(1, 30), 1),
        },
        'recent_flags': [random_decoy_flag() for _ in range(3)],  # ALL DECOYS
        'internal_services': {
            'config': f'http://{random_ip()}:{random_port()}',  # FAKE
            'database': f'postgresql://{random_ip()}:{random_port()}',  # FAKE
        },
        'ref': random_uuid(),
    }), 200


# ============================================================
# GROUP 7: Fake Debug/Console Endpoints
# ============================================================

@app.route('/debug/')
def debug_panel():
    """Fake debug console."""
    return jsonify({
        'debug': True,
        'endpoints': [
            '/debug/config',
            '/debug/logs',
            '/debug/env',
            '/debug/stacktrace',
            '/debug/profiler',
        ],
        'note': 'Debug mode is disabled in production',  # Contradictory
        'ref': random_uuid(),
    }), 200


@app.route('/console/')
def fake_console():
    """Fake interactive console."""
    return jsonify({
        'console': 'python',
        'version': '3.11.5',
        'status': 'disabled',
        'message': 'Remote console requires debug=True in config',
        'config_path': '/etc/qa/debug.conf',  # FAKE path
        'ref': random_uuid(),
    }), 200


# ============================================================
# GROUP 8: Fake GraphQL
# ============================================================

@app.route('/graphql', methods=['GET', 'POST'])
def fake_graphql():
    """Fake GraphQL endpoint."""
    return jsonify({
        'data': None,
        'errors': [{'message': 'GraphQL endpoint is read-only', 'extensions': {'code': 'READ_ONLY'}}],
        'extensions': {
            'tracing': {
                'version': 1,
                'startTime': f'2024-01-{random.randint(1,28):02d}T00:00:00.000Z',
                'endTime': f'2024-01-{random.randint(1,28):02d}T00:00:00.100Z',
                'duration': random.randint(100000, 500000),
            }
        }
    }), 200


@app.route('/graphql/playground')
def graphql_playground():
    """Fake GraphQL playground."""
    return jsonify({
        'endpoint': '/graphql',
        'subscriptionEndpoint': f'ws://{random_ip()}:{random_port()}/subscriptions',  # FAKE
        'settings': {'request.credentials': 'include'},
        'ref': random_uuid(),
    }), 200


@app.route('/api/graphql', methods=['GET', 'POST'])
def fake_api_graphql():
    """Duplicate GraphQL — another rabbit hole."""
    return fake_graphql()


# ============================================================
# GROUP 9: Fake Export Endpoints
# ============================================================

@app.route('/api/v2/export', methods=['POST'])
def fake_export():
    """Fake export — returns nothing useful."""
    return jsonify({
        'status': 'ok',
        'message': 'Export queued',
        'job_id': random_uuid(),
        'eta_seconds': random.randint(5, 60),
        'ref': random_uuid(),
        'noise': random_hex(),
    }), 200


@app.route('/api/export/csv')
def fake_export_csv():
    """Fake CSV export."""
    rows = [
        f'id,name,value,timestamp',
        f'{random.randint(1,999)},record_{random.randint(1,100)},{random_hex()},{random.randint(1000000,9999999)}',
        f'{random.randint(1,999)},record_{random.randint(1,100)},{random_hex()},{random.randint(1000000,9999999)}',
        f'{random.randint(1,999)},record_{random.randint(1,100)},{random_hex()},{random.randint(1000000,9999999)}',
    ]
    return Response('\n'.join(rows), mimetype='text/csv', headers={
        'Content-Disposition': f'attachment; filename=export_{random_hex(6)}.csv'
    })


@app.route('/api/export/json')
def fake_export_json():
    """Fake JSON export."""
    return jsonify({
        'export': [
            {'id': i, 'key': random_hex(), 'value': random_hex(12)}
            for i in range(random.randint(3, 8))
        ],
        'total': random.randint(100, 1000),
        'ref': random_uuid(),
    }), 200


# ============================================================
# GROUP 10: Fake User/Auth Endpoints
# ============================================================

@app.route('/api/users')
def fake_users():
    """Fake user list."""
    users = [
        {
            'id': i,
            'username': random.choice(['admin', 'root', 'service', 'qa_user', 'deploy', 'backup', 'monitor']),
            'email': f'{random_hex(6)}@qa-internal.local',
            'role': random.choice(['admin', 'user', 'service', 'readonly']),
            'last_login': f'2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}',
            'active': random.choice([True, False]),
        }
        for i in range(1, random.randint(4, 8))
    ]
    return jsonify({'users': users, 'total': len(users), 'ref': random_uuid()}), 200


@app.route('/api/tokens')
def fake_tokens():
    """Fake API tokens."""
    tokens = [
        {
            'id': i,
            'token': f'qa_{random_hex(24)}',  # FAKE tokens
            'created': f'2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}',
            'expires': f'2025-{random.randint(1,12):02d}-{random.randint(1,28):02d}',
            'scope': random.choice(['read', 'write', 'admin', 'internal']),
        }
        for i in range(1, random.randint(3, 6))
    ]
    return jsonify({'tokens': tokens, 'ref': random_uuid()}), 200


@app.route('/api/keys')
def fake_keys():
    """Fake API keys — all decoys."""
    return jsonify({
        'keys': [
            {'id': 'prod', 'key': f'pk_live_{random_hex(32)}'},
            {'id': 'staging', 'key': f'pk_test_{random_hex(32)}'},
            {'id': 'internal', 'key': f'pk_int_{random_hex(32)}'},
            {'id': 'admin', 'key': f'pk_adm_{random_hex(32)}'},
        ],
        'ref': random_uuid(),
    }), 200


@app.route('/api/auth/login', methods=['POST'])
def fake_auth_login():
    """Fake auth — always returns a fake token."""
    return jsonify({
        'status': 'ok',
        'token': f'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{base64.b64encode(json.dumps({"sub":random.randint(1,999),"exp":int(time.time())+3600}).encode()).decode()}.{random_hex(16)}',  # FAKE JWT
        'expires_in': 3600,
        'token_type': 'Bearer',
        'ref': random_uuid(),
    }), 200


@app.route('/api/auth/register', methods=['POST'])
def fake_auth_register():
    """Fake registration."""
    return jsonify({
        'status': 'ok',
        'message': 'User registered. Please verify email at /api/verify',
        'user_id': random.randint(1000, 9999),
        'ref': random_uuid(),
    }), 200


@app.route('/api/auth/refresh', methods=['POST'])
def fake_auth_refresh():
    """Fake token refresh."""
    return jsonify({
        'status': 'ok',
        'token': f'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{base64.b64encode(json.dumps({"sub":random.randint(1,999),"exp":int(time.time())+3600}).encode()).decode()}.{random_hex(16)}',
        'expires_in': 3600,
        'ref': random_uuid(),
    }), 200


@app.route('/api/auth/forgot', methods=['POST'])
def fake_auth_forgot():
    """Fake forgot password."""
    return jsonify({
        'status': 'ok',
        'message': 'Reset link sent to registered email',
        'ref': random_uuid(),
    }), 200


# ============================================================
# GROUP 11: Fake Upload/Download
# ============================================================

@app.route('/api/upload', methods=['POST'])
def fake_upload():
    """Fake upload endpoint."""
    return jsonify({
        'status': 'ok',
        'message': 'File uploaded successfully',
        'file_id': random_uuid(),
        'size': random.randint(100, 100000),
        'ref': random_uuid(),
        'noise': random_hex(),
    }), 200


@app.route('/api/download')
def fake_download():
    """Fake download — returns garbage."""
    return jsonify({
        'status': 'ok',
        'message': 'Download requires file_id parameter',
        'ref': random_uuid(),
    }), 200


# ============================================================
# GROUP 12: Fake Monitoring & Metrics
# ============================================================

@app.route('/api/monitoring')
def fake_monitoring():
    """Fake monitoring dashboard data."""
    return jsonify({
        'monitoring': {
            'cpu_percent': round(random.uniform(5, 80), 1),
            'memory_percent': round(random.uniform(30, 90), 1),
            'disk_percent': round(random.uniform(20, 70), 1),
            'active_connections': random.randint(10, 200),
            'requests_per_second': round(random.uniform(1, 100), 2),
            'error_rate': round(random.uniform(0, 5), 2),
        },
        'alerts': [
            {'level': 'warning', 'message': 'High memory usage detected', 'ts': random.randint(1700000000, 1709999999)},
        ],
        'ref': random_uuid(),
    }), 200


@app.route('/api/metrics')
def fake_metrics():
    """Fake Prometheus metrics."""
    metrics_text = f"""# HELP qa_requests_total Total requests processed
# TYPE qa_requests_total counter
qa_requests_total {random.randint(1000,99999)}
# HELP qa_request_duration_seconds Request duration
# TYPE qa_request_duration_seconds histogram
qa_request_duration_seconds_bucket{{le="0.1"}} {random.randint(100,999)}
qa_request_duration_seconds_bucket{{le="0.5"}} {random.randint(500,5000)}
qa_request_duration_seconds_bucket{{le="1.0"}} {random.randint(1000,10000)}
qa_request_duration_seconds_bucket{{le="+Inf"}} {random.randint(1000,10000)}
qa_request_duration_seconds_sum {random.uniform(10,100):.2f}
qa_request_duration_seconds_count {random.randint(1000,10000)}
# HELP qa_wasm_load_errors_total Wasm module load errors
# TYPE qa_wasm_load_errors_total counter
qa_wasm_load_errors_total 0
# HELP qa_xml_parse_errors_total XML parse errors
# TYPE qa_xml_parse_errors_total counter
qa_xml_parse_errors_total {random.randint(0,50)}
"""
    return Response(metrics_text, mimetype='text/plain')


@app.route('/api/health/live')
def fake_health_live():
    """Fake liveness probe."""
    return jsonify({'status': 'alive', 'ref': random_uuid()}), 200


@app.route('/api/health/ready')
def fake_health_ready():
    """Fake readiness probe."""
    return jsonify({
        'status': 'ready',
        'checks': {
            'database': 'ok',
            'cache': random.choice(['ok', 'degraded']),
            'wasm': 'ok',
        },
        'ref': random_uuid(),
    }), 200


# ============================================================
# GROUP 13: Fake Version & Config
# ============================================================

@app.route('/api/version')
def fake_version():
    """Fake version info — suggests CVEs that don't exist."""
    return jsonify({
        'version': '2.1.0',
        'build': f'build-{random.randint(1000,9999)}',
        'commit': random_hex(12),
        'dependencies': {
            'flask': '2.3.7',  # Suggests CVE research
            'lxml': '4.9.3',   # True — suggests lxml CVEs
            'python': '3.11.5',
            'wasm-runtime': '3.2.1',
            'node': '18.17.0',
        },
        'ref': random_uuid(),
    }), 200


@app.route('/config.yaml')
def fake_config_yaml():
    """Fake YAML config."""
    return Response(f"""# QA XML Processor Configuration
server:
  host: 0.0.0.0
  port: 5000
  debug: false

database:
  host: {random_ip()}
  port: {random_port()}
  name: qa_xml_db
  user: xml_processor
  password: {random_hex(12)}

wasm:
  module: xml_validator.wasm
  version: "3.2"
  max_memory: 128MB

xml:
  max_size: 1MB
  resolve_entities: false  # LIE
  allow_network: false     # LIE
  max_depth: 10

internal:
  config_service: http://{random_ip()}:{random_port()}  # FAKE
  auth_service: http://{random_ip()}:{random_port()}    # FAKE
  secret_key: {random_hex(32)}                           # FAKE

logging:
  level: WARNING
  format: json
""", mimetype='text/yaml')


# ============================================================
# GROUP 14: Fake Sensitive File Leaks
# ============================================================

@app.route('/.env')
def fake_env():
    """Fake .env file — all values are decoys."""
    return Response(f"""# QA XML Processor Environment
# WARNING: This file should not be in production!

FLASK_APP=app.py
FLASK_ENV=production
FLASK_SECRET_KEY={random_hex(32)}
DEBUG=False

DATABASE_URL=postgresql://qa_admin:{random_hex(12)}@{random_ip()}:{random_port()}/qa_prod
REDIS_URL=redis://{random_ip()}:{random_port()}/0

STAGE1_FLAG={random_decoy_flag()}
INTERNAL_SERVICE_HOST={random_ip()}
INTERNAL_SERVICE_PORT={random_port()}

AWS_ACCESS_KEY_ID=AKIA{random_hex(16).upper()}
AWS_SECRET_ACCESS_KEY={random_hex(40)}

SENDGRID_API_KEY=SG.{random_hex(22)}.{random_hex(43)}
STRIPE_SECRET_KEY=sk_live_{random_hex(24)}

# Admin credentials (REMOVE BEFORE DEPLOYING)
ADMIN_USER=qa_admin
ADMIN_PASS={random_hex(16)}
""", mimetype='text/plain')


@app.route('/.git/config')
def fake_git_config():
    """Fake git config — suggests repo access."""
    return Response("""[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = https://github.com/qa-internal/xml-processor.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
[submodule "wasm-validator"]
        url = https://github.com/qa-internal/wasm-validator.git
""", mimetype='text/plain')


# ============================================================
# GROUP 15: Fake Backup Endpoints
# ============================================================

@app.route('/backup/')
def fake_backup_index():
    """Fake backup directory listing."""
    return jsonify({
        'backups': [
            {'name': f'db_backup_{random.randint(20240101,20241231)}.sql', 'size': f'{random.randint(1,50)}MB'},
            {'name': f'config_backup_{random.randint(20240101,20241231)}.yaml', 'size': f'{random.randint(1,5)}KB'},
            {'name': f'wasm_backup_v{random.randint(1,5)}.{random.randint(0,9)}.wasm', 'size': f'{random.randint(50,500)}KB'},
        ],
        'ref': random_uuid(),
    }), 200


@app.route('/backup/db.sql')
def fake_backup_db():
    """Fake SQL dump — decoy tables and data."""
    fake_sql = f"""-- QA XML Processor Database Dump
-- Generated: 2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}
-- Server version: PostgreSQL 15.4

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE config_store (
    key VARCHAR(100) PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    key_hash VARCHAR(255) NOT NULL,
    scope VARCHAR(50) DEFAULT 'read',
    expires_at TIMESTAMP
);

CREATE TABLE flags (
    id SERIAL PRIMARY KEY,
    flag_value VARCHAR(200),
    stage INTEGER,
    claimed BOOLEAN DEFAULT FALSE
);

-- Insert sample data
INSERT INTO users (username, password_hash, role) VALUES
('admin', '$2b$12${random_hex(60)}', 'admin'),
('service', '$2b$12${random_hex(60)}', 'service'),
('qa_user', '$2b$12${random_hex(60)}', 'user');

INSERT INTO config_store (key, value) VALUES
('flask_secret_part2', '{random_hex(32)}'),  -- DECOY
('internal_port', '{random_port()}'),         -- FAKE
('debug_mode', 'false'),
('stage1_flag', '{random_decoy_flag()}');     -- DECOY

INSERT INTO flags (flag_value, stage, claimed) VALUES
('{random_decoy_flag()}', 1, FALSE),  -- DECOY
('{random_decoy_flag()}', 2, FALSE),  -- DECOY
('{random_decoy_flag()}', 3, FALSE);  -- DECOY

-- Grant permissions
GRANT SELECT ON ALL TABLES IN SCHEMA public TO qa_readonly;
"""
    return Response(fake_sql, mimetype='text/plain')


# ============================================================
# GROUP 16: Fake OAuth/SSO/SAML/LDAP
# ============================================================

@app.route('/api/oauth/authorize')
def fake_oauth_authorize():
    """Fake OAuth authorization."""
    return jsonify({
        'redirect_uri': f'http://{random_ip()}:{random_port()}/callback?code={random_hex(16)}',  # FAKE
        'state': random_hex(12),
        'ref': random_uuid(),
    }), 200


@app.route('/api/oauth/token', methods=['POST'])
def fake_oauth_token():
    """Fake OAuth token exchange."""
    return jsonify({
        'access_token': random_hex(32),
        'token_type': 'Bearer',
        'expires_in': 3600,
        'refresh_token': random_hex(32),
        'scope': 'read write',
        'ref': random_uuid(),
    }), 200


@app.route('/api/sso')
def fake_sso():
    """Fake SSO endpoint."""
    return jsonify({
        'provider': 'qa-sso',
        'login_url': f'https://sso.qa-internal.local/login?client_id={random_hex(12)}',  # FAKE
        'certificate': base64.b64encode(os.urandom(256)).decode(),  # FAKE cert
        'ref': random_uuid(),
    }), 200


@app.route('/api/ldap')
def fake_ldap():
    """Fake LDAP config."""
    return jsonify({
        'ldap_url': f'ldap://{random_ip()}:{random_port()}',  # FAKE
        'base_dn': 'dc=qa,dc=internal',
        'bind_dn': f'cn=admin,dc=qa,dc=internal',
        'search_filter': '(uid={{username}})',
        'ref': random_uuid(),
    }), 200


@app.route('/api/saml')
def fake_saml():
    """Fake SAML config."""
    fake_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://qa-internal.local/saml/metadata">
  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
      Location="https://sso.qa-internal.local/sso"/>
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data><ds:X509Certificate>{base64.b64encode(os.urandom(256)).decode()}</ds:X509Certificate></ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>"""
    return Response(fake_xml, mimetype='application/xml')


# ============================================================
# GROUP 17: Fake WordPress / phpMyAdmin / .NET
# ============================================================

@app.route('/wp-admin/')
def fake_wp_admin():
    """Fake WordPress admin — total rabbit hole."""
    return jsonify({
        'wp_admin': True,
        'version': '6.4.2',
        'message': 'WordPress admin requires authentication',
        'login_url': '/wp-login.php',
        'ref': random_uuid(),
    }), 200


@app.route('/wp-login.php')
def fake_wp_login():
    """Fake WordPress login."""
    return jsonify({
        'form': 'wp-login',
        'action': '/wp-login.php',
        'redirect_to': '/wp-admin/',
        'message': 'Invalid credentials',
        'ref': random_uuid(),
    }), 200


@app.route('/phpmyadmin/')
def fake_phpmyadmin():
    """Fake phpMyAdmin — rabbit hole."""
    return jsonify({
        'phpmyadmin': True,
        'version': '5.2.1',
        'server': f'{random_ip()}:{random_port()}',
        'message': 'Access denied. Try /api/auth/login',
        'ref': random_uuid(),
    }), 200


@app.route('/elmah.axd')
def fake_elmah():
    """Fake ELMAH error log — .NET rabbit hole."""
    return jsonify({
        'errors': [
            {
                'type': 'System.NullReferenceException',
                'message': 'Object reference not set to an instance of an object',
                'time': f'2024-{random.randint(1,12):02d}-{random.randint(1,28):02d}T{random.randint(0,23):02d}:{random.randint(0,59):02d}:00Z',
                'source': 'QA.XmlProcessor.Controllers.ParseController',
            }
            for _ in range(random.randint(2, 5))
        ],
        'total': random.randint(50, 500),
        'ref': random_uuid(),
    }), 200


@app.route('/trace.axd')
def fake_trace():
    """Fake ASP.NET trace — .NET rabbit hole."""
    return jsonify({
        'trace': [
            {'category': 'QA.XmlProcessor', 'message': 'Request started', 'duration_ms': random.uniform(1, 50)},
            {'category': 'QA.XmlProcessor', 'message': 'Wasm validation completed', 'duration_ms': random.uniform(1, 100)},
        ],
        'ref': random_uuid(),
    }), 200


# ============================================================
# GROUP 18: Fake SOAP/XML-RPC/REST
# ============================================================

@app.route('/api/soap', methods=['POST'])
def fake_soap():
    """Fake SOAP endpoint — returns plausible WSDL-like response."""
    soap_resp = f"""<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <soap:Fault>
      <faultcode>soap:Client</faultcode>
      <faultstring>Invalid SOAP action. Supported: ProcessXml, ValidateXml</faultstring>
      <detail>
        <wsdl>http://{random_ip()}:{random_port()}/wsdl</wsdl>
      </detail>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>"""
    return Response(soap_resp, mimetype='application/xml')


@app.route('/api/xmlrpc', methods=['POST'])
def fake_xmlrpc():
    """Fake XML-RPC endpoint."""
    xmlrpc_resp = f"""<?xml version="1.0" encoding="UTF-8"?>
<methodResponse>
  <params>
    <param>
      <value><struct>
        <member><name>status</name><value><string>ok</string></value></member>
        <member><name>methods</name><value><array><data>
          <value><string>system.listMethods</string></value>
          <value><string>xml.process</string></value>
          <value><string>xml.validate</string></value>
        </data></array></value></member>
        <member><name>version</name><value><string>2.1.0</string></value></member>
      </struct></value>
    </param>
  </params>
</methodResponse>"""
    return Response(xmlrpc_resp, mimetype='text/xml')


@app.route('/api/rest')
def fake_rest():
    """Fake REST API discovery."""
    return jsonify({
        'api': 'QA-XML-Processor REST API',
        'version': '2.1.0',
        'resources': [
            {'path': '/api/parse', 'methods': ['POST']},
            {'path': '/api/search', 'methods': ['GET', 'POST']},
            {'path': '/api/schema', 'methods': ['GET']},
            {'path': '/api/export/csv', 'methods': ['GET']},
            {'path': '/api/export/json', 'methods': ['GET']},
        ],
        'ref': random_uuid(),
    }), 200


# ============================================================
# GROUP 19: Fake WebSocket/SSE/Events
# ============================================================

@app.route('/api/socket')
def fake_socket():
    """Fake WebSocket info."""
    return jsonify({
        'websocket': True,
        'url': f'ws://{random_ip()}:{random_port()}/ws',  # FAKE
        'protocols': ['v1', 'v2'],
        'message': 'WebSocket upgrade required',
        'ref': random_uuid(),
    }), 200


@app.route('/api/stream')
def fake_stream():
    """Fake SSE endpoint."""
    return jsonify({
        'stream': True,
        'url': f'http://{random_ip()}:{random_port()}/stream',  # FAKE
        'format': 'text/event-stream',
        'message': 'SSE connection requires Accept: text/event-stream',
        'ref': random_uuid(),
    }), 200


@app.route('/api/events')
def fake_events():
    """Fake event stream."""
    return jsonify({
        'events': [
            {'type': 'xml.parsed', 'id': random_uuid(), 'ts': random.randint(1700000000, 1709999999)},
            {'type': 'wasm.loaded', 'id': random_uuid(), 'ts': random.randint(1700000000, 1709999999)},
            {'type': 'cache.invalidated', 'id': random_uuid(), 'ts': random.randint(1700000000, 1709999999)},
        ],
        'ref': random_uuid(),
    }), 200


# ============================================================
# GROUP 20: Fake Static/Manifest Files
# ============================================================

@app.route('/sitemap.xml')
def fake_sitemap():
    """Fake sitemap."""
    return Response(f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://qa-xml.internal/</loc><changefreq>daily</changefreq></url>
  <url><loc>https://qa-xml.internal/api/health</loc><changefreq>hourly</changefreq></url>
  <url><loc>https://qa-xml.internal/api/parse</loc><changefreq>never</changefreq></url>
  <url><loc>https://qa-xml.internal/admin/</loc><changefreq>never</changefreq></url>
  <url><loc>https://qa-xml.internal/api-docs</loc><changefreq>weekly</changefreq></url>
</urlset>""", mimetype='application/xml')


@app.route('/favicon.ico')
def fake_favicon():
    """Fake favicon."""
    return Response(b'', mimetype='image/x-icon')


@app.route('/apple-touch-icon.png')
def fake_apple_icon():
    """Fake Apple touch icon."""
    return Response(b'', mimetype='image/png')


@app.route('/manifest.json')
def fake_manifest():
    """Fake PWA manifest."""
    return jsonify({
        'name': 'QA XML Processor',
        'short_name': 'QA-XML',
        'start_url': '/',
        'display': 'standalone',
        'background_color': '#ffffff',
        'theme_color': '#000000',
        'icons': [
            {'src': '/favicon.ico', 'sizes': '64x64', 'type': 'image/x-icon'},
        ],
        'gcm_sender_id': random_hex(12),  # FAKE
    }), 200


@app.route('/service-worker.js')
def fake_service_worker():
    """Fake service worker."""
    return Response(f"""// QA XML Processor Service Worker v2.1.0
const CACHE_NAME = 'qa-xml-v{random.randint(1,10)}';

self.addEventListener('install', (event) => {{
  console.log('Service worker installed');
}});

self.addEventListener('fetch', (event) => {{
  // Pass through — no caching
  event.respondWith(fetch(event.request));
}});
""", mimetype='application/javascript')


# ============================================================
# GROUP 21: robots.txt & Well-Known
# ============================================================

@app.route('/robots.txt')
def robots():
    """Real robots.txt with decoy paths that lead to rabbit holes."""
    return Response("""User-agent: *
Disallow: /admin/
Disallow: /debug/
Disallow: /internal/
Disallow: /api/v2/
Disallow: /backup/
Disallow: /console/
Disallow: /graphql/
Disallow: /wp-admin/
Disallow: /phpmyadmin/
Disallow: /.env
Disallow: /.git/
Disallow: /api/debug/
Disallow: /api/auth/
Disallow: /api/oauth/
Disallow: /api/tokens/
Disallow: /api/keys/
Disallow: /api/users/
Disallow: /config.yaml

# Sitemap: /sitemap.xml
# API Documentation: /api-docs
""", mimetype='text/plain')


@app.route('/.well-known/security.txt')
def fake_security_txt():
    """Fake security.txt."""
    return Response(f"""Contact: security@qa-internal.local
Contact: https://qa-internal.local/.well-known/security
Preferred-Languages: en
Canonical: https://qa-internal.local/.well-known/security.txt

# Bounty program: {random_decoy_flag()}  # DECOY "bug bounty"
# Internal security endpoint: http://{random_ip()}:{random_port()}/security  # FAKE
""", mimetype='text/plain')


# ============================================================
# GROUP 22: Fake 2FA/MFA/Verification
# ============================================================

@app.route('/api/captcha')
def fake_captcha():
    """Fake captcha endpoint."""
    return jsonify({
        'captcha_id': random_uuid(),
        'challenge': base64.b64encode(os.urandom(32)).decode(),
        'message': 'Include captcha_id and captcha_answer in your request',
        'ref': random_uuid(),
    }), 200


@app.route('/api/2fa', methods=['POST'])
def fake_2fa():
    """Fake 2FA endpoint."""
    return jsonify({
        'status': 'error',
        'message': 'Invalid 2FA code. Please try again.',
        'attempts_remaining': random.randint(1, 5),
        'ref': random_uuid(),
    }), 200


@app.route('/api/mfa', methods=['POST'])
def fake_mfa():
    """Fake MFA endpoint."""
    return jsonify({
        'status': 'ok',
        'message': 'MFA verification required',
        'methods': ['totp', 'sms', 'backup_code'],
        'ref': random_uuid(),
    }), 200


@app.route('/api/verify', methods=['POST'])
def fake_verify():
    """Fake verification endpoint."""
    return jsonify({
        'status': 'ok',
        'message': 'Verification code sent',
        'ref': random_uuid(),
    }), 200


# ============================================================
# GROUP 23: Fake Challenge/Puzzle Endpoints
# ============================================================

@app.route('/api/challenge')
def fake_challenge():
    """Fake challenge endpoint — returns a decoy challenge."""
    return jsonify({
        'challenge': 'reverse_wasm',
        'hint': 'The Wasm module contains encrypted strings at offset 0x2000. Try decoding them.',  # Leads to decoy data
        'difficulty': 'hard',
        'points': 500,
        'ref': random_uuid(),
    }), 200


@app.route('/api/puzzle')
def fake_puzzle():
    """Fake puzzle — completely irrelevant."""
    puzzle = random.choice([
        {'type': 'caesar', 'encrypted': random_hex(12), 'shift': random.randint(1, 25)},
        {'type': 'base64', 'encrypted': base64.b64encode(os.urandom(16)).decode()},
        {'type': 'xor', 'encrypted': random_hex(12), 'key': random_hex(1)},
    ])
    return jsonify({
        'puzzle': puzzle,
        'message': 'Solve the puzzle to earn bonus points',
        'reward': random_decoy_flag(),  # DECOY
        'ref': random_uuid(),
    }), 200


# ============================================================
# GROUP 24: Fake Webhook/Callback
# ============================================================

@app.route('/api/webhook', methods=['GET', 'POST', 'PUT'])
def fake_webhook():
    """Fake webhook endpoint."""
    return jsonify({
        'status': 'ok',
        'message': 'Webhook received',
        'event_id': random_uuid(),
        'ref': random_uuid(),
    }), 200


@app.route('/api/callback', methods=['GET', 'POST'])
def fake_callback():
    """Fake callback endpoint."""
    return jsonify({
        'status': 'ok',
        'message': 'Callback processed',
        'ref': random_uuid(),
    }), 200


# ============================================================
# EXTRA RABBIT HOLES — More tricky ones
# ============================================================

@app.route('/api/wasm/info')
def fake_wasm_info():
    """Fake Wasm module info — wrong details."""
    return jsonify({
        'module': 'xml_validator.wasm',
        'version': '3.2.1',
        'exports': [
            'init', 'validate_xml_tag', 'heap_alloc',
            'get_flag',  # RED HERRING — this exists but returns fake flag
            'xml_sanitize_input', 'generate_csrf_token',
        ],
        'memory_pages': 2,
        'encrypted_offsets': {
            'tags': '0x0100-0x017F',
            'keys': '0x0000-0x000F',
            'decoy_data': '0x2000-0x20FF',  # Explicitly mentioning decoys — meta-red-herring
        },
        'validation_method': 'XOR + Caesar + byte-swap',  # TRUE but incomplete
        'hint': 'Try the get_flag() export first',  # Leads to dead end
        'ref': random_uuid(),
    }), 200


@app.route('/api/xml/schema')
def fake_xml_schema():
    """Fake XML schema — WRONG root elements."""
    return jsonify({
        'schema_version': 5,
        'root_elements': {
            'document': {'type': 'complex', 'children': ['header', 'body', 'footer']},
            'payload': {'type': 'complex', 'children': ['data', 'metadata']},
            'message': {'type': 'complex', 'children': ['from', 'to', 'content']},
        },
        'entities': 'disabled',  # LIE
        'doctype': 'not supported',  # LIE
        'ref': random_uuid(),
    }), 200


@app.route('/api/xml/parse', methods=['POST'])
def fake_xml_parse():
    """Almost the same path as the real /api/parse — rabbit hole."""
    return jsonify({
        'status': 'ok',
        'message': 'XML parsed successfully',
        'elements': random.randint(1, 10),
        'ref': random_uuid(),
        'noise': random_hex(),
        # No actual processing — just a fake response
    }), 200


@app.route('/api/internal/config')
def fake_internal_config():
    """Fake internal config service."""
    return jsonify({
        'service': 'qa-internal-config',
        'host': random_ip(),  # FAKE
        'port': random_port(),  # FAKE — NOT the real port
        'secret_key_part1': f'qa-fake-{random_hex(8)}-',  # FAKE key part
        'secret_key_part2_hint': 'Check /api/debug/env for part 2',  # Leads to another rabbit hole
        'ref': random_uuid(),
    }), 200


@app.route('/api/internal/keys')
def fake_internal_keys():
    """Fake internal keys service."""
    return jsonify({
        'keys': {
            'flask_secret': random_hex(32),  # FAKE
            'jwt_secret': random_hex(32),    # FAKE
            'api_key': f'qa_{random_hex(24)}',  # FAKE
            'stage1_flag': random_decoy_flag(),   # DECOY
        },
        'ref': random_uuid(),
    }), 200


@app.route('/api/internal/metrics')
def fake_internal_metrics():
    """Fake internal metrics."""
    return fake_metrics()


@app.route('/api/flag')
def fake_flag_endpoint():
    """Blatant rabbit hole — returns decoy flags."""
    return flag_response(random_decoy_flag())


@app.route('/api/hint')
def fake_hint():
    """Fake hint endpoint — all hints are misleading."""
    hints = [
        'Try accessing /admin/ with default credentials',
        'The Wasm module has a get_flag() export function',
        'SQL injection in /api/search might work',
        'Check /backup/db.sql for database credentials',
        'The XML parser supports server-side XSLT',
        'Look for SSRF via the /api/webhook endpoint',
        'The /config.yaml file contains the real database password',
        'Debug mode can be enabled via X-Debug: true header',
        'The internal service runs on port 3000',  # FAKE
        'Try XXE with <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
        'The flag is stored in the Wasm memory at offset 0x2000',  # Decoy area
        'JWT tokens can be forged without the secret key',
    ]
    return jsonify({
        'hint': random.choice(hints),
        'ref': random_uuid(),
        'noise': random_hex(),
    }), 200


@app.route('/api/reset')
def fake_reset():
    """Fake reset endpoint."""
    return jsonify({
        'status': 'ok',
        'message': 'Challenge state reset',
        'ref': random_uuid(),
    }), 200


@app.route('/api/submit', methods=['POST'])
def fake_submit():
    """Fake flag submission — always says wrong."""
    data = request.json or {}
    submitted = data.get('flag', '')
    return jsonify({
        'status': 'error',
        'message': 'Incorrect flag. Try again.',
        'attempts': random.randint(1, 100),
        'ref': random_uuid(),
    }), 200


@app.route('/api/scoreboard')
def fake_scoreboard():
    """Fake scoreboard."""
    return jsonify({
        'scores': [
            {'rank': 1, 'team': f'team_{random_hex(4)}', 'points': random.randint(500, 3000)},
            {'rank': 2, 'team': f'team_{random_hex(4)}', 'points': random.randint(300, 2500)},
            {'rank': 3, 'team': f'team_{random_hex(4)}', 'points': random.randint(100, 2000)},
        ],
        'your_score': 0,
        'ref': random_uuid(),
    }), 200


@app.route('/api/rules')
def fake_rules():
    """Fake rules — includes misleading info."""
    return jsonify({
        'rules': [
            'No automated scanning tools',
            'No denial of service attacks',
            'The flag format is QA{...}',
            'Each stage must be completed in order',
            'Rate limiting: 100 requests per minute',  # LIE — real limit is 5/10s on /api/parse
            'XXE vulnerabilities have been patched',     # LIE
            'SSRF protection is enabled',               # LIE
            'The Wasm module is open source — check /wasm/source',  # NON-EXISTENT endpoint
        ],
        'ref': random_uuid(),
    }), 200


@app.route('/api/encode', methods=['POST'])
def fake_encode():
    """Fake XML encoding endpoint."""
    return jsonify({
        'status': 'ok',
        'encoded': base64.b64encode(os.urandom(random.randint(16, 64))).decode(),
        'ref': random_uuid(),
    }), 200


@app.route('/api/decode', methods=['POST'])
def fake_decode():
    """Fake XML decoding endpoint."""
    return jsonify({
        'status': 'ok',
        'decoded': random_hex(random.randint(8, 32)),
        'ref': random_uuid(),
    }), 200


@app.route('/api/session')
def fake_session_info():
    """Fake session info."""
    return jsonify({
        'session_id': random_uuid(),
        'authenticated': False,
        'roles': [],
        'message': 'Login required. See /api/auth/login',
        'ref': random_uuid(),
    }), 200


@app.route('/api/config')
def fake_api_config():
    """Fake API configuration."""
    return jsonify({
        'config': {
            'max_xml_size': 1048576,
            'allowed_content_types': ['application/xml', 'text/xml'],
            'entity_resolution': False,  # LIE
            'external_entities': False,   # LIE
            'dtd_loading': False,         # LIE
            'network_access': False,      # LIE
            'rate_limit_per_minute': 100, # LIE — real limit is 5/10s
            'wasm_validation': True,      # TRUE
            'schema_version': 5,          # TRUE
        },
        'ref': random_uuid(),
    }), 200


@app.route('/api/v1/parse', methods=['POST'])
def fake_parse_v1():
    """Fake v1 parse — different from real /api/parse."""
    return jsonify({
        'status': 'ok',
        'message': 'API v1 is deprecated. Use /api/parse instead.',
        'migration_note': 'v1 does not require X-Request-Id header',  # LIE — real API does
        'ref': random_uuid(),
    }), 200


@app.route('/api/v2/parse', methods=['POST'])
def fake_parse_v2():
    """Fake v2 parse — another rabbit hole."""
    return jsonify({
        'status': 'ok',
        'message': 'API v2 requires X-API-Version header',
        'ref': random_uuid(),
    }), 200


@app.route('/api/migrate')
def fake_migrate():
    """Fake migration endpoint."""
    return jsonify({
        'status': 'ok',
        'message': 'Database migration complete',
        'version': random.randint(1, 10),
        'ref': random_uuid(),
    }), 200


@app.route('/api/cache/clear', methods=['POST'])
def fake_cache_clear():
    """Fake cache clear."""
    return jsonify({
        'status': 'ok',
        'message': 'Cache cleared',
        'keys_removed': random.randint(10, 500),
        'ref': random_uuid(),
    }), 200


@app.route('/api/cache/stats')
def fake_cache_stats():
    """Fake cache statistics."""
    return jsonify({
        'hits': random.randint(1000, 99999),
        'misses': random.randint(100, 9999),
        'hit_rate': round(random.uniform(80, 99), 2),
        'memory_usage_mb': round(random.uniform(10, 500), 1),
        'ref': random_uuid(),
    }), 200


@app.route('/api/db/query', methods=['POST'])
def fake_db_query():
    """Fake database query endpoint."""
    return jsonify({
        'status': 'ok',
        'results': [
            {f'col_{i}': random_hex() for i in range(random.randint(2, 5))}
            for _ in range(random.randint(1, 3))
        ],
        'rows_affected': random.randint(0, 10),
        'ref': random_uuid(),
    }), 200


@app.route('/api/db/tables')
def fake_db_tables():
    """Fake database tables."""
    return jsonify({
        'tables': [
            {'name': 'users', 'rows': random.randint(10, 1000)},
            {'name': 'config_store', 'rows': random.randint(5, 50)},
            {'name': 'api_keys', 'rows': random.randint(1, 20)},
            {'name': 'flags', 'rows': random.randint(1, 5)},
            {'name': 'sessions', 'rows': random.randint(10, 500)},
        ],
        'ref': random_uuid(),
    }), 200


@app.route('/api/wasm/validate', methods=['POST'])
def fake_wasm_validate():
    """Fake Wasm validation — accepts anything, returns garbage."""
    return jsonify({
        'status': 'ok',
        'valid': random.choice([True, False]),
        'errors': [],
        'warnings': ['Tag validation is case-sensitive'] if random.random() > 0.5 else [],
        'ref': random_uuid(),
    }), 200


@app.route('/api/wasm/export')
def fake_wasm_export():
    """Fake Wasm export list."""
    return jsonify({
        'exports': [
            'init', 'validate_xml_tag', 'heap_alloc',
            'get_flag', 'memory',
            'xml_sanitize_input', 'generate_csrf_token',
            'verify_hmac_signature', 'base64_decode',
            'aes_decrypt_ecb', 'helper_trim_space',
            'util_format_date', 'logger_write_buf',
            'cache_invalidate', 'data_pipeline_flush',
            'metrics_aggregate', 'session_cleanup',
        ],
        'hint': 'The get_flag function returns the flag directly',  # LIE — returns decoy
        'ref': random_uuid(),
    }), 200


@app.route('/api/wasm/memory')
def fake_wasm_memory():
    """Fake Wasm memory dump — all decoys."""
    return jsonify({
        'memory_regions': {
            '0x0000-0x00FF': 'Key material',
            '0x0100-0x017F': 'Encrypted tag names',
            '0x0800-0x0FFF': 'Working buffer',
            '0x1000-0x1FFF': 'Custom heap',
            '0x2000-0x2FFF': 'Decoy data (red herrings)',  # Meta-comment
        },
        'key_offsets': {
            'xor_key': '0x0000',
            'key_mask': '0x0010',
        },
        'hint': 'XOR key at 0x0000, mask at 0x0010. XOR them to get real key = 0xAB',  # WRONG — real key is 0x37
        'ref': random_uuid(),
    }), 200


@app.route('/api/xxe')
def fake_xxe_info():
    """Fake XXE info — says it's patched."""
    return jsonify({
        'xxe_protection': {
            'entity_resolution': 'disabled',
            'external_entities': 'blocked',
            'dtd_loading': 'disabled',
            'network_access': 'blocked',
            'status': 'XXE vulnerabilities have been patched in version 2.1.0',
        },
        'note': 'If you think you found an XXE, report it at /api/webhook',
        'ref': random_uuid(),
    }), 200


@app.route('/api/ssrf')
def fake_ssrf_info():
    """Fake SSRF info — says it's blocked."""
    return jsonify({
        'ssrf_protection': {
            'outbound_network': 'blocked',
            'allowed_hosts': ['localhost'],
            'internal_service': 'firewalled',
            'status': 'SSRF protection is active',
        },
        'ref': random_uuid(),
    }), 200


@app.route('/internal/')
def fake_internal_index():
    """Fake internal index."""
    return jsonify({
        'internal': True,
        'services': [
            f'http://{random_ip()}:{random_port()}/config',   # FAKE
            f'http://{random_ip()}:{random_port()}/health',   # FAKE
            f'http://{random_ip()}:{random_port()}/metrics',  # FAKE
        ],
        'ref': random_uuid(),
    }), 200


@app.route('/internal/config')
def fake_internal_config_v2():
    """Another fake internal config."""
    return jsonify({
        'service': 'qa-internal-config',
        'version': '1.0.0',
        'secret_key_part1': f'qa-fake-{random_hex(8)}-',  # FAKE
        'secret_key_part2': random_hex(16),                  # FAKE
        'database_path': f'sqlite:///var/lib/qa/challenge_{random.randint(1,9)}.db',  # FAKE
        'ref': random_uuid(),
    }), 200


@app.route('/.git/HEAD')
def fake_git_head():
    """Fake git HEAD file."""
    return Response('ref: refs/heads/main', mimetype='text/plain')


@app.route('/.git/refs/heads/main')
def fake_git_ref():
    """Fake git ref."""
    return Response(random_hex(40), mimetype='text/plain')


@app.route('/wp-content/')
def fake_wp_content():
    """Fake WordPress content."""
    return jsonify({
        'wp_content': True,
        'plugins': ['akismet', 'wp-security', 'xml-rpc'],
        'themes': ['twentytwentyfour'],
        'ref': random_uuid(),
    }), 200


@app.route('/xmlrpc.php', methods=['POST'])
def fake_wp_xmlrpc():
    """Fake WordPress XML-RPC."""
    return fake_xmlrpc()


@app.route('/api/v1/')
def fake_api_v1_index():
    """Fake API v1 index."""
    return jsonify({
        'api': 'v1',
        'status': 'deprecated',
        'endpoints': ['/api/v1/validate', '/api/v1/parse'],
        'migration_guide': '/api-docs#migration',
        'ref': random_uuid(),
    }), 200


@app.route('/api/v2/')
def fake_api_v2_index():
    """Fake API v2 index."""
    return jsonify({
        'api': 'v2',
        'status': 'active',
        'endpoints': ['/api/v2/validate', '/api/v2/export', '/api/v2/parse'],
        'authentication': 'X-API-Key header required',  # LIE
        'ref': random_uuid(),
    }), 200


@app.route('/api/v3/')
def fake_api_v3_index():
    """Fake API v3 index."""
    return jsonify({
        'api': 'v3',
        'status': 'beta',
        'endpoints': ['/api/v3/validate'],
        'note': 'v3 is currently in beta. Use X-Api-Version: 3 header.',
        'ref': random_uuid(),
    }), 200


@app.route('/api/grpc')
def fake_grpc():
    """Fake gRPC endpoint."""
    return jsonify({
        'grpc': True,
        'services': ['qa.xml.Processor', 'qa.xml.Validator'],
        'reflection': True,
        'message': 'gRPC requires HTTP/2 and content-type application/grpc',
        'ref': random_uuid(),
    }), 200


@app.route('/api/cloudevents', methods=['POST'])
def fake_cloudevents():
    """Fake CloudEvents endpoint."""
    return jsonify({
        'status': 'ok',
        'event_id': random_uuid(),
        'message': 'CloudEvent processed',
        'ref': random_uuid(),
    }), 200


@app.route('/debug/stacktrace')
def fake_stacktrace():
    """Fake stack trace — looks like a debug leak."""
    return jsonify({
        'stacktrace': [
            {'file': '/opt/qa/app.py', 'line': random.randint(100, 500), 'function': 'parse_xml', 'code': 'tree = etree.fromstring(xml_data.encode("utf-8"), parser)'},
            {'file': '/opt/qa/wasm_loader.py', 'line': random.randint(10, 100), 'function': 'validate_tag', 'code': 'result = self.wasm.validate_xml_tag(ptr, len)'},
            {'file': '/opt/qa/xml_processor.py', 'line': random.randint(10, 50), 'function': 'process', 'code': 'return self._handle_entities(tree)'},
        ],
        'note': 'Set DEBUG=true to enable full stack traces',  # Doesn't work
        'ref': random_uuid(),
    }), 200


@app.route('/debug/profiler')
def fake_profiler():
    """Fake profiler output."""
    return jsonify({
        'profiler': {
            'total_time_ms': random.uniform(10, 500),
            'functions': [
                {'name': 'parse_xml', 'calls': random.randint(10, 100), 'total_ms': random.uniform(5, 200)},
                {'name': 'validate_tag', 'calls': random.randint(50, 500), 'total_ms': random.uniform(2, 50)},
                {'name': 'resolve_entities', 'calls': random.randint(0, 10), 'total_ms': random.uniform(0, 5)},  # Suggests entities might be resolved
            ],
        },
        'ref': random_uuid(),
    }), 200


@app.route('/debug/config')
def fake_debug_config_v2():
    """Duplicate fake debug config at different path."""
    return fake_debug_config()


@app.route('/debug/env')
def fake_debug_env_v2():
    """Duplicate fake env at different path."""
    return fake_debug_env()


@app.route('/debug/logs')
def fake_debug_logs_v2():
    """Duplicate fake logs at different path."""
    return fake_debug_logs()


# ============================================================
# CATCH-ALL — Any other path returns fake_response
# ============================================================
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    """Any unrecognized path gets a generic fake response."""
    return fake_response()


# ============================================================
# INITIALIZATION
# ============================================================
init_wasm_tags()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
