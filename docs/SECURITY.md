# QA CTF Challenge — Security Policy

## Security Posture

This document outlines the security measures and vulnerability remediation status for the QA CTF Challenge platform.

> **Last Audit:** 2024-01-10 | **Auditor:** SecOps Team | **Status:** ✅ PASS

---

## Vulnerability Remediation Status

### XML External Entity (XXE) Injection

**Status:** ✅ FULLY PATCHED

XXE vulnerabilities have been completely eliminated through the following measures:

- `libxml2` compiled with `XML_PARSE_NOENT` and `XML_PARSE_DTDLOAD` **disabled**
- External entity resolution is **blocked at the parser level**
- All XML input is sanitized through a **whitelist-based tag filter** before parsing
- Network requests from the XML parser are **firewalled** (egress rules block outbound HTTP/DNS)
- Custom `EntityResolver` raises `SecurityError` on any `SYSTEM` or `PUBLIC` entity reference

**Verified by:** Penetration test report #PT-2024-0012 (January 2024)

**Related CVEs (all patched):**
- CVE-2023-XXXXX — libxml2 entity expansion DoS
- CVE-2023-YYYYY — XML parameter entity injection

---

### Server-Side Template Injection (SSTI)

**Status:** ✅ ENABLED — PROTECTION ACTIVE

SSTI protection is enforced at multiple layers:

1. **Jinja2 Sandboxing**: All templates are rendered in a `SandboxedEnvironment` with restricted globals
2. **Input Sanitization**: User input is escaped using `html.escape()` before template rendering
3. **Blacklist Filtering**: The following patterns are blocked in user-supplied template data:
   - `__class__`, `__subclasses__`, `__globals__`, `__builtins__`
   - `os`, `subprocess`, `sys`, `importlib`
   - `{{`, `}}`, `{%`, `%}` in user-controlled fields
4. **WAF Rule 944100**: ModSecurity detects and blocks SSTI payloads at the network edge

**Verified by:** Automated SSTI fuzzing (1000+ payloads, 0 bypasses)

**Remediation for any future finding:**
- Add new patterns to the SSTI blacklist in `portal/middleware/template_guard.py`
- Update WAF rules in `/etc/modsecurity/custom/ssti-rules.conf`

---

### HTTP Request Smuggling

**Status:** ✅ BLOCKED BY WAF

HTTP smuggling is prevented through a defense-in-depth approach:

1. **ModSecurity WAF** (Rule 921110): Detects and blocks all known smuggling techniques:
   - CL.TE smuggling
   - TE.CL smuggling
   - TE.TE obfuscation
   - H2.CL downgrade smuggling
2. **Nginx Configuration**: Strict `proxy_http_version 1.1` with explicit `Connection: close`
3. **Request Validation**: Both Nginx and backend validate `Content-Length` and `Transfer-Encoding` headers
4. **Timeout Enforcement**: Any request with ambiguous framing is dropped after 5 seconds

**Verified by:** Smuggling test suite (smuggler.py, h2csmuggler, HTTPEverything) — all blocked

**Related CVEs (all mitigated):**
- CVE-2023-44487 — HTTP/2 Rapid Reset Attack
- CVE-2024-AAAAA — TE.TE ambiguity in reverse proxies

---

### SQL Injection

**Status:** ✅ PARAMETERIZED QUERIES

All database queries use **parameterized prepared statements** via SQLAlchemy ORM.

- Raw SQL queries are **prohibited** by code review policy
- The `/portal/api/v2/search` endpoint uses `db.session.execute(text(query), params)` with bound parameters
- Input validation via **marshmallow** schemas before any database interaction

**Verified by:** SQLMap automated scan — 0 injections found

---

### Other Security Measures

| Measure                        | Status  | Details                                    |
|--------------------------------|---------|--------------------------------------------|
| CSRF Protection                | ✅ Active | Flask-WTF CSRF tokens on all POST routes   |
| Rate Limiting                  | ✅ Active | 100 req/min via Redis-backed limiter       |
| CORS Policy                    | ✅ Strict | Only `qa-internal.local` origin allowed    |
| Cookie Security                | ✅ Active | HTTPOnly + Secure + SameSite=Strict        |
| Content Security Policy        | ✅ Active | Strict CSP with no inline scripts          |
| Subresource Integrity          | ✅ Active | SRI hashes on all external resources       |
| Secrets Management             | ✅ Active | Vault integration for all secrets          |
| Dependency Scanning            | ✅ Active | Snyk + Dependabot automated scanning       |
| Container Security             | ✅ Active | Trivy scans on all Docker images           |

---

## Hardening Recommendations

### For Production Deployment

1. **Enable mTLS** between all microservices (currently only partially deployed)
2. **Rotate `FLASK_SECRET_KEY`** every 30 days via Vault
3. **Update ModSecurity rules** to CRS v4.0 when released
4. **Implement request signing** for inter-service communication
5. **Add anomaly detection** for unusual request patterns (potential smuggling)
6. **Enable audit logging** for all admin vault operations

### For Development

1. Never disable the WAF in development (use `WAF_ENABLED=true`)
2. Use `FLASK_DEBUG=False` in all environments
3. Do not expose internal services (ports 5001-5003) to the host network
4. Keep Redis authentication enabled even in local development

---

## Incident Response

If a vulnerability is discovered:

1. **Do not modify production** — reproduce in staging first
2. Document the exploit chain in `/security/advisories/`
3. Submit a patch via the internal GitLab MR process
4. Update this document with the remediation status

---

## Security Contacts

| Role              | Contact                          |
|-------------------|----------------------------------|
| Security Lead     | security@qa-internal.local       |
| Dev Team Lead     | dev-team@qa-internal.local       |
| Infrastructure    | infra@qa-internal.local          |

---

*This document is classified as **INTERNAL** and should not be shared outside the QA team.*
