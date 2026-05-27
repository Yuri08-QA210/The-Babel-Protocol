# QA CTF Challenge — System Architecture

## Overview

The QA CTF Challenge is a multi-stage security training platform built on a **microservices architecture** using **Redis** for session management and **PostgreSQL** as the primary data store.

> **Last Updated:** 2024-01-15 | **Version:** 3.2.1

---

## Technology Stack

| Component       | Technology         | Version  |
|-----------------|--------------------|----------|
| Web Server      | Nginx              | 1.24.0   |
| App Server      | Gunicorn           | 21.2.0   |
| Framework       | Flask              | 2.3.x    |
| Database        | PostgreSQL         | 15.4     |
| Cache           | Redis              | 7.2      |
| Message Queue   | RabbitMQ           | 3.12     |
| WAF             | ModSecurity        | 3.0      |

---

## Service Architecture

```
                    ┌─────────────┐
                    │   Nginx     │
                    │  :80/:443   │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
       ┌──────▼──────┐ ┌──▼────────┐ ┌─▼───────────┐
       │ XML Parser  │ │  Portal   │ │ Admin Vault  │
       │  :5001      │ │  :5002    │ │  :5003       │
       └──────┬──────┘ └──┬───────┘ └──┬───────────┘
              │           │            │
       ┌──────▼───────────▼────────────▼──────┐
       │         PostgreSQL + Redis            │
       │              :5432 / :6379            │
       └──────────────────────────────────────┘
```

---

## API Endpoints

### XML Parser Service (Port 5001)

| Method | Endpoint               | Description                        |
|--------|------------------------|------------------------------------|
| POST   | `/api/v2/parse`        | Parse and validate XML documents   |
| GET    | `/api/v2/status`       | Service health check               |
| POST   | `/api/v2/validate`     | Validate XML against schema        |
| GET    | `/api/v2/schema/list`  | List available schemas             |

> **Note:** The XML parser uses **libxml2** with external entity processing **disabled** by default.

### Portal Service (Port 5002)

| Method | Endpoint                    | Description                     |
|--------|-----------------------------|---------------------------------|
| GET    | `/portal/dashboard`         | User dashboard                  |
| POST   | `/portal/api/v2/login`      | User authentication             |
| GET    | `/portal/api/v2/search`     | Search functionality            |
| GET    | `/portal/api/v2/profile`    | User profile                    |
| POST   | `/portal/api/v2/config`     | Configuration management        |

### Admin Vault Service (Port 5003)

| Method | Endpoint                    | Description                     |
|--------|-----------------------------|---------------------------------|
| GET    | `/admin/vault/status`       | Vault status check              |
| POST   | `/admin/vault/unlock`       | Unlock vault with credentials   |
| GET    | `/admin/vault/flag`         | Retrieve challenge flag         |
| POST   | `/admin/vault/grant`        | Grant temporary access          |

---

## Flag Rotation Mechanism

The challenge implements an **automated flag rotation system** that cycles flags every **15 minutes** using a cron job:

```cron
*/15 * * * * /opt/qa-ctf/scripts/rotate-flags.sh >> /var/log/flag-rotation.log 2>&1
```

Flags are stored in **Redis** with TTL and automatically rotated. The rotation key is derived from the current timestamp and the `FLAG_ROTATION_SECRET` environment variable.

> **Important:** If you capture a flag, submit it immediately — it may become invalid after rotation.

---

## Security Measures

### Web Application Firewall (WAF)

ModSecurity is configured with the **OWASP Core Rule Set v3.3** and custom rules:

- **Rule 942100**: SQL Injection detection (all variants)
- **Rule 941100**: XSS detection (all variants)
- **Rule 944100**: Server-Side Template Injection detection
- **Rule 930100**: Local File Inclusion detection
- **Rule 932100**: Remote Code Execution detection
- **Rule 921110**: HTTP Request Smuggling detection

### Network Security

- All inter-service communication uses **mTLS**
- Redis requires authentication with `REDIS_AUTH_TOKEN`
- PostgreSQL uses **SCRAM-SHA-256** authentication
- Internal services are on isolated Docker network `qa-ctf-internal`

### Application Security

- Flask **SECRET_KEY** is loaded from environment variable (never hardcoded)
- Session cookies use **HTTPOnly**, **Secure**, and **SameSite=Strict** flags
- Input validation on all endpoints using **marshmallow** schemas
- Rate limiting: 100 requests/minute per IP (enforced by Redis)

---

## Deployment

### Docker Compose

```bash
# Build and deploy
docker-compose -f docker-compose.prod.yml up -d --build

# Verify services
docker-compose -f docker-compose.prod.yml ps

# Check logs
docker-compose -f docker-compose.prod.yml logs -f
```

### Environment Variables

| Variable                  | Description                        | Default                       |
|---------------------------|------------------------------------|-------------------------------|
| `POSTGRES_HOST`           | PostgreSQL hostname                | `qa-ctf-db`                   |
| `POSTGRES_PORT`           | PostgreSQL port                    | `5432`                        |
| `REDIS_HOST`              | Redis hostname                     | `qa-ctf-redis`                |
| `FLASK_SECRET_KEY`        | Flask session secret               | *(required)*                  |
| `FLAG_ROTATION_SECRET`    | Key for flag rotation              | *(required)*                  |
| `WAF_ENABLED`             | Enable ModSecurity WAF             | `true`                        |

---

## Attack Chain (Intended Order)

Based on the challenge design, the intended attack chain is:

1. **Reconnaissance** → Enumerate API endpoints on `/api/v2/`
2. **SQL Injection** → Exploit `/portal/api/v2/search` to extract credentials
3. **Authentication Bypass** → Use stolen credentials to access admin panel
4. **Template Injection** → Exploit `/portal/api/v2/config` SSTI for RCE
5. **Privilege Escalation** → Use RCE to read flag rotation secret
6. **Flag Recovery** → Use rotation secret to derive current flag

> **Warning:** Attempts to bypass the intended order (e.g., HTTP smuggling first) will fail due to the WAF and mTLS requirements.

---

## Monitoring

- **Prometheus** scrapes metrics from all services on port `9090`
- **Grafana** dashboard available at `http://localhost:3000` (admin/admin)
- **AlertManager** sends alerts on suspicious activity patterns

---

## Troubleshooting

| Issue                        | Solution                                        |
|------------------------------|-------------------------------------------------|
| Services not starting        | Check Redis connectivity: `redis-cli -h qa-ctf-redis ping` |
| WAF blocking valid requests  | Review ModSecurity audit log: `/var/log/modsec/` |
| Flag rotation not working    | Verify `FLAG_ROTATION_SECRET` is set            |
| Session errors               | Check `FLASK_SECRET_KEY` matches across services |
