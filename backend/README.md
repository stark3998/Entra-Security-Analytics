# Log Analytics – Backend

FastAPI-based backend for the Log Analytics SIEM-lite platform.

---

## Table of Contents

- [Tech Stack](#tech-stack)
- [Module Architecture](#module-architecture)
- [Collectors](#collectors)
- [Correlation Rules Engine](#correlation-rules-engine)
- [Risk Scoring](#risk-scoring)
- [Alerting Subsystem](#alerting-subsystem)
- [Authentication & Authorization](#authentication--authorization)
- [Database Models](#database-models)
- [API Routes](#api-routes)
- [CLI](#cli)
- [Configuration](#configuration)
- [Testing](#testing)
- [Development](#development)

---

## Tech Stack

| Component | Library | Version |
|---|---|---|
| Web framework | FastAPI + Uvicorn | latest |
| ORM | SQLAlchemy 2.0 | ≥ 2.0.48 |
| Auth | MSAL + PyJWT[crypto] | ≥ 1.28.0 / ≥ 2.8.0 |
| HTTP client | httpx | latest |
| Scheduler | APScheduler | latest |
| CLI | Click + Rich | latest |
| Settings | pydantic-settings + python-dotenv | latest |
| Alerting | aiosmtplib (email), httpx (webhooks) | latest |
| Analytics | pandas, scipy | latest |
| Testing | pytest, pytest-asyncio, pytest-cov, respx | latest |
| Linting | ruff, mypy | latest |

---

## Module Architecture

```
app/
├── main.py               # FastAPI app factory, lifespan, router wiring
├── config.py             # Pydantic Settings (loads .env)
├── database.py           # SQLAlchemy engine, session, 16 ORM models, 5 enums
├── cli.py                # Click CLI with 6 command groups
├── auth.py               # JWT validation, JWKS cache, get_current_user dependency
├── rules_engine.py       # 35 correlation rules + 5 meta-rules
├── risk_scoring.py       # Compounding risk score calculator
├── alerting.py           # Multi-channel alert dispatcher (email, Teams, Slack)
├── scheduler.py          # APScheduler daemon (collect → analyze → alert loop)
├── collectors/
│   ├── base.py           # Abstract BaseCollector with retry & pagination
│   ├── entra_signin.py   # Entra sign-in logs → SignInLog model
│   ├── entra_audit.py    # Entra audit logs → AuditLog model
│   ├── office365.py      # O365 activity → O365ActivityLog model
│   ├── sharepoint.py     # SharePoint activity → O365ActivityLog model
│   ├── powerapps.py      # Power Apps activity → O365ActivityLog model
│   └── ca_policies.py    # CA policy snapshot sync → 4 CA models
└── routes/
    ├── routes_logs.py        # GET /api/logs/*
    ├── routes_incidents.py   # GET/PATCH /api/incidents/*
    ├── routes_rules.py       # CRUD /api/rules/*
    ├── routes_dashboard.py   # GET /api/dashboard/*
    ├── routes_auth.py        # GET /api/auth/*
    ├── routes_settings.py    # GET/PUT /api/settings
    └── routes_capolicies.py  # 11 endpoints under /api/ca-policies/*
```

---

## Collectors

### Base Collector Pattern

`BaseCollector` (abstract) provides:

- **Retry with exponential backoff** — up to 5 retries, 2× multiplier
- **HTTP 429 rate-limit handling** — respects `Retry-After` header
- **Automatic pagination** — follows `@odata.nextLink`
- **`httpx.AsyncClient`** with 30 s timeout

Subclasses implement:
- `_fetch_page(token, since, until, next_link)` — build the Graph/O365 request
- `normalize(raw_record)` — map JSON to an ORM model instance

### Available Collectors

| Collector | Source | Graph/API Endpoint | Model |
|---|---|---|---|
| `EntraSignInCollector` | Entra sign-in | `/v1.0/auditLogs/signIns` | `SignInLog` |
| `EntraAuditCollector` | Entra audit | `/v1.0/auditLogs/directoryAudits` | `AuditLog` |
| `Office365Collector` | Office 365 | O365 Management API | `O365ActivityLog` |
| `SharePointCollector` | SharePoint | O365 Management API | `O365ActivityLog` |
| `PowerAppsCollector` | Power Apps | O365 Management API | `O365ActivityLog` |

### CA Policy Collector

`CAPolicyCollector` differs from the log collectors — it performs a **full
snapshot sync** (replaces all rows on each run) rather than incremental
time-range pagination. It syncs:

1. Conditional Access policies
2. Named locations (IP ranges and countries)
3. Authentication strength definitions
4. Directory groups and roles referenced by policies

---

## Correlation Rules Engine

The rules engine (`rules_engine.py`) evaluates logs against 35 built-in rules:

| Category | Count | Trigger Sources |
|---|---|---|
| Identity / Authentication | 10 | `entra-signin`, `entra-audit` |
| Privilege Escalation | 6 | `entra-audit` |
| Data Exfiltration / DLP | 8 | `office365`, `sharepoint` |
| Consent & Application | 5 | `entra-audit` |
| Shadow IT / Power Platform | 7 | `powerapps`, `office365` |
| Meta-rules | 5 | Cross-source correlation |

### How It Works

1. **`analyze()`** loads all enabled rules from the DB.
2. Each rule defines a `trigger_event_source` and `trigger_logic` — a Python
   dict describing matching conditions.
3. New logs since last analysis are evaluated; matches create `Incident` records
   with severity, evidence JSON, and user watch windows.
4. **Meta-rules** look for *combinations* of incidents (e.g., "MFA change +
   risky sign-in within 1 hour") and create compounded incidents.

### Custom Rules

Rules can be created via API (`POST /api/rules`) with fields:
- `name`, `slug`, `description`, `severity`
- `event_source`, `trigger_logic` (JSON conditions)
- `enabled` flag

System (built-in) rules can only be enabled/disabled, not deleted.

---

## Risk Scoring

`risk_scoring.py` computes per-user risk scores:

```
score = min(100, (base_risk + entra_risk) × multiplier)
```

- Each incident creates a **watch window** (configurable duration).
- `base_risk` = sum of risk contributions from active windows.
- `entra_risk` = Entra ID risk level mapped to 0 / 5 / 15 / 30.
- `multiplier` compounds when multiple windows overlap: 1.0 → 1.25 → 1.5.

---

## Alerting Subsystem

`alerting.py` dispatches alerts through three channels:

| Channel | Transport | Configuration |
|---|---|---|
| **Email** | aiosmtplib (STARTTLS) | `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `ALERT_EMAIL_FROM`, `ALERT_EMAIL_TO` |
| **Teams** | httpx POST to webhook | `TEAMS_WEBHOOK_URL` |
| **Slack** | httpx POST to webhook | `SLACK_WEBHOOK_URL` |

Alerts are sent for new high-severity incidents. Delivery status is tracked in
the `alert_history` table to prevent duplicate sends.

---

## Authentication & Authorization

### JWT Validation (`auth.py`)

- Downloads JWKS from `https://login.microsoftonline.com/{tenant}/v2.0` and
  caches for 24 hours.
- Validates: `exp`, `iss`, `aud`, `sub` claims.
- Algorithm: RS256.
- The `get_current_user` FastAPI dependency extracts the user from the
  `Authorization: Bearer <token>` header.

### Auth Modes

| Mode | Behavior |
|---|---|
| `client_credentials` | No JWT required; API is unprotected; backend acquires Graph tokens via MSAL `ConfidentialClientApplication` |
| `interactive` | All protected endpoints require a valid Entra ID v2 JWT |
| `both` | JWT is validated if present but not required |

Mode is set via `AUTH_MODE` env var and can be changed at runtime via
`PUT /api/settings`.

### MSAL Bootstrap

`GET /api/auth/config` returns the MSAL.js configuration the frontend needs:
```json
{
  "auth_mode": "interactive",
  "tenant_id": "...",
  "client_id": "...",
  "scopes": ["openid", "profile", "User.Read"]
}
```

---

## Database Models

16 models across 4 categories:

### Log Models

| Model | Table | Key Fields |
|---|---|---|
| `SignInLog` | `sign_in_logs` | `log_id`, `user_principal_name`, `app_display_name`, `ip_address`, `status`, `risk_level`, `location`, `created_at` |
| `AuditLog` | `audit_logs` | `log_id`, `category`, `activity`, `actor_upn`, `target_resources`, `result`, `created_at` |
| `O365ActivityLog` | `o365_activity_logs` | `log_id`, `workload`, `operation`, `user_id`, `object_id`, `client_ip`, `created_at` |

### Analysis Models

| Model | Table | Key Fields |
|---|---|---|
| `CorrelationRule` | `correlation_rules` | `slug`, `name`, `severity`, `event_source`, `trigger_logic`, `enabled`, `is_system` |
| `UserWatchState` | `user_watch_states` | `user_principal_name`, `risk_score`, `watch_windows`, `last_updated` |
| `Incident` | `incidents` | `rule_slug`, `severity`, `user_principal_name`, `evidence`, `status`, `notes`, `created_at` |

### Alerting Models

| Model | Table | Key Fields |
|---|---|---|
| `AlertHistoryEntry` | `alert_history` | `incident_id`, `channel`, `delivery_status`, `sent_at` |

### Infrastructure Models

| Model | Table | Key Fields |
|---|---|---|
| `CollectorState` | `collector_states` | `collector_name`, `last_run`, `last_success`, `cursor` |
| `AppSettings` | `app_settings` | `key`, `value` |

### Conditional Access Models

| Model | Table | Key Fields |
|---|---|---|
| `ConditionalAccessPolicy` | `conditional_access_policies` | `policy_id`, `display_name`, `state`, `conditions`, `grant_controls`, `session_controls`, `synced_at` |
| `NamedLocation` | `named_locations` | `location_id`, `display_name`, `location_type`, `definition`, `synced_at` |
| `AuthenticationStrength` | `authentication_strengths` | `strength_id`, `display_name`, `description`, `allowed_combinations`, `synced_at` |
| `DirectoryGroup` | `directory_groups` | `group_id`, `display_name`, `group_type`, `synced_at` |
| `PolicyCoverageCache` | `policy_coverage_cache` | `policy_id`, `coverage_data`, `computed_at` |

### Enums

`LogSource`, `Severity`, `IncidentStatus`, `AlertChannel`, `AlertDeliveryStatus`

---

## API Routes

See the [main README](../README.md#api-endpoints) for the full endpoint
reference. The backend exposes 7 route groups:

| Prefix | Module | Endpoints |
|---|---|---|
| `/api/auth` | `routes_auth.py` | 2 |
| `/api/settings` | `routes_settings.py` | 2 |
| `/api/logs` | `routes_logs.py` | 3 |
| `/api/incidents` | `routes_incidents.py` | 4 |
| `/api/rules` | `routes_rules.py` | 5 |
| `/api/dashboard` | `routes_dashboard.py` | 5 |
| `/api/ca-policies` | `routes_capolicies.py` | 10 |
| `/health` | `main.py` | 1 |

**Total: 32 endpoints**

---

## CLI

Entry point: `log-analytics` (registered via `pyproject.toml`
`[project.scripts]`).

```
Usage: log-analytics [OPTIONS] COMMAND [ARGS]...

Commands:
  collect      One-shot log collection
  analyze      Run correlation engine + anomaly detection
  serve        Start FastAPI web server
  daemon       Start polling daemon (scheduler + server)
  risk         Show high-risk users
  rules        Manage correlation rules
    list         List rules
    toggle       Toggle rule on/off
  incidents    Manage incidents
    list         List recent incidents
    resolve      Resolve an incident
  ca-policies  Manage CA policies
    sync         Sync from Graph API
    list         List cached policies
    show         Show policy detail
    coverage     Coverage summary

Options:
  -v, --verbose  Enable debug logging
  --help         Show this message and exit
```

---

## Configuration

Configuration is managed through `config.py` using Pydantic Settings. All
values can be set via environment variables or a `.env` file in the backend
directory.

See [Environment Variables](../README.md#environment-variables) in the main
README for the full reference.

### `.env.example`

A template `.env.example` file is included with all supported variables and
sensible defaults.

---

## Testing

### Test Suite

| File | Tests | Coverage Area |
|---|---|---|
| `test_collectors.py` | Collector fetch, normalize, pagination, error handling |
| `test_rules_engine.py` | Rule matching, meta-rules, trigger logic |
| `test_risk_scoring.py` | Score calculation, watch windows, multipliers |
| `test_alerting.py` | Email, Teams, Slack dispatch, deduplication |
| `test_api.py` | All REST endpoints (logs, incidents, rules, dashboard, settings) |
| `test_auth.py` | JWT validation, auth modes, MSAL config, protected endpoints |
| `test_capolicies.py` | CA policy CRUD, sync, coverage, gaps, stats (27 tests) |

### Running Tests

```bash
# All tests with coverage
pytest --cov=app --cov-report=term-missing

# Specific file
pytest tests/test_capolicies.py -v

# With verbose output
pytest -v --tb=short
```

### Test Infrastructure

- **`conftest.py`** provides:
  - In-memory SQLite with `StaticPool` for isolation
  - `async_session` fixture for DB tests
  - `client` fixture (FastAPI `TestClient` with dependency overrides)
  - Factory functions for all models (logs, incidents, rules, CA policies, etc.)
  - MSAL and auth mocks

- **Mocking strategy:**
  - `respx` for HTTP mocking (Graph API, O365 API, webhooks)
  - `unittest.mock.patch` for MSAL, SMTP, and internal dependencies
  - No external services contacted during tests

### Coverage

Current: **162 tests passing**, 0 failures.
CI gate: **≥ 80%** on changed files.

---

## Development

### Linting

```bash
ruff check app/ tests/
```

### Type Checking

```bash
mypy app/ --ignore-missing-imports
```

### Adding a New Collector

1. Create `app/collectors/my_collector.py` subclassing `BaseCollector`.
2. Implement `_fetch_page()` and `normalize()`.
3. Register in `cli.py` collection dispatch and `scheduler.py`.

### Adding a New Correlation Rule

1. Add the rule definition to the seed list in `rules_engine.py`.
2. Define `trigger_logic` JSON matching conditions.
3. Run `log-analytics analyze` to test against existing logs.
