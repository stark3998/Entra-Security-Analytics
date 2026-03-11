# Log Analytics – SIEM-lite for Microsoft Cloud

A lightweight Security Information and Event Management (SIEM) tool that
collects, correlates, and alerts on logs from Microsoft Entra ID, Office 365,
SharePoint, and Power Apps — plus a **Conditional Access Policy Visualizer** for
posture assessment.

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Azure App Registration Setup](#azure-app-registration-setup)
- [Environment Variables](#environment-variables)
- [Authentication Modes](#authentication-modes)
- [Microsoft Graph API Permissions](#microsoft-graph-api-permissions)
- [Correlation Rules](#correlation-rules)
- [Risk Scoring](#risk-scoring)
- [Conditional Access Policy Visualizer](#conditional-access-policy-visualizer)
- [API Endpoints](#api-endpoints)
- [CLI Commands](#cli-commands)
- [Frontend Pages](#frontend-pages)
- [Running Tests](#running-tests)
- [CI/CD Pipeline](#cicd-pipeline)
- [Project Structure](#project-structure)
- [License](#license)

---

## Features

| Area | Highlights |
|---|---|
| **Log Collection** | Five collectors — Entra sign-in, Entra audit, Office 365, SharePoint, Power Apps — with automatic pagination, retry & rate-limit handling |
| **Correlation Engine** | 35 built-in rules across 5 categories + 5 meta-rules; custom rule creation via API |
| **Risk Scoring** | Compounding per-user risk score with watch windows and Entra risk-level integration |
| **Incident Management** | Auto-created incidents with severity, status workflow, and notes |
| **Multi-Channel Alerting** | Email (SMTP/TLS), Microsoft Teams webhook, Slack webhook |
| **CA Policy Visualizer** | Snapshot sync of Conditional Access policies with coverage-gap analysis and Mermaid flow diagrams |
| **Dual Authentication** | Three auth modes — daemon-only (`client_credentials`), interactive Entra ID login (`interactive`), or hybrid (`both`) |
| **Daemon Mode** | APScheduler-based polling with configurable interval (1–1 440 min) |
| **Dashboard** | Real-time KPIs, risk scores, incident trends, log volume charts, watched-user list |
| **CLI** | Full-featured Click CLI for collection, analysis, rules, incidents, risk, and CA policy management |

---

## Architecture

```
┌──────────────────┐        ┌──────────────────────┐        ┌──────────────┐
│   React 18 SPA   │───────▶│   FastAPI Backend     │───────▶│  SQLite DB   │
│   (Vite / TS)    │  REST  │   (Python 3.11+)      │  ORM   │  (16 models) │
│                  │◀───────│                        │◀───────│              │
│  MSAL.js popup   │  JSON  │  MSAL client-creds     │        └──────────────┘
│  auth (optional) │        │  + JWT validation       │
└──────────────────┘        └───────────┬────────────┘
                                        │
                 ┌──────────────────────┬┴──────────────────────┐
                 ▼                      ▼                       ▼
          Microsoft Graph         O365 Management          APScheduler
          API  (v1.0)             Activity API             (Daemon mode)
          ─ Sign-in logs          ─ Office 365 logs
          ─ Audit logs            ─ SharePoint logs
          ─ CA policies           ─ Power Apps logs
          ─ Named locations
          ─ Auth strengths
          ─ Groups / Roles
```

**Backend** — Python / FastAPI with SQLAlchemy 2.0 (SQLite), MSAL
client-credentials *and* interactive auth, five log collectors, a Conditional
Access policy collector, a 35-rule correlation engine, compounding risk scorer,
and multi-channel alerting (Email, Teams, Slack).

**Frontend** — React 18 / TypeScript SPA built with Vite. Eight pages:
Dashboard, Sign-in Logs, Audit Logs, Activity Logs, Incidents, Rules,
**CA Policies**, and Settings. Supports MSAL.js popup login with
`@azure/msal-browser`.

---

## Prerequisites

| Requirement | Version |
|---|---|
| Python | ≥ 3.11 |
| Node.js | ≥ 18 |
| npm | ≥ 9 |
| Azure tenant | Any Entra ID (Azure AD) tenant |

You will need **one or two** Azure app registrations depending on your chosen
[authentication mode](#authentication-modes).

---

## Installation

### Backend

```bash
cd backend
python -m venv .venv

# Activate virtual environment
# Linux / macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

pip install -e ".[dev]"

# Create .env from the example
cp .env.example .env
# Edit .env with your Azure and alerting settings (see Environment Variables)
```

### Frontend

```bash
cd frontend
npm install
npm run dev          # Dev server on http://localhost:5173
npm run build        # Production build → dist/
```

### Running the Application

```bash
# One-shot log collection
log-analytics collect

# Start web server only
log-analytics serve

# Start daemon mode (scheduler + web server)
log-analytics daemon

# Sync CA policies from Graph
log-analytics ca-policies sync
```

---

## Azure App Registration Setup

### 1. Backend Registration (required)

This registration is used for server-side Graph API calls (log collection, CA
policy sync).

1. In the [Azure Portal → App registrations](https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade), click **New registration**.
2. Name: `log-analytics-backend` (or any name).
3. Supported account types: **Single tenant**.
4. Click **Register**.
5. Go to **Certificates & secrets → New client secret** — copy the value.
6. Go to **API permissions → Add a permission → Microsoft Graph → Application permissions** and add:
   - `AuditLog.Read.All`
   - `Directory.Read.All`
   - `Policy.Read.All`
   - `Group.Read.All`
7. Go to **API permissions → Add a permission → Office 365 Management APIs → Application permissions** and add:
   - `ActivityFeed.Read`
   - `ActivityFeed.ReadDlp`
8. Click **Grant admin consent** for your tenant.
9. Copy **Application (client) ID** and **Directory (tenant) ID** into your `.env`.

### 2. Frontend / SPA Registration (optional — for interactive auth)

Only needed if you set `AUTH_MODE=interactive` or `AUTH_MODE=both`.

1. Create a second app registration: `log-analytics-spa`.
2. Supported account types: **Single tenant**.
3. Under **Authentication → Add a platform → Single-page application**, add redirect URI: `http://localhost:5173` (and your production URL).
4. Go to **Expose an API**:
   - Set Application ID URI (e.g., `api://<spa-client-id>`).
   - Add a scope: `access_as_user` (admin and user consent).
5. No client secret is needed (SPA uses public client flow).
6. Copy the **Application (client) ID** into `FRONTEND_CLIENT_ID` in `.env`.
7. Set `JWT_AUDIENCE` to the Application ID URI (e.g., `api://<spa-client-id>`).

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| **Azure / Auth** | | | |
| `AZURE_TENANT_ID` | ✅ | – | Entra tenant (directory) ID |
| `AZURE_CLIENT_ID` | ✅ | – | Backend app registration client ID |
| `AZURE_CLIENT_SECRET` | ✅ | – | Backend app registration client secret |
| `AUTH_MODE` | | `client_credentials` | Auth mode: `client_credentials` \| `interactive` \| `both` |
| `FRONTEND_CLIENT_ID` | ★ | `""` | SPA app registration client ID (required for `interactive` / `both`) |
| `JWT_AUDIENCE` | ★ | `""` | Expected JWT audience, e.g. `api://<spa-client-id>` |
| **Database** | | | |
| `DATABASE_URL` | | `sqlite:///./log_analytics.db` | SQLAlchemy database URL |
| **Alerting – Email** | | | |
| `SMTP_HOST` | | `""` | SMTP server hostname |
| `SMTP_PORT` | | `587` | SMTP server port |
| `SMTP_USER` | | `""` | SMTP username |
| `SMTP_PASSWORD` | | `""` | SMTP password |
| `SMTP_USE_TLS` | | `true` | Use STARTTLS |
| `ALERT_EMAIL_FROM` | | `""` | Sender address for alerts |
| `ALERT_EMAIL_TO` | | `""` | Comma-separated recipient addresses |
| **Alerting – Webhooks** | | | |
| `TEAMS_WEBHOOK_URL` | | `""` | Teams incoming webhook URL |
| `SLACK_WEBHOOK_URL` | | `""` | Slack incoming webhook URL |
| **Scheduler / Server** | | | |
| `POLL_INTERVAL_MINUTES` | | `15` | Polling interval in minutes (1–1 440) |
| `LOG_LEVEL` | | `INFO` | Python logging level |
| `APP_HOST` | | `0.0.0.0` | FastAPI bind host |
| `APP_PORT` | | `8000` | FastAPI bind port |
| `CORS_ORIGINS` | | `http://localhost:5173` | Comma-separated CORS origins |

> ★ = required when `AUTH_MODE` is `interactive` or `both`.

---

## Authentication Modes

The application supports three authentication modes, controlled by the
`AUTH_MODE` environment variable:

### `client_credentials` (default)

- **Use case:** Daemon / background service; no interactive users.
- The backend uses MSAL `ConfidentialClientApplication` to acquire tokens for
  Graph API calls.
- API endpoints are **unprotected** — suitable for internal/behind-firewall
  deployments.
- No frontend login is shown.

### `interactive`

- **Use case:** Multi-user deployment where each user signs in.
- The frontend shows a **Sign in with Microsoft** screen.
- Users authenticate via MSAL.js popup → receive an Entra ID v2 JWT.
- The JWT is attached as `Authorization: Bearer <token>` on every API request.
- The backend validates the JWT (RS256, JWKS from
  `login.microsoftonline.com/{tenant}/v2.0`) checking `exp`, `iss`, `aud`, and
  `sub`.
- Requires the [SPA app registration](#2-frontend--spa-registration-optional--for-interactive-auth).

### `both`

- **Use case:** Optional login — most features work without auth, but users can
  sign in for personalization or audit trail.
- Combines both modes: token is sent when the user is logged in; requests
  without a token are still accepted.

---

## Microsoft Graph API Permissions

### Graph Application Permissions (required)

| Permission | Used By | Purpose |
|---|---|---|
| `AuditLog.Read.All` | Entra sign-in & audit collectors | Read sign-in and directory audit logs |
| `Directory.Read.All` | CA policy collector | Read directory roles |
| `Policy.Read.All` | CA policy collector | Read Conditional Access policies, named locations, auth strengths |
| `Group.Read.All` | CA policy collector | Resolve group display names referenced in CA policies |

### Graph API Endpoints Consumed

| Endpoint | Collector |
|---|---|
| `GET /v1.0/auditLogs/signIns` | `entra_signin` |
| `GET /v1.0/auditLogs/directoryAudits` | `entra_audit` |
| `GET /v1.0/identity/conditionalAccess/policies` | `ca_policies` |
| `GET /v1.0/identity/conditionalAccess/namedLocations` | `ca_policies` |
| `GET /v1.0/identity/conditionalAccess/authenticationStrength/policies` | `ca_policies` |
| `GET /v1.0/groups/{id}` | `ca_policies` |
| `GET /v1.0/directoryRoles` | `ca_policies` |

### Office 365 Management API Permissions

| Permission | Used By |
|---|---|
| `ActivityFeed.Read` | Office 365, SharePoint, Power Apps collectors |
| `ActivityFeed.ReadDlp` | DLP event collection |

API base: `https://manage.office.com/api/v1.0`

### MSAL Scopes

| Scope | Protocol |
|---|---|
| `https://graph.microsoft.com/.default` | Graph API (backend) |
| `https://manage.office.com/.default` | O365 Management API (backend) |
| `openid`, `profile`, `User.Read` | MSAL.js interactive login (frontend) |

---

## Correlation Rules

35 built-in rules across 5 categories plus 5 meta-rules:

| Category | Count | Examples |
|---|---|---|
| 1. Identity / Authentication | 10 | MFA change, password reset, risky sign-in |
| 2. Privilege Escalation | 6 | Role assignment, PIM activation |
| 3. Data Exfiltration / DLP | 8 | Mass download, external sharing |
| 4. Consent & Application | 5 | OAuth consent, service principal creation |
| 5. Shadow IT / Power Platform | 7 | Unmanaged app, Power Automate flow |
| M. Meta-rules | 5 | Multi-signal compounding correlation |

Custom rules can be created via the API (`POST /api/rules`) or the Rules page in
the frontend.

---

## Risk Scoring

```
score = min(100, (base_risk + entra_risk) × multiplier)
```

| Component | Calculation |
|---|---|
| `base_risk` | Sum of active watch-window risk contributions |
| `entra_risk` | Mapped from Entra ID risk level: none → 0, low → 5, medium → 15, high → 30 |
| `multiplier` | 1.0 (1 window), 1.25 (2 windows), 1.5 (3+ windows) |

The compounding multiplier increases risk for users who trigger multiple
correlation rules within overlapping time windows.

---

## Conditional Access Policy Visualizer

The CA Policy Visualizer provides a comprehensive view of your tenant's
Conditional Access posture:

- **Policy List** — browse all policies with expandable detail rows showing
  conditions, grant/session controls, and auto-generated **Mermaid flow
  diagrams**.
- **Coverage Map** — see which resource areas are covered (users, apps,
  platforms, locations, sign-in risk, MFA) and identify **coverage gaps** with
  actionable recommendations.
- **Reference Data** — inspect named locations, authentication strength
  definitions, and directory groups/roles referenced by policies.

### Sync

The CA policy collector performs a **full snapshot sync** — it replaces all
cached data on each run (unlike the log collectors which use incremental
time-range pagination).

```bash
# Via CLI
log-analytics ca-policies sync

# Via API
POST /api/ca-policies/sync
```

---

## API Endpoints

### Health

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | Public | Health check |

### Auth (`/api/auth`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/auth/config` | Public | MSAL.js bootstrap config (tenant, client ID, scopes) |
| GET | `/api/auth/me` | Protected | Current user claims from JWT |

### Settings (`/api/settings`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/settings` | Public | Current auth mode and status flags |
| PUT | `/api/settings` | Public | Update auth mode or app registration |

### Logs (`/api/logs`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/logs/signin` | Protected | Sign-in logs (filterable, paginated) |
| GET | `/api/logs/audit` | Protected | Audit logs (filterable, paginated) |
| GET | `/api/logs/activity` | Protected | O365 / SharePoint / Power Apps activity logs |

### Incidents (`/api/incidents`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/incidents` | Protected | List incidents |
| GET | `/api/incidents/stats/summary` | Protected | Stats summary by status and severity |
| GET | `/api/incidents/{id}` | Protected | Incident detail |
| PATCH | `/api/incidents/{id}` | Protected | Update incident status or notes |

### Rules (`/api/rules`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/rules` | Protected | List correlation rules |
| GET | `/api/rules/{id}` | Protected | Rule detail |
| POST | `/api/rules` | Protected | Create custom rule |
| PATCH | `/api/rules/{id}` | Protected | Update rule (system rules: enable/disable only) |
| DELETE | `/api/rules/{id}` | Protected | Delete custom rule |

### Dashboard (`/api/dashboard`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/dashboard/summary` | Protected | Dashboard KPI summary |
| GET | `/api/dashboard/risk-scores` | Protected | User risk scores |
| GET | `/api/dashboard/incident-trend` | Protected | Incident trend data (daily) |
| GET | `/api/dashboard/log-volume` | Protected | Log ingestion volume stats |
| GET | `/api/dashboard/watched-users` | Protected | Users under active watch |

### CA Policies (`/api/ca-policies`)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/ca-policies` | Protected | List policies (paginated, filterable by state) |
| GET | `/api/ca-policies/stats` | Protected | Policy statistics |
| GET | `/api/ca-policies/coverage` | Protected | Coverage breakdown by area |
| GET | `/api/ca-policies/coverage/gaps` | Protected | Coverage gaps with recommendations |
| GET | `/api/ca-policies/coverage/summary` | Protected | Overall coverage summary |
| GET | `/api/ca-policies/named-locations` | Protected | Named locations |
| GET | `/api/ca-policies/auth-strengths` | Protected | Authentication strength definitions |
| GET | `/api/ca-policies/directory-entries` | Protected | Directory groups and roles |
| POST | `/api/ca-policies/sync` | Protected | Trigger full Graph sync |
| GET | `/api/ca-policies/{policy_id}` | Protected | Single policy detail |

---

## CLI Commands

All commands are available via the `log-analytics` entry point. Use `-v` /
`--verbose` for debug logging on any command.

### Collection & Analysis

```
log-analytics collect [--source entra-signin|entra-audit|office365|sharepoint|powerapps|all]
log-analytics analyze
```

### Server

```
log-analytics serve [--host 0.0.0.0] [--port 8000] [--reload]
log-analytics daemon
```

### Rules Management

```
log-analytics rules list [--enabled-only]
log-analytics rules toggle <slug>
```

### Incident Management

```
log-analytics incidents list [--status open|investigating|resolved|closed|false_positive] [--limit N]
log-analytics incidents resolve <id> [--notes "..."]
```

### Risk

```
log-analytics risk [--threshold 50]
```

### CA Policy Management

```
log-analytics ca-policies sync
log-analytics ca-policies list [--state enabled|disabled|enabledForReportingButNotEnforced]
log-analytics ca-policies show <policy_id>
log-analytics ca-policies coverage
```

---

## Frontend Pages

| Route | Page | Description |
|---|---|---|
| `/` | Dashboard | KPI cards, risk scores, incident trends, log volume charts, watched users |
| `/signin-logs` | Sign-in Logs | Searchable, filterable sign-in log viewer |
| `/audit-logs` | Audit Logs | Searchable, filterable audit log viewer |
| `/activity-logs` | Activity Logs | O365 / SharePoint / Power Apps activity logs |
| `/incidents` | Incidents | Incident list with status workflow and detail view |
| `/rules` | Rules | Correlation rules CRUD with enable/disable toggles |
| `/ca-policies` | CA Policies | 3-tab visualizer: Policies, Coverage Map, Reference Data |
| `/settings` | Settings | Auth mode configuration and app registration management |

When `AUTH_MODE` is `interactive`, unauthenticated users see a **Sign in with
Microsoft** screen. Authentication uses MSAL.js popup on the
`@azure/msal-react` provider, with tokens stored in `sessionStorage`.

---

## Running Tests

### Backend

```bash
cd backend
pip install -e ".[dev]"

# Run all tests with coverage
pytest --cov=app --cov-report=term-missing

# Run a specific test file
pytest tests/test_capolicies.py -v
```

**162 tests**, 0 failures. Coverage gate: **≥ 80%** on changed files (enforced
in CI).

### Frontend

```bash
cd frontend
npx tsc --noEmit      # Type check
npm run build         # Production build (also validates)
```

---

## CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/ci.yml`) runs on every push to
`main` and on pull requests.

### Backend Job (ubuntu-latest, Python 3.11)

1. `pip install -e ".[dev]"`
2. `ruff check app/ tests/` — lint
3. `mypy app/ --ignore-missing-imports` — type check (continue-on-error)
4. `pytest --cov=app --cov-report=term-missing --cov-fail-under=80` — tests + coverage gate

### Frontend Job (ubuntu-latest, Node 20)

1. `npm ci`
2. `npx tsc --noEmit` — type check
3. `npm run build` — production build

---

## Project Structure

```
log-analytics/
├── .github/workflows/ci.yml     # CI pipeline
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py               # FastAPI app, router wiring, lifespan
│   │   ├── config.py             # Pydantic settings (env vars)
│   │   ├── database.py           # SQLAlchemy models (16 models, 5 enums)
│   │   ├── cli.py                # Click CLI entry point
│   │   ├── auth.py               # JWT validation, MSAL helpers
│   │   ├── rules_engine.py       # 35 correlation rules + meta-rules
│   │   ├── risk_scoring.py       # Compounding risk score calculator
│   │   ├── alerting.py           # Email, Teams, Slack alert dispatch
│   │   ├── scheduler.py          # APScheduler polling daemon
│   │   ├── collectors/
│   │   │   ├── base.py           # Abstract base collector (retry, pagination)
│   │   │   ├── entra_signin.py   # Entra sign-in log collector
│   │   │   ├── entra_audit.py    # Entra audit log collector
│   │   │   ├── office365.py      # O365 activity collector
│   │   │   ├── sharepoint.py     # SharePoint activity collector
│   │   │   ├── powerapps.py      # Power Apps activity collector
│   │   │   └── ca_policies.py    # CA policy snapshot collector
│   │   └── routes/
│   │       ├── routes_logs.py    # /api/logs endpoints
│   │       ├── routes_incidents.py  # /api/incidents endpoints
│   │       ├── routes_rules.py   # /api/rules endpoints
│   │       ├── routes_dashboard.py  # /api/dashboard endpoints
│   │       ├── routes_auth.py    # /api/auth endpoints
│   │       ├── routes_settings.py   # /api/settings endpoints
│   │       └── routes_capolicies.py # /api/ca-policies endpoints (11 routes)
│   ├── tests/
│   │   ├── conftest.py           # Fixtures, factories, DB setup
│   │   ├── test_collectors.py
│   │   ├── test_rules_engine.py
│   │   ├── test_risk_scoring.py
│   │   ├── test_alerting.py
│   │   ├── test_api.py
│   │   ├── test_auth.py
│   │   └── test_capolicies.py    # 27 CA-specific tests
│   ├── pyproject.toml            # Python project config & dependencies
│   └── .env.example              # Environment variable template
├── frontend/
│   ├── src/
│   │   ├── main.tsx              # React entry point
│   │   ├── App.tsx               # Router, nav, auth gate
│   │   ├── api.ts                # API client, types, fetch functions
│   │   ├── AuthProvider.tsx      # MSAL context provider
│   │   ├── index.css             # Global styles (~660 lines)
│   │   └── pages/
│   │       ├── Dashboard.tsx
│   │       ├── SignInLogs.tsx
│   │       ├── AuditLogs.tsx
│   │       ├── ActivityLogs.tsx
│   │       ├── Incidents.tsx
│   │       ├── RulesPage.tsx
│   │       ├── CAPolicies.tsx    # 3-tab CA policy visualizer
│   │       └── Settings.tsx
│   ├── index.html
│   ├── package.json
│   ├── tsconfig.json
│   └── vite.config.ts
└── README.md                     # This file
```

---

## Dependencies

### Backend (Python)

**Runtime:** fastapi, uvicorn[standard], msal, httpx, sqlalchemy, alembic,
apscheduler, click, pydantic, pydantic-settings, python-dotenv, pandas, scipy,
aiosmtplib, rich, python-multipart, PyJWT[crypto]

**Dev:** pytest, pytest-cov, pytest-asyncio, respx, ruff, mypy, httpx[http2]

### Frontend (npm)

**Runtime:** react, react-dom, react-router-dom, recharts, @tanstack/react-query,
@azure/msal-browser, @azure/msal-react, mermaid

**Dev:** @types/react, @types/react-dom, @vitejs/plugin-react, typescript, vite,
eslint, @typescript-eslint/eslint-plugin, @typescript-eslint/parser,
eslint-plugin-react-hooks

---

## License

MIT
