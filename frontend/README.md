# Log Analytics – Frontend

React 18 / TypeScript single-page application for the Log Analytics SIEM-lite
platform. Built with Vite, featuring MSAL.js authentication, interactive data
tables, and Mermaid-powered Conditional Access policy diagrams.

---

## Table of Contents

- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [Pages](#pages)
- [Authentication](#authentication)
- [API Client](#api-client)
- [Styling](#styling)
- [Building for Production](#building-for-production)
- [Configuration](#configuration)

---

## Tech Stack

| Library | Version | Purpose |
|---|---|---|
| React | 18 | UI framework |
| TypeScript | latest | Type safety |
| Vite | latest | Build tool & dev server |
| react-router-dom | ^6.26.0 | Client-side routing |
| @tanstack/react-query | ^5.51.0 | Server-state management & caching |
| recharts | ^2.12.7 | Dashboard charts (area, bar, pie) |
| @azure/msal-browser | ^3.27.0 | MSAL.js authentication |
| @azure/msal-react | ^2.1.0 | React MSAL context & hooks |
| mermaid | ^11.0.0 | Flowchart rendering for CA policies |

---

## Getting Started

```bash
# Install dependencies
npm install

# Start dev server (proxies /api to backend on port 8000)
npm run dev

# Type check
npx tsc --noEmit

# Production build
npm run build
```

The dev server runs at **http://localhost:5173** and proxies all `/api` requests
to the FastAPI backend at `http://localhost:8000`.

---

## Project Structure

```
frontend/
├── index.html              # HTML entry point
├── package.json            # Dependencies & scripts
├── tsconfig.json           # TypeScript config
├── vite.config.ts          # Vite config with API proxy
└── src/
    ├── main.tsx            # React DOM render entry
    ├── App.tsx             # Router, navigation sidebar, auth gate
    ├── api.ts              # API client — types, fetch functions, token injection
    ├── AuthProvider.tsx    # MSAL configuration & provider wrapper
    ├── index.css           # Global styles (~660 lines)
    └── pages/
        ├── Dashboard.tsx       # KPI cards, charts, risk scores, watched users
        ├── SignInLogs.tsx      # Entra sign-in log viewer
        ├── AuditLogs.tsx       # Entra audit log viewer
        ├── ActivityLogs.tsx    # O365/SharePoint/Power Apps log viewer
        ├── Incidents.tsx       # Incident management with status workflow
        ├── RulesPage.tsx       # Correlation rules CRUD
        ├── CAPolicies.tsx      # 3-tab CA policy visualizer
        └── Settings.tsx        # Auth mode & app registration config
```

---

## Pages

### Dashboard (`/`)

Main overview page with:
- **KPI cards** — total logs, active incidents, high-risk users, enabled rules
- **Incident trend** — daily area chart (via recharts)
- **Log volume** — stacked bar chart by source
- **Risk scores** — sorted table of users with color-coded risk levels
- **Watched users** — active watch windows with remaining duration

### Sign-in Logs (`/signin-logs`)

Paginated, searchable table of Entra sign-in events. Filterable by user, app,
IP address, and risk level. Columns include timestamp, user, application,
location, status, and risk level.

### Audit Logs (`/audit-logs`)

Paginated table of Entra directory audit events. Filterable by category,
activity, and actor. Shows operation details, targets, and results.

### Activity Logs (`/activity-logs`)

Unified viewer for O365, SharePoint, and Power Apps activity. Filterable by
workload type, operation, and user. Includes timestamps, operations, objects,
and client IPs.

### Incidents (`/incidents`)

Incident management page with:
- **List view** — sortable table with severity badges and status chips
- **Status filter** — open, investigating, resolved, closed, false positive
- **Detail view** — full incident evidence, timeline, and status update form
- **Notes** — add investigation notes when resolving or updating

### Rules (`/rules`)

CRUD interface for correlation rules:
- **List** — all rules with enable/disable toggle
- **Create** — form for custom rules (name, slug, severity, event source,
  trigger logic JSON)
- **Edit** — modify custom rules; system rules only allow enable/disable
- **Delete** — remove custom rules (system rules are protected)

### CA Policies (`/ca-policies`)

Three-tab Conditional Access policy visualizer:

#### Tab 1: Policies
- Expandable policy list with state badges (enabled / disabled / report-only)
- Each expanded row shows:
  - **Conditions** — users, apps, platforms, locations, sign-in risk, client apps
  - **Grant controls** — MFA, compliant device, domain join, auth strength, etc.
  - **Session controls** — sign-in frequency, persistent browser, app restrictions
  - **Mermaid flow diagram** — auto-generated decision flowchart for the policy

#### Tab 2: Coverage Map
- Matrix showing which policy areas are covered (users, apps, platforms,
  locations, sign-in risk, MFA)
- **Gap analysis** — identified gaps with descriptions and recommendations
- Summary statistics (total coverage percentage, gap count)

#### Tab 3: Reference Data
- **Named locations** — IP ranges and country-based locations
- **Authentication strengths** — allowed MFA combinations per strength level
- **Directory entries** — groups and roles referenced by policies

### Settings (`/settings`)

- View and change the current authentication mode
- Configure app registration settings
- Status flags for backend connectivity

---

## Authentication

### MSAL.js Integration

Authentication is handled by `AuthProvider.tsx` which wraps the app in an
`MsalProvider` from `@azure/msal-react`.

**Bootstrap flow:**
1. On app load, `GET /api/auth/config` is called to fetch auth configuration.
2. If `auth_mode` is `interactive` or `both`, MSAL is initialized with:
   - `clientId` from the backend config
   - `authority`: `https://login.microsoftonline.com/{tenant_id}`
   - `redirectUri`: current window origin
   - `cacheLocation`: `sessionStorage`
3. The MSAL instance is stored in React context.

**Login flow:**
1. User clicks "Sign in with Microsoft".
2. `loginPopup()` is called with scopes: `openid`, `profile`, `User.Read`.
3. On success, the access token is stored and a `tokenGetter` function is
   registered with the API client.
4. All subsequent `fetch()` calls include `Authorization: Bearer <token>`.

**Auth gate:**
- When `auth_mode` is `interactive`, unauthenticated users see a full-screen
  "Sign in with Microsoft" prompt instead of the app routes.
- When `auth_mode` is `both`, the app is accessible without login but the nav
  shows a "Sign In" button.
- When `auth_mode` is `client_credentials`, no login UI is shown.

### Token Injection

`api.ts` exports a `setTokenGetter(fn)` function. When set, every API call
automatically adds the `Authorization` header:

```typescript
let tokenGetter: (() => Promise<string | null>) | null = null;

export function setTokenGetter(fn: () => Promise<string | null>) {
  tokenGetter = fn;
}
```

---

## API Client

All backend communication goes through `api.ts` (~435 lines). It provides:

### Type Definitions

TypeScript interfaces for all API responses:
- `SignInLog`, `AuditLog`, `ActivityLog`
- `Incident`, `IncidentStats`
- `CorrelationRule`
- `DashboardSummary`, `RiskScore`, `IncidentTrend`, `LogVolume`, `WatchedUser`
- `CAPolicy`, `CAPolicyStats`, `CoverageBreakdown`, `CoverageGap`,
  `CoverageSummary`, `NamedLocation`, `AuthStrength`, `DirectoryEntry`
- `AuthConfig`, `AppSettings`

### Fetch Functions

Each API endpoint has a corresponding typed function:

```typescript
// Examples
export async function fetchSignInLogs(params): Promise<PaginatedResponse<SignInLog>>
export async function fetchIncidents(params): Promise<PaginatedResponse<Incident>>
export async function fetchCAPolicies(params): Promise<PaginatedResponse<CAPolicy>>
export async function fetchCoverageGaps(): Promise<CoverageGap[]>
export async function syncCAPolicies(): Promise<{ message: string }>
```

### Configuration

- **Base URL:** `/api` (relative — proxied by Vite in dev)
- **Error handling:** Throws on non-OK responses with status text
- **Content type:** JSON for all requests

---

## Styling

All styles are in `src/index.css` (~660 lines). The approach is plain CSS with
no CSS-in-JS or utility framework.

### Key Style Areas

| Area | Description |
|---|---|
| **Layout** | Sidebar navigation + main content area |
| **Cards** | KPI cards, stat cards, incident cards |
| **Tables** | Striped tables with hover, sortable headers |
| **Forms** | Input fields, selects, buttons, toggles |
| **Badges** | Severity (critical/high/medium/low/info), status, state |
| **Charts** | Recharts container sizing and colors |
| **CA Policies** | Tab navigation, expandable rows, coverage matrix, gap cards |
| **Auth** | Full-screen login prompt, user info display |
| **Responsive** | Basic responsive breakpoints for sidebar collapse |

### CA Policy-Specific Styles

- `.ca-tabs` — tab bar with active indicator
- `.ca-policy-row` — expandable policy list items
- `.ca-coverage-matrix` — grid layout for coverage areas
- `.ca-gap-card` — gap analysis cards with recommendation text
- `.mermaid-container` — sized container for Mermaid SVG output

---

## Building for Production

```bash
npm run build
```

Outputs to `dist/`. Serve with any static file server. In production, configure
the reverse proxy to route `/api/*` to the FastAPI backend.

### Vite Proxy Configuration

`vite.config.ts` sets up a dev proxy:

```typescript
server: {
  proxy: {
    '/api': {
      target: 'http://localhost:8000',
      changeOrigin: true,
    },
  },
}
```

---

## Configuration

### Environment / Build Variables

The frontend has no build-time environment variables. All configuration is
fetched at runtime from the backend:

| Endpoint | Data |
|---|---|
| `GET /api/auth/config` | Auth mode, tenant ID, client ID, scopes |
| `GET /api/settings` | Current auth mode, status flags |

This means a single production build works across environments — only the
backend configuration needs to change.

### CORS

The backend's `CORS_ORIGINS` env var must include the frontend's origin
(default: `http://localhost:5173`). For production, add your domain.
