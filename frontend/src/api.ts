/* ── TypeScript API client for the Log Analytics backend ────── */

const BASE = "/api";

/**
 * Token getter function — set by AuthProvider so every API call
 * can attach an Authorization header when interactive auth is active.
 */
let _getAccessToken: (() => Promise<string | null>) | null = null;

export function setTokenGetter(fn: (() => Promise<string | null>) | null) {
  _getAccessToken = fn;
}

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };

  // Attach bearer token when available
  if (_getAccessToken) {
    try {
      const token = await _getAccessToken();
      if (token) {
        headers["Authorization"] = `Bearer ${token}`;
      }
    } catch {
      // Token acquisition failed — continue without auth header
    }
  }

  const resp = await fetch(url, { ...init, headers });
  if (!resp.ok) {
    const body = await resp.text();
    throw new Error(`${resp.status} ${resp.statusText}: ${body}`);
  }
  if (resp.status === 204) return undefined as unknown as T;
  return resp.json() as Promise<T>;
}

/* ── Generic paginated response ────────────────────────────── */
export interface PaginatedResponse<T> {
  total: number;
  offset: number;
  limit: number;
  items: T[];
}

/* ── Sign-In Logs ──────────────────────────────────────────── */
export interface SignInLog {
  id: string;
  user_display_name: string;
  user_principal_name: string;
  app_display_name: string;
  ip_address: string;
  location_city: string;
  location_country: string;
  status_error_code: number;
  status_failure_reason: string;
  risk_level_during_signin: string;
  risk_level_aggregated: string;
  conditional_access_status: string;
  is_interactive: boolean;
  created_datetime: string;
}

export function fetchSignInLogs(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return request<PaginatedResponse<SignInLog>>(`${BASE}/logs/signin?${qs}`);
}

/* ── Audit Logs ────────────────────────────────────────────── */
export interface AuditLogEntry {
  id: string;
  category: string;
  activity_display_name: string;
  activity_datetime: string;
  result: string;
  result_reason: string;
  initiated_by_user: string;
  initiated_by_app: string;
  target_resources: unknown[];
  correlation_id: string;
}

export function fetchAuditLogs(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return request<PaginatedResponse<AuditLogEntry>>(`${BASE}/logs/audit?${qs}`);
}

/* ── Activity Logs (O365/SharePoint/PowerApps) ─────────────── */
export interface ActivityLog {
  id: string;
  source: string;
  workload: string;
  operation: string;
  user_id: string;
  client_ip: string;
  creation_time: string;
  result_status: string;
  object_id: string;
  site_url: string;
  source_file_name: string;
  app_name: string;
  environment_name: string;
}

export function fetchActivityLogs(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return request<PaginatedResponse<ActivityLog>>(`${BASE}/logs/activity?${qs}`);
}

/* ── Event Lookup (cross-table) ───────────────────────────── */
export interface EventLookupResult {
  event_type: "signin" | "audit" | "activity";
  event: Record<string, unknown>;
}

export function fetchEvent(eventId: string) {
  return request<EventLookupResult>(`${BASE}/logs/event/${encodeURIComponent(eventId)}`);
}

/* ── Incidents ─────────────────────────────────────────────── */
export interface IncidentEntry {
  id: number;
  rule_slug: string;
  rule_name: string;
  rule_description: string;
  rule_risk_points: number;
  rule_category: string;
  severity: string;
  user_id: string;
  user_display_name: string;
  title: string;
  description: string;
  evidence: unknown;
  risk_score_contribution: number;
  status: string;
  assigned_to: string;
  notes: string;
  mitre_tactic: string;
  mitre_technique: string;
  created_at: string;
  updated_at: string;
}

export function fetchIncidents(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return request<PaginatedResponse<IncidentEntry>>(`${BASE}/incidents?${qs}`);
}

export function patchIncident(id: number, data: Record<string, unknown>) {
  return request<IncidentEntry>(`${BASE}/incidents/${id}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export interface IncidentStats {
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  total: number;
}

export function fetchIncidentStats() {
  return request<IncidentStats>(`${BASE}/incidents/stats/summary`);
}

/* ── Rules ─────────────────────────────────────────────────── */
export interface RuleEntry {
  id: number;
  slug: string;
  name: string;
  description: string;
  severity: string;
  risk_points: number;
  watch_window_days: number;
  rule_json: unknown;
  enabled: boolean;
  is_system: boolean;
  created_at: string;
}

export function fetchRules(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return request<PaginatedResponse<RuleEntry>>(`${BASE}/rules?${qs}`);
}

export function patchRule(id: number, data: Record<string, unknown>) {
  return request<RuleEntry>(`${BASE}/rules/${id}`, {
    method: "PATCH",
    body: JSON.stringify(data),
  });
}

export function deleteRule(id: number) {
  return request<void>(`${BASE}/rules/${id}`, { method: "DELETE" });
}

/* ── Log Sync ──────────────────────────────────────────────── */
export interface SyncResult {
  status: string;
  message: string;
}

export interface SyncLogEntry {
  timestamp: string;
  level: string;
  message: string;
}

export interface SyncStatus {
  state: "idle" | "running" | "completed" | "failed";
  started_at: string | null;
  completed_at: string | null;
  entries: SyncLogEntry[];
}

export function syncLogs() {
  return request<SyncResult>(`${BASE}/logs/sync`, { method: "POST" });
}

export function fetchSyncStatus() {
  return request<SyncStatus>(`${BASE}/logs/sync/status`);
}

/* ── Dashboard ─────────────────────────────────────────────── */
export interface DashboardSummary {
  open_incidents: number;
  critical_incidents_24h: number;
  incidents_7d: number;
  active_watch_windows: number;
  signin_events_24h: number;
}

export function fetchDashboardSummary() {
  return request<DashboardSummary>(`${BASE}/dashboard/summary`);
}

export interface WindowDetail {
  rule_id: number;
  rule_name: string | null;
  rule_slug: string | null;
  rule_description: string | null;
  risk_contribution: number;
  window_start: string | null;
  window_end: string;
  trigger_event_id: string;
  trigger_event_source: string;
}

export interface RiskScore {
  user_id: string;
  score: number;
  base_risk: number;
  entra_risk: number;
  entra_risk_level: string | null;
  multiplier: number;
  active_windows: number;
  window_details: WindowDetail[];
}

export function fetchRiskScores(threshold = 0) {
  return request<{ users: RiskScore[] }>(
    `${BASE}/dashboard/risk-scores?threshold=${threshold}`
  );
}

export interface LogVolumes {
  days: number;
  volumes: Record<string, number>;
}

export function fetchLogVolume(days = 7) {
  return request<LogVolumes>(`${BASE}/dashboard/log-volume?days=${days}`);
}

export interface IncidentTrend {
  days: number;
  trend: Record<string, Record<string, number>>;
}

export function fetchIncidentTrend(days = 30) {
  return request<IncidentTrend>(`${BASE}/dashboard/incident-trend?days=${days}`);
}

export interface WatchedUser {
  user_id: string;
  rule_slug: string;
  risk_contribution: number;
  started_at: string;
  expires_at: string;
}

export function fetchWatchedUsers() {
  return request<{ count: number; users: WatchedUser[] }>(
    `${BASE}/dashboard/watched-users`
  );
}

/* ── Auth & Settings ───────────────────────────────────────── */

export interface AuthConfig {
  auth_mode: "client_credentials" | "interactive" | "both";
  authority: string;
  client_id: string;
  redirect_uri: string;
  scopes: string[];
}

export function fetchAuthConfig() {
  return request<AuthConfig>(`${BASE}/auth/config`);
}

export interface CurrentUser {
  sub: string;
  name: string;
  preferred_username: string;
  oid: string;
  tid: string;
}

export function fetchCurrentUser() {
  return request<CurrentUser>(`${BASE}/auth/me`);
}

export interface SettingsResponse {
  auth_mode: string;
  client_credentials_configured: boolean;
  interactive_auth_enabled: boolean;
  azure_tenant_id: string;
  azure_client_id: string;
  has_client_secret: boolean;
  frontend_client_id: string;
  jwt_audience: string;
  available_collectors: string[];
}

export function fetchSettings() {
  return request<SettingsResponse>(`${BASE}/settings`);
}

export interface SettingsUpdate {
  auth_mode?: string;
  azure_tenant_id?: string;
  azure_client_id?: string;
  azure_client_secret?: string;
  frontend_client_id?: string;
  jwt_audience?: string;
}

export function updateSettings(data: SettingsUpdate) {
  return request<SettingsResponse>(`${BASE}/settings`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

/* ── Conditional Access Policies ──────────────────────────── */

export interface CAPolicy {
  id: string;
  display_name: string;
  state: string;
  created_date_time: string | null;
  modified_date_time: string | null;
  conditions: Record<string, unknown>;
  grant_controls: Record<string, unknown>;
  session_controls: Record<string, unknown>;
  coverage?: CoverageEntry[];
}

export interface CoverageEntry {
  entity_type: string;
  entity_id: string;
  entity_display_name: string;
  inclusion_type: string;
}

export interface CAPolicyStats {
  total_policies: number;
  by_state: Record<string, number>;
  named_locations: number;
  auth_strengths: number;
  directory_entries: number;
}

export interface CoverageByEntity {
  entity_type: string;
  entity_id: string;
  entity_display_name: string;
  policies: { policy_id: string; inclusion_type: string }[];
}

export interface CoverageByPolicy {
  policy_id: string;
  entities: CoverageEntry[];
}

export interface CoverageResponse {
  total_entries: number;
  by_entity: CoverageByEntity[];
  by_policy: CoverageByPolicy[];
}

export interface CoverageGap {
  policy_id: string;
  display_name: string;
  state: string;
  issues: string[];
}

export interface CoverageSummary {
  entity_coverage: Record<string, { included: number; excluded: number }>;
  policy_states: Record<string, number>;
  total_policies: number;
}

export interface NamedLocationEntry {
  id: string;
  display_name: string;
  is_trusted: boolean;
  location_type: string;
  ip_ranges: string[];
  countries_and_regions: string[];
  include_unknown_countries: boolean;
}

export interface AuthStrengthEntry {
  id: string;
  display_name: string;
  description: string;
  policy_type: string;
  requirements_satisfied: string;
  allowed_combinations: string[];
}

export interface DirectoryEntry {
  id: string;
  display_name: string;
  object_type: string;
  description: string;
}

export function fetchCAPolicies(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return request<PaginatedResponse<CAPolicy>>(`${BASE}/ca-policies?${qs}`);
}

export function fetchCAPolicy(id: string) {
  return request<CAPolicy>(`${BASE}/ca-policies/${id}`);
}

export function fetchCAPolicyStats() {
  return request<CAPolicyStats>(`${BASE}/ca-policies/stats`);
}

export function fetchCACoverage(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return request<CoverageResponse>(`${BASE}/ca-policies/coverage?${qs}`);
}

export function fetchCACoverageGaps() {
  return request<{ total_gaps: number; gaps: CoverageGap[] }>(
    `${BASE}/ca-policies/coverage/gaps`
  );
}

export function fetchCACoverageSummary() {
  return request<CoverageSummary>(`${BASE}/ca-policies/coverage/summary`);
}

export function fetchNamedLocations() {
  return request<{ total: number; items: NamedLocationEntry[] }>(
    `${BASE}/ca-policies/named-locations`
  );
}

export function fetchAuthStrengths() {
  return request<{ total: number; items: AuthStrengthEntry[] }>(
    `${BASE}/ca-policies/auth-strengths`
  );
}

export function fetchDirectoryEntries(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return request<{ total: number; items: DirectoryEntry[] }>(
    `${BASE}/ca-policies/directory-entries?${qs}`
  );
}

/* ── CA Policy Overlap Graph ──────────────────────────────── */

export interface OverlapGraphNode {
  id: string;
  type: "policy" | "entity";
  label: string;
  state?: string;
  grant_controls?: string[];
  entity_type?: string;
  is_overlap?: boolean;
  policy_count?: number;
}

export interface OverlapGraphLink {
  source: string;
  target: string;
  inclusion_type: string;
}

export interface OverlapResponse {
  nodes: OverlapGraphNode[];
  links: OverlapGraphLink[];
  overlap_summary: Record<string, number>;
}

export function fetchCAOverlaps(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return request<OverlapResponse>(`${BASE}/ca-policies/overlaps?${qs}`);
}

/* ── CA Policy Lookup ────────────────────────────────────── */

export interface PolicyMatch {
  entity_type: string;
  entity_id: string;
  entity_display_name: string;
  inclusion_type: string;
  is_wildcard: boolean;
}

export interface LookupPolicyResult {
  policy: CAPolicy;
  matches: PolicyMatch[];
}

export interface LookupResponse {
  query: string;
  entity_type: string | null;
  total_policies: number;
  policies: LookupPolicyResult[];
}

export interface ResolvedEntity {
  type: string;
  id: string;
  display_name: string;
  upn?: string;
  app_id?: string;
  group_ids: string[];
}

export interface ResolveLookupResponse {
  query: string;
  entity_type: string | null;
  resolved: ResolvedEntity | null;
  total_policies: number;
  policies: LookupPolicyResult[];
}

export function fetchCALookup(query: string, entityType?: string) {
  const params: Record<string, string> = { query };
  if (entityType) params.entity_type = entityType;
  const qs = new URLSearchParams(params).toString();
  return request<LookupResponse>(`${BASE}/ca-policies/lookup?${qs}`);
}

export function resolveCALookup(query: string, entityType?: string) {
  const params: Record<string, string> = { query };
  if (entityType) params.entity_type = entityType;
  const qs = new URLSearchParams(params).toString();
  return request<ResolveLookupResponse>(`${BASE}/ca-policies/lookup/resolve?${qs}`, {
    method: "POST",
  });
}

export function syncCAPolicies() {
  return request<{ status: string; synced: Record<string, number> }>(
    `${BASE}/ca-policies/sync`,
    { method: "POST" }
  );
}

/* ── User Sign-In Profiles ────────────────────────────────── */

export interface KnownLocation {
  city: string;
  state: string;
  country: string;
  lat: number | null;
  lon: number | null;
  first_seen: string;
  last_seen: string;
  count: number;
}

export interface KnownDevice {
  device_os: string;
  device_browser: string;
  device_id: string;
  first_seen: string;
  last_seen: string;
  count: number;
}

export interface KnownIP {
  ip_address: string;
  first_seen: string;
  last_seen: string;
  count: number;
}

export interface UserProfile {
  user_principal_name: string;
  user_display_name: string;
  user_id: string;
  known_locations: KnownLocation[];
  known_devices: KnownDevice[];
  known_ips: KnownIP[];
  sign_in_hour_histogram: number[];
  total_sign_ins: number;
  first_seen: string | null;
  last_seen: string | null;
  is_risky: boolean;
  risk_reasons: string[];
  risk_flagged_at: string | null;
  updated_at: string | null;
}

export interface SignInSummary {
  id: string;
  created_datetime: string | null;
  ip_address: string;
  location_city: string;
  location_country: string;
  device_os: string;
  device_browser: string;
  risk_level: string;
  app_display_name: string;
  status_error_code: number;
  conditional_access_status: string;
}

export interface UserProfileDetail {
  profile: UserProfile;
  recent_signin_logs: SignInSummary[];
}

export interface GroupedUserEntry {
  profile: UserProfile;
  recent_logs: SignInSummary[];
}

export function fetchUserProfiles(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return request<PaginatedResponse<UserProfile>>(`${BASE}/users/profiles?${qs}`);
}

export function fetchUserProfile(upn: string) {
  return request<UserProfileDetail>(`${BASE}/users/profiles/${encodeURIComponent(upn)}`);
}

export function refreshUserProfiles() {
  return request<{ status: string; updated: number; newly_risky: number }>(
    `${BASE}/users/profiles/refresh`,
    { method: "POST" }
  );
}

export function fetchSignInGroupedByUser(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return request<PaginatedResponse<GroupedUserEntry>>(`${BASE}/users/signin-grouped?${qs}`);
}

/* ── PIM (Privileged Identity Management) ────────────────── */

export interface PIMRoleDefinition {
  id: string;
  display_name: string;
  description: string;
  is_built_in: boolean;
  is_enabled: boolean;
}

export interface PIMAssignment {
  id: string;
  principal_id: string;
  principal_display_name: string;
  principal_type: string;
  role_definition_id: string;
  role_display_name: string;
  directory_scope_id: string;
  assignment_type: string;
  member_type: string;
  start_date_time: string | null;
  end_date_time: string | null;
  is_permanent: boolean;
  raw_json: Record<string, unknown>;
}

export interface PIMEligibility {
  id: string;
  principal_id: string;
  principal_display_name: string;
  principal_type: string;
  role_definition_id: string;
  role_display_name: string;
  directory_scope_id: string;
  member_type: string;
  start_date_time: string | null;
  end_date_time: string | null;
  raw_json: Record<string, unknown>;
}

export interface PIMActivation {
  id: string;
  principal_id: string;
  principal_display_name: string;
  role_definition_id: string;
  role_display_name: string;
  action: string;
  status: string;
  justification: string;
  created_date_time: string | null;
  schedule_start: string | null;
  schedule_end: string | null;
  raw_json: Record<string, unknown>;
}

export interface PIMAuditLog {
  id: string;
  activity_display_name: string;
  activity_date_time: string | null;
  category: string;
  result: string;
  result_reason: string;
  initiated_by_user_upn: string;
  initiated_by_user_display_name: string;
  initiated_by_app_display_name: string;
  target_resources: unknown[];
  additional_details: unknown[];
  raw_json: Record<string, unknown>;
}

export interface PIMStats {
  total_assignments: number;
  total_eligibilities: number;
  permanent_assignments: number;
  activations_24h: number;
  activations_7d: number;
}

export interface PIMInsights {
  top_activated_roles: { role: string; count: number }[];
  top_activating_users: { user: string; count: number }[];
  role_distribution: { role: string; active: number; eligible: number }[];
  permanent_vs_timebound: { permanent: number; time_bound: number };
}

export function fetchPIMRoleDefinitions() {
  return request<{ total: number; items: PIMRoleDefinition[] }>(`${BASE}/pim/role-definitions`);
}

export function fetchPIMAssignments(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return request<PaginatedResponse<PIMAssignment>>(`${BASE}/pim/assignments?${qs}`);
}

export function fetchPIMEligibilities(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return request<PaginatedResponse<PIMEligibility>>(`${BASE}/pim/eligibilities?${qs}`);
}

export function fetchPIMActivations(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return request<PaginatedResponse<PIMActivation>>(`${BASE}/pim/activations?${qs}`);
}

export function fetchPIMAuditLogs(params: Record<string, string> = {}) {
  const qs = new URLSearchParams(params).toString();
  return request<PaginatedResponse<PIMAuditLog>>(`${BASE}/pim/audit-logs?${qs}`);
}

export function fetchPIMStats() {
  return request<PIMStats>(`${BASE}/pim/stats`);
}

export function fetchPIMInsights() {
  return request<PIMInsights>(`${BASE}/pim/insights`);
}

export function syncPIM() {
  return request<{ status: string; synced: Record<string, number> }>(
    `${BASE}/pim/sync`,
    { method: "POST" }
  );
}
