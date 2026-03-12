import { BrowserRouter, Routes, Route, NavLink } from "react-router-dom";
import "./index.css";
import { useAuth } from "./auth/AuthProvider";
import Dashboard from "./pages/Dashboard";
import SignInLogs from "./pages/SignInLogs";
import AuditLogs from "./pages/AuditLogs";
import ActivityLogs from "./pages/ActivityLogs";
import Incidents from "./pages/Incidents";
import RulesPage from "./pages/RulesPage";
import CAPolicies from "./pages/CAPolicies";
import PIMDashboard from "./pages/PIMDashboard";
import Settings from "./pages/Settings";
import UserProfiles from "./pages/UserProfiles";

interface NavItem {
  to: string;
  label: string;
  tooltip: string;
  section?: string;
}

const links: NavItem[] = [
  {
    to: "/",
    label: "Security Overview",
    tooltip: "KPIs, log volume trends, and top risk scores at a glance",
    section: "analytics",
  },
  {
    to: "/signin-logs",
    label: "Sign-In Logs",
    tooltip: "Entra ID authentication events — filter by user, risk level, and status",
    section: "logs",
  },
  {
    to: "/user-profiles",
    label: "User Risk Profiles",
    tooltip: "Per-user risk scoring, sign-in patterns, and behavioral anomalies",
    section: "logs",
  },
  {
    to: "/audit-logs",
    label: "Directory Audit Logs",
    tooltip: "Entra ID directory changes — role updates, app registrations, and policy modifications",
    section: "logs",
  },
  {
    to: "/activity-logs",
    label: "Activity Timeline",
    tooltip: "Unified timeline of all collected cloud activity across sources",
    section: "logs",
  },
  {
    to: "/incidents",
    label: "Security Incidents",
    tooltip: "Correlated alerts triggered by detection rules — triage and resolve threats",
    section: "detection",
  },
  {
    to: "/rules",
    label: "Detection Rules",
    tooltip: "Manage correlation rules that analyze logs and generate security incidents",
    section: "detection",
  },
  {
    to: "/ca-policies",
    label: "Conditional Access",
    tooltip: "Visualize Conditional Access policies, coverage gaps, and policy overlaps",
    section: "identity",
  },
  {
    to: "/pim",
    label: "Privileged Access",
    tooltip: "PIM role assignments, activations, eligibilities, and privileged access insights",
    section: "identity",
  },
  {
    to: "/settings",
    label: "Configuration",
    tooltip: "Authentication mode, app registration credentials, and sync settings",
    section: "system",
  },
];

const sectionLabels: Record<string, string> = {
  analytics: "Analytics",
  logs: "Log Explorer",
  detection: "Threat Detection",
  identity: "Identity & Access",
  system: "System",
};

export default function App() {
  const { isInteractiveMode, account, login, logout } = useAuth();

  // Group links by section
  const sections = links.reduce<Record<string, NavItem[]>>((acc, link) => {
    const section = link.section ?? "other";
    if (!acc[section]) acc[section] = [];
    acc[section].push(link);
    return acc;
  }, {});

  return (
    <BrowserRouter>
      <div className="app-layout">
        <aside className="sidebar">
          <h1>Entra Security Analytics</h1>
          <nav>
            {Object.entries(sections).map(([section, items]) => (
              <div key={section} className="nav-section">
                <div className="nav-section-label">{sectionLabels[section] ?? section}</div>
                {items.map((l) => (
                  <NavLink key={l.to} to={l.to} end={l.to === "/"} title={l.tooltip}>
                    {l.label}
                  </NavLink>
                ))}
              </div>
            ))}
          </nav>

          {/* Auth status in sidebar footer */}
          <div className="sidebar-footer">
            {isInteractiveMode && (
              <>
                {account ? (
                  <div className="auth-info">
                    <span className="auth-user" title={account.username}>
                      {account.name ?? account.username}
                    </span>
                    <button className="btn btn-sm btn-outline" onClick={logout}>
                      Sign Out
                    </button>
                  </div>
                ) : (
                  <button className="btn btn-primary" onClick={login}>
                    Sign In
                  </button>
                )}
              </>
            )}
          </div>
        </aside>

        <main className="main-content">
          {isInteractiveMode && !account ? (
            <div className="auth-gate">
              <h2>Authentication Required</h2>
              <p>Please sign in with your Entra ID account to access the dashboard.</p>
              <button className="btn btn-primary btn-lg" onClick={login}>
                Sign In with Microsoft
              </button>
            </div>
          ) : (
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/signin-logs" element={<SignInLogs />} />
              <Route path="/user-profiles" element={<UserProfiles />} />
              <Route path="/audit-logs" element={<AuditLogs />} />
              <Route path="/activity-logs" element={<ActivityLogs />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="/rules" element={<RulesPage />} />
              <Route path="/ca-policies" element={<CAPolicies />} />
              <Route path="/pim" element={<PIMDashboard />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          )}
        </main>
      </div>
    </BrowserRouter>
  );
}
