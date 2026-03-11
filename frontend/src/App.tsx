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
import Settings from "./pages/Settings";
import UserProfiles from "./pages/UserProfiles";

const links = [
  { to: "/", label: "Dashboard" },
  { to: "/signin-logs", label: "Sign-In Logs" },
  { to: "/user-profiles", label: "User Profiles" },
  { to: "/audit-logs", label: "Audit Logs" },
  { to: "/activity-logs", label: "Activity Logs" },
  { to: "/incidents", label: "Incidents" },
  { to: "/rules", label: "Rules" },
  { to: "/ca-policies", label: "CA Policies" },
  { to: "/settings", label: "Settings" },
];

export default function App() {
  const { isInteractiveMode, account, login, logout } = useAuth();

  return (
    <BrowserRouter>
      <div className="app-layout">
        <aside className="sidebar">
          <h1>Log Analytics</h1>
          <nav>
            {links.map((l) => (
              <NavLink key={l.to} to={l.to} end={l.to === "/"}>
                {l.label}
              </NavLink>
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
              <Route path="/settings" element={<Settings />} />
            </Routes>
          )}
        </main>
      </div>
    </BrowserRouter>
  );
}
