import { useState, useEffect, createContext, useContext } from "react";
import { NavLink, useNavigate, useLocation } from "react-router-dom";
import {
  Server, ShieldAlert, Layers, Rocket, KeyRound,
  Terminal, LogOut, Activity, Search,
} from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { NAV, AUTH, CLI } from "@/constants/testIds";
import { CliDrawer } from "@/components/CliDrawer";
import { api } from "@/lib/api";

const CliCtx = createContext(null);
export const useCli = () => useContext(CliCtx);

const NAV_ITEMS = [
  { to: "/fleet", label: "fleet-overview", icon: Server, testId: NAV.fleet, cmd: "sec-master fleet list" },
  { to: "/cves", label: "cve-alerts", icon: ShieldAlert, testId: NAV.cve, cmd: "sec-master cve list --severity high" },
  { to: "/profiles", label: "profile-dist", icon: Layers, testId: NAV.profiles, cmd: "sec-master profiles stats" },
  { to: "/releases", label: "signed-releases", icon: Rocket, testId: NAV.releases, cmd: "sec-master releases --verify-sig" },
  { to: "/enroll", label: "enroll-workstation", icon: KeyRound, testId: NAV.enroll, cmd: "sec-master enroll --generate-token" },
];

export function Layout({ children }) {
  const { user, logout } = useAuth();
  const nav = useNavigate();
  const loc = useLocation();
  const [cliState, setCliState] = useState({ open: false, title: "", command: "", description: "" });
  const [health, setHealth] = useState({ fleet_total: "-", by_status: { online: 0, drift: 0, offline: 0 } });

  const openCli = (payload) => setCliState({ open: true, ...payload });
  const closeCli = () => setCliState((s) => ({ ...s, open: false }));

  useEffect(() => {
    let mounted = true;
    const load = async () => {
      try {
        const { data } = await api.get("/stats/overview");
        if (mounted) setHealth(data);
      } catch (_) { /* ignore */ }
    };
    load();
    const t = setInterval(load, 20000);
    return () => { mounted = false; clearInterval(t); };
  }, []);

  return (
    <CliCtx.Provider value={{ openCli }}>
      <div className="grain min-h-screen text-[#c0caf5] relative">
        {/* Top status bar */}
        <div className="sticky top-0 z-40 border-b" style={{ background: "var(--bg-terminal)", borderColor: "var(--border-subtle)" }}>
          <div className="flex items-center justify-between px-4 py-2 text-xs font-mono">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <span className="dot" style={{ color: "var(--status-online)", background: "var(--status-online)" }} />
                <span className="font-semibold tracking-widest uppercase" style={{ color: "var(--purple-analyst)" }}>security-master</span>
                <span className="text-[#565f89]">/ v0.11.0-rc1</span>
              </div>
              <div className="hidden md:flex items-center gap-3 text-[#565f89]">
                <Activity size={12} />
                <span>fleet: <span className="text-[#c0caf5]">{health.fleet_total}</span></span>
                <span>online: <span style={{ color: "var(--status-online)" }}>{health.by_status?.online || 0}</span></span>
                <span>drift: <span style={{ color: "var(--status-drift)" }}>{health.by_status?.drift || 0}</span></span>
                <span>offline: <span style={{ color: "var(--status-offline)" }}>{health.by_status?.offline || 0}</span></span>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <button
                data-testid={CLI.toggle}
                onClick={() => openCli({
                  title: "Open command palette",
                  command: "sec-master --help",
                  description: "Universal CLI. Every dashboard action has a CLI equivalent.",
                })}
                className="flex items-center gap-1.5 px-2 py-1 border rounded-sm hover:bg-[#292e42] text-[#a9b1d6]"
                style={{ borderColor: "var(--border-subtle)" }}
              >
                <Terminal size={12} /> <span className="hidden sm:inline">CLI</span>
                <kbd className="text-[10px] px-1 border rounded-sm" style={{ borderColor: "var(--border-subtle)" }}>⌘K</kbd>
              </button>
              <span className="hidden md:inline text-[#565f89]">{user?.email}</span>
              <button
                data-testid={AUTH.logoutBtn}
                onClick={async () => { await logout(); nav("/login"); }}
                className="flex items-center gap-1 px-2 py-1 border rounded-sm hover:bg-[#292e42]"
                style={{ borderColor: "var(--border-subtle)" }}
              >
                <LogOut size={12} /> logout
              </button>
            </div>
          </div>
        </div>

        <div className="flex">
          {/* Sidebar */}
          <aside
            className="hidden md:flex flex-col w-56 border-r sticky top-[37px] h-[calc(100vh-37px)]"
            style={{ background: "var(--bg-sidebar)", borderColor: "var(--border-subtle)" }}
          >
            <nav className="flex-1 py-3">
              {NAV_ITEMS.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  data-testid={item.testId}
                  className={({ isActive }) =>
                    `group flex items-center gap-3 px-4 py-2 text-xs font-mono border-l-2 transition-colors ${
                      isActive
                        ? "border-[#bb9af7] bg-[#292e42] text-[#c0caf5]"
                        : "border-transparent text-[#a9b1d6] hover:bg-[#24283b] hover:text-[#c0caf5]"
                    }`
                  }
                >
                  <item.icon size={14} />
                  <span className="tracking-tight">{item.label}</span>
                </NavLink>
              ))}
            </nav>
            <div className="p-3 border-t text-[10px] font-mono text-[#565f89] leading-relaxed" style={{ borderColor: "var(--border-subtle)" }}>
              <div className="mb-1 tracking-widest uppercase">motd</div>
              CLI-first. Every action shows the underlying command. No hidden GUI paths.
            </div>
          </aside>

          {/* Mobile nav */}
          <nav className="md:hidden flex overflow-x-auto border-b sticky top-[37px] z-30" style={{ background: "var(--bg-sidebar)", borderColor: "var(--border-subtle)" }}>
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                data-testid={item.testId + "-mobile"}
                className={({ isActive }) =>
                  `flex-shrink-0 px-3 py-2 text-[11px] font-mono border-b-2 ${
                    isActive ? "border-[#bb9af7] text-[#c0caf5]" : "border-transparent text-[#a9b1d6]"
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </nav>

          <main className="flex-1 min-w-0 p-3 sm:p-4 md:p-6 relative z-10">
            {children}
          </main>
        </div>

        <CliDrawer open={cliState.open} onClose={closeCli} {...cliState} />
      </div>
    </CliCtx.Provider>
  );
}
