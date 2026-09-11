import { useEffect, useState, useMemo } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "@/lib/api";
import { FLEET } from "@/constants/testIds";
import { useCli } from "@/components/Layout";
import { Search, RefreshCw, Filter, Terminal, Radar } from "lucide-react";
import { toast } from "sonner";

const PROFILE_META = {
  offense: { label: "OFFENSE", color: "var(--red-offense)", bg: "rgba(247,118,142,0.15)" },
  defense: { label: "DEFENSE", color: "var(--blue-defense)", bg: "rgba(125,207,255,0.15)" },
  analyst: { label: "ANALYST", color: "var(--purple-analyst)", bg: "rgba(187,154,247,0.15)" },
};
const STATUS_COLOR = { online: "var(--status-online)", drift: "var(--status-drift)", offline: "var(--status-offline)" };

export default function FleetOverview() {
  const [rows, setRows] = useState([]);
  const [filter, setFilter] = useState("all");
  const [q, setQ] = useState("");
  const [loading, setLoading] = useState(true);
  const { openCli } = useCli();
  const nav = useNavigate();

  const load = async () => {
    setLoading(true);
    try {
      const params = {};
      if (filter !== "all") params.profile = filter;
      if (q) params.q = q;
      const { data } = await api.get("/workstations", { params });
      setRows(data);
    } catch (e) { toast.error("Fleet load failed"); }
    setLoading(false);
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [filter]);

  const stats = useMemo(() => ({
    total: rows.length,
    online: rows.filter((r) => r.status === "online").length,
    drift: rows.filter((r) => r.status === "drift").length,
    offline: rows.filter((r) => r.status === "offline").length,
  }), [rows]);

  const filtered = useMemo(() => {
    if (!q) return rows;
    const needle = q.toLowerCase();
    return rows.filter((r) =>
      r.hostname.toLowerCase().includes(needle) ||
      r.ip_address?.toLowerCase().includes(needle) ||
      r.profile.includes(needle) ||
      r.tags?.some((t) => t.toLowerCase().includes(needle))
    );
  }, [rows, q]);

  const switchProfile = async (ws, next) => {
    try {
      const { data } = await api.post(`/workstations/${ws.id}/switch-profile`, { profile: next });
      toast.success(data.pending ? `${ws.hostname} → ${next} requested · agent applies on next heartbeat` : `${ws.hostname} → ${next}`);
      load();
    } catch { toast.error("Switch failed"); }
  };

  const [sweeping, setSweeping] = useState(false);
  const bulkSweep = async () => {
    setSweeping(true);
    try {
      const { data } = await api.post("/ioc/bulk-sweep", { scope: "online" });
      const providers = Object.entries(data.providers_used || {}).filter(([, v]) => v).map(([k]) => k).join("+");
      toast.success(`Swept ${data.hosts_swept} host(s) · ${data.total_lookups} lookups via ${providers || "no providers"}`);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Bulk sweep failed — is VirusTotal or Shodan enabled?");
    }
    setSweeping(false);
  };

  return (
    <div className="space-y-4">
      <header className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">// fleet</div>
          <h1 className="font-mono text-2xl sm:text-3xl tracking-tight text-[#c0caf5]">
            fleet-overview<span className="cursor" />
          </h1>
          <p className="text-xs text-[#a9b1d6] mt-1">
            <span className="font-mono">{stats.total}</span> workstations // {stats.online} online // {stats.drift} drift // {stats.offline} offline
          </p>
        </div>
        <div className="flex gap-2">
          <button
            data-testid="fleet-bulk-sweep-btn"
            onClick={bulkSweep} disabled={sweeping}
            className="flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-xs font-mono hover:bg-[#292e42] disabled:opacity-60"
            style={{ borderColor: "var(--purple-analyst)", color: "var(--purple-analyst)" }}
          >
            <Radar size={12} className={sweeping ? "animate-spin" : ""} /> {sweeping ? "sweeping…" : "bulk-sweep IOCs"}
          </button>
          <button
            onClick={load}
            className="flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-xs font-mono hover:bg-[#292e42]"
            style={{ borderColor: "var(--border-subtle)" }}
          ><RefreshCw size={12} /> refresh</button>
          <button
            onClick={() => openCli({
              title: "List all fleet workstations",
              command: "sec-master fleet list --profile all --format table\nsec-master ioc bulk-sweep --scope online",
              description: "Runs against the fleet daemon API, prints hostname/profile/status/tool-count.",
            })}
            className="flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-xs font-mono hover:bg-[#292e42]"
            style={{ borderColor: "var(--border-subtle)" }}
          ><Terminal size={12} /> cli</button>
        </div>
      </header>

      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2 border rounded-sm p-2" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
        <div className="flex items-center gap-1.5 flex-1 min-w-[200px] px-2">
          <Search size={12} className="text-[#565f89]" />
          <input
            data-testid={FLEET.search}
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="profile:red status:drift host:hydra-*"
            className="flex-1 bg-transparent font-mono text-xs focus:outline-none text-[#c0caf5] placeholder:text-[#565f89]"
          />
        </div>
        <Filter size={12} className="text-[#565f89]" />
        {[
          ["all", FLEET.filterAll, "text-[#c0caf5]"],
          ["offense", FLEET.filterRed, "text-[#f7768e]"],
          ["defense", FLEET.filterBlue, "text-[#7dcfff]"],
          ["analyst", FLEET.filterAnalyst, "text-[#bb9af7]"],
        ].map(([key, tid, cls]) => (
          <button
            key={key}
            data-testid={tid}
            onClick={() => setFilter(key)}
            className={`px-2 py-1 text-[10px] font-mono uppercase tracking-widest border rounded-sm ${
              filter === key ? "bg-[#292e42]" : "hover:bg-[#292e42]"
            } ${cls}`}
            style={{ borderColor: filter === key ? "var(--border-focus)" : "var(--border-subtle)" }}
          >{key}</button>
        ))}
      </div>

      {/* Table */}
      <div className="border rounded-sm overflow-x-auto" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
        <table className="min-w-full text-xs">
          <thead className="sticky-head">
            <tr className="text-left font-mono uppercase text-[10px] tracking-widest text-[#565f89] border-b" style={{ borderColor: "var(--border-subtle)" }}>
              {["hostname", "os", "profile", "agent", "tools", "last-heartbeat", "status", ""].map((h) => (
                <th key={h} className="px-3 py-2 whitespace-nowrap">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="font-mono text-[#c0caf5]">
            {loading && (
              <tr><td colSpan={8} className="px-3 py-6 text-center text-[#565f89]">loading fleet …</td></tr>
            )}
            {!loading && filtered.length === 0 && (
              <tr><td colSpan={8} className="px-3 py-6 text-center text-[#565f89]">
                {rows.length === 0 ? <>no workstations enrolled yet — go to <Link to="/enroll" className="underline text-[#bb9af7]">enroll-workstation</Link> and run the one-liner on a host</> : "no workstations match filter"}
              </td></tr>
            )}
            {filtered.map((ws) => {
              const pm = PROFILE_META[ws.profile];
              return (
                <tr key={ws.id} data-testid={FLEET.row} className="row-hover border-b" style={{ borderColor: "var(--border-subtle)" }}>
                  <td className="px-3 py-2">
                    <Link data-testid={FLEET.wsLink} to={`/fleet/${ws.id}`} className="hover:text-[#bb9af7] underline-offset-4 hover:underline">
                      {ws.hostname}
                    </Link>
                    {ws.demo && (
                      <span data-testid="fleet-demo-tag" className="ml-2 px-1 py-px text-[9px] uppercase tracking-widest border rounded-sm" style={{ color: "var(--status-drift)", borderColor: "var(--status-drift)" }}>demo</span>
                    )}
                    <div className="text-[10px] text-[#565f89]">{ws.ip_address}{ws.local_ip && ws.local_ip !== ws.ip_address ? ` · lan ${ws.local_ip}` : ""}</div>
                  </td>
                  <td className="px-3 py-2 text-[#a9b1d6]">{ws.os === "nixos" ? "nixos-flake" : "win-dsc"}</td>
                  <td className="px-3 py-2">
                    <span
                      className="inline-block px-2 py-0.5 text-[10px] tracking-widest border rounded-sm"
                      style={{ color: pm.color, borderColor: pm.color, background: pm.bg }}
                    >{pm.label}</span>
                    {ws.desired_profile && ws.desired_profile !== ws.profile && (
                      <div data-testid="fleet-pending-profile" className="mt-1 text-[9px] uppercase tracking-widest" style={{ color: "var(--status-drift)" }}>
                        → {ws.desired_profile} pending
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2 text-[#a9b1d6]">v{ws.agent_version}</td>
                  <td className="px-3 py-2">{ws.tools?.length ?? 0}</td>
                  <td className="px-3 py-2 text-[#a9b1d6]">{ws.last_heartbeat ? new Date(ws.last_heartbeat).toISOString().replace("T", " ").slice(0, 19) : "—"}</td>
                  <td className="px-3 py-2">
                    <span className="inline-flex items-center gap-1.5">
                      <span className="dot" style={{ color: STATUS_COLOR[ws.status], background: STATUS_COLOR[ws.status] }} />
                      <span className="text-[10px] uppercase tracking-widest" style={{ color: STATUS_COLOR[ws.status] }}>{ws.status}</span>
                    </span>
                  </td>
                  <td className="px-3 py-2 text-right">
                    <div className="flex gap-1 justify-end">
                      {["offense", "defense", "analyst"].filter((p) => p !== ws.profile).map((p) => (
                        <button
                          key={p}
                          data-testid={FLEET.switchBtn}
                          onClick={() => switchProfile(ws, p)}
                          title={`Switch to ${p}`}
                          className="px-1.5 py-0.5 text-[9px] uppercase tracking-widest border rounded-sm hover:bg-[#292e42]"
                          style={{ borderColor: PROFILE_META[p].color, color: PROFILE_META[p].color }}
                        >→ {p.slice(0, 3)}</button>
                      ))}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
