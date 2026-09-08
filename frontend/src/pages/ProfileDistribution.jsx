import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { useCli } from "@/components/Layout";
import { Terminal } from "lucide-react";

const PROFILE_COLOR = { offense: "var(--red-offense)", defense: "var(--blue-defense)", analyst: "var(--purple-analyst)" };
const OS_COLOR = { nixos: "var(--status-info)", windows: "var(--border-accent)" };

function Bar({ label, value, total, color }) {
  const pct = total > 0 ? Math.round((value / total) * 100) : 0;
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-[11px] font-mono">
        <span className="uppercase tracking-widest text-[#a9b1d6]">{label}</span>
        <span style={{ color }}>{value} / {total} <span className="text-[#565f89]">({pct}%)</span></span>
      </div>
      <div className="h-2 border rounded-sm overflow-hidden" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-terminal)" }}>
        <div style={{ width: `${pct}%`, background: color, height: "100%" }} />
      </div>
    </div>
  );
}

export default function ProfileDistribution() {
  const [stats, setStats] = useState(null);
  const { openCli } = useCli();

  useEffect(() => { api.get("/stats/overview").then(({ data }) => setStats(data)); }, []);

  if (!stats) return <div className="text-[#565f89] font-mono text-xs">loading stats …</div>;

  const total = stats.fleet_total || 0;

  return (
    <div className="space-y-4">
      <header className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">// distribution</div>
          <h1 className="font-mono text-2xl sm:text-3xl tracking-tight text-[#c0caf5]">profile-dist<span className="cursor" /></h1>
          <p className="text-xs text-[#a9b1d6] mt-1">fleet health, profile mix, and OS coverage</p>
        </div>
        <button onClick={() => openCli({
          title: "Fleet health report",
          command: "sec-master profiles stats --json | jq .",
          description: "Aggregates workstations by profile, OS, and heartbeat status.",
        })} className="flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-xs font-mono hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)" }}>
          <Terminal size={12} /> cli
        </button>
      </header>

      <div className="grid gap-4 md:grid-cols-3">
        <section className="border rounded-sm p-4 space-y-3" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89]">by profile</div>
          <Bar label="offense" value={stats.by_profile.offense} total={total} color={PROFILE_COLOR.offense} />
          <Bar label="defense" value={stats.by_profile.defense} total={total} color={PROFILE_COLOR.defense} />
          <Bar label="analyst" value={stats.by_profile.analyst} total={total} color={PROFILE_COLOR.analyst} />
        </section>

        <section className="border rounded-sm p-4 space-y-3" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89]">by OS</div>
          <Bar label="nixos-flake" value={stats.by_os.nixos} total={total} color={OS_COLOR.nixos} />
          <Bar label="windows-dsc" value={stats.by_os.windows} total={total} color={OS_COLOR.windows} />
          <div className="mt-3 text-[10px] font-mono text-[#565f89] leading-relaxed">
            windows parity: ~72% coverage of linux tooling (per project honesty policy)
          </div>
        </section>

        <section className="border rounded-sm p-4 space-y-3" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89]">by status</div>
          <Bar label="online" value={stats.by_status.online} total={total} color="var(--status-online)" />
          <Bar label="drift" value={stats.by_status.drift} total={total} color="var(--status-drift)" />
          <Bar label="offline" value={stats.by_status.offline} total={total} color="var(--status-offline)" />
        </section>
      </div>

      <section className="border rounded-sm p-4" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
        <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-3">cve severity mix</div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 font-mono">
          {["critical", "high", "medium", "low"].map((s) => (
            <div key={s} className="border rounded-sm p-3" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-terminal)" }}>
              <div className="text-[10px] uppercase tracking-widest" style={{ color: `var(--sev-${s})` }}>{s}</div>
              <div className="text-2xl mt-1" style={{ color: `var(--sev-${s})` }}>{stats.cve_by_severity[s]}</div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
