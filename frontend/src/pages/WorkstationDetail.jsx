import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "@/lib/api";
import { WS } from "@/constants/testIds";
import { useCli } from "@/components/Layout";
import { ArrowLeft, Terminal, Trash2 } from "lucide-react";
import { toast } from "sonner";
import IocPanel from "@/components/IocPanel";

const PROFILE_META = {
  offense: { color: "var(--red-offense)", bg: "rgba(247,118,142,0.15)" },
  defense: { color: "var(--blue-defense)", bg: "rgba(125,207,255,0.15)" },
  analyst: { color: "var(--purple-analyst)", bg: "rgba(187,154,247,0.15)" },
};

export default function WorkstationDetail() {
  const { id } = useParams();
  const [ws, setWs] = useState(null);
  const [audit, setAudit] = useState([]);
  const [showDrift, setShowDrift] = useState(false);
  const { openCli } = useCli();

  const load = async () => {
    try {
      const { data } = await api.get(`/workstations/${id}`);
      setWs(data.workstation);
      setAudit(data.audit || []);
    } catch { toast.error("Failed to load workstation"); }
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [id]);

  if (!ws) return <div className="text-[#565f89] font-mono text-xs">loading workstation …</div>;

  const pm = PROFILE_META[ws.profile];

  const switchTo = async (p) => {
    try { await api.post(`/workstations/${id}/switch-profile`, { profile: p }); toast.success(`switched to ${p}`); load(); }
    catch { toast.error("switch failed"); }
  };

  const destroy = async () => {
    if (!confirm(`Deregister ${ws.hostname}?`)) return;
    try { await api.delete(`/workstations/${id}`); toast.success("workstation deregistered"); window.history.back(); }
    catch { toast.error("delete failed"); }
  };

  return (
    <div className="space-y-4">
      <Link to="/fleet" className="inline-flex items-center gap-1 text-xs font-mono text-[#565f89] hover:text-[#c0caf5]">
        <ArrowLeft size={12} /> back to fleet
      </Link>

      <div className="border rounded-sm p-4" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
        <div className="flex flex-wrap items-center gap-3 justify-between">
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">// workstation</div>
            <h1 data-testid={WS.hostname} className="font-mono text-2xl text-[#c0caf5]">{ws.hostname}<span className="cursor" /></h1>
            <div className="mt-1 flex flex-wrap gap-2 text-[10px] font-mono text-[#a9b1d6]">
              <span>{ws.ip_address}</span>
              <span>·</span>
              <span>{ws.os === "nixos" ? "nixos-flake" : "windows-dsc"}</span>
              <span>·</span>
              <span>agent v{ws.agent_version}</span>
              <span>·</span>
              <span>{ws.status}</span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span
              data-testid={WS.profileBadge}
              className="px-3 py-1 text-xs font-mono tracking-widest uppercase border rounded-sm"
              style={{ color: pm.color, borderColor: pm.color, background: pm.bg }}
            >{ws.profile}</span>
            <div className="flex gap-1" data-testid={WS.switchTrigger}>
              {["offense", "defense", "analyst"].filter((p) => p !== ws.profile).map((p) => (
                <button key={p} onClick={() => switchTo(p)}
                  className="px-2 py-1 text-[10px] uppercase tracking-widest border rounded-sm hover:bg-[#292e42]"
                  style={{ borderColor: PROFILE_META[p].color, color: PROFILE_META[p].color }}
                >→ {p}</button>
              ))}
            </div>
            <button onClick={() => openCli({
              title: `Switch profile on ${ws.hostname}`,
              command: ws.os === "nixos"
                ? `ssh ${ws.hostname} 'nixos-rebuild switch --specialisation offense --flake github:sec-master/flake'`
                : `Invoke-Command -ComputerName ${ws.hostname} -ScriptBlock { Set-SMProfile offense }`,
              description: "Atomic profile switch. On NixOS this reboots into the specialisation. On Windows it applies the DSC config set.",
            })} className="p-1.5 border rounded-sm hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)" }}>
              <Terminal size={12} />
            </button>
            <button onClick={destroy} className="p-1.5 border rounded-sm hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)", color: "var(--sev-high)" }}>
              <Trash2 size={12} />
            </button>
          </div>
        </div>

        <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
          {[
            ["flake hash", ws.flake_hash || "—"],
            ["dsc hash", ws.dsc_hash || "—"],
            ["enrolled", new Date(ws.enrolled_at).toISOString().slice(0, 10)],
            ["last heartbeat", ws.last_heartbeat ? new Date(ws.last_heartbeat).toISOString().replace("T", " ").slice(0, 19) : "—"],
          ].map(([k, v]) => (
            <div key={k} className="border rounded-sm p-2" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-terminal)" }}>
              <div className="text-[10px] uppercase tracking-widest text-[#565f89]">{k}</div>
              <div className="text-[#c0caf5] truncate">{v}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Main grid: left = tools+audit, right = IOC enrichment */}
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="lg:col-span-2 space-y-4">
          {/* Tools */}
          <div className="border rounded-sm" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
            <div className="px-4 py-2 border-b flex items-center justify-between" style={{ borderColor: "var(--border-subtle)" }}>
              <div className="font-mono text-xs uppercase tracking-widest text-[#565f89]">installed tools ({ws.tools?.length || 0})</div>
              <button data-testid={WS.driftToggle} onClick={() => setShowDrift(!showDrift)} className="text-[10px] font-mono uppercase tracking-widest text-[#a9b1d6] hover:text-[#c0caf5]">
                {showDrift ? "hide" : "show"} drift-diff
              </button>
            </div>
            <div className="overflow-x-auto">
              <table data-testid={WS.toolTable} className="min-w-full text-xs font-mono">
                <thead>
                  <tr className="text-left uppercase text-[10px] tracking-widest text-[#565f89] border-b" style={{ borderColor: "var(--border-subtle)" }}>
                    <th className="px-4 py-2">tool</th>
                    <th className="px-4 py-2">version</th>
                    <th className="px-4 py-2">expected</th>
                    <th className="px-4 py-2">status</th>
                  </tr>
                </thead>
                <tbody>
                  {(ws.tools || []).map((t, i) => (
                    <tr key={i} className="row-hover border-b" style={{ borderColor: "var(--border-subtle)" }}>
                      <td className="px-4 py-2 text-[#c0caf5]">{t.name}</td>
                      <td className="px-4 py-2 text-[#a9b1d6]">{t.version}</td>
                      <td className="px-4 py-2 text-[#565f89]">{t.version}</td>
                      <td className="px-4 py-2"><span className="dot" style={{ color: "var(--status-online)", background: "var(--status-online)" }} /> <span className="text-[10px] uppercase tracking-widest text-[#9ece6a]">pinned</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Audit */}
          <div className="border rounded-sm" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
            <div className="px-4 py-2 border-b font-mono text-xs uppercase tracking-widest text-[#565f89]" style={{ borderColor: "var(--border-subtle)" }}>audit timeline</div>
            <ul data-testid={WS.auditTimeline} className="divide-y" style={{ borderColor: "var(--border-subtle)" }}>
              {audit.length === 0 && <li className="px-4 py-6 text-center text-[10px] font-mono text-[#565f89]">no audit events yet</li>}
              {audit.map((a) => (
                <li key={a.id} className="px-4 py-2 flex gap-3 text-xs font-mono">
                  <span className="text-[#565f89] w-40 flex-shrink-0">{new Date(a.at).toISOString().replace("T", " ").slice(0, 19)}</span>
                  <span className="text-[#bb9af7] w-28 flex-shrink-0">{a.kind}</span>
                  <span className="text-[#c0caf5]">{a.message}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* IOC right rail */}
        <aside className="lg:col-span-1">
          <div className="lg:sticky lg:top-16">
            <IocPanel workstationId={id} />
          </div>
        </aside>
      </div>
    </div>
  );
}
