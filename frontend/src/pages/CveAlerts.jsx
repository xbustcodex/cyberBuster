import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { CVE } from "@/constants/testIds";
import { useCli } from "@/components/Layout";
import { RefreshCw, ShieldAlert, Copy, Terminal } from "lucide-react";
import { toast } from "sonner";

const SEV_META = {
  critical: { color: "var(--sev-critical)", bg: "rgba(219,75,75,0.18)" },
  high:     { color: "var(--sev-high)",     bg: "rgba(247,118,142,0.18)" },
  medium:   { color: "var(--sev-medium)",   bg: "rgba(224,175,104,0.18)" },
  low:      { color: "var(--sev-low)",      bg: "rgba(158,206,106,0.18)" },
};

export default function CveAlerts() {
  const [rows, setRows] = useState([]);
  const [sev, setSev] = useState("all");
  const [expanded, setExpanded] = useState(null);
  const { openCli } = useCli();

  const load = async () => {
    try {
      const { data } = await api.get("/cves", { params: sev === "all" ? {} : { severity: sev } });
      setRows(data);
    } catch { toast.error("CVE load failed"); }
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [sev]);

  const rescan = async () => {
    try { await api.post("/cves/rescan"); toast.success("Fleet rescanned against CVE database"); load(); }
    catch { toast.error("rescan failed"); }
  };

  return (
    <div className="space-y-4">
      <header className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">// vulnerabilities</div>
          <h1 className="font-mono text-2xl sm:text-3xl tracking-tight text-[#c0caf5]">cve-alerts<span className="cursor" /></h1>
          <p className="text-xs text-[#a9b1d6] mt-1">{rows.length} advisories matched against installed tool versions</p>
        </div>
        <div className="flex gap-2">
          <button onClick={rescan} className="flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-xs font-mono hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)" }}>
            <RefreshCw size={12} /> rescan fleet
          </button>
          <button onClick={() => openCli({
            title: "CVE feed sync + fleet match",
            command: "sec-master cve sync --source nvd && sec-master cve match --fleet all",
            description: "Pulls latest NVD advisories, then matches CVEs against tool versions installed on every enrolled workstation.",
          })} className="flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-xs font-mono hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)" }}>
            <Terminal size={12} /> cli
          </button>
        </div>
      </header>

      {/* Severity filter chips */}
      <div className="flex flex-wrap items-center gap-2">
        {[
          ["all", null, "text-[#c0caf5]"],
          ["critical", CVE.filterCritical, ""],
          ["high", CVE.filterHigh, ""],
          ["medium", null, ""],
          ["low", null, ""],
        ].map(([key, tid, cls]) => {
          const m = SEV_META[key];
          return (
            <button
              key={key}
              data-testid={tid || undefined}
              onClick={() => setSev(key)}
              className={`px-3 py-1 text-[10px] font-mono uppercase tracking-widest border rounded-sm ${cls}`}
              style={{
                borderColor: m?.color || "var(--border-subtle)",
                color: m?.color || "var(--text-primary)",
                background: sev === key ? (m?.bg || "var(--bg-card-hover)") : "transparent",
              }}
            >{key}</button>
          );
        })}
      </div>

      <div className="border rounded-sm overflow-x-auto" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
        <table className="min-w-full text-xs">
          <thead>
            <tr className="text-left font-mono uppercase text-[10px] tracking-widest text-[#565f89] border-b" style={{ borderColor: "var(--border-subtle)" }}>
              {["cve-id", "sev", "cvss", "tool", "matches", "summary", "published", ""].map((h) => <th key={h} className="px-3 py-2">{h}</th>)}
            </tr>
          </thead>
          <tbody className="font-mono">
            {rows.map((c) => {
              const m = SEV_META[c.severity];
              return (
                <>
                  <tr key={c.id} data-testid={CVE.row} className="row-hover border-b" style={{ borderColor: "var(--border-subtle)" }}>
                    <td className="px-3 py-2 text-[#c0caf5]">{c.cve_id}</td>
                    <td className="px-3 py-2">
                      <span className="px-1.5 py-0.5 text-[10px] uppercase tracking-widest border rounded-sm" style={{ color: m.color, borderColor: m.color, background: m.bg }}>
                        {c.severity}
                      </span>
                    </td>
                    <td className="px-3 py-2" style={{ color: m.color }}>{c.cvss.toFixed(1)}</td>
                    <td className="px-3 py-2 text-[#a9b1d6]">{c.affected_tool}</td>
                    <td className="px-3 py-2">
                      <span className="inline-flex items-center gap-1">
                        <ShieldAlert size={10} style={{ color: c.matched_workstations > 0 ? m.color : "var(--text-muted)" }} />
                        <span style={{ color: c.matched_workstations > 0 ? m.color : "var(--text-muted)" }}>{c.matched_workstations}</span>
                      </span>
                    </td>
                    <td className="px-3 py-2 text-[#a9b1d6] max-w-md truncate">{c.summary}</td>
                    <td className="px-3 py-2 text-[#565f89]">{new Date(c.published).toISOString().slice(0, 10)}</td>
                    <td className="px-3 py-2 text-right">
                      <button data-testid={CVE.remediate} onClick={() => setExpanded(expanded === c.id ? null : c.id)}
                        className="px-2 py-1 text-[10px] uppercase tracking-widest border rounded-sm hover:bg-[#292e42]"
                        style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
                      >remediate</button>
                    </td>
                  </tr>
                  {expanded === c.id && (
                    <tr key={c.id + "-e"} className="bg-[#15161e]">
                      <td colSpan={8} className="px-3 py-3">
                        <div className="text-[10px] uppercase tracking-widest text-[#565f89] mb-1 flex justify-between">
                          <span>remediation command</span>
                          <button onClick={() => { navigator.clipboard.writeText(c.remediation); toast.success("copied"); }} className="hover:text-[#c0caf5] flex items-center gap-1">
                            <Copy size={10} /> copy
                          </button>
                        </div>
                        <pre data-testid={CVE.cliPreview} className="font-mono text-[11px] p-2 border rounded-sm text-[#c0caf5] whitespace-pre-wrap" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-main)" }}>
{`$ ${c.remediation}`}
                        </pre>
                        <div className="mt-2 text-[11px] font-mono text-[#a9b1d6] leading-relaxed">
                          Affected versions: <span className="text-[#c0caf5]">{c.affected_versions.join(", ")}</span>
                        </div>
                      </td>
                    </tr>
                  )}
                </>
              );
            })}
            {rows.length === 0 && (
              <tr><td colSpan={8} className="px-3 py-6 text-center text-[#565f89] font-mono text-xs">no CVEs at this severity</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
