import { useEffect, useState, useCallback } from "react";
import { api } from "@/lib/api";
import { Link } from "react-router-dom";
import {
  Radar, RefreshCw, Plus, Trash2, ExternalLink, AlertTriangle,
  Shield, ShieldCheck, ShieldAlert, Globe, ChevronRight, Loader2,
} from "lucide-react";
import { toast } from "sonner";

const PROVIDER_META = {
  virustotal: { label: "VT", color: "var(--red-offense)" },
  shodan:     { label: "SH", color: "var(--blue-defense)" },
};

function ProviderStatus({ label, enabled }) {
  return (
    <div className="flex items-center gap-1.5 text-[10px] font-mono">
      <span className="w-1.5 h-1.5 rounded-full"
        style={{ background: enabled ? "var(--status-online)" : "var(--text-muted)" }} />
      <span className="uppercase tracking-widest" style={{ color: enabled ? "var(--text-primary)" : "var(--text-muted)" }}>
        {label}
      </span>
    </div>
  );
}

function VtSummary({ s }) {
  const mal = s.malicious || 0;
  const sus = s.suspicious || 0;
  const clean = (s.harmless || 0) + (s.undetected || 0);
  const total = mal + sus + clean;
  const verdict = mal > 3 ? "malicious" : mal > 0 || sus > 0 ? "suspicious" : total > 0 ? "clean" : "unknown";
  const color = { malicious: "var(--sev-critical)", suspicious: "var(--sev-medium)", clean: "var(--status-online)", unknown: "var(--text-muted)" }[verdict];
  const Icon = { malicious: ShieldAlert, suspicious: AlertTriangle, clean: ShieldCheck, unknown: Shield }[verdict];
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2">
        <Icon size={14} style={{ color }} />
        <span className="text-xs font-mono uppercase tracking-widest" style={{ color }}>{verdict}</span>
        <span className="text-[10px] font-mono text-[#565f89]">· {mal}/{total} engines</span>
      </div>
      <div className="grid grid-cols-4 gap-2 text-[10px] font-mono">
        {[["malicious", mal, "var(--sev-critical)"], ["suspicious", sus, "var(--sev-medium)"],
          ["harmless", s.harmless || 0, "var(--status-online)"], ["undetected", s.undetected || 0, "var(--text-muted)"]
        ].map(([k, v, c]) => (
          <div key={k} className="border rounded-sm p-1.5" style={{ borderColor: "var(--border-subtle)" }}>
            <div className="uppercase tracking-widest text-[9px] text-[#565f89]">{k}</div>
            <div style={{ color: c }}>{v}</div>
          </div>
        ))}
      </div>
      {(s.country || s.as_owner) && (
        <div className="text-[10px] font-mono text-[#a9b1d6]">
          {s.country && <>country: <span className="text-[#c0caf5]">{s.country}</span> </>}
          {s.as_owner && <>· asn: <span className="text-[#c0caf5]">{s.as_owner}</span></>}
        </div>
      )}
    </div>
  );
}

function ShodanSummary({ s }) {
  return (
    <div className="space-y-2 text-[10px] font-mono">
      {(s.org || s.isp) && <div><span className="text-[#565f89]">org:</span> <span className="text-[#c0caf5]">{s.org || s.isp}</span></div>}
      {s.country && <div><span className="text-[#565f89]">country:</span> <span className="text-[#c0caf5]">{s.country}</span></div>}
      {s.os && <div><span className="text-[#565f89]">os:</span> <span className="text-[#c0caf5]">{s.os}</span></div>}
      {s.ports?.length > 0 && (
        <div>
          <span className="text-[#565f89]">open ports:</span>
          <div className="flex flex-wrap gap-1 mt-1">
            {s.ports.map((p) => (
              <span key={p} className="px-1.5 py-0.5 border rounded-sm" style={{ borderColor: "var(--blue-defense)", color: "var(--blue-defense)" }}>{p}</span>
            ))}
          </div>
        </div>
      )}
      {s.vulns?.length > 0 && (
        <div>
          <span className="text-[#565f89]">shodan vulns:</span>
          <div className="flex flex-wrap gap-1 mt-1">
            {s.vulns.map((v) => (
              <span key={v} className="px-1.5 py-0.5 border rounded-sm" style={{ borderColor: "var(--sev-high)", color: "var(--sev-high)" }}>{v}</span>
            ))}
          </div>
        </div>
      )}
      {s.tags?.length > 0 && (
        <div>
          <span className="text-[#565f89]">tags:</span>
          <div className="flex flex-wrap gap-1 mt-1">
            {s.tags.map((t) => (
              <span key={t} className="px-1.5 py-0.5 border rounded-sm" style={{ borderColor: "var(--border-subtle)", color: "var(--text-secondary)" }}>{t}</span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function IocPanel({ workstationId }) {
  const [data, setData] = useState(null);
  const [hash, setHash] = useState("");
  const [note, setNote] = useState("");
  const [running, setRunning] = useState(false);

  const load = useCallback(async () => {
    try {
      const { data } = await api.get(`/workstations/${workstationId}/ioc`);
      setData(data);
    } catch { /* silent */ }
  }, [workstationId]);

  useEffect(() => { load(); }, [load]);

  const addHash = async (e) => {
    e.preventDefault();
    const h = hash.trim().toLowerCase();
    if (![32, 40, 64].includes(h.length)) {
      toast.error("Hash must be MD5 (32), SHA1 (40), or SHA256 (64) hex chars");
      return;
    }
    try {
      await api.post(`/workstations/${workstationId}/ioc/hashes`, { hash: h, note });
      setHash(""); setNote("");
      toast.success("Hash added to IOC watchlist");
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "Add failed"); }
  };

  const delHash = async (h) => {
    try { await api.delete(`/workstations/${workstationId}/ioc/hashes/${h}`); toast.success("removed"); load(); }
    catch { toast.error("delete failed"); }
  };

  const runLookup = async () => {
    setRunning(true);
    try {
      const { data: result } = await api.post(`/workstations/${workstationId}/ioc/lookup`, {});
      const providers = result.providers_used || {};
      if (!providers.virustotal && !providers.shodan) {
        toast.error("No VirusTotal / Shodan plugin enabled — install one first");
      } else {
        toast.success(`Enriched ${result.count} target(s) across ${Object.values(providers).filter(Boolean).length} provider(s)`);
      }
      load();
    } catch { toast.error("Lookup failed"); }
    setRunning(false);
  };

  if (!data) return (
    <div className="border rounded-sm p-4 text-xs font-mono text-[#565f89]" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
      loading ioc panel …
    </div>
  );

  const { history = [], providers = {}, ip_address, suspicious_hashes = [] } = data;
  const anyProvider = providers.virustotal?.enabled || providers.shodan?.enabled;

  // Group history by target
  const byTarget = {};
  for (const h of history) {
    const key = `${h.target_type}:${h.target_value}`;
    if (!byTarget[key]) byTarget[key] = { type: h.target_type, value: h.target_value, entries: [] };
    byTarget[key].entries.push(h);
  }
  // Keep only most recent per (target, provider)
  Object.values(byTarget).forEach((g) => {
    const seen = new Set();
    g.entries = g.entries.filter((e) => {
      const k = e.provider;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  });

  return (
    <div className="border rounded-sm" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
      <header className="border-b px-4 py-2 flex items-center justify-between" style={{ borderColor: "var(--border-subtle)" }}>
        <div className="flex items-center gap-2">
          <Radar size={14} style={{ color: "var(--purple-analyst)" }} />
          <div className="font-mono text-xs uppercase tracking-widest text-[#c0caf5]">IOC enrichment</div>
        </div>
        <div className="flex items-center gap-3">
          <ProviderStatus label="virustotal" enabled={providers.virustotal?.enabled} />
          <ProviderStatus label="shodan" enabled={providers.shodan?.enabled} />
        </div>
      </header>

      <div className="p-4 space-y-4">
        {!anyProvider && (
          <div className="border rounded-sm p-3 text-[11px] font-mono flex items-start gap-2"
            style={{ borderColor: "var(--sev-medium)", background: "rgba(224,175,104,0.08)", color: "var(--sev-medium)" }}>
            <AlertTriangle size={12} className="mt-0.5 flex-shrink-0" />
            <div>
              no enrichment plugin enabled ·
              <Link to="/plugins" data-testid="ioc-goto-plugins" className="underline hover:text-[#c0caf5] ml-1">install VirusTotal or Shodan</Link>
            </div>
          </div>
        )}

        <div className="flex items-center justify-between gap-2">
          <div className="text-[10px] font-mono text-[#565f89]">
            ip <span className="text-[#c0caf5]">{ip_address || "unknown"}</span> · {suspicious_hashes.length} hash(es) watched
          </div>
          <button data-testid="ioc-run-lookup" onClick={runLookup} disabled={running || !anyProvider}
            className="flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-[10px] font-mono uppercase tracking-widest hover:bg-[#292e42] disabled:opacity-40 disabled:cursor-not-allowed"
            style={{ borderColor: "var(--border-accent)", color: "var(--text-primary)" }}>
            {running ? <Loader2 size={10} className="animate-spin" /> : <RefreshCw size={10} />}
            {running ? "querying" : "enrich now"}
          </button>
        </div>

        {/* Add hash form */}
        <form onSubmit={addHash} className="space-y-2 border-t pt-3" style={{ borderColor: "var(--border-subtle)" }}>
          <div className="text-[10px] uppercase tracking-widest text-[#565f89] font-mono">watch suspicious hash</div>
          <div className="flex gap-2 flex-col sm:flex-row">
            <input data-testid="ioc-hash-input" value={hash} onChange={(e) => setHash(e.target.value)}
              placeholder="md5 / sha1 / sha256"
              className="flex-1 px-2 py-1.5 font-mono text-[11px] bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
              style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }} />
            <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="note (optional)"
              className="sm:w-32 px-2 py-1.5 font-mono text-[11px] bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
              style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }} />
            <button data-testid="ioc-hash-add" type="submit"
              className="flex items-center gap-1 px-2 py-1.5 text-[10px] font-mono uppercase tracking-widest border rounded-sm hover:bg-[#292e42]"
              style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}>
              <Plus size={10} /> add
            </button>
          </div>
        </form>

        {/* Enrichment cards */}
        <div className="space-y-3">
          {/* IP card */}
          {ip_address && (
            <IocTargetCard
              title="workstation ip"
              type="ip"
              value={ip_address}
              entries={byTarget[`ip:${ip_address}`]?.entries || []}
            />
          )}
          {/* Hash cards */}
          {suspicious_hashes.map((h) => (
            <IocTargetCard
              key={h.hash}
              title={h.note || "watchlist hash"}
              type="hash"
              value={h.hash}
              added_at={h.added_at}
              entries={byTarget[`hash:${h.hash}`]?.entries || []}
              onDelete={() => delHash(h.hash)}
            />
          ))}
          {suspicious_hashes.length === 0 && (
            <div className="text-[10px] font-mono text-[#565f89] text-center py-2">
              no watchlist hashes yet
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function IocTargetCard({ title, type, value, added_at, entries, onDelete }) {
  const externalLink = type === "ip"
    ? `https://www.virustotal.com/gui/ip-address/${value}`
    : `https://www.virustotal.com/gui/file/${value}`;
  return (
    <article data-testid="ioc-target-card" className="border rounded-sm" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-terminal)" }}>
      <header className="flex items-center justify-between px-3 py-2 border-b" style={{ borderColor: "var(--border-subtle)" }}>
        <div className="min-w-0">
          <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89]">{title}</div>
          <div className="font-mono text-[11px] text-[#c0caf5] truncate flex items-center gap-2">
            {type === "ip" ? <Globe size={10} /> : <ChevronRight size={10} />}
            {value}
          </div>
        </div>
        <div className="flex gap-1 flex-shrink-0">
          <a href={externalLink} target="_blank" rel="noopener noreferrer"
            className="p-1 border rounded-sm hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)", color: "var(--text-secondary)" }}>
            <ExternalLink size={10} />
          </a>
          {onDelete && (
            <button onClick={onDelete} className="p-1 border rounded-sm hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)", color: "var(--sev-high)" }}>
              <Trash2 size={10} />
            </button>
          )}
        </div>
      </header>
      <div className="p-3 space-y-3">
        {entries.length === 0 && (
          <div className="text-[10px] font-mono text-[#565f89]">no enrichment yet · click "enrich now" above</div>
        )}
        {entries.map((e) => {
          const pm = PROVIDER_META[e.provider];
          return (
            <div key={e.id}>
              <div className="flex items-center justify-between mb-1">
                <div className="flex items-center gap-2">
                  <span className="px-1.5 py-0.5 text-[9px] font-mono uppercase tracking-widest border rounded-sm"
                    style={{ borderColor: pm?.color || "var(--border-subtle)", color: pm?.color || "var(--text-primary)" }}>
                    {e.provider}
                  </span>
                  <span className="text-[9px] font-mono text-[#565f89]">HTTP {e.http_status ?? "—"} · {new Date(e.at).toISOString().replace("T", " ").slice(11, 19)}Z</span>
                </div>
              </div>
              {e.status === "ok" ? (
                e.provider === "virustotal"
                  ? <VtSummary s={e.summary || {}} />
                  : <ShodanSummary s={e.summary || {}} />
              ) : (
                <div className="text-[10px] font-mono" style={{ color: "var(--sev-high)" }}>
                  error: {e.raw_snippet?.slice(0, 200) || "unknown"}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </article>
  );
}
