import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { useCli } from "@/components/Layout";
import {
  Clock, Github, Cloud, Plus, Play, Trash2, RefreshCw, Terminal,
  CheckCircle2, XCircle, Loader2, Copy, ShieldCheck, RotateCw, Users,
} from "lucide-react";
import { toast } from "sonner";

// Utility widgets --------------------------------------------------------
function StatusPill({ status, at }) {
  if (!status) return <span className="text-[10px] font-mono text-[#565f89]">never run</span>;
  const color = status === "ok" ? "var(--status-online)" : "var(--sev-high)";
  const Icon = status === "ok" ? CheckCircle2 : XCircle;
  return (
    <span className="inline-flex items-center gap-1 text-[10px] font-mono" style={{ color }}>
      <Icon size={10} /> {status}
      {at && <span className="text-[#565f89] ml-1">{new Date(at).toISOString().replace("T", " ").slice(0, 19)}</span>}
    </span>
  );
}

function IntervalBadge({ hours }) {
  const label = hours >= 24 ? `${hours / 24}d` : `${hours}h`;
  return (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-widest border rounded-sm"
      style={{ borderColor: "var(--border-subtle)", color: "var(--text-secondary)" }}>
      <Clock size={9} /> every {label}
    </span>
  );
}

async function copyText(t) {
  try { await navigator.clipboard.writeText(t); toast.success("copied"); }
  catch { toast.error("copy failed"); }
}

// Section: Scheduled Sweeps ---------------------------------------------
function SchedulesSection() {
  const [rows, setRows] = useState([]);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ name: "", scope: "online", interval_hours: 24 });

  const load = async () => {
    try { const { data } = await api.get("/schedules"); setRows(data); }
    catch { toast.error("load schedules failed"); }
  };
  useEffect(() => { load(); }, []);

  const create = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post("/schedules", { ...form, interval_hours: Number(form.interval_hours) });
      setForm({ name: "", scope: "online", interval_hours: 24 });
      toast.success("schedule created");
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "create failed"); }
    setBusy(false);
  };

  const toggle = async (r) => {
    try { await api.patch(`/schedules/${r.id}`, { enabled: !r.enabled }); load(); }
    catch { toast.error("toggle failed"); }
  };
  const runNow = async (r) => {
    try {
      const { data } = await api.post(`/schedules/${r.id}/run-now`);
      if (data.skipped) toast.error(`skipped · ${data.reason}`);
      else toast.success(`swept ${data.hosts_swept} host(s) · ${data.total_lookups} lookups`);
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "run failed"); }
  };
  const remove = async (r) => {
    if (!confirm(`Delete schedule "${r.name}"?`)) return;
    try { await api.delete(`/schedules/${r.id}`); toast.success("deleted"); load(); }
    catch { toast.error("delete failed"); }
  };

  return (
    <section className="border rounded-sm" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
      <header className="px-4 py-2 border-b flex items-center gap-2" style={{ borderColor: "var(--border-subtle)" }}>
        <Clock size={12} style={{ color: "var(--purple-analyst)" }} />
        <div className="font-mono text-xs uppercase tracking-widest text-[#c0caf5]">scheduled bulk sweeps</div>
        <div className="text-[10px] font-mono text-[#565f89] ml-auto">background loop · 60s tick</div>
      </header>

      <form onSubmit={create} className="p-3 flex flex-wrap items-end gap-2 border-b" style={{ borderColor: "var(--border-subtle)" }}>
        <div className="flex-1 min-w-[140px]">
          <label className="block text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">name</label>
          <input data-testid="schedule-name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
            placeholder="nightly online sweep"
            className="w-full px-2 py-1.5 font-mono text-xs bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
            style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }} />
        </div>
        <div>
          <label className="block text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">scope</label>
          <select data-testid="schedule-scope" value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value })}
            className="px-2 py-1.5 font-mono text-xs bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
            style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}>
            <option value="online">online only</option>
            <option value="all">all hosts</option>
          </select>
        </div>
        <div>
          <label className="block text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">every (hrs)</label>
          <input data-testid="schedule-interval" type="number" min="1" max="720" value={form.interval_hours}
            onChange={(e) => setForm({ ...form, interval_hours: e.target.value })}
            className="w-20 px-2 py-1.5 font-mono text-xs bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
            style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }} />
        </div>
        <button data-testid="schedule-add" type="submit" disabled={busy}
          className="flex items-center gap-1 px-3 py-1.5 border rounded-sm text-[11px] font-mono uppercase tracking-widest hover:bg-[#292e42] disabled:opacity-60"
          style={{ borderColor: "var(--border-accent)", color: "var(--text-primary)" }}>
          <Plus size={11} /> add
        </button>
      </form>

      {rows.length === 0 ? (
        <div className="p-4 text-center text-xs font-mono text-[#565f89]">no schedules yet · create one above to enable nightly sweeps</div>
      ) : (
        <ul className="divide-y" style={{ borderColor: "var(--border-subtle)" }}>
          {rows.map((r) => (
            <li key={r.id} data-testid="schedule-row" className="px-4 py-3 flex flex-wrap items-center gap-3">
              <div className="min-w-0 flex-1">
                <div className="font-mono text-xs text-[#c0caf5]">{r.name}</div>
                <div className="mt-1 flex flex-wrap items-center gap-2">
                  <IntervalBadge hours={r.interval_hours} />
                  <span className="text-[10px] font-mono uppercase tracking-widest"
                    style={{ color: r.scope === "all" ? "var(--sev-medium)" : "var(--purple-analyst)" }}>
                    scope: {r.scope}
                  </span>
                  <StatusPill status={r.last_run_status} at={r.last_run_at} />
                </div>
              </div>
              <button data-testid="schedule-toggle" onClick={() => toggle(r)}
                className={`px-2 py-0.5 text-[10px] font-mono uppercase tracking-widest border rounded-sm ${r.enabled ? "" : "opacity-60"}`}
                style={{ borderColor: r.enabled ? "var(--status-online)" : "var(--border-subtle)",
                         color: r.enabled ? "var(--status-online)" : "var(--text-muted)" }}>
                {r.enabled ? "ON" : "OFF"}
              </button>
              <button data-testid="schedule-run-now" onClick={() => runNow(r)} title="run now"
                className="p-1 border rounded-sm hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)" }}>
                <Play size={11} />
              </button>
              <button onClick={() => remove(r)} title="delete"
                className="p-1 border rounded-sm hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)", color: "var(--sev-high)" }}>
                <Trash2 size={11} />
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

// Section: Sigma Repo Sync ----------------------------------------------
function SigmaSourcesSection() {
  const [rows, setRows] = useState([]);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ name: "", github_url: "", scope: "all-online", interval_hours: 24 });

  const load = async () => {
    try { const { data } = await api.get("/sigma-sources"); setRows(data); }
    catch { toast.error("load sigma sources failed"); }
  };
  useEffect(() => { load(); }, []);

  const create = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post("/sigma-sources", { ...form, interval_hours: Number(form.interval_hours) });
      setForm({ name: "", github_url: "", scope: "all-online", interval_hours: 24 });
      toast.success("sigma source added");
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "add failed"); }
    setBusy(false);
  };

  const toggle = async (r) => {
    try { await api.patch(`/sigma-sources/${r.id}`, { enabled: !r.enabled }); load(); }
    catch { toast.error("toggle failed"); }
  };

  const syncNow = async (r) => {
    try {
      const { data } = await api.post(`/sigma-sources/${r.id}/sync-now`);
      toast.success(`${data.repo} · ${data.rules_parsed} rules · +${data.hashes_added} hash(es)`);
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "sync failed"); }
  };

  const remove = async (r) => {
    if (!confirm(`Delete Sigma source "${r.name}"?`)) return;
    try { await api.delete(`/sigma-sources/${r.id}`); toast.success("deleted"); load(); }
    catch { toast.error("delete failed"); }
  };

  return (
    <section className="border rounded-sm" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
      <header className="px-4 py-2 border-b flex items-center gap-2" style={{ borderColor: "var(--border-subtle)" }}>
        <Github size={12} style={{ color: "var(--purple-analyst)" }} />
        <div className="font-mono text-xs uppercase tracking-widest text-[#c0caf5]">sigma repo sync</div>
        <div className="text-[10px] font-mono text-[#565f89] ml-auto">public github repos · md5 / sha1 / sha256 extraction</div>
      </header>

      <form onSubmit={create} className="p-3 border-b space-y-2" style={{ borderColor: "var(--border-subtle)" }}>
        <div className="grid gap-2 md:grid-cols-3">
          <div>
            <label className="block text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">name</label>
            <input data-testid="sigma-src-name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="sigmahq malware"
              className="w-full px-2 py-1.5 font-mono text-xs bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
              style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }} />
          </div>
          <div className="md:col-span-2">
            <label className="block text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">github repo · owner/repo[/path] or full URL</label>
            <input data-testid="sigma-src-url" value={form.github_url} onChange={(e) => setForm({ ...form, github_url: e.target.value })}
              placeholder="SigmaHQ/sigma/rules-emerging-threats/2024"
              required
              className="w-full px-2 py-1.5 font-mono text-xs bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
              style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }} />
          </div>
        </div>
        <div className="flex flex-wrap items-end gap-2">
          <div>
            <label className="block text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">scope</label>
            <select value={form.scope} onChange={(e) => setForm({ ...form, scope: e.target.value })}
              className="px-2 py-1.5 font-mono text-xs bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
              style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}>
              <option value="all-online">online hosts</option>
              <option value="all">entire fleet</option>
            </select>
          </div>
          <div>
            <label className="block text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">every (hrs)</label>
            <input type="number" min="1" max="720" value={form.interval_hours}
              onChange={(e) => setForm({ ...form, interval_hours: e.target.value })}
              className="w-20 px-2 py-1.5 font-mono text-xs bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
              style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }} />
          </div>
          <button data-testid="sigma-src-add" type="submit" disabled={busy}
            className="flex items-center gap-1 px-3 py-1.5 border rounded-sm text-[11px] font-mono uppercase tracking-widest hover:bg-[#292e42] disabled:opacity-60"
            style={{ borderColor: "var(--border-accent)", color: "var(--text-primary)" }}>
            <Plus size={11} /> add
          </button>
          <div className="text-[10px] font-mono text-[#565f89]">
            github unauth = 60 req/hr · file cap 200
          </div>
        </div>
      </form>

      {rows.length === 0 ? (
        <div className="p-4 text-center text-xs font-mono text-[#565f89]">no sigma sources yet</div>
      ) : (
        <ul className="divide-y" style={{ borderColor: "var(--border-subtle)" }}>
          {rows.map((r) => (
            <li key={r.id} data-testid="sigma-src-row" className="px-4 py-3 flex flex-wrap items-center gap-3">
              <div className="min-w-0 flex-1">
                <div className="font-mono text-xs text-[#c0caf5]">{r.name}</div>
                <div className="font-mono text-[10px] text-[#a9b1d6] truncate">{r.github_url}</div>
                <div className="mt-1 flex flex-wrap items-center gap-2">
                  <IntervalBadge hours={r.interval_hours} />
                  <span className="text-[10px] font-mono uppercase tracking-widest" style={{ color: "var(--purple-analyst)" }}>
                    scope: {r.scope}
                  </span>
                  <StatusPill status={r.last_run_status} at={r.last_run_at} />
                  {r.last_run_meta?.hashes_added !== undefined && (
                    <span className="text-[10px] font-mono text-[#565f89]">
                      +{r.last_run_meta.hashes_added} · {r.last_run_meta.rules_parsed} rules
                    </span>
                  )}
                </div>
              </div>
              <button onClick={() => toggle(r)}
                className={`px-2 py-0.5 text-[10px] font-mono uppercase tracking-widest border rounded-sm ${r.enabled ? "" : "opacity-60"}`}
                style={{ borderColor: r.enabled ? "var(--status-online)" : "var(--border-subtle)",
                         color: r.enabled ? "var(--status-online)" : "var(--text-muted)" }}>
                {r.enabled ? "ON" : "OFF"}
              </button>
              <button data-testid="sigma-src-sync" onClick={() => syncNow(r)} title="sync now"
                className="p-1 border rounded-sm hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)" }}>
                <RefreshCw size={11} />
              </button>
              <button onClick={() => remove(r)} title="delete"
                className="p-1 border rounded-sm hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)", color: "var(--sev-high)" }}>
                <Trash2 size={11} />
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

// Section: Marketplace --------------------------------------------------
function MarketplaceSection() {
  const [info, setInfo] = useState(null);
  const [subs, setSubs] = useState([]);
  const [form, setForm] = useState({ name: "", feed_url: "", signing_key: "", interval_hours: 24 });
  const [busy, setBusy] = useState(false);

  const load = async () => {
    try {
      const [i, s] = await Promise.all([
        api.get("/marketplace/info"),
        api.get("/marketplace/subscriptions"),
      ]);
      setInfo(i.data); setSubs(s.data);
    } catch { toast.error("load marketplace failed"); }
  };
  useEffect(() => { load(); }, []);

  const rotate = async () => {
    if (!confirm("Rotate signing key? Subscribers using the old key will fail verification until you re-share it.")) return;
    try { await api.post("/marketplace/rotate-key"); toast.success("signing key rotated"); load(); }
    catch { toast.error("rotate failed"); }
  };

  const create = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api.post("/marketplace/subscriptions", { ...form, interval_hours: Number(form.interval_hours) });
      setForm({ name: "", feed_url: "", signing_key: "", interval_hours: 24 });
      toast.success("subscription added");
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "add failed"); }
    setBusy(false);
  };

  const syncNow = async (r) => {
    try {
      const { data } = await api.post(`/marketplace/subscriptions/${r.id}/sync-now`);
      toast.success(`${r.name} · ${data.templates_seen} template(s) · verified=${data.verified}`);
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "sync failed"); }
  };

  const toggle = async (r) => {
    try { await api.patch(`/marketplace/subscriptions/${r.id}`, { enabled: !r.enabled }); load(); }
    catch { toast.error("toggle failed"); }
  };

  const remove = async (r) => {
    if (!confirm(`Unsubscribe from "${r.name}"? Imported templates will be removed.`)) return;
    try { await api.delete(`/marketplace/subscriptions/${r.id}`); toast.success("unsubscribed"); load(); }
    catch { toast.error("delete failed"); }
  };

  return (
    <section className="border rounded-sm" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
      <header className="px-4 py-2 border-b flex items-center gap-2" style={{ borderColor: "var(--border-subtle)" }}>
        <Cloud size={12} style={{ color: "var(--purple-analyst)" }} />
        <div className="font-mono text-xs uppercase tracking-widest text-[#c0caf5]">template marketplace</div>
        <div className="text-[10px] font-mono text-[#565f89] ml-auto">HMAC-SHA256 signed · public feed URL</div>
      </header>

      {/* Own feed */}
      {info && (
        <div className="p-3 border-b space-y-2" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-terminal)" }}>
          <div className="flex items-center gap-2">
            <Users size={12} style={{ color: "var(--purple-analyst)" }} />
            <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89]">your team feed</div>
          </div>
          <div>
            <div className="text-[10px] font-mono text-[#565f89] mb-1 flex justify-between">
              <span>feed url · share with peer dashboards</span>
              <button data-testid="mp-copy-feed" onClick={() => copyText(info.feed_url)} className="hover:text-[#c0caf5] flex items-center gap-1"><Copy size={9} /> copy</button>
            </div>
            <pre data-testid="mp-feed-url" className="font-mono text-[11px] p-2 border rounded-sm break-all whitespace-pre-wrap"
              style={{ borderColor: "var(--border-subtle)", background: "var(--bg-main)", color: "var(--text-primary)" }}>{info.feed_url}</pre>
          </div>
          <div>
            <div className="text-[10px] font-mono text-[#565f89] mb-1 flex justify-between">
              <span>signing key · share out-of-band</span>
              <div className="flex items-center gap-3">
                <button onClick={() => copyText(info.signing_key)} className="hover:text-[#c0caf5] flex items-center gap-1"><Copy size={9} /> copy</button>
                <button data-testid="mp-rotate-key" onClick={rotate} className="hover:text-[#f7768e] flex items-center gap-1"><RotateCw size={9} /> rotate</button>
              </div>
            </div>
            <pre className="font-mono text-[11px] p-2 border rounded-sm break-all whitespace-pre-wrap"
              style={{ borderColor: "var(--border-subtle)", background: "var(--bg-main)", color: "var(--text-primary)" }}>{info.signing_key}</pre>
          </div>
        </div>
      )}

      {/* Subscriptions */}
      <form onSubmit={create} className="p-3 border-b space-y-2" style={{ borderColor: "var(--border-subtle)" }}>
        <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89]">subscribe to peer feed</div>
        <div className="grid gap-2 md:grid-cols-3">
          <input data-testid="mp-sub-name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
            placeholder="peer-name"
            className="px-2 py-1.5 font-mono text-xs bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
            style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }} />
          <input data-testid="mp-sub-url" value={form.feed_url} onChange={(e) => setForm({ ...form, feed_url: e.target.value })}
            placeholder="https://peer.example/api/marketplace/feed?fid=..."
            required
            className="md:col-span-2 px-2 py-1.5 font-mono text-xs bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
            style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }} />
        </div>
        <div className="flex flex-wrap items-end gap-2">
          <input data-testid="mp-sub-key" value={form.signing_key} onChange={(e) => setForm({ ...form, signing_key: e.target.value })}
            placeholder="peer signing key (optional but recommended)"
            className="flex-1 px-2 py-1.5 font-mono text-xs bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
            style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }} />
          <input type="number" min="1" max="720" value={form.interval_hours}
            onChange={(e) => setForm({ ...form, interval_hours: e.target.value })}
            className="w-20 px-2 py-1.5 font-mono text-xs bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
            style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }} />
          <button data-testid="mp-sub-add" type="submit" disabled={busy}
            className="flex items-center gap-1 px-3 py-1.5 border rounded-sm text-[11px] font-mono uppercase tracking-widest hover:bg-[#292e42] disabled:opacity-60"
            style={{ borderColor: "var(--border-accent)", color: "var(--text-primary)" }}>
            <Plus size={11} /> subscribe
          </button>
        </div>
      </form>

      {subs.length === 0 ? (
        <div className="p-4 text-center text-xs font-mono text-[#565f89]">no subscriptions</div>
      ) : (
        <ul className="divide-y" style={{ borderColor: "var(--border-subtle)" }}>
          {subs.map((r) => (
            <li key={r.id} data-testid="mp-sub-row" className="px-4 py-3 flex flex-wrap items-center gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-[#c0caf5]">{r.name}</span>
                  {r.last_run_meta?.verified !== undefined && (
                    <span className="inline-flex items-center gap-0.5 px-1 py-0.5 text-[9px] uppercase tracking-widest border rounded-sm"
                      style={{
                        borderColor: r.last_run_meta.verified ? "var(--status-online)" : "var(--sev-medium)",
                        color: r.last_run_meta.verified ? "var(--status-online)" : "var(--sev-medium)",
                      }}>
                      <ShieldCheck size={9} /> {r.last_run_meta.verified ? "verified" : "unverified"}
                    </span>
                  )}
                </div>
                <div className="font-mono text-[10px] text-[#a9b1d6] truncate">{r.feed_url}</div>
                <div className="mt-1 flex flex-wrap items-center gap-2">
                  <IntervalBadge hours={r.interval_hours} />
                  <StatusPill status={r.last_run_status} at={r.last_run_at} />
                  {r.last_run_meta?.imported !== undefined && (
                    <span className="text-[10px] font-mono text-[#565f89]">
                      +{r.last_run_meta.imported} imported · {r.last_run_meta.updated} updated
                    </span>
                  )}
                </div>
              </div>
              <button onClick={() => toggle(r)}
                className={`px-2 py-0.5 text-[10px] font-mono uppercase tracking-widest border rounded-sm ${r.enabled ? "" : "opacity-60"}`}
                style={{ borderColor: r.enabled ? "var(--status-online)" : "var(--border-subtle)",
                         color: r.enabled ? "var(--status-online)" : "var(--text-muted)" }}>
                {r.enabled ? "ON" : "OFF"}
              </button>
              <button data-testid="mp-sub-sync" onClick={() => syncNow(r)} title="sync now"
                className="p-1 border rounded-sm hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)" }}>
                <RefreshCw size={11} />
              </button>
              <button onClick={() => remove(r)} title="unsubscribe"
                className="p-1 border rounded-sm hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)", color: "var(--sev-high)" }}>
                <Trash2 size={11} />
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

// Main page --------------------------------------------------------------
export default function Automations() {
  const { openCli } = useCli();
  return (
    <div className="space-y-4">
      <header className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">// automations</div>
          <h1 className="font-mono text-2xl sm:text-3xl tracking-tight text-[#c0caf5]">automations<span className="cursor" /></h1>
          <p className="text-xs text-[#a9b1d6] mt-1">scheduled sweeps · sigma repo sync · team template marketplace</p>
        </div>
        <button onClick={() => openCli({
          title: "Manage automations from CLI",
          command: "sec-master schedule create --scope online --every 24h\nsec-master sigma-source add SigmaHQ/sigma\nsec-master marketplace subscribe https://peer.example/api/marketplace/feed",
          description: "All schedule primitives are exposed on the CLI. Background scheduler ticks every 60s.",
        })} className="flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-xs font-mono hover:bg-[#292e42]"
          style={{ borderColor: "var(--border-subtle)" }}>
          <Terminal size={12} /> cli
        </button>
      </header>
      <SchedulesSection />
      <SigmaSourcesSection />
      <MarketplaceSection />
    </div>
  );
}
