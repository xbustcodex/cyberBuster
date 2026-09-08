import { useEffect, useState, useMemo } from "react";
import { api } from "@/lib/api";
import { PLUGINS } from "@/constants/testIds";
import { useCli } from "@/components/Layout";
import {
  Plug, Plus, RefreshCw, Play, Trash2, Pencil, Bookmark, Sparkles,
  CheckCircle2, XCircle, Terminal, ChevronDown, X, Search,
} from "lucide-react";
import { toast } from "sonner";

const CATEGORY_COLOR = {
  alerting: "var(--red-offense)",
  siem: "var(--blue-defense)",
  enrichment: "var(--purple-analyst)",
  custom: "var(--status-drift)",
};

// ---------------- Save-as-template modal ----------------
function SaveTemplateModal({ open, plugin, onClose, onSaved }) {
  const [name, setName] = useState("");
  const [includeSecrets, setIncludeSecrets] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open && plugin) {
      setName(`${plugin.name} template`);
      setIncludeSecrets(false);
    }
  }, [open, plugin]);

  if (!open || !plugin) return null;

  const save = async () => {
    if (!name.trim()) { toast.error("Name required"); return; }
    setBusy(true);
    try {
      await api.post(`/plugins/${plugin.id}/save-as-template`, { name: name.trim(), include_secrets: includeSecrets });
      toast.success(`Template "${name}" saved`);
      onSaved(); onClose();
    } catch (e) { toast.error(e.response?.data?.detail || "Save failed"); }
    setBusy(false);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={onClose}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <div onClick={(e) => e.stopPropagation()}
        className="relative z-10 max-w-md w-full border rounded-sm p-5 space-y-4 enter"
        style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
        <div className="flex items-center gap-2">
          <Bookmark size={14} style={{ color: "var(--purple-analyst)" }} />
          <div className="font-mono text-xs uppercase tracking-widest text-[#c0caf5]">save as template</div>
        </div>
        <p className="text-xs text-[#a9b1d6]">
          Templates are reusable plugin configs. Install a fresh {plugin.type} plugin with one click.
        </p>
        <div>
          <label className="block text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">template name</label>
          <input data-testid="template-save-name" value={name} onChange={(e) => setName(e.target.value)}
            className="w-full px-3 py-2 font-mono text-sm bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
            style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }} />
        </div>
        <label className="flex items-start gap-2 text-xs font-mono cursor-pointer">
          <input type="checkbox" checked={includeSecrets} onChange={(e) => setIncludeSecrets(e.target.checked)} className="mt-0.5" />
          <span>
            <span className="text-[#c0caf5]">include encrypted secrets</span>
            <span className="block text-[10px] text-[#565f89] leading-relaxed">
              secrets stay encrypted at rest · anyone with dashboard access can spawn a working copy · leave off for public templates
            </span>
          </span>
        </label>
        <div className="flex gap-2 justify-end pt-2 border-t" style={{ borderColor: "var(--border-subtle)" }}>
          <button onClick={onClose} className="px-3 py-1.5 text-xs font-mono uppercase tracking-widest border rounded-sm hover:bg-[#292e42]"
            style={{ borderColor: "var(--border-subtle)" }}>cancel</button>
          <button data-testid="template-save-submit" onClick={save} disabled={busy}
            className="px-3 py-1.5 text-xs font-mono uppercase tracking-widest border rounded-sm hover:bg-[#292e42] disabled:opacity-60"
            style={{ borderColor: "var(--border-accent)", color: "var(--text-primary)" }}>{busy ? "saving…" : "save"}</button>
        </div>
      </div>
    </div>
  );
}

// ---------------- Drawer for install / edit ----------------
function PluginDrawer({ open, onClose, mode, plugin, template, catalog, events, onSaved }) {
  const type = mode === "install"
    ? plugin
    : mode === "from-template"
    ? catalog.find((c) => c.kind === template?.type)
    : catalog.find((c) => c.kind === plugin?.type);
  const [name, setName] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [config, setConfig] = useState({});
  const [secretsInput, setSecretsInput] = useState({});
  const [subs, setSubs] = useState([]);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open || !type) return;
    if (mode === "install") {
      setName(type.display_name);
      setEnabled(true);
      const defaults = {};
      (type.config_schema || []).forEach((f) => { if (f.default !== undefined) defaults[f.key] = f.default; });
      setConfig(defaults);
      setSecretsInput({});
      setSubs([...(type.supported_events || [])]);
    } else if (mode === "from-template") {
      setName(`${type.display_name} · ${template.name}`);
      setEnabled(true);
      setConfig({ ...(template.config || {}) });
      setSecretsInput({});
      setSubs([...(template.event_subscriptions || [])]);
    } else {
      setName(plugin.name);
      setEnabled(plugin.enabled);
      setConfig({ ...(plugin.config || {}) });
      setSecretsInput({});
      setSubs([...(plugin.event_subscriptions || [])]);
    }
  }, [open, mode, plugin, template, type]);

  if (!open || !type) return null;

  const kind = mode === "install" ? type.kind : mode === "from-template" ? template.type : plugin.type;

  const save = async () => {
    setBusy(true);
    try {
      if (mode === "install") {
        await api.post("/plugins", {
          type: kind, name, enabled, config,
          secrets: secretsInput, event_subscriptions: subs,
        });
        toast.success(`${type.display_name} installed`);
      } else if (mode === "from-template") {
        await api.post(`/plugins/from-template/${template.id}`, {
          name, enabled,
          config_overrides: config,
          secrets: secretsInput,
          event_subscriptions: subs,
        });
        toast.success(`Installed from template "${template.name}"`);
      } else {
        const patch = { name, enabled, config, event_subscriptions: subs };
        if (Object.values(secretsInput).some(Boolean)) patch.secrets = secretsInput;
        await api.patch(`/plugins/${plugin.id}`, patch);
        toast.success("Plugin updated");
      }
      onSaved();
      onClose();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Save failed");
    }
    setBusy(false);
  };

  const isQueryOnly = (type.capabilities || []).includes("query") && !(type.capabilities || []).includes("dispatch");
  const secretsExisting = mode === "edit"
    ? plugin.secrets_masked || {}
    : mode === "from-template"
    ? template.secrets_masked || {}
    : {};

  return (
    <div className="fixed inset-0 z-50" onClick={onClose}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <aside onClick={(e) => e.stopPropagation()}
        className="absolute right-0 top-0 h-full w-full max-w-2xl border-l bg-[#1f2335]/95 backdrop-blur-md enter overflow-y-auto"
        style={{ borderColor: "var(--border-subtle)" }}>
        <header className="flex items-center justify-between border-b px-4 py-3 sticky top-0 bg-[#1f2335]" style={{ borderColor: "var(--border-subtle)" }}>
          <div className="font-mono text-xs uppercase tracking-widest" style={{ color: "var(--purple-analyst)" }}>
            sec-master:~$ plugin {mode}
          </div>
          <button onClick={onClose} className="p-1 hover:bg-[#292e42] rounded"><X size={16} /></button>
        </header>

        <div className="p-4 space-y-5">
          <div>
            <div className="text-[10px] uppercase tracking-widest text-[#565f89] font-mono mb-1">plugin type</div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-mono text-[#c0caf5]">{type.display_name}</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 border rounded-sm uppercase tracking-widest"
                style={{ borderColor: CATEGORY_COLOR[type.category], color: CATEGORY_COLOR[type.category] }}>
                {type.category}
              </span>
            </div>
            <p className="text-xs text-[#a9b1d6] mt-1 leading-relaxed">{type.description}</p>
          </div>

          <div>
            <label className="block text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">name</label>
            <input data-testid={PLUGINS.drawerName} value={name} onChange={(e) => setName(e.target.value)}
              className="w-full px-3 py-2 font-mono text-sm bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
              style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }} />
          </div>

          <label className="flex items-center gap-2 text-xs font-mono">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            <span className="text-[#c0caf5]">enabled</span>
          </label>

          {/* Config fields */}
          {(type.config_schema || []).length > 0 && (
            <section className="space-y-3">
              <div className="text-[10px] uppercase tracking-widest text-[#565f89] font-mono">config</div>
              {(type.config_schema || []).map((f) => (
                <div key={f.key}>
                  <label className="block text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">
                    {f.label}{f.required && <span className="text-[#f7768e]"> *</span>}
                  </label>
                  {f.type === "select" ? (
                    <select value={config[f.key] ?? f.default ?? ""} onChange={(e) => setConfig({ ...config, [f.key]: e.target.value })}
                      className="w-full px-3 py-2 font-mono text-sm bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
                      style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}>
                      <option value="">—</option>
                      {(f.options || []).map((o) => <option key={o} value={o}>{o}</option>)}
                    </select>
                  ) : f.type === "bool" ? (
                    <label className="flex items-center gap-2 text-xs font-mono">
                      <input type="checkbox" checked={!!config[f.key] ?? f.default ?? false}
                        onChange={(e) => setConfig({ ...config, [f.key]: e.target.checked })} />
                      <span className="text-[#c0caf5]">{f.label}</span>
                    </label>
                  ) : (
                    <input type={f.type === "url" ? "url" : "text"}
                      value={config[f.key] ?? ""} onChange={(e) => setConfig({ ...config, [f.key]: e.target.value })}
                      placeholder={f.placeholder || ""}
                      className="w-full px-3 py-2 font-mono text-sm bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
                      style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }} />
                  )}
                </div>
              ))}
            </section>
          )}

          {/* Secrets */}
          {(type.secrets_schema || []).length > 0 && (
            <section className="space-y-3">
              <div className="text-[10px] uppercase tracking-widest text-[#565f89] font-mono">secrets · encrypted at rest</div>
              {(type.secrets_schema || []).map((f) => (
                <div key={f.key}>
                  <label className="block text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">
                    {f.label}{f.required && <span className="text-[#f7768e]"> *</span>}
                  </label>
                  <input type="password" autoComplete="off"
                    value={secretsInput[f.key] ?? ""} onChange={(e) => setSecretsInput({ ...secretsInput, [f.key]: e.target.value })}
                    placeholder={(mode === "edit" || mode === "from-template") && secretsExisting[f.key] ? `current: ${secretsExisting[f.key]}` : "•••••••"}
                    className="w-full px-3 py-2 font-mono text-sm bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
                    style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }} />
                </div>
              ))}
            </section>
          )}

          {/* Events */}
          {!isQueryOnly && (type.supported_events || []).length > 0 && (
            <section className="space-y-2">
              <div className="text-[10px] uppercase tracking-widest text-[#565f89] font-mono">subscribed events</div>
              <div className="grid grid-cols-2 gap-2">
                {(type.supported_events || []).map((ev) => (
                  <label key={ev} className="flex items-center gap-2 text-xs font-mono cursor-pointer">
                    <input type="checkbox" checked={subs.includes(ev)}
                      onChange={(e) => setSubs(e.target.checked ? [...subs, ev] : subs.filter((s) => s !== ev))} />
                    <span className="text-[#c0caf5]">{ev}</span>
                  </label>
                ))}
              </div>
            </section>
          )}

          {isQueryOnly && (
            <div className="border rounded-sm p-3 text-xs font-mono text-[#a9b1d6]"
              style={{ borderColor: "var(--border-subtle)", background: "var(--bg-terminal)" }}>
              on-demand query plugin · use the query tab after install
            </div>
          )}

          <button data-testid={PLUGINS.drawerSubmit} onClick={save} disabled={busy}
            className="w-full py-2 font-mono text-xs uppercase tracking-widest border rounded-sm hover:bg-[#292e42] disabled:opacity-60"
            style={{ borderColor: "var(--border-accent)", color: "var(--text-primary)" }}>
            {busy ? "saving…"
              : mode === "install" ? "install plugin"
              : mode === "from-template" ? "install from template"
              : "save changes"}
          </button>
        </div>
      </aside>
    </div>
  );
}

// ---------------- Executions viewer ----------------
function ExecutionsViewer({ plugin, onClose }) {
  const [rows, setRows] = useState([]);
  useEffect(() => {
    if (!plugin) return;
    api.get(`/plugins/${plugin.id}/executions`).then(({ data }) => setRows(data));
  }, [plugin]);
  if (!plugin) return null;
  return (
    <div className="fixed inset-0 z-50" onClick={onClose}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <aside onClick={(e) => e.stopPropagation()}
        className="absolute right-0 top-0 h-full w-full max-w-3xl border-l bg-[#1f2335]/95 backdrop-blur-md enter overflow-y-auto"
        style={{ borderColor: "var(--border-subtle)" }}>
        <header className="flex items-center justify-between border-b px-4 py-3 sticky top-0 bg-[#1f2335]" style={{ borderColor: "var(--border-subtle)" }}>
          <div className="font-mono text-xs uppercase tracking-widest" style={{ color: "var(--purple-analyst)" }}>
            sec-master:~$ plugin executions · {plugin.name}
          </div>
          <button onClick={onClose} className="p-1 hover:bg-[#292e42] rounded"><X size={16} /></button>
        </header>
        <div className="p-4">
          {rows.length === 0 && <div className="text-center text-xs font-mono text-[#565f89] py-6">no executions yet</div>}
          <ul className="space-y-2">
            {rows.map((r) => (
              <li key={r.id} data-testid={PLUGINS.executionsRow} className="border rounded-sm p-3 font-mono text-xs" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-terminal)" }}>
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    {r.status === "ok"
                      ? <CheckCircle2 size={12} style={{ color: "var(--status-online)" }} />
                      : <XCircle size={12} style={{ color: "var(--sev-high)" }} />}
                    <span className="text-[#c0caf5]">{r.event}</span>
                    <span className="text-[#565f89]">· HTTP {r.http_status ?? "—"} · {r.latency_ms}ms</span>
                  </div>
                  <span className="text-[10px] text-[#565f89]">{new Date(r.at).toISOString().replace("T", " ").slice(0, 19)}</span>
                </div>
                {r.response && (
                  <pre className="mt-2 text-[10px] text-[#a9b1d6] whitespace-pre-wrap break-all">{r.response}</pre>
                )}
              </li>
            ))}
          </ul>
        </div>
      </aside>
    </div>
  );
}

// ---------------- Main page ----------------
export default function Plugins() {
  const [catalog, setCatalog] = useState([]);
  const [installed, setInstalled] = useState([]);
  const [templates, setTemplates] = useState([]);
  const [events, setEvents] = useState([]);
  const [q, setQ] = useState("");
  const [category, setCategory] = useState("all");
  const [drawer, setDrawer] = useState(null);   // {mode, plugin, template}
  const [execFor, setExecFor] = useState(null);
  const [saveTplFor, setSaveTplFor] = useState(null);
  const { openCli } = useCli();

  const load = async () => {
    try {
      const [c, p, t, e] = await Promise.all([
        api.get("/plugins/catalog"),
        api.get("/plugins"),
        api.get("/plugin-templates"),
        api.get("/plugins/events"),
      ]);
      setCatalog(c.data); setInstalled(p.data); setTemplates(t.data); setEvents(e.data.event_kinds || []);
    } catch { toast.error("Failed to load plugins"); }
  };
  useEffect(() => { load(); }, []);

  const filteredCatalog = useMemo(() => {
    return catalog.filter((c) =>
      (category === "all" || c.category === category) &&
      (!q || c.display_name.toLowerCase().includes(q.toLowerCase()) || c.kind.toLowerCase().includes(q.toLowerCase()))
    );
  }, [catalog, q, category]);

  const toggle = async (p) => {
    try {
      await api.patch(`/plugins/${p.id}`, { enabled: !p.enabled });
      toast.success(`${p.name} ${!p.enabled ? "enabled" : "disabled"}`);
      load();
    } catch { toast.error("Toggle failed"); }
  };

  const fire = async (p) => {
    try {
      const { data } = await api.post(`/plugins/${p.id}/test`, { note: "dashboard test-fire" });
      const r = data.results?.[0];
      if (r?.status === "ok") toast.success(`${p.name} · HTTP ${r.http_status}`);
      else toast.error(`${p.name} · ${r?.response?.slice(0, 80) || "failed"}`);
      load();
    } catch { toast.error("Test-fire failed"); }
  };

  const remove = async (p) => {
    if (!confirm(`Uninstall ${p.name}?`)) return;
    try { await api.delete(`/plugins/${p.id}`); toast.success("uninstalled"); load(); }
    catch { toast.error("delete failed"); }
  };

  const deleteTemplate = async (t) => {
    if (!confirm(`Delete template "${t.name}"?`)) return;
    try { await api.delete(`/plugin-templates/${t.id}`); toast.success("template deleted"); load(); }
    catch { toast.error("delete failed"); }
  };

  return (
    <div className="space-y-4">
      <header className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">// integrations</div>
          <h1 className="font-mono text-2xl sm:text-3xl tracking-tight text-[#c0caf5]">plugins<span className="cursor" /></h1>
          <p className="text-xs text-[#a9b1d6] mt-1">
            {installed.length} installed · {catalog.length} available · secrets encrypted at rest
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={load} className="flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-xs font-mono hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)" }}>
            <RefreshCw size={12} /> refresh
          </button>
          <button onClick={() => openCli({
            title: "List plugins via CLI",
            command: "sec-master plugin list --format table && sec-master plugin test <plugin-id>",
            description: "Manage plugin catalog, install, config, and test-fire from the shell.",
          })} className="flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-xs font-mono hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)" }}>
            <Terminal size={12} /> cli
          </button>
        </div>
      </header>

      {/* Installed */}
      <section className="border rounded-sm" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
        <div className="px-4 py-2 border-b flex items-center justify-between" style={{ borderColor: "var(--border-subtle)" }}>
          <div className="font-mono text-xs uppercase tracking-widest text-[#565f89]">installed ({installed.length})</div>
        </div>
        {installed.length === 0 ? (
          <div className="p-6 text-center text-xs font-mono text-[#565f89]">
            no plugins yet · pick one from the catalog below
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="min-w-full text-xs font-mono">
              <thead>
                <tr className="text-left uppercase text-[10px] tracking-widest text-[#565f89] border-b" style={{ borderColor: "var(--border-subtle)" }}>
                  {["name", "type", "events", "runs", "last-status", "enabled", ""].map((h) => <th key={h} className="px-3 py-2">{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {installed.map((p) => {
                  const type = catalog.find((c) => c.kind === p.type);
                  const cat = type?.category || "custom";
                  return (
                    <tr key={p.id} data-testid={PLUGINS.installedRow} className="row-hover border-b" style={{ borderColor: "var(--border-subtle)" }}>
                      <td className="px-3 py-2 text-[#c0caf5]">
                        {p.name}
                        <div className="text-[10px] text-[#565f89]">{p.id}</div>
                      </td>
                      <td className="px-3 py-2">
                        <span className="inline-block text-[10px] uppercase tracking-widest px-1.5 py-0.5 border rounded-sm"
                          style={{ color: CATEGORY_COLOR[cat], borderColor: CATEGORY_COLOR[cat] }}>
                          {p.type}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-[#a9b1d6]">
                        {p.event_subscriptions?.length ? p.event_subscriptions.join(", ") : "—"}
                      </td>
                      <td className="px-3 py-2 text-[#c0caf5]">{p.execution_count || 0}</td>
                      <td className="px-3 py-2">
                        {p.last_run_status === "ok" && <span className="inline-flex items-center gap-1" style={{ color: "var(--status-online)" }}><CheckCircle2 size={10} />ok</span>}
                        {p.last_run_status === "error" && <span className="inline-flex items-center gap-1" style={{ color: "var(--sev-high)" }}><XCircle size={10} />err</span>}
                        {!p.last_run_status && <span className="text-[#565f89]">—</span>}
                        {p.last_run_at && <div className="text-[10px] text-[#565f89]">{new Date(p.last_run_at).toISOString().replace("T", " ").slice(0, 19)}</div>}
                      </td>
                      <td className="px-3 py-2">
                        <button data-testid={PLUGINS.toggleEnabled} onClick={() => toggle(p)}
                          className={`px-2 py-0.5 text-[10px] uppercase tracking-widest border rounded-sm ${p.enabled ? "" : "opacity-60"}`}
                          style={{ borderColor: p.enabled ? "var(--status-online)" : "var(--border-subtle)", color: p.enabled ? "var(--status-online)" : "var(--text-muted)" }}>
                          {p.enabled ? "ON" : "OFF"}
                        </button>
                      </td>
                      <td className="px-3 py-2 text-right">
                        <div className="flex gap-1 justify-end">
                          <button data-testid={PLUGINS.testBtn} onClick={() => fire(p)} title="test-fire"
                            className="p-1 border rounded-sm hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)" }}>
                            <Play size={10} />
                          </button>
                          <button onClick={() => setExecFor(p)} title="executions"
                            className="p-1 border rounded-sm hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)" }}>
                            <ChevronDown size={10} />
                          </button>
                          <button data-testid={PLUGINS.editBtn} onClick={() => setDrawer({ mode: "edit", plugin: p })} title="edit"
                            className="p-1 border rounded-sm hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)" }}>
                            <Pencil size={10} />
                          </button>
                          <button data-testid="plugin-save-template-btn" onClick={() => setSaveTplFor(p)} title="save as template"
                            className="p-1 border rounded-sm hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)", color: "var(--purple-analyst)" }}>
                            <Bookmark size={10} />
                          </button>
                          <button data-testid={PLUGINS.deleteBtn} onClick={() => remove(p)} title="delete"
                            className="p-1 border rounded-sm hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)", color: "var(--sev-high)" }}>
                            <Trash2 size={10} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Templates */}
      {templates.length > 0 && (
        <section className="border rounded-sm" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
          <div className="px-4 py-2 border-b flex items-center gap-2" style={{ borderColor: "var(--border-subtle)" }}>
            <Bookmark size={12} style={{ color: "var(--purple-analyst)" }} />
            <div className="font-mono text-xs uppercase tracking-widest text-[#565f89]">templates ({templates.length})</div>
            <div className="text-[10px] font-mono text-[#565f89] ml-2">one-click reuse · secrets encrypted</div>
          </div>
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3 p-4">
            {templates.map((t) => {
              const type = catalog.find((c) => c.kind === t.type);
              const cat = type?.category || "custom";
              return (
                <article key={t.id} data-testid="template-card" className="border rounded-sm p-3 flex flex-col gap-2"
                  style={{ borderColor: "var(--border-subtle)", background: "var(--bg-terminal)" }}>
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <Sparkles size={12} style={{ color: CATEGORY_COLOR[cat] }} />
                        <div className="font-mono text-sm text-[#c0caf5] truncate">{t.name}</div>
                      </div>
                      <div className="mt-1 flex items-center gap-2 text-[10px] font-mono">
                        <span className="uppercase tracking-widest" style={{ color: CATEGORY_COLOR[cat] }}>{t.type}</span>
                        {t.has_secrets && <span className="px-1 py-0.5 border rounded-sm uppercase tracking-widest text-[9px]"
                          style={{ borderColor: "var(--purple-analyst)", color: "var(--purple-analyst)" }}>with secrets</span>}
                      </div>
                    </div>
                    <button onClick={() => deleteTemplate(t)} className="p-1 border rounded-sm hover:bg-[#292e42]"
                      style={{ borderColor: "var(--border-subtle)", color: "var(--sev-high)" }}>
                      <Trash2 size={10} />
                    </button>
                  </div>
                  <div className="text-[10px] font-mono text-[#565f89]">
                    events: {t.event_subscriptions?.length ? t.event_subscriptions.join(", ") : "none"}
                  </div>
                  <button data-testid="template-use-btn" onClick={() => setDrawer({ mode: "from-template", template: t })}
                    className="mt-1 flex items-center justify-center gap-1 px-2 py-1 text-[10px] font-mono uppercase tracking-widest border rounded-sm hover:bg-[#292e42]"
                    style={{ borderColor: "var(--border-accent)", color: "var(--text-primary)" }}>
                    <Plus size={10} /> use template
                  </button>
                </article>
              );
            })}
          </div>
        </section>
      )}

      {/* Catalog */}
      <section>
        <div className="flex flex-col sm:flex-row sm:items-center gap-2 mb-3">
          <div className="font-mono text-xs uppercase tracking-widest text-[#565f89]">catalog</div>
          <div className="flex-1 flex items-center gap-2 border rounded-sm px-2 py-1" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
            <Search size={12} className="text-[#565f89]" />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="search plugin type"
              className="flex-1 bg-transparent font-mono text-xs focus:outline-none text-[#c0caf5] placeholder:text-[#565f89]" />
          </div>
          <div className="flex gap-1 flex-wrap">
            {["all", "alerting", "siem", "enrichment", "custom"].map((c) => (
              <button key={c} onClick={() => setCategory(c)}
                className={`px-2 py-1 text-[10px] font-mono uppercase tracking-widest border rounded-sm ${category === c ? "bg-[#292e42]" : "hover:bg-[#292e42]"}`}
                style={{ borderColor: c === "all" ? "var(--border-subtle)" : CATEGORY_COLOR[c], color: c === "all" ? "var(--text-primary)" : CATEGORY_COLOR[c] }}>
                {c}
              </button>
            ))}
          </div>
        </div>

        <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
          {filteredCatalog.map((c) => (
            <article key={c.kind} data-testid={PLUGINS.catalogCard}
              className="border rounded-sm p-4 flex flex-col gap-3 transition-colors hover:border-[#7aa2f7]"
              style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2">
                    <Plug size={14} style={{ color: CATEGORY_COLOR[c.category] }} />
                    <div className="font-mono text-sm text-[#c0caf5]">{c.display_name}</div>
                  </div>
                  <div className="text-[10px] font-mono uppercase tracking-widest mt-1" style={{ color: CATEGORY_COLOR[c.category] }}>{c.category}</div>
                </div>
                <div className="flex gap-1">
                  {(c.capabilities || []).map((cap) => (
                    <span key={cap} className="text-[9px] font-mono uppercase tracking-widest px-1 py-0.5 border rounded-sm"
                      style={{ borderColor: "var(--border-subtle)", color: "var(--text-secondary)" }}>{cap}</span>
                  ))}
                </div>
              </div>
              <p className="text-xs text-[#a9b1d6] leading-relaxed flex-1">{c.description}</p>
              <div className="flex justify-between items-center pt-2 border-t" style={{ borderColor: "var(--border-subtle)" }}>
                <div className="text-[10px] font-mono text-[#565f89]">
                  {c.supported_events?.length || 0} event hooks
                </div>
                <button data-testid={PLUGINS.installBtn}
                  onClick={() => setDrawer({ mode: "install", plugin: c })}
                  className="flex items-center gap-1 px-2.5 py-1 text-[10px] font-mono uppercase tracking-widest border rounded-sm hover:bg-[#292e42]"
                  style={{ borderColor: "var(--border-accent)", color: "var(--text-primary)" }}>
                  <Plus size={10} /> install
                </button>
              </div>
            </article>
          ))}
        </div>
      </section>

      <PluginDrawer
        open={!!drawer}
        onClose={() => setDrawer(null)}
        mode={drawer?.mode}
        plugin={drawer?.plugin}
        template={drawer?.template}
        catalog={catalog}
        events={events}
        onSaved={load}
      />
      <ExecutionsViewer plugin={execFor} onClose={() => setExecFor(null)} />
      <SaveTemplateModal open={!!saveTplFor} plugin={saveTplFor} onClose={() => setSaveTplFor(null)} onSaved={load} />
    </div>
  );
}
