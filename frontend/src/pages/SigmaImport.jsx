import { useState } from "react";
import { api } from "@/lib/api";
import { useCli } from "@/components/Layout";
import {
  FileCode, Play, Loader2, AlertTriangle, CheckCircle2, Radar, Terminal,
} from "lucide-react";
import { toast } from "sonner";

const SAMPLE = `title: Suspicious EICAR variant
id: 4e0f2a6a-eicar-demo
level: high
detection:
  selection:
    Hashes|contains:
      - md5=44d88612fea8a8f36de82e1278abb02f
      - sha1=3395856ce81f2b7382dee72602f798b642f14140
      - sha256=275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
  condition: selection
---
title: Known ransomware dropper
id: 111-222-333
level: critical
detection:
  selection:
    sha256:
      - e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  condition: selection
`;

const LEVEL_COLOR = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
};

export default function SigmaImport() {
  const [text, setText] = useState(SAMPLE);
  const [preview, setPreview] = useState(null);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [importBusy, setImportBusy] = useState(false);
  const [scope, setScope] = useState("all-online");
  const [result, setResult] = useState(null);
  const { openCli } = useCli();

  const doPreview = async () => {
    if (!text.trim()) { toast.error("Paste Sigma YAML first"); return; }
    setPreviewBusy(true);
    try {
      const { data } = await api.post("/sigma/preview", { sigma_yaml: text });
      setPreview(data);
    } catch (e) { toast.error(e.response?.data?.detail || "Preview failed"); }
    setPreviewBusy(false);
  };

  const doImport = async () => {
    if (!preview || preview.hash_count === 0) { toast.error("Run preview first · nothing to import"); return; }
    setImportBusy(true);
    try {
      const { data } = await api.post("/sigma/import", { sigma_yaml: text, scope });
      setResult(data);
      toast.success(`Imported ${data.unique_hashes} hash(es) to ${data.targets} workstation(s)`);
    } catch (e) { toast.error(e.response?.data?.detail || "Import failed"); }
    setImportBusy(false);
  };

  return (
    <div className="space-y-4">
      <header className="flex flex-col sm:flex-row sm:items-end sm:justify-between gap-3">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">// dfir</div>
          <h1 className="font-mono text-2xl sm:text-3xl tracking-tight text-[#c0caf5]">sigma-import<span className="cursor" /></h1>
          <p className="text-xs text-[#a9b1d6] mt-1">
            Paste one or more Sigma rules · hashes become watchlist entries · works across dialects
          </p>
        </div>
        <button onClick={() => openCli({
          title: "Import Sigma rules from CLI",
          command: "cat rules.yml | sec-master sigma import --scope all-online",
          description: "Extracts MD5 / SHA1 / SHA256 hashes from Sigma detection blocks and adds them to each host's IOC watchlist.",
        })} className="flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-xs font-mono hover:bg-[#292e42]"
          style={{ borderColor: "var(--border-subtle)" }}>
          <Terminal size={12} /> cli
        </button>
      </header>

      <div className="grid gap-4 lg:grid-cols-2">
        {/* Editor */}
        <section className="border rounded-sm" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
          <div className="px-3 py-2 border-b flex items-center justify-between" style={{ borderColor: "var(--border-subtle)" }}>
            <div className="flex items-center gap-2">
              <FileCode size={12} style={{ color: "var(--purple-analyst)" }} />
              <div className="font-mono text-xs uppercase tracking-widest text-[#565f89]">sigma yaml</div>
            </div>
            <button data-testid="sigma-load-sample" onClick={() => setText(SAMPLE)}
              className="text-[10px] font-mono uppercase tracking-widest text-[#565f89] hover:text-[#c0caf5]">
              load sample
            </button>
          </div>
          <textarea
            data-testid="sigma-yaml-input"
            value={text} onChange={(e) => setText(e.target.value)}
            spellCheck={false}
            className="w-full p-3 font-mono text-[11px] bg-[#15161e] focus:outline-none resize-none"
            style={{ color: "var(--text-primary)", minHeight: "420px", borderColor: "var(--border-subtle)" }}
          />
          <div className="border-t px-3 py-2 flex items-center gap-2" style={{ borderColor: "var(--border-subtle)" }}>
            <button data-testid="sigma-preview-btn" onClick={doPreview} disabled={previewBusy}
              className="flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-xs font-mono hover:bg-[#292e42] disabled:opacity-60"
              style={{ borderColor: "var(--border-accent)", color: "var(--text-primary)" }}>
              {previewBusy ? <Loader2 size={12} className="animate-spin" /> : <Play size={12} />}
              parse rules
            </button>
            <span className="text-[10px] font-mono text-[#565f89]">
              multi-doc supported · md5 / sha1 / sha256 hex literals extracted
            </span>
          </div>
        </section>

        {/* Preview / Import */}
        <section className="space-y-3">
          <div className="border rounded-sm" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
            <div className="px-3 py-2 border-b font-mono text-xs uppercase tracking-widest text-[#565f89]" style={{ borderColor: "var(--border-subtle)" }}>
              preview
            </div>
            <div className="p-3">
              {!preview && (
                <div className="text-[10px] font-mono text-[#565f89] text-center py-6">
                  hit "parse rules" to preview extracted hashes
                </div>
              )}
              {preview && (
                <div className="space-y-3">
                  <div className="flex gap-4 text-xs font-mono">
                    <div><span className="text-[#565f89]">rules:</span> <span className="text-[#c0caf5]">{preview.rules.length}</span></div>
                    <div><span className="text-[#565f89]">unique hashes:</span> <span className="text-[#c0caf5]">{preview.hash_count}</span></div>
                  </div>
                  <ul className="space-y-2">
                    {preview.rules.map((r, i) => (
                      <li key={i} data-testid="sigma-rule-item" className="border rounded-sm p-2 text-[11px] font-mono"
                        style={{ borderColor: "var(--border-subtle)", background: "var(--bg-terminal)" }}>
                        <div className="flex justify-between gap-2 items-start flex-wrap">
                          <div className="min-w-0">
                            <div className="text-[#c0caf5] truncate">{r.title}</div>
                            {r.id && <div className="text-[9px] text-[#565f89]">{r.id}</div>}
                          </div>
                          {r.level && (
                            <span className="px-1.5 py-0.5 text-[9px] uppercase tracking-widest border rounded-sm"
                              style={{ color: LEVEL_COLOR[r.level] || "var(--text-secondary)",
                                       borderColor: LEVEL_COLOR[r.level] || "var(--border-subtle)" }}>
                              {r.level}
                            </span>
                          )}
                        </div>
                        {r.hashes.length > 0 && (
                          <div className="mt-2 text-[#a9b1d6] break-all leading-relaxed">
                            {r.hashes.map((h) => (
                              <span key={h} className="inline-block px-1.5 py-0.5 mr-1 mb-1 border rounded-sm text-[9px] text-[#c0caf5]"
                                style={{ borderColor: "var(--border-subtle)", background: "var(--bg-main)" }}>{h}</span>
                            ))}
                          </div>
                        )}
                        {r.warnings.length > 0 && (
                          <div className="mt-1 flex items-start gap-1 text-[10px]" style={{ color: "var(--sev-medium)" }}>
                            <AlertTriangle size={10} className="mt-0.5 flex-shrink-0" />
                            {r.warnings.join(" · ")}
                          </div>
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </div>

          <div className="border rounded-sm p-3 space-y-3" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
            <div className="font-mono text-xs uppercase tracking-widest text-[#565f89]">apply scope</div>
            <div className="flex gap-2">
              {[
                ["all-online", "online only"],
                ["all", "entire fleet"],
              ].map(([k, l]) => (
                <button key={k} data-testid={`sigma-scope-${k}`} onClick={() => setScope(k)}
                  className={`px-3 py-1.5 text-[10px] font-mono uppercase tracking-widest border rounded-sm ${scope === k ? "bg-[#292e42]" : "hover:bg-[#292e42]"}`}
                  style={{ borderColor: scope === k ? "var(--border-focus)" : "var(--border-subtle)",
                           color: scope === k ? "var(--text-primary)" : "var(--text-secondary)" }}>
                  {l}
                </button>
              ))}
            </div>
            <button data-testid="sigma-import-btn" onClick={doImport} disabled={importBusy || !preview || preview?.hash_count === 0}
              className="w-full flex items-center justify-center gap-2 py-2 border rounded-sm text-xs font-mono uppercase tracking-widest hover:bg-[#292e42] disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ borderColor: "var(--purple-analyst)", color: "var(--purple-analyst)" }}>
              {importBusy ? <Loader2 size={12} className="animate-spin" /> : <Radar size={12} />}
              import to watchlists
            </button>
          </div>

          {result && (
            <div className="border rounded-sm p-3" style={{ background: "var(--bg-terminal)", borderColor: "var(--status-online)" }}>
              <div className="flex items-center gap-2 font-mono text-xs" style={{ color: "var(--status-online)" }}>
                <CheckCircle2 size={12} />
                imported {result.unique_hashes} hash(es) into {result.targets} workstation(s)
              </div>
              <ul className="mt-2 space-y-1 font-mono text-[10px]">
                {result.per_workstation.map((r) => (
                  <li key={r.workstation_id} className="flex justify-between text-[#a9b1d6]">
                    <span>{r.hostname}</span>
                    <span className="text-[#565f89]">+{r.added} new</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
