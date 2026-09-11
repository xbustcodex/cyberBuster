import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { useCli } from "@/components/Layout";
import { CheckCircle2, ShieldOff, Terminal, Copy, RefreshCw, ExternalLink, Github } from "lucide-react";
import { toast } from "sonner";

const CHANNEL_COLOR = { stable: "var(--status-online)", beta: "var(--status-drift)", nightly: "var(--purple-analyst)" };
const SIG_META = {
  signed: { color: "var(--status-online)", Icon: CheckCircle2, label: "signed" },
  valid: { color: "var(--status-online)", Icon: CheckCircle2, label: "valid (demo)" },
  unsigned: { color: "var(--status-drift)", Icon: ShieldOff, label: "unsigned" },
  invalid: { color: "var(--sev-high)", Icon: ShieldOff, label: "invalid" },
};

const verifyCmd = (r) => {
  const bundle = (r.assets || []).find((a) => a.name.endsWith(".bundle"));
  const blob = (r.assets || []).find((a) => a.name.endsWith(".tar.gz"));
  if (!bundle || !blob) return `gh release view ${r.version} -R ${r.repo}`;
  return `gh release download ${r.version} -R ${r.repo} -p '${blob.name}' -p '${bundle.name}'
cosign verify-blob --bundle ${bundle.name} \\
  --certificate-identity-regexp 'https://github.com/${r.repo}/' \\
  --certificate-oidc-issuer https://token.actions.githubusercontent.com ${blob.name}`;
};

export default function SignedReleases() {
  const [rows, setRows] = useState([]);
  const [status, setStatus] = useState(null);
  const [pick, setPick] = useState(null);
  const [syncing, setSyncing] = useState(false);
  const { openCli } = useCli();

  const load = async () => {
    try {
      const [{ data }, { data: st }] = await Promise.all([api.get("/releases"), api.get("/releases/status")]);
      setRows(data); setStatus(st);
    } catch { toast.error("releases load failed"); }
  };
  useEffect(() => { load(); }, []);

  const sync = async () => {
    setSyncing(true);
    try {
      const { data } = await api.post("/releases/sync");
      toast.success(`${data.repo}: ${data.releases} release(s), ${data.signed} signed`);
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "GitHub sync failed"); }
    setSyncing(false);
  };

  const real = rows.filter((r) => r.source === "github");
  const demo = rows.filter((r) => r.demo);

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between gap-3 flex-col sm:flex-row">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">// releases</div>
          <h1 className="font-mono text-2xl sm:text-3xl tracking-tight text-[#c0caf5]">signed-releases<span className="cursor" /></h1>
          <p className="text-xs text-[#a9b1d6] mt-1 flex items-center gap-1.5 flex-wrap">
            <Github size={12} /> <span data-testid="releases-repo">github.com/{status?.repo}</span>
            <span className="text-[#565f89]">· last sync {status?.finished_at ? new Date(status.finished_at).toISOString().replace("T", " ").slice(0, 19) : "never"}</span>
            {status?.status === "error" && <span style={{ color: "var(--sev-high)" }}>· {status.error}</span>}
          </p>
        </div>
        <div className="flex gap-2">
          <button data-testid="releases-sync-btn" onClick={sync} disabled={syncing} className="flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-xs font-mono hover:bg-[#292e42] disabled:opacity-60" style={{ borderColor: "var(--border-accent)" }}>
            <RefreshCw size={12} className={syncing ? "animate-spin" : ""} /> sync from github
          </button>
          <button onClick={() => openCli({
            title: "Cut a signed release",
            command: `git tag v1.0.0 && git push origin v1.0.0\n# .github/workflows/release.yml builds the bundle, signs it with cosign (keyless) and publishes assets\nsec-master releases sync`,
            description: "Pushing a v* tag triggers the release workflow. The dashboard then lists the release with its cosign .bundle asset.",
          })} className="flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-xs font-mono hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)" }}>
            <Terminal size={12} /> cli
          </button>
        </div>
      </header>

      {real.length === 0 && (
        <div data-testid="releases-empty" className="border rounded-sm p-5 font-mono text-xs space-y-2" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
          <div className="text-[#c0caf5]">no GitHub releases found in <span style={{ color: "var(--purple-analyst)" }}>{status?.repo}</span></div>
          <div className="text-[#a9b1d6]">The release pipeline is committed at <span className="text-[#c0caf5]">.github/workflows/release.yml</span>. Publish your first signed release:</div>
          <pre className="p-3 border rounded-sm whitespace-pre-wrap" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-terminal)", color: "var(--text-secondary)" }}>
{`$ git tag v1.0.0 && git push origin v1.0.0
# GitHub Actions: tar infrastructure/ → cosign sign-blob (keyless OIDC) → gh release with .tar.gz + .bundle
$ sec-master releases sync`}
          </pre>
        </div>
      )}

      <div className="grid gap-3 md:grid-cols-2">
        {[...real, ...demo].map((r) => {
          const sm = SIG_META[r.signature_status] || SIG_META.unsigned;
          return (
            <article key={r.id} data-testid="release-card" onClick={() => setPick(r)} className="border rounded-sm p-4 cursor-pointer hover:border-[#7aa2f7] transition-colors" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
              <div className="flex justify-between items-start">
                <div>
                  <div className="font-mono text-lg text-[#c0caf5]">{r.version}
                    {r.demo && <span className="ml-2 align-middle px-1 py-px text-[9px] uppercase tracking-widest border rounded-sm" style={{ color: "var(--status-drift)", borderColor: "var(--status-drift)" }}>demo</span>}
                  </div>
                  <div className="text-[10px] font-mono uppercase tracking-widest mt-1" style={{ color: CHANNEL_COLOR[r.channel] }}>{r.channel}</div>
                </div>
                <div className="flex items-center gap-1 text-[10px] font-mono uppercase tracking-widest" style={{ color: sm.color }}>
                  <sm.Icon size={12} /> {sm.label}
                </div>
              </div>
              <div className="mt-3 font-mono text-[11px] text-[#a9b1d6] break-all">sha:{r.commit_sha ? r.commit_sha.slice(0, 24) + "…" : "—"}</div>
              <div className="mt-1 text-[10px] font-mono text-[#565f89]">by {r.signer} · {new Date(r.published_at).toISOString().slice(0, 10)}{r.assets ? ` · ${r.assets.length} asset(s)` : ""}</div>
              <p className="mt-3 text-xs text-[#a9b1d6] leading-relaxed line-clamp-3 whitespace-pre-line">{r.changelog || "no release notes"}</p>
            </article>
          );
        })}
      </div>

      {pick && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={() => setPick(null)}>
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
          <div onClick={(e) => e.stopPropagation()} className="relative z-10 max-w-lg w-full border rounded-sm p-5 enter" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
            <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-2">release manifest</div>
            <div className="font-mono text-xl text-[#c0caf5] mb-3 flex items-center gap-2">{pick.version}
              {pick.html_url && <a href={pick.html_url} target="_blank" rel="noreferrer" className="text-[#7aa2f7]"><ExternalLink size={14} /></a>}
            </div>
            <div className="space-y-2 font-mono text-xs">
              {[
                ["commit", pick.commit_sha || "—"],
                ["author", pick.signer],
                ["channel", pick.channel],
                ["signature", pick.signature_assets?.length ? `${pick.signature_status}: ${pick.signature_assets.join(", ")}` : pick.signature_status],
                ["published", new Date(pick.published_at).toISOString()],
                ["source", pick.demo ? "demo seed (fabricated)" : `github.com/${pick.repo}`],
              ].map(([k, v]) => (
                <div key={k} className="flex gap-3">
                  <span className="w-24 text-[#565f89] uppercase tracking-widest text-[10px]">{k}</span>
                  <span className="flex-1 text-[#c0caf5] break-all">{v}</span>
                </div>
              ))}
            </div>
            {pick.assets?.length > 0 && (
              <ul className="mt-3 space-y-1 font-mono text-[11px]">
                {pick.assets.map((a) => (
                  <li key={a.name} className="flex justify-between gap-2 text-[#a9b1d6]">
                    <a href={a.download_url} className="hover:text-[#c0caf5] truncate" target="_blank" rel="noreferrer">{a.name}</a>
                    <span className="text-[#565f89]">{(a.size / 1024).toFixed(1)} KiB</span>
                  </li>
                ))}
              </ul>
            )}
            {!pick.demo && (
              <>
                <pre className="mt-4 font-mono text-[11px] p-3 border rounded-sm whitespace-pre-wrap" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-terminal)", color: "var(--text-secondary)" }}>{verifyCmd(pick)}</pre>
                <button onClick={() => { navigator.clipboard.writeText(verifyCmd(pick)); toast.success("copied"); }} className="mt-3 flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-xs font-mono hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)" }}>
                  <Copy size={12} /> copy verify cmd
                </button>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
