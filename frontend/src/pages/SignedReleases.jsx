import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { useCli } from "@/components/Layout";
import { CheckCircle2, Terminal, Copy } from "lucide-react";
import { toast } from "sonner";

const CHANNEL_COLOR = { stable: "var(--status-online)", beta: "var(--status-drift)", nightly: "var(--purple-analyst)" };

export default function SignedReleases() {
  const [rows, setRows] = useState([]);
  const [pick, setPick] = useState(null);
  const { openCli } = useCli();

  useEffect(() => { api.get("/releases").then(({ data }) => setRows(data)); }, []);

  return (
    <div className="space-y-4">
      <header className="flex items-end justify-between gap-3 flex-col sm:flex-row">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">// releases</div>
          <h1 className="font-mono text-2xl sm:text-3xl tracking-tight text-[#c0caf5]">signed-releases<span className="cursor" /></h1>
          <p className="text-xs text-[#a9b1d6] mt-1">cosign-verified flake + dsc bundle stream</p>
        </div>
        <button onClick={() => openCli({
          title: "Verify latest release signature",
          command: "cosign verify --key sec-master.pub github.com/sec-master/flake:latest",
          description: "Downloads the release manifest, checks cosign signature against the pinned public key.",
        })} className="flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-xs font-mono hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)" }}>
          <Terminal size={12} /> cli
        </button>
      </header>

      <div className="grid gap-3 md:grid-cols-2">
        {rows.map((r) => (
          <article key={r.id} onClick={() => setPick(r)} className="border rounded-sm p-4 cursor-pointer hover:border-[#7aa2f7] transition-colors" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
            <div className="flex justify-between items-start">
              <div>
                <div className="font-mono text-lg text-[#c0caf5]">{r.version}</div>
                <div className="text-[10px] font-mono uppercase tracking-widest mt-1" style={{ color: CHANNEL_COLOR[r.channel] }}>{r.channel}</div>
              </div>
              <div className="flex items-center gap-1 text-[10px] font-mono uppercase tracking-widest" style={{ color: "var(--status-online)" }}>
                <CheckCircle2 size={12} /> {r.signature_status}
              </div>
            </div>
            <div className="mt-3 font-mono text-[11px] text-[#a9b1d6] break-all">sha:{r.commit_sha.slice(0, 24)}…</div>
            <div className="mt-1 text-[10px] font-mono text-[#565f89]">signed by {r.signer} · {new Date(r.published_at).toISOString().slice(0, 10)}</div>
            <p className="mt-3 text-xs text-[#a9b1d6] leading-relaxed">{r.changelog}</p>
          </article>
        ))}
      </div>

      {pick && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4" onClick={() => setPick(null)}>
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
          <div onClick={(e) => e.stopPropagation()} className="relative z-10 max-w-lg w-full border rounded-sm p-5 enter" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
            <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-2">release manifest</div>
            <div className="font-mono text-xl text-[#c0caf5] mb-3">{pick.version}</div>
            <div className="space-y-2 font-mono text-xs">
              {[
                ["commit", pick.commit_sha],
                ["signer", pick.signer],
                ["channel", pick.channel],
                ["signature", pick.signature_status],
                ["published", new Date(pick.published_at).toISOString()],
              ].map(([k, v]) => (
                <div key={k} className="flex gap-3">
                  <span className="w-24 text-[#565f89] uppercase tracking-widest text-[10px]">{k}</span>
                  <span className="flex-1 text-[#c0caf5] break-all">{v}</span>
                </div>
              ))}
            </div>
            <pre className="mt-4 font-mono text-[11px] p-3 border rounded-sm whitespace-pre-wrap" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-terminal)", color: "var(--text-secondary)" }}>
{`$ nix run github:sec-master/flake/${pick.version}#update
$ cosign verify --key sec-master.pub sec-master/flake:${pick.version}`}
            </pre>
            <button onClick={() => { navigator.clipboard.writeText(`nix run github:sec-master/flake/${pick.version}#update`); toast.success("copied"); }} className="mt-3 flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-xs font-mono hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)" }}>
              <Copy size={12} /> copy install cmd
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
