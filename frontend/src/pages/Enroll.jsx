import { useState, useEffect } from "react";
import { api } from "@/lib/api";
import { ENROLL } from "@/constants/testIds";
import { useCli } from "@/components/Layout";
import { Copy, Terminal, Loader2, Download } from "lucide-react";
import { toast } from "sonner";

export default function EnrollWorkstation() {
  const [hostname, setHostname] = useState("");
  const [os, setOs] = useState("nixos");
  const [tok, setTok] = useState(null);
  const [busy, setBusy] = useState(false);
  const [remaining, setRemaining] = useState(0);
  const { openCli } = useCli();

  useEffect(() => {
    if (!tok) return;
    const tick = () => {
      const ms = new Date(tok.expires_at).getTime() - Date.now();
      setRemaining(Math.max(0, Math.floor(ms / 1000)));
    };
    tick();
    const t = setInterval(tick, 1000);
    return () => clearInterval(t);
  }, [tok]);

  const generate = async (e) => {
    e.preventDefault();
    if (!hostname) return;
    setBusy(true);
    try {
      const { data } = await api.post("/enroll/generate", { hostname, os });
      setTok(data);
      toast.success("Enrollment token generated");
    } catch { toast.error("Token generation failed"); }
    setBusy(false);
  };

  const fmt = (s) => `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;

  return (
    <div className="space-y-4 max-w-3xl">
      <header>
        <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">// enroll</div>
        <h1 className="font-mono text-2xl sm:text-3xl tracking-tight text-[#c0caf5]">enroll-workstation<span className="cursor" /></h1>
        <p className="text-xs text-[#a9b1d6] mt-1">generate a one-time token · workstation exchanges it for a long-lived agent bearer</p>
      </header>

      <form onSubmit={generate} className="border rounded-sm p-4 space-y-4" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label className="block text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">hostname</label>
            <input
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              required
              placeholder="hydra-red-99"
              className="w-full px-3 py-2 font-mono text-sm bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
              style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
            />
          </div>
          <div>
            <label className="block text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">os</label>
            <select
              value={os}
              onChange={(e) => setOs(e.target.value)}
              className="w-full px-3 py-2 font-mono text-sm bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
              style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
            >
              <option value="nixos">nixos (flake)</option>
              <option value="windows">windows (dsc)</option>
            </select>
          </div>
        </div>
        <button
          data-testid={ENROLL.generateBtn}
          disabled={busy}
          className="px-4 py-2 font-mono text-xs uppercase tracking-widest border rounded-sm hover:bg-[#292e42] flex items-center gap-2 disabled:opacity-60"
          style={{ borderColor: "var(--border-accent)", color: "var(--text-primary)" }}
        >
          {busy && <Loader2 size={12} className="animate-spin" />} generate one-time token
        </button>
      </form>

      {tok && (
        <div className="border rounded-sm p-4 space-y-4 enter" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
          <div className="flex justify-between items-start flex-wrap gap-2">
            <div>
              <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89]">token · 30-min ttl</div>
              <div data-testid={ENROLL.tokenValue} className="font-mono text-sm text-[#c0caf5] break-all mt-1">{tok.token}</div>
            </div>
            <div data-testid={ENROLL.expiration} className="font-mono text-xs text-[#e0af68]">
              expires in {fmt(remaining)}
            </div>
          </div>

          {[
            ["bash", tok.bash_command, ENROLL.copyBash],
            ["powershell", tok.powershell_command, ENROLL.copyPs],
          ].map(([shell, cmd, tid]) => (
            <div key={shell}>
              <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1 flex justify-between">
                <span>{shell}</span>
                <button data-testid={tid} onClick={() => { navigator.clipboard.writeText(cmd); toast.success(`${shell} copied`); }} className="hover:text-[#c0caf5] flex items-center gap-1">
                  <Copy size={10} /> copy
                </button>
              </div>
              <pre className="font-mono text-[11px] p-3 border rounded-sm whitespace-pre-wrap break-all" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-terminal)", color: "var(--text-primary)" }}>
                <span style={{ color: "var(--purple-analyst)" }}>{shell === "bash" ? "$ " : "PS> "}</span>{cmd}
              </pre>
            </div>
          ))}

          <button onClick={() => openCli({
            title: "Enroll workstation into fleet",
            command: os === "nixos" ? tok.bash_command : tok.powershell_command,
            description: "Downloads agent.py from this dashboard, exchanges the one-time token for a persistent bearer, installs a systemd unit (Linux) / Scheduled Task (Windows) that heartbeats every 60s and applies profile switches requested here.",
            shell: os === "nixos" ? "bash" : "powershell",
          })} className="flex items-center gap-1.5 px-3 py-1.5 border rounded-sm text-xs font-mono hover:bg-[#292e42]" style={{ borderColor: "var(--border-subtle)" }}>
            <Terminal size={12} /> open in cli-mirror
          </button>
        </div>
      )}

      <div data-testid="enroll-how-it-works" className="border rounded-sm p-4 space-y-3 font-mono text-xs" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
        <div className="text-[10px] uppercase tracking-widest text-[#565f89]">what the one-liner does on the host</div>
        <ol className="list-decimal list-inside space-y-1 text-[#a9b1d6]">
          <li>fetches <span className="text-[#c0caf5]">agent.py</span> from this dashboard into <span className="text-[#c0caf5]">/opt/sec-master</span> (Linux) or <span className="text-[#c0caf5]">%ProgramData%\SecMaster</span> (Windows)</li>
          <li>POSTs the one-time token to <span className="text-[#c0caf5]">/api/agent/enroll</span> → stores the agent bearer with mode 0600</li>
          <li>installs <span className="text-[#c0caf5]">sec-master-agent</span> (systemd / transient unit on NixOS / Scheduled Task on Windows) heartbeating every 60s with detected tool versions, flake/DSC hash, local IP</li>
          <li>when you switch a profile here, the agent runs <span className="text-[#c0caf5]">nixos-rebuild switch --specialisation &lt;p&gt;</span> or <span className="text-[#c0caf5]">Set-SMProfile</span> and reports back — status shows <span style={{ color: "var(--status-drift)" }}>drift</span> until applied; <span style={{ color: "var(--status-offline)" }}>offline</span> after 5 min without heartbeat</li>
        </ol>
        <div className="text-[10px] uppercase tracking-widest text-[#565f89] pt-1">artifacts served by this dashboard</div>
        <div className="flex flex-wrap gap-2">
          {[["agent.py", "/api/agent/agent.py"], ["bootstrap.sh", "/api/agent/bootstrap.sh"], ["bootstrap.ps1", "/api/agent/bootstrap.ps1"], ["SecurityMaster.psm1", "/api/agent/SecurityMaster.psm1"], ["sec-master (cli)", "/api/agent/sec-master"]].map(([label, path]) => (
            <a key={path} data-testid={`enroll-artifact-${label.split(" ")[0]}`} href={`${process.env.REACT_APP_BACKEND_URL}${path}`} target="_blank" rel="noreferrer"
              className="flex items-center gap-1 px-2 py-1 border rounded-sm hover:bg-[#292e42] text-[#a9b1d6]" style={{ borderColor: "var(--border-subtle)" }}>
              <Download size={10} /> {label}
            </a>
          ))}
        </div>
        <pre className="p-3 border rounded-sm whitespace-pre-wrap" style={{ borderColor: "var(--border-subtle)", background: "var(--bg-terminal)", color: "var(--text-secondary)" }}>
{`# install the operator CLI
$ curl -fsSL ${process.env.REACT_APP_BACKEND_URL}/api/agent/sec-master -o /usr/local/bin/sec-master && chmod +x /usr/local/bin/sec-master
$ sec-master login --dashboard ${process.env.REACT_APP_BACKEND_URL} --email <you>
$ sec-master fleet list`}
        </pre>
      </div>
    </div>
  );
}
