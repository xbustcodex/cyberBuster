import { useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { AUTH } from "@/constants/testIds";
import { Terminal, Loader2, Copy } from "lucide-react";
import { toast } from "sonner";

export default function Login() {
  const { user, login, error, setError } = useAuth();
  const nav = useNavigate();
  const [email, setEmail] = useState("admin@secmaster.io");
  const [password, setPassword] = useState("admin1234");
  const [busy, setBusy] = useState(false);

  if (user && user !== false) return <Navigate to="/fleet" replace />;

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setError(null);
    const ok = await login(email, password);
    setBusy(false);
    if (ok) nav("/fleet");
  };

  const curl = `curl -c cookies.txt -X POST ${process.env.REACT_APP_BACKEND_URL}/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"email":"${email}","password":"***"}'`;

  return (
    <div className="grain min-h-screen flex items-center justify-center p-4 relative">
      <div className="relative z-10 w-full max-w-md">
        <div className="mb-6 flex items-center gap-2 font-mono text-xs tracking-widest uppercase" style={{ color: "var(--purple-analyst)" }}>
          <Terminal size={14} /> security-master // hardened-analyst
        </div>

        <div className="border rounded-md" style={{ background: "var(--bg-card)", borderColor: "var(--border-subtle)" }}>
          <div className="border-b px-5 py-3 flex items-center gap-2" style={{ borderColor: "var(--border-subtle)" }}>
            <div className="flex gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-[#f7768e]" />
              <span className="w-2.5 h-2.5 rounded-full bg-[#e0af68]" />
              <span className="w-2.5 h-2.5 rounded-full bg-[#9ece6a]" />
            </div>
            <div className="font-mono text-[11px] text-[#565f89] ml-2">sec-master:~$ login</div>
          </div>

          <form onSubmit={submit} className="p-5 space-y-4">
            <h1 className="font-mono text-xl tracking-tight text-[#c0caf5]">Access fleet dashboard<span className="cursor" /></h1>
            <p className="text-xs text-[#a9b1d6] leading-relaxed">
              JWT auth via httpOnly cookies. Bearer fallback stored client-side.
            </p>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">operator email</label>
              <input
                data-testid={AUTH.emailInput}
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                autoComplete="email"
                className="w-full px-3 py-2 font-mono text-sm bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
                style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
              />
            </div>

            <div>
              <label className="block text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1">password</label>
              <input
                data-testid={AUTH.passwordInput}
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                autoComplete="current-password"
                className="w-full px-3 py-2 font-mono text-sm bg-[#16161e] border rounded-sm focus:outline-none focus:border-[#bb9af7]"
                style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
              />
            </div>

            {error && (
              <div className="text-xs font-mono border rounded-sm px-3 py-2" style={{ background: "rgba(219,75,75,0.12)", borderColor: "var(--sev-critical)", color: "var(--sev-high)" }}>
                error: {error}
              </div>
            )}

            <button
              data-testid={AUTH.submitBtn}
              disabled={busy}
              className="w-full py-2 font-mono text-sm tracking-widest uppercase border rounded-sm hover:bg-[#292e42] flex items-center justify-center gap-2 disabled:opacity-60"
              style={{ borderColor: "var(--border-accent)", color: "var(--text-primary)" }}
            >
              {busy && <Loader2 size={14} className="animate-spin" />}
              {busy ? "authenticating" : "[ENTER] authenticate"}
            </button>

            <div className="pt-2 border-t" style={{ borderColor: "var(--border-subtle)" }}>
              <div className="text-[10px] font-mono uppercase tracking-widest text-[#565f89] mb-1 flex justify-between">
                <span>cli equivalent</span>
                <button
                  type="button"
                  onClick={() => { navigator.clipboard.writeText(curl); toast.success("Copied"); }}
                  className="hover:text-[#c0caf5] flex items-center gap-1"
                ><Copy size={10} /> copy</button>
              </div>
              <pre data-testid={AUTH.cliSnippet} className="font-mono text-[10px] leading-relaxed bg-[#15161e] border rounded-sm p-3 whitespace-pre-wrap break-all" style={{ borderColor: "var(--border-subtle)", color: "var(--text-secondary)" }}>
{curl}
              </pre>
            </div>
          </form>
        </div>

        <div className="mt-4 text-[10px] font-mono text-[#565f89] text-center leading-relaxed">
          seeded admin // admin@secmaster.io / admin1234
        </div>
      </div>
    </div>
  );
}
