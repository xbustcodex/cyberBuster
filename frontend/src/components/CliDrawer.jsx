import { useState, useEffect } from "react";
import { Copy, Check, X } from "lucide-react";
import { CLI } from "@/constants/testIds";
import { toast } from "sonner";

/**
 * Slide-over drawer that shows the CLI equivalent for a given UI action.
 * Every page can invoke `openCli({title, command, description})`.
 */
export function CliDrawer({ open, onClose, title, command, description, shell = "bash" }) {
  const [copied, setCopied] = useState(false);
  const [currentShell, setCurrentShell] = useState(shell);

  useEffect(() => setCurrentShell(shell), [shell]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command || "");
      setCopied(true);
      toast.success("Command copied to clipboard");
      setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error("Copy failed");
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50" onClick={onClose}>
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
      <aside
        onClick={(e) => e.stopPropagation()}
        className="absolute right-0 top-0 h-full w-full max-w-xl border-l bg-[#1f2335]/95 backdrop-blur-md enter"
        style={{ borderColor: "var(--border-subtle)" }}
      >
        <header className="flex items-center justify-between border-b px-4 py-3" style={{ borderColor: "var(--border-subtle)" }}>
          <div className="font-mono text-xs uppercase tracking-widest" style={{ color: "var(--purple-analyst)" }}>
            sec-master:~$ cli-mirror
          </div>
          <button data-testid="cli-drawer-close" onClick={onClose} className="p-1 hover:bg-[#292e42] rounded">
            <X size={16} />
          </button>
        </header>

        <div className="p-4 space-y-4">
          <div>
            <div className="text-[10px] uppercase tracking-widest text-[#565f89] font-mono mb-1">Action</div>
            <div className="text-sm font-semibold text-[#c0caf5]">{title}</div>
            {description && <p className="text-xs text-[#a9b1d6] mt-1 leading-relaxed">{description}</p>}
          </div>

          <div className="flex gap-2 border-b" style={{ borderColor: "var(--border-subtle)" }}>
            {["bash", "powershell"].map((s) => (
              <button
                key={s}
                onClick={() => setCurrentShell(s)}
                className={`px-3 py-1.5 text-xs font-mono uppercase tracking-widest border-b-2 -mb-px transition-colors ${
                  currentShell === s
                    ? "border-[#bb9af7] text-[#c0caf5]"
                    : "border-transparent text-[#565f89] hover:text-[#a9b1d6]"
                }`}
              >
                {s}
              </button>
            ))}
          </div>

          <div className="relative">
            <pre
              data-testid={CLI.output}
              className="font-mono text-xs bg-[#15161e] border rounded-sm p-4 pr-16 whitespace-pre-wrap break-all leading-relaxed"
              style={{ borderColor: "var(--border-subtle)", color: "var(--text-primary)" }}
            >
              <span style={{ color: "var(--purple-analyst)" }}>{currentShell === "bash" ? "$ " : "PS> "}</span>
              {command}
            </pre>
            <button
              data-testid={CLI.copy}
              onClick={copy}
              className="absolute right-2 top-2 flex items-center gap-1 px-2 py-1 text-[10px] uppercase tracking-widest font-mono border rounded-sm hover:bg-[#292e42]"
              style={{ borderColor: "var(--border-subtle)", color: "var(--text-secondary)" }}
            >
              {copied ? <Check size={12} /> : <Copy size={12} />} {copied ? "copied" : "copy"}
            </button>
          </div>

          <div className="text-[10px] font-mono text-[#565f89] leading-relaxed">
            Every GUI action in Security Master has a documented CLI equivalent.
            <br />No hidden GUI-only paths.
          </div>
        </div>
      </aside>
    </div>
  );
}
