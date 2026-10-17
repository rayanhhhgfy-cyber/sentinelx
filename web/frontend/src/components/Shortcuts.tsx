import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Modal } from "./ui";
import { Keyboard } from "lucide-react";

const SEQ: Record<string, string> = { d: "/overview", f: "/findings", h: "/history", s: "/dashboard", t: "/targets" };

export function useGlobalShortcuts(opts: { onPalette: () => void; onHelp: () => void }) {
  const nav = useNavigate();
  const [gPending, setGPending] = useState(false);
  useEffect(() => {
    let t: ReturnType<typeof setTimeout>;
    const h = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      const typing = tag === "INPUT" || tag === "TEXTAREA" || (e.target as HTMLElement)?.isContentEditable;
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); opts.onPalette(); return; }
      if (typing) return;
      if (e.key === "?") { opts.onHelp(); return; }
      if (e.key === "g") { setGPending(true); clearTimeout(t); t = setTimeout(() => setGPending(false), 800); return; }
      if (gPending && SEQ[e.key]) { setGPending(false); nav(SEQ[e.key]); }
    };
    window.addEventListener("keydown", h);
    return () => { window.removeEventListener("keydown", h); clearTimeout(t); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [gPending]);
  return gPending;
}

export function ShortcutsHelp({ open, onClose }: { open: boolean; onClose: () => void }) {
  const rows: [string, string][] = [
    ["Ctrl / ⌘ + K", "Command palette"],
    ["g then d", "Go to Overview"],
    ["g then f", "Go to Findings"],
    ["g then h", "Go to History"],
    ["g then s", "New scan"],
    ["g then t", "Go to Targets"],
    ["?", "This help"],
    ["Esc", "Close dialogs"],
  ];
  return (
    <Modal open={open} onClose={onClose} title="Keyboard shortcuts">
      <div className="flex items-center gap-2 mb-4 text-slate-500 dark:text-slate-400 text-sm">
        <Keyboard className="h-4 w-4" /> Navigate SentinelX without touching the mouse.
      </div>
      <div className="space-y-1.5">
        {rows.map(([k, d]) => (
          <div key={k} className="flex items-center justify-between px-4 py-3 rounded-2xl bg-slate-50 dark:bg-white/5 border border-slate-100 dark:border-white/5">
            <span className="text-sm font-medium text-slate-700 dark:text-slate-200">{d}</span>
            <kbd className="font-mono text-xs px-2.5 py-1.5 rounded-lg bg-white dark:bg-white/10 border border-slate-200 dark:border-white/10 text-slate-600 dark:text-slate-300">{k}</kbd>
          </div>
        ))}
      </div>
    </Modal>
  );
}
