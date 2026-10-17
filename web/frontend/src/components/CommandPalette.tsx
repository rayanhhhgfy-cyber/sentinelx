import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Search, Radar, FileWarning, History, LayoutDashboard, Target, Layers, CalendarClock, KeyRound, Bell, Key, ScrollText, Users, GitCompareArrows, Download, Cpu, User, Settings, Moon, LogOut, Plus, Zap } from "lucide-react";

interface Item { label: string; hint?: string; icon: any; run: () => void; group: string; }

export default function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const nav = useNavigate();
  const [q, setQ] = useState("");
  const [idx, setIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);

  const go = (to: string) => { onClose(); nav(to); };
  const items: Item[] = useMemo(() => [
    { label: "New scan wizard", hint: "Start a configured scan", icon: Radar, group: "Actions", run: () => go("/scan/new") },
    { label: "Quick scan", hint: "Fast target-only scan", icon: Zap, group: "Actions", run: () => go("/dashboard") },
    { label: "Add target", icon: Plus, group: "Actions", run: () => go("/targets?action=new") },
    { label: "Go to Overview", icon: LayoutDashboard, group: "Navigate", run: () => go("/overview") },
    { label: "Go to Dashboard", icon: Radar, group: "Navigate", run: () => go("/dashboard") },
    { label: "Go to Findings", icon: FileWarning, group: "Navigate", run: () => go("/findings") },
    { label: "Findings kanban", icon: FileWarning, group: "Navigate", run: () => go("/kanban") },
    { label: "Findings timeline", icon: FileWarning, group: "Navigate", run: () => go("/timeline") },
    { label: "Global search", icon: Search, group: "Navigate", run: () => go("/search") },
    { label: "SLA overdue", icon: FileWarning, group: "Navigate", run: () => go("/sla") },
    { label: "Scan history", icon: History, group: "Navigate", run: () => go("/history") },
    { label: "Compare scans", icon: GitCompareArrows, group: "Navigate", run: () => go("/compare") },
    { label: "Export center", icon: Download, group: "Navigate", run: () => go("/exports") },
    { label: "Targets", icon: Target, group: "Manage", run: () => go("/targets") },
    { label: "Scan templates", icon: Layers, group: "Manage", run: () => go("/templates") },
    { label: "Schedules", icon: CalendarClock, group: "Manage", run: () => go("/schedules") },
    { label: "Auth profiles", icon: KeyRound, group: "Manage", run: () => go("/auth-profiles") },
    { label: "Notifications", icon: Bell, group: "Manage", run: () => go("/notifications") },
    { label: "API keys", icon: Key, group: "Manage", run: () => go("/api-keys") },
    { label: "Audit log", icon: ScrollText, group: "Manage", run: () => go("/audit-log") },
    { label: "Engine stats", icon: Cpu, group: "Manage", run: () => go("/engine") },
    { label: "Profile", icon: User, group: "Account", run: () => go("/profile") },
    { label: "Settings", icon: Settings, group: "Account", run: () => go("/settings") },
    { label: "Toggle dark mode", icon: Moon, group: "Account", run: () => { document.dispatchEvent(new CustomEvent("sx:theme-toggle")); } },
    { label: "Admin users", icon: Users, group: "Account", run: () => go("/admin/users") },
    { label: "Log out", icon: LogOut, group: "Account", run: () => { localStorage.removeItem("sx_token"); location.href = "/login"; } },
    // eslint-disable-next-line react-hooks/exhaustive-deps
  ], []);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return items;
    const score = (s: string) => {
      s = s.toLowerCase(); let si = 0, sc = 0;
      for (const ch of needle) { const i = s.indexOf(ch, si); if (i < 0) return -1; sc += i === si ? 2 : 1; si = i + 1; }
      return sc;
    };
    return items.map(it => ({ it, sc: Math.max(score(it.label), it.hint ? score(it.hint) : -1) }))
      .filter(x => x.sc >= 0).sort((a, b) => b.sc - a.sc).map(x => x.it);
  }, [q, items]);

  useEffect(() => { setQ(""); setIdx(0); if (open) setTimeout(() => inputRef.current?.focus(), 50); }, [open ]);
  useEffect(() => setIdx(0), [q]);
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (!open) return;
      if (e.key === "ArrowDown") { e.preventDefault(); setIdx(i => Math.min(i + 1, filtered.length - 1)); }
      else if (e.key === "ArrowUp") { e.preventDefault(); setIdx(i => Math.max(i - 1, 0)); }
      else if (e.key === "Enter") { e.preventDefault(); filtered[idx]?.run(); }
    };
    window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [open, filtered, idx]);

  let lastGroup = "";
  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            onClick={onClose} className="fixed inset-0 z-[70] bg-slate-900/40 dark:bg-black/60 backdrop-blur-sm" />
          <div className="fixed inset-0 z-[71] flex items-start justify-center px-4 pt-[12vh] pointer-events-none">
            <motion.div initial={{ y: -20, opacity: 0, scale: 0.98 }} animate={{ y: 0, opacity: 1, scale: 1 }} exit={{ y: -20, opacity: 0, scale: 0.98 }}
              transition={{ type: "spring", damping: 30, stiffness: 400 }}
              className="pointer-events-auto w-full max-w-xl glass rounded-3xl overflow-hidden shadow-2xl">
              <div className="flex items-center gap-3 px-5 py-4 border-b border-slate-100 dark:border-white/5">
                <Search className="h-5 w-5 text-slate-400" />
                <input ref={inputRef} value={q} onChange={e => setQ(e.target.value)}
                  placeholder="Type a command or search pages…"
                  className="flex-1 bg-transparent text-slate-900 dark:text-white placeholder:text-slate-400 text-[15px] focus:outline-none" />
                <kbd className="text-[11px] font-mono px-2 py-1 rounded-lg bg-slate-100 dark:bg-white/10 text-slate-500">esc</kbd>
              </div>
              <div className="max-h-[50vh] overflow-y-auto p-2">
                {filtered.length === 0 && <p className="text-center text-sm text-slate-400 py-10">No matches.</p>}
                {filtered.map((it, i) => {
                  const head = it.group !== lastGroup ? it.group : "";
                  lastGroup = it.group;
                  return (
                    <div key={it.label}>
                      {head && <div className="px-4 pt-3 pb-1 text-[11px] font-bold uppercase tracking-wider text-slate-400">{head}</div>}
                      <button onClick={it.run}
                        className={`w-full flex items-center gap-3 px-4 py-3 rounded-2xl text-left transition-colors ${i === idx ? "bg-indigo-50 dark:bg-indigo-500/15" : "hover:bg-slate-50 dark:hover:bg-white/5"}`}>
                        <span className={`p-2 rounded-xl ${i === idx ? "bg-indigo-100 dark:bg-indigo-500/25 text-indigo-600 dark:text-indigo-300" : "bg-slate-100 dark:bg-white/10 text-slate-500"}`}>
                          <it.icon className="h-4 w-4" />
                        </span>
                        <span className="flex-1 min-w-0">
                          <span className="block text-sm font-semibold text-slate-800 dark:text-slate-100">{it.label}</span>
                          {it.hint && <span className="block text-xs text-slate-400 truncate">{it.hint}</span>}
                        </span>
                      </button>
                    </div>
                  );
                })}
              </div>
              <div className="px-5 py-3 border-t border-slate-100 dark:border-white/5 flex items-center gap-4 text-[11px] text-slate-400">
                <span><kbd className="font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-white/10">↑↓</kbd> navigate</span>
                <span><kbd className="font-mono px-1.5 py-0.5 rounded bg-slate-100 dark:bg-white/10">↵</kbd> select</span>
              </div>
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>
  );
}
