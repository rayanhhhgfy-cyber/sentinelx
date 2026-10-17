import { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, Inbox, Loader2, AlertTriangle } from "lucide-react";
import type { ReactNode } from "react";

/* ---------- page header ---------- */
export function PageHeader({ icon, title, sub, actions }: { icon: ReactNode; title: string; sub?: string; actions?: ReactNode }) {
  return (
    <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="flex flex-wrap items-center gap-3 mb-8">
      <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-500 shadow-lg shadow-indigo-500/25 shrink-0">
        {icon}
      </div>
      <div className="flex-1 min-w-0">
        <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight">{title}</h1>
        {sub && <p className="text-slate-500 dark:text-slate-400 text-sm mt-0.5">{sub}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2 w-full sm:w-auto">{actions}</div>}
    </motion.div>
  );
}

export function PageWrap({ children, wide }: { children: ReactNode; wide?: boolean }) {
  return (
    <div className="min-h-[calc(100vh-4rem)] px-4 sm:px-6 py-8 sm:py-10 bg-slate-50 dark:bg-transparent pb-24 md:pb-10">
      <div className={`mx-auto ${wide ? "max-w-7xl" : "max-w-5xl"}`}>{children}</div>
    </div>
  );
}

/* ---------- buttons ---------- */
export function Btn({ children, onClick, variant = "primary", className = "", disabled, type = "button" }: {
  children: ReactNode; onClick?: () => void; variant?: "primary"|"ghost"|"danger"|"outline"|"success";
  className?: string; disabled?: boolean; type?: "button"|"submit";
}) {
  const v = {
    primary: "text-white bg-gradient-to-r from-indigo-600 to-violet-600 hover:from-indigo-500 hover:to-violet-500 shadow-lg shadow-indigo-600/25",
    ghost: "text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-white/10",
    danger: "text-rose-600 dark:text-rose-400 hover:bg-rose-50 dark:hover:bg-rose-500/10",
    outline: "text-slate-700 dark:text-slate-200 bg-white dark:bg-white/5 border border-slate-200 dark:border-white/10 shadow-sm hover:shadow-md",
    success: "text-white bg-gradient-to-r from-emerald-600 to-teal-600 shadow-lg shadow-emerald-600/25",
  }[variant];
  return (
    <motion.button type={type} whileTap={{ scale: 0.97 }} onClick={onClick} disabled={disabled}
      className={`inline-flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold transition-all hover:-translate-y-0.5 disabled:opacity-50 disabled:pointer-events-none ${v} ${className}`}>
      {children}
    </motion.button>
  );
}

/* ---------- form fields ---------- */
export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block">
      <span className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">{label}</span>
      <div className="mt-1.5">{children}</div>
      {hint && <p className="mt-1 text-xs text-slate-400 dark:text-slate-500">{hint}</p>}
    </label>
  );
}
export const inputCls = "w-full px-4 py-3 rounded-xl bg-slate-50 dark:bg-white/5 border border-slate-200 dark:border-white/10 text-slate-900 dark:text-white text-sm placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-all";
export function TextInput(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={`${inputCls} ${props.className || ""}`} />;
}
export function TextArea(props: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea {...props} className={`${inputCls} ${props.className || ""}`} />;
}
export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={`${inputCls} ${props.className || ""}`} />;
}

/* ---------- modal ---------- */
export function Modal({ open, onClose, title, children, wide }: { open: boolean; onClose: () => void; title: string; children: ReactNode; wide?: boolean }) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    if (open) window.addEventListener("keydown", h);
    return () => window.removeEventListener("keydown", h);
  }, [open, onClose]);
  return (
    <AnimatePresence>
      {open && (
        <>
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
            onClick={onClose} className="fixed inset-0 z-[60] bg-slate-900/40 dark:bg-black/60 backdrop-blur-sm" />
          <div className="fixed inset-0 z-[61] flex items-end sm:items-center justify-center p-0 sm:p-6 pointer-events-none">
            <motion.div initial={{ y: 60, opacity: 0, scale: 0.98 }} animate={{ y: 0, opacity: 1, scale: 1 }} exit={{ y: 60, opacity: 0, scale: 0.98 }}
              transition={{ type: "spring", damping: 28, stiffness: 320 }}
              className={`pointer-events-auto w-full ${wide ? "max-w-3xl" : "max-w-lg"} max-h-[92vh] overflow-y-auto glass rounded-t-3xl sm:rounded-3xl p-6 sm:p-8`}>
              <div className="flex items-center gap-3 mb-6">
                <h3 className="flex-1 text-lg font-extrabold text-slate-900 dark:text-white">{title}</h3>
                <button onClick={onClose} className="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-white/10 transition-colors" aria-label="Close">
                  <X className="h-5 w-5 text-slate-500" />
                </button>
              </div>
              {children}
            </motion.div>
          </div>
        </>
      )}
    </AnimatePresence>
  );
}

export function Confirm({ open, onClose, onYes, title, body, danger }: {
  open: boolean; onClose: () => void; onYes: () => void; title: string; body: string; danger?: boolean;
}) {
  return (
    <Modal open={open} onClose={onClose} title={title}>
      <div className="flex items-start gap-3 mb-6">
        <div className={`p-2.5 rounded-xl shrink-0 ${danger ? "bg-rose-100 dark:bg-rose-500/15" : "bg-amber-100 dark:bg-amber-500/15"}`}>
          <AlertTriangle className={`h-5 w-5 ${danger ? "text-rose-600 dark:text-rose-400" : "text-amber-600 dark:text-amber-400"}`} />
        </div>
        <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed pt-1.5">{body}</p>
      </div>
      <div className="flex justify-end gap-2">
        <Btn variant="ghost" onClick={onClose}>Cancel</Btn>
        <Btn variant={danger ? "danger" : "primary"} onClick={() => { onYes(); onClose(); }}>Confirm</Btn>
      </div>
    </Modal>
  );
}

/* ---------- misc ---------- */
export function EmptyState({ icon, title, sub, action }: { icon?: ReactNode; title: string; sub?: string; action?: ReactNode }) {
  return (
    <div className="glass rounded-3xl p-12 sm:p-16 text-center">
      <div className="mx-auto mb-4 text-slate-300 dark:text-slate-600">{icon || <Inbox className="mx-auto h-12 w-12" />}</div>
      <p className="text-slate-700 dark:text-slate-200 font-bold">{title}</p>
      {sub && <p className="text-sm text-slate-500 dark:text-slate-400 mt-1">{sub}</p>}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}
export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2.5 py-16 text-slate-500 dark:text-slate-400">
      <Loader2 className="h-6 w-6 animate-spin text-indigo-500" />
      <span className="text-sm font-medium">{label || "Loading…"}</span>
    </div>
  );
}
export function SevBadge({ sev, className = "" }: { sev: string; className?: string }) {
  return <span className={`sev-${sev} shrink-0 text-[11px] font-extrabold uppercase tracking-wide px-2.5 py-1 rounded-lg ${className}`}>{sev}</span>;
}
export function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open: "bg-rose-50 dark:bg-rose-500/10 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-500/20",
    in_progress: "bg-amber-50 dark:bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-500/20",
    resolved: "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-500/20",
    verified: "bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-500/20",
    false_positive: "bg-slate-100 dark:bg-white/10 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-white/10",
    accepted_risk: "bg-violet-50 dark:bg-violet-500/10 text-violet-700 dark:text-violet-300 border-violet-200 dark:border-violet-500/20",
    done: "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-500/20",
    running: "bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-500/20",
    paused: "bg-amber-50 dark:bg-amber-500/10 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-500/20",
  };
  const cls = map[status] || map.open;
  return <span className={`inline-block text-[11px] font-bold uppercase tracking-wide px-2.5 py-1 rounded-full border ${cls}`}>{status.replace(/_/g, " ")}</span>;
}
export function StatCard({ label, value, icon, tint, delay = 0, onClick }: {
  label: string; value: ReactNode; icon: ReactNode; tint: string; delay?: number; onClick?: () => void;
}) {
  return (
    <motion.button initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay }}
      onClick={onClick} disabled={!onClick}
      className={`glass card-hover rounded-2xl p-5 text-left ${onClick ? "cursor-pointer" : "cursor-default"}`}>
      <div className={`inline-flex p-2.5 rounded-xl mb-3 ${tint}`}>{icon}</div>
      <div className="text-2xl sm:text-3xl font-black text-slate-900 dark:text-white">{value}</div>
      <div className="text-xs font-semibold text-slate-500 dark:text-slate-400 mt-1 uppercase tracking-wide">{label}</div>
    </motion.button>
  );
}
export const fmtDate = (ts?: number) => ts ? new Date(ts * 1000).toLocaleString() : "—";
export const fmtDateShort = (ts?: number) => ts ? new Date(ts * 1000).toLocaleDateString() : "—";
