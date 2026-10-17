import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { KanbanSquare, ChevronLeft, ChevronRight } from "lucide-react";
import { api } from "../lib/api";
import type { Finding } from "../lib/api";
import { PageHeader, PageWrap, Spinner, EmptyState, SevBadge } from "../components/ui";
import FindingDetail from "../components/FindingDetail";

const COLS = [
  { id: "open", label: "Open", tint: "border-rose-200 dark:border-rose-500/20" },
  { id: "in_progress", label: "In progress", tint: "border-amber-200 dark:border-amber-500/20" },
  { id: "resolved", label: "Resolved", tint: "border-emerald-200 dark:border-emerald-500/20" },
  { id: "verified", label: "Verified", tint: "border-blue-200 dark:border-blue-500/20" },
];

export default function Kanban() {
  const [all, setAll] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [sel, setSel] = useState<Finding | null>(null);

  const load = () => api.listFindings().then(setAll).catch(() => {}).finally(() => setLoading(false));
  useEffect(() => { load(); }, []);

  const statusOf = (f: Finding) => f.status || "open";
  const move = async (f: Finding, dir: 1 | -1) => {
    const order = COLS.map(c => c.id);
    const i = order.indexOf(statusOf(f));
    const ni = Math.min(Math.max(i + dir, 0), order.length - 1);
    if (ni === i) return;
    try {
      await api.setFindingStatus(f.id, order[ni]);
      setAll(p => p.map(x => x.id === f.id ? { ...x, status: order[ni] } : x));
    } catch (e: any) { alert(e.message); }
  };

  return (
    <PageWrap wide>
      <PageHeader icon={<KanbanSquare className="h-6 w-6 text-white" />} title="Kanban" sub="Drag-free triage — move findings through the pipeline" />
      {loading ? <Spinner /> : all.length === 0 ? (
        <EmptyState title="No findings" sub="Run a scan to populate the board." />
      ) : (
        <div className="grid sm:grid-cols-2 xl:grid-cols-4 gap-4 items-start">
          {COLS.map(col => {
            const items = all.filter(f => statusOf(f) === col.id);
            return (
              <div key={col.id} className={`rounded-3xl border-2 ${col.tint} bg-white/40 dark:bg-white/[.02] p-3 min-h-[300px]`}>
                <div className="flex items-center justify-between px-2 py-2 mb-2">
                  <span className="text-xs font-extrabold uppercase tracking-wider text-slate-600 dark:text-slate-300">{col.label}</span>
                  <span className="text-xs font-black bg-slate-100 dark:bg-white/10 text-slate-600 dark:text-slate-300 px-2.5 py-1 rounded-full">{items.length}</span>
                </div>
                <div className="space-y-2.5">
                  <AnimatePresence>
                    {items.map(f => (
                      <motion.div key={f.id} layout initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} exit={{ opacity: 0, scale: 0.95 }}
                        className="glass rounded-2xl p-4 cursor-pointer card-hover" onClick={() => setSel(f)}>
                        <div className="flex items-center gap-2 mb-2">
                          <SevBadge sev={f.severity} />
                          <span className="text-[11px] text-slate-400 font-mono truncate">{f.subtype}</span>
                        </div>
                        <div className="text-sm font-bold text-slate-900 dark:text-white mb-1">{f.type}</div>
                        <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400 truncate mb-3">{f.url}</div>
                        <div className="flex justify-between" onClick={e => e.stopPropagation()}>
                          <button onClick={() => move(f, -1)} disabled={col.id === "open"}
                            className="p-1.5 rounded-lg text-slate-400 hover:bg-slate-100 dark:hover:bg-white/10 disabled:opacity-20" aria-label="Move back">
                            <ChevronLeft className="h-4 w-4" />
                          </button>
                          <button onClick={() => move(f, 1)} disabled={col.id === "verified"}
                            className="p-1.5 rounded-lg text-slate-400 hover:bg-slate-100 dark:hover:bg-white/10 disabled:opacity-20" aria-label="Move forward">
                            <ChevronRight className="h-4 w-4" />
                          </button>
                        </div>
                      </motion.div>
                    ))}
                  </AnimatePresence>
                  {items.length === 0 && <p className="text-center text-xs text-slate-300 dark:text-slate-600 py-8">Empty</p>}
                </div>
              </div>
            );
          })}
        </div>
      )}
      <AnimatePresence>{sel && <FindingDetail finding={sel} onClose={() => setSel(null)} onChanged={load} />}</AnimatePresence>
    </PageWrap>
  );
}
