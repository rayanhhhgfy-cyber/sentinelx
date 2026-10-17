import { useEffect, useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { History as TimelineIcon, Circle } from "lucide-react";
import { api } from "../lib/api";
import type { Finding } from "../lib/api";
import { PageHeader, PageWrap, Spinner, EmptyState, fmtDate, SevBadge, StatusBadge } from "../components/ui";
import FindingDetail from "../components/FindingDetail";

export default function Timeline() {
  const [all, setAll] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [sel, setSel] = useState<Finding | null>(null);

  useEffect(() => { api.listFindings().then(setAll).catch(() => {}).finally(() => setLoading(false)); }, []);

  const groups = useMemo(() => {
    const sorted = [...all].sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
    const m = new Map<string, Finding[]>();
    for (const f of sorted) {
      const d = new Date((f.timestamp || 0) * 1000).toLocaleDateString(undefined, { weekday: "long", month: "long", day: "numeric" });
      if (!m.has(d)) m.set(d, []);
      m.get(d)!.push(f);
    }
    return [...m.entries()];
  }, [all]);

  return (
    <PageWrap>
      <PageHeader icon={<TimelineIcon className="h-6 w-6 text-white" />} title="Timeline" sub="Findings in chronological order" />
      {loading ? <Spinner /> : all.length === 0 ? (
        <EmptyState title="No findings" sub="Run a scan to see the timeline." />
      ) : (
        <div className="space-y-8">
          {groups.map(([day, items]) => (
            <div key={day}>
              <div className="flex items-center gap-3 mb-4">
                <h3 className="text-sm font-extrabold uppercase tracking-wider text-slate-500 dark:text-slate-400">{day}</h3>
                <div className="flex-1 h-px bg-slate-200 dark:bg-white/10" />
                <span className="text-xs font-bold text-slate-400">{items.length}</span>
              </div>
              <div className="relative pl-8 space-y-3 before:absolute before:left-[9px] before:top-2 before:bottom-2 before:w-0.5 before:bg-gradient-to-b before:from-indigo-300 before:via-violet-300 before:to-transparent dark:before:from-indigo-500/40 dark:before:via-violet-500/40">
                {items.map((f, i) => (
                  <motion.button key={f.id} initial={{ opacity: 0, x: -14 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: Math.min(i * 0.04, 0.3) }}
                    onClick={() => setSel(f)}
                    className="relative w-full text-left glass card-hover rounded-2xl p-4 sm:p-5">
                    <Circle className="absolute -left-8 top-6 h-[18px] w-[18px] fill-indigo-500 text-indigo-500" />
                    <div className="flex flex-wrap items-center gap-2 mb-1.5">
                      <SevBadge sev={f.severity} />
                      <StatusBadge status={f.status || "open"} />
                      <span className="text-[11px] text-slate-400 ml-auto">{fmtDate(f.timestamp)}</span>
                    </div>
                    <div className="font-bold text-slate-900 dark:text-white text-sm">{f.type} <span className="font-normal text-slate-400">· {f.subtype}</span></div>
                    <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400 truncate mt-1">{f.method} {f.url}</div>
                  </motion.button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
      <AnimatePresence>{sel && <FindingDetail finding={sel} onClose={() => setSel(null)} />}</AnimatePresence>
    </PageWrap>
  );
}
