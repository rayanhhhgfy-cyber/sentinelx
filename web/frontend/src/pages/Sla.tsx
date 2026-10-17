import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { AlarmClock, Flame } from "lucide-react";
import { api } from "../lib/api";
import type { Finding } from "../lib/api";
import { PageHeader, PageWrap, Spinner, EmptyState, SevBadge } from "../components/ui";
import FindingDetail from "../components/FindingDetail";

type Row = Finding & { days_overdue: number };

export default function Sla() {
  const [list, setList] = useState<Row[]>([]);
  const [loading, setLoading] = useState(true);
  const [sel, setSel] = useState<Finding | null>(null);

  useEffect(() => { api.slaOverdue().then(setList).catch(() => {}).finally(() => setLoading(false)); }, []);

  const badge = (d: number) =>
    d >= 30 ? "bg-rose-100 dark:bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-500/25"
    : d >= 7 ? "bg-amber-100 dark:bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-500/25"
    : "bg-blue-50 dark:bg-blue-500/10 text-blue-700 dark:text-blue-300 border-blue-200 dark:border-blue-500/20";

  return (
    <PageWrap wide>
      <PageHeader icon={<AlarmClock className="h-6 w-6 text-white" />} title="SLA breaches" sub="Open findings past their remediation deadline" />
      {loading ? <Spinner /> : list.length === 0 ? (
        <EmptyState icon={<Flame className="mx-auto h-12 w-12" />} title="All clear" sub="No findings are past their SLA." />
      ) : (
        <div className="space-y-2.5">
          {list.map((f, i) => (
            <motion.button key={f.id} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: Math.min(i * 0.04, 0.4) }}
              onClick={() => setSel(f)} className="w-full text-left glass card-hover rounded-2xl p-5 flex items-center gap-4">
              <SevBadge sev={f.severity} />
              <div className="min-w-0 flex-1">
                <div className="font-bold text-slate-900 dark:text-white text-sm">{f.type} <span className="font-normal text-slate-400">· {f.subtype}</span></div>
                <div className="mt-1 truncate font-mono text-xs text-slate-500 dark:text-slate-400">{f.url}</div>
              </div>
              <span className={`shrink-0 text-[11px] font-extrabold uppercase tracking-wide px-3 py-1.5 rounded-full border ${badge(f.days_overdue)}`}>
                {f.days_overdue}d overdue
              </span>
            </motion.button>
          ))}
        </div>
      )}
      <AnimatePresence>{sel && <FindingDetail finding={sel} onClose={() => setSel(null)} onChanged={() => api.slaOverdue().then(setList).catch(() => {})} />}</AnimatePresence>
    </PageWrap>
  );
}
