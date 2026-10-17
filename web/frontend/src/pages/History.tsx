import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { History as HistoryIcon, Search, RotateCcw, Trash2, ChevronRight, Inbox, Users, Share2 } from "lucide-react";
import { api } from "../lib/api";
import type { Scan } from "../lib/api";
import { PageHeader, PageWrap, Btn, Spinner, EmptyState, StatusBadge } from "../components/ui";
import { ShareDialog, ExportModal } from "../components/dialogs";
import { useAuth } from "../context/AuthContext";

export default function History() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [q, setQ] = useState("");
  const [loading, setLoading] = useState(true);
  const [shareId, setShareId] = useState<string | null>(null);
  const [exp, setExp] = useState<Scan | null>(null);
  const nav = useNavigate();
  const { user } = useAuth();

  const load = () => api.listScans().then(setScans).catch(() => {}).finally(() => setLoading(false));
  useEffect(() => { load(); }, []);

  const mine = scans.filter(s => s.target.toLowerCase().includes(q.toLowerCase()) && !(s.shared_with || []).includes(user?.email || "~~"));
  const shared = scans.filter(s => (s.shared_with || []).includes(user?.email || "~~") && s.target.toLowerCase().includes(q.toLowerCase()));

  const del = async (id: string) => { if (!confirm("Delete this scan?")) return; await api.deleteScan(id); load(); };
  const rerun = async (id: string) => { const r = await api.rerunScan(id); nav(`/scan/${r.scan_id}`); };

  const row = (s: Scan, i: number, canManage: boolean) => (
    <motion.div key={s.id} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
      className="glass rounded-2xl p-5 flex flex-wrap items-center gap-3">
      <Link to={`/findings/${s.id}`} className="min-w-0 flex-1 group">
        <div className="truncate font-mono text-sm font-medium text-slate-900 dark:text-white group-hover:text-indigo-700 dark:group-hover:text-indigo-400 transition-colors">{s.target}</div>
        <div className="mt-1 text-xs text-slate-400 flex items-center gap-2 flex-wrap">
          <span className="font-semibold text-slate-500 dark:text-slate-400">{s.total_findings ?? s.finding_count ?? 0} findings</span>
          {" · "}{new Date((s.created_at || 0) * 1000).toLocaleString()}
          <StatusBadge status={s.status} />
        </div>
      </Link>
      <div className="flex items-center gap-1.5">
        <Link to={`/findings/${s.id}`} className="p-2.5 rounded-xl text-slate-500 dark:text-slate-400 hover:bg-indigo-50 dark:hover:bg-indigo-500/15 hover:text-indigo-600 transition-colors" title="Open">
          <ChevronRight className="h-5 w-5" />
        </Link>
        {canManage && (<>
          <button onClick={() => setExp(s)} className="p-2.5 rounded-xl text-slate-500 dark:text-slate-400 hover:bg-emerald-50 dark:hover:bg-emerald-500/15 hover:text-emerald-600 transition-colors" title="Export">
            <Share2 className="h-5 w-5 rotate-90" />
          </button>
          <button onClick={() => setShareId(s.id)} className="p-2.5 rounded-xl text-slate-500 dark:text-slate-400 hover:bg-violet-50 dark:hover:bg-violet-500/15 hover:text-violet-600 transition-colors" title="Share">
            <Share2 className="h-5 w-5" />
          </button>
          <button onClick={() => rerun(s.id)} className="p-2.5 rounded-xl text-slate-500 dark:text-slate-400 hover:bg-blue-50 dark:hover:bg-blue-500/15 hover:text-blue-600 transition-colors" title="Re-run">
            <RotateCcw className="h-5 w-5" />
          </button>
          <button onClick={() => del(s.id)} className="p-2.5 rounded-xl text-slate-500 dark:text-slate-400 hover:bg-rose-50 dark:hover:bg-rose-500/15 hover:text-rose-600 transition-colors" title="Delete">
            <Trash2 className="h-5 w-5" />
          </button>
        </>)}
      </div>
    </motion.div>
  );

  return (
    <PageWrap>
      <PageHeader icon={<HistoryIcon className="h-6 w-6 text-white" />} title="Scan history" sub={`${mine.length} scans${shared.length ? ` · ${shared.length} shared with you` : ""}`} />

      <div className="relative mb-6 max-w-md">
        <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400" />
        <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search by target…"
          className="w-full pl-12 pr-4 py-3.5 rounded-2xl bg-white dark:bg-white/5 border border-slate-200 dark:border-white/10 shadow-sm placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all" />
      </div>

      {loading ? <Spinner /> : (<>
        {mine.length === 0 && shared.length === 0 ? (
          <EmptyState icon={<Inbox className="mx-auto h-12 w-12" />} title="No scans yet" sub="Launch your first scan."
            action={<Link to="/scan/new"><Btn>Start your first scan</Btn></Link>} />
        ) : (<>
          <div className="space-y-3 mb-10">{mine.map((s, i) => row(s, i, true))}</div>
          {shared.length > 0 && (<>
            <div className="flex items-center gap-2 mb-4">
              <Users className="h-5 w-5 text-violet-500" />
              <h2 className="text-lg font-extrabold text-slate-900 dark:text-white">Shared with me</h2>
            </div>
            <div className="space-y-3">{shared.map((s, i) => row(s, i, false))}</div>
          </>)}
        </>)}
      </>)}

      {shareId && <ShareDialog scanId={shareId} open={!!shareId} onClose={() => { setShareId(null); load(); }} />}
      {exp && <ExportModal scanId={exp.id} target={exp.target} open={!!exp} onClose={() => setExp(null)} />}
    </PageWrap>
  );
}
