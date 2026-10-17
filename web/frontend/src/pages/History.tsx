import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { History as HistoryIcon, Search, RotateCcw, Trash2, ChevronRight, Inbox } from "lucide-react";
import { api } from "../lib/api";
import type { Scan } from "../lib/api";

export default function History() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [q, setQ] = useState("");
  const nav = useNavigate();
  const load = () => api.listScans().then(setScans).catch(() => {});
  useEffect(() => { load(); }, []);

  const list = scans.filter(s => s.target.toLowerCase().includes(q.toLowerCase()));
  const del = async (id: string) => { if (!confirm("Delete this scan?")) return; await api.deleteScan(id); load(); };
  const rerun = async (id: string) => { const r = await api.rerunScan(id); nav(`/scan/${r.scan_id}`); };

  return (
    <div className="min-h-[calc(100vh-4rem)] px-4 sm:px-6 py-10 bg-slate-50">
      <div className="mx-auto max-w-4xl">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="flex items-center gap-3 mb-8">
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-500 shadow-lg shadow-indigo-500/25">
            <HistoryIcon className="h-6 w-6 text-white" />
          </div>
          <h1 className="text-3xl font-extrabold text-slate-900 tracking-tight">Scan history</h1>
        </motion.div>

        <div className="relative mb-6 max-w-md">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search by target…"
            className="w-full pl-12 pr-4 py-3.5 rounded-2xl bg-white border border-slate-200 shadow-sm placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all" />
        </div>

        {list.length === 0 ? (
          <div className="glass rounded-3xl p-16 text-center">
            <Inbox className="mx-auto h-12 w-12 text-slate-300 mb-4" />
            <p className="text-slate-500 font-medium">No scans yet.</p>
            <Link to="/dashboard" className="mt-4 inline-flex items-center gap-2 px-6 py-3 rounded-xl text-white font-semibold bg-gradient-to-r from-indigo-600 to-violet-600 shadow-lg shadow-indigo-600/25 text-sm">
              Start your first scan
            </Link>
          </div>
        ) : (
          <div className="space-y-3">
            {list.map((s, i) => (
              <motion.div key={s.id} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
                className="glass rounded-2xl p-5 flex flex-wrap items-center gap-3">
                <Link to={`/findings/${s.id}`} className="min-w-0 flex-1 group">
                  <div className="truncate font-mono text-sm font-medium text-slate-900 group-hover:text-indigo-700 transition-colors">{s.target}</div>
                  <div className="mt-1 text-xs text-slate-400">
                    <span className="font-semibold text-slate-500">{s.total_findings ?? s.finding_count ?? 0} findings</span>
                    {" · "}{new Date((s.created_at || 0) * 1000).toLocaleString()}
                  </div>
                </Link>
                <div className="flex items-center gap-2">
                  <Link to={`/findings/${s.id}`} className="p-2.5 rounded-xl text-slate-500 hover:bg-indigo-50 hover:text-indigo-600 transition-colors" title="Open">
                    <ChevronRight className="h-5 w-5" />
                  </Link>
                  <button onClick={() => rerun(s.id)} className="p-2.5 rounded-xl text-slate-500 hover:bg-blue-50 hover:text-blue-600 transition-colors" title="Re-run">
                    <RotateCcw className="h-5 w-5" />
                  </button>
                  <button onClick={() => del(s.id)} className="p-2.5 rounded-xl text-slate-500 hover:bg-rose-50 hover:text-rose-600 transition-colors" title="Delete">
                    <Trash2 className="h-5 w-5" />
                  </button>
                </div>
              </motion.div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
