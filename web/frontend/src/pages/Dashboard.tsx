import { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Radar, Globe, Gauge, Timer, Layers, ShieldCheck, ArrowRight, Clock, ChevronRight, Loader2 } from "lucide-react";
import { api } from "../lib/api";
import type { Scan } from "../lib/api";
import { useAuth } from "../context/AuthContext";

export default function Dashboard() {
  const { token, ready } = useAuth(); const nav = useNavigate();
  const [target, setTarget] = useState("http://127.0.0.1:5055");
  const [conc, setConc] = useState(30); const [rate, setRate] = useState(10); const [depth, setDepth] = useState(2);
  const [confirm, setConfirm] = useState(false); const [busy, setBusy] = useState(false);
  const [recent, setRecent] = useState<Scan[]>([]);

  useEffect(() => {
    if (!ready) return;
    if (!token) { nav("/login"); return; }
    api.listScans().then(setRecent).catch(() => {});
  }, [token, ready]);

  const start = async () => {
    if (!target.trim()) return;
    if (!confirm) return;
    setBusy(true);
    try {
      const r = await api.startScan({ target: target.trim(), confirm_own: true, concurrency: conc, rate, depth });
      nav(`/scan/${r.scan_id}`);
    } catch (e: any) { alert("Failed: " + e.message); setBusy(false); }
  };

  const statusStyle = (s: string) =>
    s === "done" ? "bg-emerald-50 text-emerald-700 border-emerald-200"
    : s === "running" ? "bg-blue-50 text-blue-700 border-blue-200"
    : "bg-slate-100 text-slate-600 border-slate-200";

  return (
    <div className="mesh-hero min-h-[calc(100vh-4rem)] px-4 sm:px-6 py-10">
      <div className="mx-auto max-w-4xl">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
          <div className="flex items-center gap-3 mb-2">
            <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-500 shadow-lg shadow-indigo-500/25">
              <Radar className="h-6 w-6 text-white" />
            </div>
            <h1 className="text-3xl font-extrabold text-slate-900 tracking-tight">New scan</h1>
          </div>
          <p className="text-slate-500 mb-8 ml-14">Configure and launch a full vulnerability scan.</p>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
          className="glass rounded-[1.75rem] p-7 sm:p-9">
          <label className="block mb-6">
            <span className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-500 mb-2">
              <Globe className="h-4 w-4" />Target URL
            </span>
            <input value={target} onChange={e => setTarget(e.target.value)} placeholder="https://example.com"
              className="w-full px-5 py-4 rounded-2xl bg-slate-50 border border-slate-200 font-mono text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-all" />
          </label>

          <div className="grid sm:grid-cols-3 gap-4 mb-6">
            {[
              { icon: Gauge, label: "Concurrency", val: conc, set: setConc },
              { icon: Timer, label: "Rate (req/s)", val: rate, set: setRate },
              { icon: Layers, label: "Crawl depth", val: depth, set: setDepth },
            ].map(f => (
              <label key={f.label} className="block">
                <span className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-500 mb-2">
                  <f.icon className="h-4 w-4" />{f.label}
                </span>
                <input type="number" value={f.val} onChange={e => f.set(+e.target.value)} min={1}
                  className="w-full px-4 py-3.5 rounded-2xl bg-slate-50 border border-slate-200 text-slate-900 font-semibold focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all" />
              </label>
            ))}
          </div>

          <label className="flex cursor-pointer items-start gap-3.5 p-4 rounded-2xl bg-amber-50/60 border border-amber-200/60 mb-6 hover:bg-amber-50 transition-colors">
            <input type="checkbox" checked={confirm} onChange={e => setConfirm(e.target.checked)}
              className="mt-0.5 h-5 w-5 rounded accent-indigo-600" />
            <span className="text-sm text-slate-700 leading-relaxed">
              <ShieldCheck className="inline h-4 w-4 mr-1.5 text-amber-600 -mt-0.5" />
              I confirm I <strong>own this target</strong> or have explicit written permission to test it.
            </span>
          </label>

          <motion.button whileTap={{ scale: 0.98 }} onClick={start} disabled={busy || !confirm}
            className="inline-flex items-center gap-2 px-8 py-4 rounded-2xl text-white font-semibold bg-gradient-to-r from-indigo-600 to-violet-600 shadow-xl shadow-indigo-600/30 hover:shadow-2xl hover:-translate-y-0.5 transition-all disabled:opacity-40 disabled:transform-none disabled:shadow-none">
            {busy ? <Loader2 className="h-5 w-5 animate-spin" /> : <Radar className="h-5 w-5" />}
            {busy ? "Launching…" : "Start scan"}<ArrowRight className="h-4 w-4" />
          </motion.button>
        </motion.div>

        <div className="mt-10">
          <h2 className="flex items-center gap-2 text-lg font-bold text-slate-900 mb-4">
            <Clock className="h-5 w-5 text-slate-400" />Recent scans
          </h2>
          {recent.length === 0 ? (
            <div className="glass rounded-3xl p-10 text-center text-slate-400 text-sm">No scans yet — launch your first one above.</div>
          ) : (
            <div className="space-y-3">
              {recent.slice(0, 5).map((s, i) => (
                <motion.div key={s.id} initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.06 }}>
                  <Link to={`/findings/${s.id}`} className="glass card-hover rounded-2xl p-5 flex items-center gap-4 group">
                    <div className="min-w-0 flex-1">
                      <div className="truncate font-mono text-sm font-medium text-slate-900">{s.target}</div>
                      <div className="mt-1.5 flex items-center gap-2">
                        <span className={`text-[11px] font-bold uppercase tracking-wide px-2.5 py-1 rounded-full border ${statusStyle(s.status)}`}>{s.status}</span>
                        <span className="text-xs text-slate-400">{s.total_findings ?? s.finding_count ?? 0} findings</span>
                      </div>
                    </div>
                    <ChevronRight className="h-5 w-5 text-slate-300 group-hover:text-indigo-500 group-hover:translate-x-1 transition-all" />
                  </Link>
                </motion.div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
