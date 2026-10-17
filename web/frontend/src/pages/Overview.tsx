import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { LayoutDashboard, Radar, CheckCircle2, AlertTriangle, ShieldCheck, ChevronRight, Clock, Zap, Inbox, TrendingUp, PieChart as PieIcon } from "lucide-react";
import { api } from "../lib/api";
import type { TrendPoint } from "../lib/api";
import { SeverityDonut, TrendChart } from "../components/Charts";

interface Stats {
  total_scans: number; active_scans: number; completed_scans: number;
  open_findings: number; severity_counts: Record<string, number>;
  security_score: number; recent_scans: any[]; recent_findings: any[];
}

function scoreColor(s: number) {
  return s >= 80 ? "text-emerald-600" : s >= 50 ? "text-amber-600" : "text-rose-600";
}
function scoreRing(s: number) {
  const c = s >= 80 ? "#10b981" : s >= 50 ? "#f59e0b" : "#f43f5e";
  const r = 54, circ = 2 * Math.PI * r;
  return { c, dash: `${(s / 100) * circ} ${circ}` };
}

export default function Overview() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [loading, setLoading] = useState(true);
  const [trends, setTrends] = useState<TrendPoint[]>([]);

  useEffect(() => {
    fetch("/api/dashboard/stats", { headers: { Authorization: "Bearer " + localStorage.getItem("sx_token") } })
      .then(r => r.json()).then(setStats).catch(() => {}).finally(() => setLoading(false));
    api.trends(30).then(setTrends).catch(() => {});
  }, []);

  if (loading) return (
    <div className="min-h-[calc(100vh-4rem)] px-4 sm:px-6 py-10 bg-slate-50 dark:bg-white/5">
      <div className="mx-auto max-w-6xl space-y-4">
        <div className="shimmer rounded-3xl h-16 w-64" />
        <div className="grid sm:grid-cols-4 gap-4">{[1,2,3,4].map(i => <div key={i} className="shimmer rounded-3xl h-32" />)}</div>
        <div className="shimmer rounded-3xl h-64" />
      </div>
    </div>
  );

  if (!stats) return (
    <div className="min-h-[calc(100vh-4rem)] flex items-center justify-center px-4">
      <div className="text-center"><p className="text-slate-500 dark:text-slate-400">Could not load dashboard.</p></div>
    </div>
  );

  const { c, dash } = scoreRing(stats.security_score);
  const cards = [
    { icon: Radar, label: "Total scans", val: stats.total_scans, bg: "bg-indigo-100", tc: "text-indigo-600" },
    { icon: Zap, label: "Active now", val: stats.active_scans, bg: "bg-blue-100", tc: "text-blue-600" },
    { icon: CheckCircle2, label: "Completed", val: stats.completed_scans, bg: "bg-emerald-100", tc: "text-emerald-600" },
    { icon: AlertTriangle, label: "Open findings", val: stats.open_findings, bg: "bg-rose-100", tc: "text-rose-600" },
  ];

  return (
    <div className="min-h-[calc(100vh-4rem)] px-4 sm:px-6 py-10 bg-slate-50 dark:bg-white/5">
      <div className="mx-auto max-w-6xl">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="flex flex-wrap items-center gap-3 mb-8">
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-500 shadow-lg shadow-indigo-500/25">
            <LayoutDashboard className="h-6 w-6 text-white" />
          </div>
          <div className="flex-1">
            <h1 className="text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight">Security overview</h1>
            <p className="text-sm text-slate-500 dark:text-slate-400">What's happening with your security right now.</p>
          </div>
          <Link to="/dashboard" className="inline-flex items-center gap-2 px-6 py-3 rounded-xl text-white text-sm font-semibold bg-gradient-to-r from-indigo-600 to-violet-600 shadow-lg shadow-indigo-600/25 hover:-translate-y-0.5 transition-all">
            <Radar className="h-4 w-4" />New scan
          </Link>
        </motion.div>

        {/* stat cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          {cards.map((cd, i) => (
            <motion.div key={cd.label} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.07 }}
              className="glass card-hover rounded-3xl p-6">
              <div className={`inline-flex h-10 w-10 items-center justify-center rounded-xl ${cd.bg} mb-3`}>
                <cd.icon className={`h-5 w-5 ${cd.tc}`} />
              </div>
              <div className="text-3xl font-black text-slate-900 dark:text-white">{cd.val}</div>
              <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 dark:text-slate-500 mt-1">{cd.label}</div>
            </motion.div>
          ))}
        </div>

        <div className="grid lg:grid-cols-3 gap-4 mb-6">
          {/* security score */}
          <motion.div initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
            className="glass rounded-3xl p-7 flex items-center gap-6">
            <div className="relative h-32 w-32 shrink-0">
              <svg viewBox="0 0 128 128" className="h-full w-full -rotate-90">
                <circle cx="64" cy="64" r="54" fill="none" stroke="#e2e8f0" strokeWidth="12" />
                <circle cx="64" cy="64" r="54" fill="none" stroke={c} strokeWidth="12" strokeLinecap="round"
                  strokeDasharray={dash} className="transition-all duration-1000" />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className={`text-3xl font-black ${scoreColor(stats.security_score)}`}>{stats.security_score}</span>
                <span className="text-[10px] font-bold text-slate-400 dark:text-slate-500">/ 100</span>
              </div>
            </div>
            <div>
              <h3 className="font-bold text-slate-900 dark:text-white mb-1 flex items-center gap-2"><ShieldCheck className="h-4 w-4 text-emerald-500" />Security posture</h3>
              <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">Weighted by severity across all open findings. Critical −25, High −10, Medium −4, Low −1.</p>
            </div>
          </motion.div>

          {/* severity distribution */}
          <motion.div initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.16 }}
            className="glass rounded-3xl p-7 lg:col-span-2">
            <h3 className="font-bold text-slate-900 dark:text-white mb-4">Findings by severity</h3>
            <div className="space-y-3">
              {(["critical", "high", "medium", "low", "info"] as const).map(s => {
                const n = stats.severity_counts[s] || 0;
                const max = Math.max(1, ...Object.values(stats.severity_counts));
                return (
                  <div key={s} className="flex items-center gap-3">
                    <span className={`sev-${s} w-20 text-center text-[11px] font-extrabold uppercase px-2 py-1 rounded-lg shrink-0`}>{s}</span>
                    <div className="flex-1 h-2.5 rounded-full bg-slate-100 dark:bg-white/10 overflow-hidden">
                      <motion.div initial={{ width: 0 }} animate={{ width: `${(n / max) * 100}%` }} transition={{ delay: 0.3, duration: 0.6 }}
                        className={`h-full rounded-full ${s === "critical" ? "bg-rose-500" : s === "high" ? "bg-orange-500" : s === "medium" ? "bg-amber-400" : s === "low" ? "bg-sky-500" : "bg-slate-400"}`} />
                    </div>
                    <span className="w-8 text-right font-bold text-slate-700 dark:text-slate-200 text-sm">{n}</span>
                  </div>
                );
              })}
            </div>
          </motion.div>
        </div>

        <div className="grid lg:grid-cols-2 gap-4 mb-6">
          {/* severity donut */}
          <motion.div initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.18 }}
            className="glass rounded-3xl p-7">
            <h3 className="font-bold text-slate-900 dark:text-white mb-2 flex items-center gap-2"><PieIcon className="h-4 w-4 text-indigo-500" />Severity distribution</h3>
            <SeverityDonut counts={stats.severity_counts} />
          </motion.div>

          {/* trend chart */}
          <motion.div initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.22 }}
            className="glass rounded-3xl p-7">
            <h3 className="font-bold text-slate-900 dark:text-white mb-2 flex items-center gap-2"><TrendingUp className="h-4 w-4 text-violet-500" />Findings trend — 30 days</h3>
            <TrendChart data={trends} />
          </motion.div>
        </div>

        <div className="grid lg:grid-cols-2 gap-4">
          {/* recent scans */}
          <motion.div initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
            className="glass rounded-3xl p-7">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-bold text-slate-900 dark:text-white flex items-center gap-2"><Clock className="h-4 w-4 text-slate-400 dark:text-slate-500" />Recent scans</h3>
              <Link to="/history" className="text-xs font-semibold text-indigo-600 hover:text-indigo-700">View all →</Link>
            </div>
            {stats.recent_scans.length === 0 ? (
              <div className="text-center py-8 text-sm text-slate-400 dark:text-slate-500">
                <Inbox className="mx-auto h-8 w-8 text-slate-300 mb-2" />No scans yet.
              </div>
            ) : stats.recent_scans.map(s => (
              <Link key={s.id} to={`/findings/${s.id}`} className="flex items-center gap-3 py-2.5 border-b border-slate-100 dark:border-white/5 last:border-0 group">
                <span className="truncate flex-1 font-mono text-xs text-slate-700 dark:text-slate-200 group-hover:text-indigo-700">{s.target}</span>
                <span className="text-[10px] font-bold uppercase px-2 py-0.5 rounded-full bg-slate-100 dark:bg-white/10 text-slate-500 dark:text-slate-400">{s.status}</span>
                <ChevronRight className="h-4 w-4 text-slate-300" />
              </Link>
            ))}
          </motion.div>

          {/* recent findings */}
          <motion.div initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.26 }}
            className="glass rounded-3xl p-7">
            <div className="flex items-center justify-between mb-4">
              <h3 className="font-bold text-slate-900 dark:text-white flex items-center gap-2"><AlertTriangle className="h-4 w-4 text-slate-400 dark:text-slate-500" />Latest findings</h3>
              <Link to="/findings" className="text-xs font-semibold text-indigo-600 hover:text-indigo-700">View all →</Link>
            </div>
            {stats.recent_findings.length === 0 ? (
              <div className="text-center py-8 text-sm text-slate-400 dark:text-slate-500">
                <ShieldCheck className="mx-auto h-8 w-8 text-emerald-300 mb-2" />No findings — clean so far.
              </div>
            ) : stats.recent_findings.slice(0, 6).map(f => (
              <Link key={f.id} to={`/findings/${f.scan_id}`} className="flex items-center gap-3 py-2.5 border-b border-slate-100 dark:border-white/5 last:border-0 group">
                <span className={`sev-${f.severity} text-[10px] font-extrabold uppercase px-2 py-0.5 rounded-md shrink-0`}>{f.severity}</span>
                <span className="truncate flex-1 text-xs font-medium text-slate-700 dark:text-slate-200 group-hover:text-indigo-700">{f.type}</span>
              </Link>
            ))}
          </motion.div>
        </div>
      </div>
    </div>
  );
}
