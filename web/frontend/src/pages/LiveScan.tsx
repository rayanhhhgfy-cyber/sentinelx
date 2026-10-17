import { useEffect, useRef, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Radar, Square, ArrowRight, Activity, AlertTriangle, CircleDot, Pause, Play, Share2 } from "lucide-react";
import { api, scanEvents, continueScan } from "../lib/api";
import type { Finding } from "../lib/api";
import { Btn } from "../components/ui";
import { ShareDialog, ScanComments } from "../components/dialogs";

interface LogLine { text: string; color: string; }

export default function LiveScan() {
  const { id } = useParams<{ id: string }>();
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [done, setDone] = useState(false);
  const [paused, setPaused] = useState(false);
  const [shareOpen, setShareOpen] = useState(false);
  const termRef = useRef<HTMLDivElement>(null);

  const push = (text: string, color = "text-slate-400 dark:text-slate-500") =>
    setLogs(p => [...p.slice(-300), { text, color }]);

  useEffect(() => {
    if (!id) return;
    let alive = true;
    let lastSeq = 0;
    let pumping = false;
    push("◈ live polling started (2s)…");
    const seenIds = new Set<string>();
    const tick = async () => {
      if (!alive || pumping) return;
      pumping = true;
      try {
        const ev = await scanEvents(id, lastSeq);
        for (const m of ev.events) {
          lastSeq = Math.max(lastSeq, m.seq);
          if (m.type === "progress") push("… " + String(m.data));
          else if (m.type === "finding") {
            const d = m.data;
            if (!seenIds.has(String(d.db_id ?? d.id))) {
              seenIds.add(String(d.db_id ?? d.id));
              setFindings(f => [...f, d as Finding]);
              push(`● [${String(d.severity).toUpperCase()}] ${d.type} — ${d.url}`, "text-rose-400");
            }
          } else if (m.type === "done") {
            push(`✓ scan ${m.data.status}: ${m.data.findings ?? ""} findings`, "text-emerald-400");
            if (m.data.status !== "running") setDone(true);
          }
        }
        // chunked serverless scans: trigger the next chunk when ready
        const s = await api.getScan(id);
        if (!alive) return;
        if (s.status === "chunk_done") {
          push("◈ chunk complete — requesting next…");
          const r = await continueScan(id);
          if (r.status === "completed" || r.status === "failed" || r.status === "cancelled") setDone(true);
        } else if (["completed", "failed", "cancelled"].includes(s.status)) {
          // final findings refresh for accuracy
          try {
            const all = await api.listFindings(id);
            if (Array.isArray(all)) {
              setFindings(all);
              all.forEach(f => seenIds.add(String((f as any)._db_id ?? f.id)));
            }
          } catch { /* keep streamed findings */ }
          setDone(true);
        }
      } catch (e: any) {
        push("✗ poll error: " + String(e.message || e).slice(0, 120), "text-rose-400");
      } finally {
        pumping = false;
      }
    };
    tick();
    const iv = setInterval(tick, 2000);
    return () => { alive = false; clearInterval(iv); };
  }, [id]);

  useEffect(() => { termRef.current?.scrollTo(0, termRef.current.scrollHeight); }, [logs]);

  const cancel = async () => {
    if (id) { try { await api.cancelScan(id); push("■ cancel requested", "text-amber-400"); } catch (e: any) { push(e.message, "text-rose-400"); } }
  };
  const togglePause = async () => {
    if (!id) return;
    try {
      if (paused) { await api.resumeScan(id); push("▶ scan resumed", "text-emerald-400"); }
      else { await api.pauseScan(id); push("⏸ scan paused", "text-amber-400"); }
      setPaused(!paused);
    } catch (e: any) { push(e.message, "text-rose-400"); }
  };

  const crit = findings.filter(f => f.severity === "critical").length;
  const high = findings.filter(f => f.severity === "high").length;

  return (
    <div className="min-h-[calc(100vh-4rem)] px-4 sm:px-6 py-10 bg-slate-50 dark:bg-transparent">
      <div className="mx-auto max-w-5xl">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          className="flex flex-wrap items-center gap-3 mb-8">
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-500 shadow-lg shadow-indigo-500/25">
            <Radar className="h-6 w-6 text-white" />
          </div>
          <h1 className="flex-1 text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight">Live scan</h1>
          {!done && (
            <span className={`flex items-center gap-2 px-4 py-2 rounded-full border text-sm font-semibold ${paused ? "bg-amber-50 dark:bg-amber-500/10 border-amber-200 dark:border-amber-500/20 text-amber-700 dark:text-amber-300" : "bg-blue-50 dark:bg-blue-500/10 border-blue-200 dark:border-blue-500/20 text-blue-700 dark:text-blue-300"}`}>
              {!paused && (
                <span className="relative flex h-2.5 w-2.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-blue-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-blue-500" />
                </span>
              )}
              {paused ? "Paused" : "Scanning"}
            </span>
          )}
          {done && (
            <span className="flex items-center gap-2 px-4 py-2 rounded-full bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/20 text-sm font-semibold text-emerald-700 dark:text-emerald-300">
              <CircleDot className="h-4 w-4" />Complete
            </span>
          )}
          {!done && (
            <>
              <Btn variant="outline" onClick={togglePause} className="!py-2.5">
                {paused ? <><Play className="h-4 w-4" /> Resume</> : <><Pause className="h-4 w-4" /> Pause</>}
              </Btn>
              <button onClick={cancel} className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold text-rose-700 dark:text-rose-400 bg-rose-50 dark:bg-rose-500/10 border border-rose-200 dark:border-rose-500/20 hover:bg-rose-100 dark:hover:bg-rose-500/20 transition-colors">
                <Square className="h-4 w-4" />Cancel
              </button>
            </>
          )}
          <Btn variant="ghost" onClick={() => setShareOpen(true)} className="!py-2.5"><Share2 className="h-4 w-4" /> Share</Btn>
          <Link to={`/findings/${id}`} className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-semibold text-white bg-gradient-to-r from-indigo-600 to-violet-600 shadow-lg shadow-indigo-600/25 hover:-translate-y-0.5 transition-all">
            Findings ({findings.length})<ArrowRight className="h-4 w-4" />
          </Link>
        </motion.div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
          {[
            { icon: Activity, label: "Findings", val: findings.length, c: "text-indigo-600 bg-indigo-50" },
            { icon: AlertTriangle, label: "Critical", val: crit, c: "text-rose-600 bg-rose-50" },
            { icon: AlertTriangle, label: "High", val: high, c: "text-orange-600 bg-orange-50" },
            { icon: CircleDot, label: "Status", val: done ? "done" : "live", c: "text-emerald-600 bg-emerald-50" },
          ].map((s, i) => (
            <motion.div key={s.label} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.07 }}
              className="glass rounded-2xl p-5 text-center">
              <div className={`mx-auto mb-2 flex h-9 w-9 items-center justify-center rounded-xl ${s.c}`}>
                <s.icon className="h-5 w-5" />
              </div>
              <div className="text-2xl font-black text-slate-900 dark:text-white">{s.val}</div>
              <div className="text-[11px] font-bold uppercase tracking-widest text-slate-400 dark:text-slate-500">{s.label}</div>
            </motion.div>
          ))}
        </div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
          <div className="rounded-2xl overflow-hidden shadow-xl shadow-slate-900/10 border border-slate-800">
            <div className="flex items-center gap-2 px-4 py-3 bg-slate-800">
              <span className="h-3 w-3 rounded-full bg-rose-400" /><span className="h-3 w-3 rounded-full bg-amber-400" /><span className="h-3 w-3 rounded-full bg-emerald-400" />
              <span className="ml-2 text-xs font-medium text-slate-400 dark:text-slate-500">scan output — live</span>
            </div>
            <div ref={termRef} className="terminal h-72 overflow-y-auto p-5">
              {logs.map((l, i) => <div key={i} className={l.color}>{l.text}</div>)}
              {!done && <span className="inline-block w-2 h-4 bg-emerald-400 animate-pulse ml-1" />}
            </div>
          </div>
        </motion.div>

        <h2 className="text-lg font-bold text-slate-900 dark:text-white mt-10 mb-4">Findings feed</h2>
        <div className="space-y-2.5">
          <AnimatePresence>
            {findings.map(f => (
              <motion.div key={f.id} initial={{ opacity: 0, x: -30, scale: 0.98 }} animate={{ opacity: 1, x: 0, scale: 1 }}
                className="glass rounded-2xl p-4 flex items-center gap-3">
                <span className={`sev-${f.severity} text-[11px] font-extrabold uppercase tracking-wide px-2.5 py-1 rounded-lg`}>{f.severity}</span>
                <div className="min-w-0 flex-1">
                  <div className="font-semibold text-slate-900 dark:text-white text-sm">{f.type}</div>
                  <div className="truncate font-mono text-xs text-slate-400 dark:text-slate-500">{f.method} {f.url}</div>
                </div>
              </motion.div>
            ))}
          </AnimatePresence>
          {findings.length === 0 && (
            <div className="glass rounded-2xl p-10 text-center text-sm text-slate-400 dark:text-slate-500">
              No findings yet — they stream in live as modules confirm them.
            </div>
          )}
        </div>

        {id && (
          <div className="mt-10">
            <ScanComments scanId={id} />
          </div>
        )}
      </div>
      {id && <ShareDialog scanId={id} open={shareOpen} onClose={() => setShareOpen(false)} />}
    </div>
  );
}
