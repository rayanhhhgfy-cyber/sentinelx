import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Search, X, Copy, Check, Download, Filter, ChevronRight } from "lucide-react";
import { api, SEVS } from "../lib/api";
import type { Finding } from "../lib/api";

export default function Findings() {
  const { id } = useParams<{ id: string }>();
  const [all, setAll] = useState<Finding[]>([]);
  const [q, setQ] = useState(""); const [sevs, setSevs] = useState<string[]>([...SEVS]);
  const [sel, setSel] = useState<Finding | null>(null);
  const [copied, setCopied] = useState(""); const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        if (id) { const s = await api.getScan(id); setAll(s.findings || []); }
        else {
          const r = await fetch("/api/findings", { headers: { Authorization: "Bearer " + localStorage.getItem("sx_token") } });
          setAll(await r.json());
        }
      } catch {} finally { setLoading(false); }
    })();
  }, [id]);

  const toggle = (s: string) => setSevs(p => p.includes(s) ? p.filter(x => x !== s) : [...p, s]);
  const list = all.filter(f => sevs.includes(f.severity) && (f.type + f.url + (f.param || "")).toLowerCase().includes(q.toLowerCase()));
  const copy = (label: string, text: string) => { navigator.clipboard.writeText(text); setCopied(label); setTimeout(() => setCopied(""), 1500); };

  const counts = Object.fromEntries(SEVS.map(s => [s, all.filter(f => f.severity === s).length]));

  return (
    <div className="min-h-[calc(100vh-4rem)] px-4 sm:px-6 py-10 bg-slate-50">
      <div className="mx-auto max-w-6xl">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
          className="flex flex-wrap items-center gap-3 mb-8">
          <h1 className="flex-1 text-3xl font-extrabold text-slate-900 tracking-tight">
            Findings <span className="text-slate-400 font-bold">({list.length})</span>
          </h1>
          {id && ["json", "html", "sarif"].map(fmt => (
            <a key={fmt} href={`/api/scans/${id}/report.${fmt}?token=${localStorage.getItem("sx_token")}`} download
              className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-xl text-sm font-semibold text-slate-600 bg-white border border-slate-200 shadow-sm hover:shadow-md hover:-translate-y-0.5 transition-all uppercase">
              <Download className="h-4 w-4" />{fmt}
            </a>
          ))}
        </motion.div>

        {/* severity filter cards */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-6">
          {SEVS.map((s, i) => (
            <motion.button key={s} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
              onClick={() => toggle(s)}
              className={`rounded-2xl p-4 text-center border-2 transition-all ${sevs.includes(s) ? "bg-white border-indigo-300 shadow-md" : "bg-white/50 border-transparent opacity-40 hover:opacity-70"}`}>
              <div className="text-3xl font-black text-slate-900">{counts[s]}</div>
              <span className={`sev-${s} inline-block mt-1.5 text-[11px] font-extrabold uppercase tracking-wide px-2.5 py-1 rounded-lg`}>{s}</span>
            </motion.button>
          ))}
        </div>

        <div className="relative mb-6 max-w-md">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search findings…"
            className="w-full pl-12 pr-4 py-3.5 rounded-2xl bg-white border border-slate-200 text-slate-900 shadow-sm placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all" />
        </div>

        {loading ? (
          <div className="space-y-3">{[1, 2, 3].map(i => <div key={i} className="shimmer rounded-2xl h-20" />)}</div>
        ) : list.length === 0 ? (
          <div className="glass rounded-3xl p-16 text-center">
            <Filter className="mx-auto h-10 w-10 text-slate-300 mb-3" />
            <p className="text-slate-500 font-medium">No findings match your filters.</p>
          </div>
        ) : (
          <div className="space-y-2.5">
            {list.map((f, i) => (
              <motion.button key={f.id} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: Math.min(i * 0.03, 0.4) }}
                onClick={() => setSel(f)}
                className="w-full text-left glass card-hover rounded-2xl p-5 flex items-center gap-4">
                <span className={`sev-${f.severity} shrink-0 text-[11px] font-extrabold uppercase tracking-wide px-2.5 py-1 rounded-lg`}>{f.severity}</span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-bold text-slate-900">{f.type}</span>
                    <span className="text-xs text-slate-400">{f.subtype}</span>
                  </div>
                  <div className="mt-1 truncate font-mono text-xs text-slate-500">{f.method} {f.url} · CVSS {f.cvss_score}</div>
                </div>
                <ChevronRight className="h-5 w-5 text-slate-300 shrink-0" />
              </motion.button>
            ))}
          </div>
        )}
      </div>

      {/* detail slide-over */}
      <AnimatePresence>
        {sel && (
          <>
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
              onClick={() => setSel(null)} className="fixed inset-0 z-40 bg-slate-900/30 backdrop-blur-sm" />
            <motion.aside
              initial={{ x: "100%" }} animate={{ x: 0 }} exit={{ x: "100%" }}
              transition={{ type: "spring", damping: 30, stiffness: 300 }}
              className="fixed top-0 right-0 bottom-0 z-50 w-full max-w-xl bg-white shadow-2xl overflow-y-auto">
              <div className="sticky top-0 bg-white/90 backdrop-blur-xl border-b border-slate-100 px-6 py-5 flex items-center gap-3">
                <span className={`sev-${sel.severity} text-[11px] font-extrabold uppercase tracking-wide px-2.5 py-1 rounded-lg`}>{sel.severity}</span>
                <h2 className="flex-1 text-lg font-extrabold text-slate-900">{sel.type}</h2>
                <button onClick={() => setSel(null)} className="p-2 rounded-xl hover:bg-slate-100 transition-colors"><X className="h-5 w-5 text-slate-500" /></button>
              </div>
              <div className="p-6">
                <p className="text-sm text-slate-600 leading-relaxed bg-slate-50 border border-slate-100 rounded-2xl p-4 mb-6">{sel.evidence.proof}</p>
                <div className="flex flex-wrap gap-2 mb-6 text-xs">
                  <span className="px-3 py-1.5 rounded-full bg-slate-100 font-mono text-slate-600">{sel.cwe}</span>
                  <span className="px-3 py-1.5 rounded-full bg-slate-100 font-mono text-slate-600">{sel.owasp}</span>
                  <span className="px-3 py-1.5 rounded-full bg-indigo-50 text-indigo-700 font-mono">{sel.cvss_vector || "n/a"}</span>
                  <span className="px-3 py-1.5 rounded-full bg-slate-100 text-slate-600">{(sel.confidence * 100) | 0}% confidence</span>
                </div>
                {([["Payload", sel.payload], ["Request", sel.evidence.request_raw], ["Response", sel.evidence.response_raw], ["Reproduce", sel.curl_command]] as const).map(([t, c]) => (
                  <div key={t} className="mb-5">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500">{t}</h4>
                      <button onClick={() => copy(t, c)}
                        className="inline-flex items-center gap-1.5 text-xs font-semibold text-indigo-600 hover:text-indigo-700 px-3 py-1.5 rounded-lg hover:bg-indigo-50 transition-colors">
                        {copied === t ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
                        {copied === t ? "Copied!" : "Copy"}
                      </button>
                    </div>
                    <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-2xl bg-slate-900 text-slate-200 p-4 font-mono text-xs leading-relaxed">{c || "—"}</pre>
                  </div>
                ))}
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-2">Remediation</h4>
                <p className="text-sm text-slate-600 leading-relaxed bg-emerald-50/60 border border-emerald-100 rounded-2xl p-4">{sel.remediation}</p>
              </div>
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}
