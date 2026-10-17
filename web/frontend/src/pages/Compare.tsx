import { useEffect, useState } from "react";
import { GitCompareArrows, Check } from "lucide-react";
import { api } from "../lib/api";
import type { Scan } from "../lib/api";
import { PageHeader, PageWrap, Btn, Spinner, EmptyState, fmtDateShort, SevBadge } from "../components/ui";

export default function Compare() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [picked, setPicked] = useState<string[]>([]);
  const [result, setResult] = useState<{ new: string[]; fixed: string[]; persisting: string[]; scans: Scan[] } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { api.listScans().then(setScans).catch(() => {}).finally(() => setLoading(false)); }, []);

  const toggle = (id: string) => setPicked(p =>
    p.includes(id) ? p.filter(x => x !== id) : p.length >= 4 ? p : [...p, id]);

  const run = async () => {
    if (picked.length < 2) return;
    setBusy(true);
    try { setResult(await api.compareScans(picked)); }
    catch (e: any) { alert(e.message); } finally { setBusy(false); }
  };

  const cols = [
    { id: "new", label: "New", desc: "Appeared since the baseline", tint: "text-rose-600 dark:text-rose-400", bg: "bg-rose-50 dark:bg-rose-500/10 border-rose-200 dark:border-rose-500/20" },
    { id: "persisting", label: "Persisting", desc: "Still present", tint: "text-amber-600 dark:text-amber-400", bg: "bg-amber-50 dark:bg-amber-500/10 border-amber-200 dark:border-amber-500/20" },
    { id: "fixed", label: "Fixed", desc: "Gone since the baseline", tint: "text-emerald-600 dark:text-emerald-400", bg: "bg-emerald-50 dark:bg-emerald-500/10 border-emerald-200 dark:border-emerald-500/20" },
  ] as const;

  return (
    <PageWrap wide>
      <PageHeader icon={<GitCompareArrows className="h-6 w-6 text-white" />} title="Compare scans" sub="Diff 2–4 scans: new, fixed, persisting findings" />

      <div className="glass rounded-3xl p-6 mb-6">
        <h3 className="text-sm font-extrabold text-slate-900 dark:text-white mb-1">Select scans ({picked.length}/4)</h3>
        <p className="text-xs text-slate-500 dark:text-slate-400 mb-4">The oldest selected scan is the baseline.</p>
        {loading ? <Spinner /> : (
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-2.5 max-h-72 overflow-y-auto">
            {scans.map(s => {
              const on = picked.includes(s.id);
              return (
                <button key={s.id} onClick={() => toggle(s.id)}
                  className={`flex items-center gap-3 p-3.5 rounded-2xl border-2 text-left transition-all ${on ? "border-indigo-500 bg-indigo-50/60 dark:bg-indigo-500/10" : "border-slate-100 dark:border-white/5 hover:border-slate-200 dark:hover:border-white/15"}`}>
                  <span className={`flex h-6 w-6 items-center justify-center rounded-lg shrink-0 ${on ? "bg-indigo-600 text-white" : "bg-slate-100 dark:bg-white/10 text-transparent"}`}>
                    <Check className="h-4 w-4" />
                  </span>
                  <span className="min-w-0">
                    <span className="block font-mono text-xs font-bold text-slate-800 dark:text-slate-100 truncate">{s.target}</span>
                    <span className="block text-[11px] text-slate-400">{fmtDateShort(s.created_at)} · {s.total_findings ?? s.finding_count ?? 0} findings</span>
                  </span>
                </button>
              );
            })}
          </div>
        )}
        <div className="flex justify-end mt-4">
          <Btn onClick={run} disabled={picked.length < 2 || busy}>
            <GitCompareArrows className="h-4 w-4" /> {busy ? "Comparing…" : "Compare"}
          </Btn>
        </div>
      </div>

      {result && (
        <div className="grid md:grid-cols-3 gap-4 items-start">
          {cols.map(c => {
            const ids: string[] = (result as any)[c.id] || [];
            const fmap = new Map<string, any>();
            result.scans.forEach(s => (s.findings || []).forEach(f => fmap.set(f.id, f)));
            return (
              <div key={c.id} className={`rounded-3xl border-2 ${c.bg} p-4`}>
                <div className="flex items-center justify-between px-1 mb-3">
                  <span className={`text-xs font-extrabold uppercase tracking-wider ${c.tint}`}>{c.label} — {c.desc}</span>
                  <span className={`text-sm font-black ${c.tint}`}>{ids.length}</span>
                </div>
                <div className="space-y-2">
                  {ids.map(id => { const f = fmap.get(id); return (
                    <div key={id} className="bg-white dark:bg-slate-900 rounded-2xl p-3.5">
                      {f ? (<>
                        <div className="flex items-center gap-2 mb-1"><SevBadge sev={f.severity} /><span className="text-xs font-bold text-slate-800 dark:text-slate-100">{f.type}</span></div>
                        <div className="font-mono text-[11px] text-slate-500 dark:text-slate-400 truncate">{f.url}</div>
                      </>) : <span className="font-mono text-xs text-slate-400">{id.slice(0, 12)}…</span>}
                    </div>); })}
                  {ids.length === 0 && <p className="text-center text-xs text-slate-400 py-6">None</p>}
                </div>
              </div>
            );
          })}
        </div>
      )}
      {!result && !loading && <EmptyState title="Pick scans to compare" sub="Select at least two scans above." />}
    </PageWrap>
  );
}
