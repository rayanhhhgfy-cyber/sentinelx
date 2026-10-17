import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Search, X, Download, Filter, ChevronRight, CheckSquare, Square, Tags, UserPlus, KanbanSquare, History as HistIcon, FileWarning } from "lucide-react";
import { api, SEVS, dlUrl } from "../lib/api";
import type { Finding, Tag } from "../lib/api";
import { PageHeader, PageWrap, Btn, Modal, Field, TextInput, SevBadge } from "../components/ui";
import FindingDetail from "../components/FindingDetail";

export default function Findings() {
  const { id } = useParams<{ id: string }>();
  const [all, setAll] = useState<Finding[]>([]);
  const [q, setQ] = useState(""); const [sevs, setSevs] = useState<string[]>([...SEVS]);
  const [sel, setSel] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [tags, setTags] = useState<Tag[]>([]);
  const [bulkOpen, setBulkOpen] = useState<"assign" | "tag" | null>(null);
  const [bulkVal, setBulkVal] = useState("");
  const [busy, setBusy] = useState(false);

  const load = () => {
    setLoading(true);
    (async () => {
      try {
        if (id) { const s = await api.getScan(id); setAll(s.findings || []); }
        else setAll(await api.listFindings());
      } catch {} finally { setLoading(false); }
    })();
  };
  useEffect(() => { load(); api.tags.list().then(setTags).catch(() => {}); }, [id]);

  const toggle = (s: string) => setSevs(p => p.includes(s) ? p.filter(x => x !== s) : [...p, s]);
  const list = all.filter(f => sevs.includes(f.severity) && (f.type + f.url + (f.param || "")).toLowerCase().includes(q.toLowerCase()));
  const counts = Object.fromEntries(SEVS.map(s => [s, all.filter(f => f.severity === s).length]));

  const toggleCheck = (fid: string) => setChecked(p => { const n = new Set(p); n.has(fid) ? n.delete(fid) : n.add(fid); return n; });
  const allChecked = list.length > 0 && list.every(f => checked.has(f.id));

  const bulkFP = async () => {
    if (checked.size === 0 || !confirm(`Mark ${checked.size} findings as false positive?`)) return;
    setBusy(true);
    try { await Promise.all([...checked].map(fid => api.setFindingStatus(fid, "false_positive"))); setChecked(new Set()); load(); }
    catch (e: any) { alert(e.message); } finally { setBusy(false); }
  };
  const bulkApply = async () => {
    if (checked.size === 0 || !bulkVal.trim()) return;
    setBusy(true);
    try {
      if (bulkOpen === "assign") await Promise.all([...checked].map(fid => api.setFindingAssignee(fid, bulkVal.trim())));
      else await Promise.all([...checked].map(fid => api.setFindingTags(fid, [bulkVal])));
      setBulkOpen(null); setBulkVal(""); setChecked(new Set()); load();
    } catch (e: any) { alert(e.message); } finally { setBusy(false); }
  };

  return (
    <PageWrap wide>
      <PageHeader title="Findings" sub={`${list.length} matching`} icon={<FileWarning className="h-6 w-6 text-white" />}
        actions={<>
          <Link to="/kanban"><Btn variant="outline"><KanbanSquare className="h-4 w-4" /> Kanban</Btn></Link>
          <Link to="/timeline"><Btn variant="outline"><HistIcon className="h-4 w-4" /> Timeline</Btn></Link>
          {id && ["json", "html", "sarif"].map(fmt => (
            <a key={fmt} href={dlUrl(`/api/scans/${id}/export/${fmt}`)} download
              className="inline-flex items-center gap-1.5 px-4 py-2.5 rounded-xl text-sm font-semibold text-slate-600 dark:text-slate-300 bg-white dark:bg-white/5 border border-slate-200 dark:border-white/10 shadow-sm hover:shadow-md hover:-translate-y-0.5 transition-all uppercase">
              <Download className="h-4 w-4" />{fmt}
            </a>
          ))}
        </>} />

      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-6">
        {SEVS.map((s, i) => (
          <motion.button key={s} initial={{ opacity: 0, y: 15 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.05 }}
            onClick={() => toggle(s)}
            className={`rounded-2xl p-4 text-center border-2 transition-all ${sevs.includes(s) ? "bg-white dark:bg-white/5 border-indigo-300 dark:border-indigo-500/40 shadow-md" : "bg-white/50 dark:bg-white/[.02] border-transparent opacity-40 hover:opacity-70"}`}>
            <div className="text-3xl font-black text-slate-900 dark:text-white">{counts[s]}</div>
            <span className={`sev-${s} inline-block mt-1.5 text-[11px] font-extrabold uppercase tracking-wide px-2.5 py-1 rounded-lg`}>{s}</span>
          </motion.button>
        ))}
      </div>

      <div className="flex flex-wrap gap-3 mb-6">
        <div className="relative flex-1 min-w-[200px] max-w-md">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400" />
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search findings…"
            className="w-full pl-12 pr-10 py-3.5 rounded-2xl bg-white dark:bg-white/5 border border-slate-200 dark:border-white/10 text-slate-900 dark:text-white shadow-sm placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all" />
          {q && <button onClick={() => setQ("")} className="absolute right-3 top-1/2 -translate-y-1/2 p-1 text-slate-400"><X className="h-4 w-4" /></button>}
        </div>
        <button onClick={() => setChecked(new Set(allChecked ? [] : list.map(f => f.id)))}
          className="inline-flex items-center gap-2 px-4 py-3 rounded-2xl text-sm font-semibold text-slate-600 dark:text-slate-300 bg-white dark:bg-white/5 border border-slate-200 dark:border-white/10">
          {allChecked ? <CheckSquare className="h-4 w-4 text-indigo-600" /> : <Square className="h-4 w-4" />}
          Select all
        </button>
      </div>

      <AnimatePresence>
        {checked.size > 0 && (
          <motion.div initial={{ y: 80, opacity: 0 }} animate={{ y: 0, opacity: 1 }} exit={{ y: 80, opacity: 0 }}
            className="fixed bottom-24 md:bottom-8 left-1/2 -translate-x-1/2 z-40 glass rounded-2xl shadow-2xl px-5 py-3.5 flex items-center gap-2.5">
            <span className="text-sm font-bold text-slate-700 dark:text-slate-200 whitespace-nowrap">{checked.size} selected</span>
            <div className="w-px h-6 bg-slate-200 dark:bg-white/10" />
            <Btn variant="ghost" className="!py-2 !px-3" onClick={bulkFP} disabled={busy}>Mark FP</Btn>
            <Btn variant="ghost" className="!py-2 !px-3" onClick={() => setBulkOpen("assign")}><UserPlus className="h-4 w-4" /> Assign</Btn>
            <Btn variant="ghost" className="!py-2 !px-3" onClick={() => setBulkOpen("tag")}><Tags className="h-4 w-4" /> Tag</Btn>
            <Btn variant="ghost" className="!py-2 !px-3" onClick={() => setChecked(new Set())}><X className="h-4 w-4" /></Btn>
          </motion.div>
        )}
      </AnimatePresence>

      {loading ? (
        <div className="space-y-3">{[1, 2, 3].map(i => <div key={i} className="shimmer rounded-2xl h-20" />)}</div>
      ) : list.length === 0 ? (
        <div className="glass rounded-3xl p-16 text-center">
          <Filter className="mx-auto h-10 w-10 text-slate-300 dark:text-slate-600 mb-3" />
          <p className="text-slate-500 dark:text-slate-400 font-medium">No findings match your filters.</p>
        </div>
      ) : (
        <div className="space-y-2.5">
          {list.map((f, i) => (
            <motion.div key={f.id} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: Math.min(i * 0.03, 0.4) }}
              className="w-full glass card-hover rounded-2xl p-5 flex items-center gap-3 sm:gap-4">
              <button onClick={() => toggleCheck(f.id)} className="shrink-0 p-1" aria-label="Select">
                {checked.has(f.id) ? <CheckSquare className="h-5 w-5 text-indigo-600" /> : <Square className="h-5 w-5 text-slate-300 dark:text-slate-600" />}
              </button>
              <button onClick={() => setSel(f)} className="flex-1 min-w-0 flex items-center gap-4 text-left">
                <SevBadge sev={f.severity} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-bold text-slate-900 dark:text-white text-sm">{f.type}</span>
                    <span className="text-xs text-slate-400">{f.subtype}</span>
                  </div>
                  <div className="mt-1 truncate font-mono text-xs text-slate-500 dark:text-slate-400">{f.method} {f.url} · CVSS {f.cvss_score}</div>
                </div>
                <ChevronRight className="h-5 w-5 text-slate-300 dark:text-slate-600 shrink-0" />
              </button>
            </motion.div>
          ))}
        </div>
      )}

      <AnimatePresence>
        {sel && <FindingDetail finding={sel} onClose={() => setSel(null)} onChanged={load} />}
      </AnimatePresence>

      <Modal open={!!bulkOpen} onClose={() => setBulkOpen(null)} title={bulkOpen === "assign" ? `Assign ${checked.size} findings` : `Tag ${checked.size} findings`}>
        <div className="space-y-4">
          {bulkOpen === "assign" ? (
            <Field label="Assignee email"><TextInput value={bulkVal} onChange={e => setBulkVal(e.target.value)} placeholder="analyst@example.com" /></Field>
          ) : (
            <Field label="Tag">
              <select value={bulkVal} onChange={e => setBulkVal(e.target.value)}
                className="w-full px-4 py-3 rounded-xl bg-slate-50 dark:bg-white/5 border border-slate-200 dark:border-white/10 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500">
                <option value="">Choose a tag…</option>
                {tags.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
              </select>
            </Field>
          )}
          <div className="flex justify-end gap-2">
            <Btn variant="ghost" onClick={() => setBulkOpen(null)}>Cancel</Btn>
            <Btn onClick={bulkApply} disabled={busy || !bulkVal.trim()}>Apply</Btn>
          </div>
        </div>
      </Modal>
    </PageWrap>
  );
}
