import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Search, Loader2 } from "lucide-react";
import { api } from "../lib/api";
import type { Finding } from "../lib/api";
import { PageHeader, PageWrap, EmptyState, SevBadge, StatusBadge } from "../components/ui";
import FindingDetail from "../components/FindingDetail";

export default function SearchPage() {
  const [q, setQ] = useState("");
  const [results, setResults] = useState<Finding[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [sel, setSel] = useState<Finding | null>(null);

  const search = async () => {
    if (q.trim().length < 2) return;
    setBusy(true);
    try { setResults(await api.searchFindings(q.trim())); }
    catch (e: any) { alert(e.message); } finally { setBusy(false); }
  };

  return (
    <PageWrap wide>
      <PageHeader icon={<Search className="h-6 w-6 text-white" />} title="Global search" sub="Search findings across every scan" />
      <div className="relative mb-8 max-w-2xl">
        <Search className="absolute left-5 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400" />
        <input value={q} onChange={e => setQ(e.target.value)} onKeyDown={e => e.key === "Enter" && search()}
          placeholder="Try: sqli, admin panel, CVE-2024, .env…"
          className="w-full pl-14 pr-14 py-4 rounded-2xl glass text-slate-900 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all text-[15px]" />
        {busy && <Loader2 className="absolute right-5 top-1/2 -translate-y-1/2 h-5 w-5 animate-spin text-indigo-500" />}
      </div>

      {results === null ? (
        <EmptyState title="Search everything" sub="Type at least 2 characters and press Enter." />
      ) : results.length === 0 ? (
        <EmptyState title="No matches" sub={`Nothing found for "${q}".`} />
      ) : (
        <>
          <p className="text-sm font-bold text-slate-500 dark:text-slate-400 mb-4">{results.length} result{results.length === 1 ? "" : "s"} for "{q}"</p>
          <div className="space-y-2.5">
            {results.map((f, i) => (
              <motion.button key={f.id} initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: Math.min(i * 0.03, 0.3) }}
                onClick={() => setSel(f)} className="w-full text-left glass card-hover rounded-2xl p-5 flex items-center gap-4">
                <SevBadge sev={f.severity} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-bold text-slate-900 dark:text-white text-sm">{f.type}</span>
                    <StatusBadge status={f.status || "open"} />
                  </div>
                  <div className="mt-1 truncate font-mono text-xs text-slate-500 dark:text-slate-400">{f.method} {f.url}</div>
                </div>
              </motion.button>
            ))}
          </div>
        </>
      )}
      <AnimatePresence>{sel && <FindingDetail finding={sel} onClose={() => setSel(null)} />}</AnimatePresence>
    </PageWrap>
  );
}
