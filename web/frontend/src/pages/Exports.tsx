import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Download, FileJson, FileText, FileSpreadsheet, ShieldCheck, Inbox } from "lucide-react";
import { api, dlUrl } from "../lib/api";
import type { Scan } from "../lib/api";
import { PageHeader, PageWrap, Btn, Spinner, EmptyState, fmtDateShort } from "../components/ui";
import { ExportModal } from "../components/dialogs";

const FMTS = [
  { id: "json", icon: FileJson }, { id: "html", icon: FileText }, { id: "csv", icon: FileSpreadsheet },
  { id: "pdf", icon: FileText }, { id: "sarif", icon: ShieldCheck },
];

export default function Exports() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [exp, setExp] = useState<Scan | null>(null);

  useEffect(() => { api.listScans().then(setScans).catch(() => {}).finally(() => setLoading(false)); }, []);

  return (
    <PageWrap>
      <PageHeader icon={<Download className="h-6 w-6 text-white" />} title="Export center" sub="Download reports in any format" />
      {loading ? <Spinner /> : scans.length === 0 ? (
        <EmptyState icon={<Inbox className="mx-auto h-12 w-12" />} title="No scans to export" sub="Run a scan first." />
      ) : (
        <div className="space-y-3">
          {scans.map(s => (
            <div key={s.id} className="glass card-hover rounded-2xl p-5">
              <div className="flex flex-wrap items-center gap-3 mb-4">
                <Link to={`/findings/${s.id}`} className="min-w-0 flex-1">
                  <div className="font-mono text-sm font-bold text-slate-900 dark:text-white truncate hover:text-indigo-600 dark:hover:text-indigo-400">{s.target}</div>
                  <div className="text-xs text-slate-400 mt-0.5">{fmtDateShort(s.created_at)} · {s.total_findings ?? s.finding_count ?? 0} findings</div>
                </Link>
                <Btn variant="outline" className="!px-4" onClick={() => setExp(s)}>Preview & export</Btn>
              </div>
              <div className="flex flex-wrap gap-2">
                {FMTS.map(f => (
                  <a key={f.id} href={dlUrl(`/api/scans/${s.id}/export/${f.id}`)} download
                    className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-xl text-xs font-bold uppercase tracking-wide text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-white/10 hover:bg-indigo-50 dark:hover:bg-indigo-500/15 hover:text-indigo-700 dark:hover:text-indigo-300 transition-colors">
                    <f.icon className="h-3.5 w-3.5" />{f.id}
                  </a>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
      {exp && <ExportModal scanId={exp.id} target={exp.target} open={!!exp} onClose={() => setExp(null)} />}
    </PageWrap>
  );
}
