import { useEffect, useState } from "react";
import { ScrollText, Search, Filter } from "lucide-react";
import { api } from "../lib/api";
import type { AuditEntry } from "../lib/api";
import { PageHeader, PageWrap, Btn, Field, TextInput, Select, EmptyState, Spinner, fmtDate } from "../components/ui";

export default function AuditLog() {
  const [list, setList] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [action, setAction] = useState("");
  const [actor, setActor] = useState("");
  const [limit, setLimit] = useState("100");

  const load = (a = action, u = actor, l = limit) => {
    setLoading(true);
    api.auditLog({ action: a || undefined, actor: u || undefined, limit: Number(l) || 100 })
      .then(setList).catch(() => {}).finally(() => setLoading(false));
  };
  useEffect(() => { load("", "", "100"); }, []);

  const actions = [...new Set(list.map(e => e.action))].sort();

  return (
    <PageWrap wide>
      <PageHeader icon={<ScrollText className="h-6 w-6 text-white" />} title="Audit log" sub="Every significant action, attributed" />

      <div className="glass rounded-3xl p-5 mb-5">
        <div className="grid sm:grid-cols-4 gap-3">
          <Field label="Action">
            <Select value={action} onChange={e => setAction(e.target.value)}>
              <option value="">All actions</option>
              {actions.map(a => <option key={a} value={a}>{a}</option>)}
            </Select>
          </Field>
          <Field label="Actor">
            <div className="relative">
              <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <TextInput value={actor} onChange={e => setActor(e.target.value)} placeholder="email…" className="pl-10" />
            </div>
          </Field>
          <Field label="Limit">
            <Select value={limit} onChange={e => setLimit(e.target.value)}>
              {["50", "100", "250", "500"].map(n => <option key={n} value={n}>{n}</option>)}
            </Select>
          </Field>
          <div className="flex items-end">
            <Btn onClick={() => load()} className="w-full"><Filter className="h-4 w-4" /> Apply</Btn>
          </div>
        </div>
      </div>

      {loading ? <Spinner /> : list.length === 0 ? (
        <EmptyState title="No audit entries" sub="Actions will appear here once recorded." />
      ) : (
        <>
          <div className="hidden md:block glass rounded-3xl overflow-hidden">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs uppercase tracking-wider text-slate-400 border-b border-slate-100 dark:border-white/5">
                <th className="px-6 py-4 font-bold">Time</th><th className="px-6 py-4 font-bold">Actor</th>
                <th className="px-6 py-4 font-bold">Action</th><th className="px-6 py-4 font-bold">Detail</th>
                <th className="px-6 py-4 font-bold">IP</th>
              </tr></thead>
              <tbody className="divide-y divide-slate-100 dark:divide-white/5">
                {list.map(e => (
                  <tr key={e.id} className="hover:bg-slate-50/60 dark:hover:bg-white/[.02]">
                    <td className="px-6 py-3.5 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">{fmtDate(e.created_at)}</td>
                    <td className="px-6 py-3.5 font-semibold text-slate-800 dark:text-slate-100">{e.actor}</td>
                    <td className="px-6 py-3.5"><span className="font-mono text-xs px-2.5 py-1 rounded-lg bg-indigo-50 dark:bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 font-bold">{e.action}</span></td>
                    <td className="px-6 py-3.5 text-slate-500 dark:text-slate-400 text-xs max-w-md truncate">{e.detail}</td>
                    <td className="px-6 py-3.5 font-mono text-xs text-slate-400">{e.ip || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="md:hidden space-y-3">
            {list.map(e => (
              <div key={e.id} className="glass rounded-2xl p-4">
                <div className="flex items-center justify-between gap-2 mb-1.5">
                  <span className="font-mono text-xs px-2 py-1 rounded-lg bg-indigo-50 dark:bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 font-bold">{e.action}</span>
                  <span className="text-[11px] text-slate-400">{fmtDate(e.created_at)}</span>
                </div>
                <div className="text-sm font-semibold text-slate-800 dark:text-slate-100">{e.actor}</div>
                <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">{e.detail}</div>
              </div>
            ))}
          </div>
        </>
      )}
    </PageWrap>
  );
}
