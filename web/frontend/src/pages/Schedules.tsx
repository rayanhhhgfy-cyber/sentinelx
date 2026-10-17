import { useEffect, useState } from "react";
import { CalendarClock, Plus, Pencil, Trash2, Power, PowerOff, Info } from "lucide-react";
import { api } from "../lib/api";
import type { Schedule, Target, Template } from "../lib/api";
import { PageHeader, PageWrap, Btn, Modal, Field, Select, Confirm, EmptyState, Spinner, StatusBadge, fmtDateShort } from "../components/ui";

const PRESETS = [
  { label: "Every hour", expr: "0 * * * *" },
  { label: "Daily at 02:00", expr: "0 2 * * *" },
  { label: "Weekly (Mon 03:00)", expr: "0 3 * * 1" },
  { label: "Monthly (1st 04:00)", expr: "0 4 1 * *" },
];

export default function Schedules() {
  const [list, setList] = useState<Schedule[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [templates, setTemplates] = useState<Template[]>([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(false);
  const [editing, setEditing] = useState<Schedule | null>(null);
  const [form, setForm] = useState({ target_id: "", template_id: "", cron_expr: "0 2 * * *", enabled: true });
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = () => {
    Promise.all([api.schedules.list(), api.targets.list(), api.templates.list()])
      .then(([s, t, tm]) => { setList(s); setTargets(t); setTemplates(tm); })
      .catch(() => {}).finally(() => setLoading(false));
  };
  useEffect(() => { load(); }, []);

  const openNew = () => { setEditing(null); setForm({ target_id: targets[0]?.id || "", template_id: templates[0]?.id || "", cron_expr: "0 2 * * *", enabled: true }); setModal(true); };
  const openEdit = (s: Schedule) => { setEditing(s); setForm({ target_id: s.target_id, template_id: s.template_id, cron_expr: s.cron_expr, enabled: s.enabled }); setModal(true); };
  const save = async () => {
    if (!form.target_id) return;
    setBusy(true);
    try {
      if (editing) await api.schedules.update(editing.id, form);
      else await api.schedules.create(form);
      setModal(false); load();
    } catch (e: any) { alert(e.message); } finally { setBusy(false); }
  };
  const toggle = async (s: Schedule) => {
    try { await api.schedules.update(s.id, { enabled: !s.enabled }); load(); }
    catch (e: any) { alert(e.message); }
  };
  const tName = (id: string) => targets.find(t => t.id === id)?.name || targets.find(t => t.id === id)?.url || id;
  const tplName = (id: string) => templates.find(t => t.id === id)?.name || "—";

  return (
    <PageWrap wide>
      <PageHeader icon={<CalendarClock className="h-6 w-6 text-white" />} title="Schedules" sub="Recurring scans on autopilot"
        actions={<Btn onClick={openNew}><Plus className="h-4 w-4" /> New schedule</Btn>} />
      {loading ? <Spinner /> : list.length === 0 ? (
        <EmptyState title="No schedules yet" sub="Set up recurring scans with cron expressions." action={<Btn onClick={openNew}><Plus className="h-4 w-4" /> New schedule</Btn>} />
      ) : (
        <>
          <div className="hidden md:block glass rounded-3xl overflow-hidden mb-4">
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs uppercase tracking-wider text-slate-400 border-b border-slate-100 dark:border-white/5">
                <th className="px-6 py-4 font-bold">Target</th><th className="px-6 py-4 font-bold">Template</th>
                <th className="px-6 py-4 font-bold">Cron</th><th className="px-6 py-4 font-bold">Next run</th>
                <th className="px-6 py-4 font-bold">Status</th><th className="px-6 py-4 font-bold text-right">Actions</th>
              </tr></thead>
              <tbody className="divide-y divide-slate-100 dark:divide-white/5">
                {list.map(s => (
                  <tr key={s.id} className="hover:bg-slate-50/60 dark:hover:bg-white/[.02]">
                    <td className="px-6 py-4 font-semibold text-slate-800 dark:text-slate-100">{tName(s.target_id)}</td>
                    <td className="px-6 py-4 text-slate-500 dark:text-slate-400">{tplName(s.template_id)}</td>
                    <td className="px-6 py-4 font-mono text-xs text-slate-600 dark:text-slate-300">{s.cron_expr}</td>
                    <td className="px-6 py-4 text-slate-500 dark:text-slate-400 text-xs">{fmtDateShort(s.next_run_at)}</td>
                    <td className="px-6 py-4"><StatusBadge status={s.enabled ? "running" : "paused"} /></td>
                    <td className="px-6 py-4"><div className="flex justify-end gap-1.5">
                      <Btn variant="ghost" className="!px-3 !py-2" onClick={() => toggle(s)}>
                        {s.enabled ? <PowerOff className="h-4 w-4" /> : <Power className="h-4 w-4" />}
                      </Btn>
                      <Btn variant="ghost" className="!px-3 !py-2" onClick={() => openEdit(s)}><Pencil className="h-4 w-4" /></Btn>
                      <Btn variant="danger" className="!px-3 !py-2" onClick={() => setConfirmId(s.id)}><Trash2 className="h-4 w-4" /></Btn>
                    </div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="md:hidden space-y-3">
            {list.map(s => (
              <div key={s.id} className="glass rounded-3xl p-5">
                <div className="flex items-center justify-between mb-2">
                  <div className="font-bold text-slate-900 dark:text-white truncate">{tName(s.target_id)}</div>
                  <StatusBadge status={s.enabled ? "running" : "paused"} />
                </div>
                <div className="text-xs text-slate-500 dark:text-slate-400 mb-1">Template: {tplName(s.template_id)}</div>
                <div className="font-mono text-xs text-slate-600 dark:text-slate-300 mb-1">{s.cron_expr}</div>
                <div className="text-xs text-slate-400 mb-4">Next: {fmtDateShort(s.next_run_at)}</div>
                <div className="flex gap-2">
                  <Btn variant="ghost" className="flex-1 !px-3" onClick={() => toggle(s)}>{s.enabled ? "Disable" : "Enable"}</Btn>
                  <Btn variant="ghost" className="!px-3" onClick={() => openEdit(s)}><Pencil className="h-4 w-4" /></Btn>
                  <Btn variant="danger" className="!px-3" onClick={() => setConfirmId(s.id)}><Trash2 className="h-4 w-4" /></Btn>
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      <Modal open={modal} onClose={() => setModal(false)} title={editing ? "Edit schedule" : "New schedule"}>
        <div className="space-y-4">
          <Field label="Target">
            <Select value={form.target_id} onChange={e => setForm({ ...form, target_id: e.target.value })}>
              {targets.map(t => <option key={t.id} value={t.id}>{t.name} — {t.url}</option>)}
            </Select>
          </Field>
          <Field label="Template">
            <Select value={form.template_id} onChange={e => setForm({ ...form, template_id: e.target.value })}>
              <option value="">Default (all modules)</option>
              {templates.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
            </Select>
          </Field>
          <Field label="Cron expression" hint="min hour day month weekday — e.g. 0 2 * * * = daily at 02:00">
            <Select value={PRESETS.some(p => p.expr === form.cron_expr) ? form.cron_expr : "__custom"}
              onChange={e => setForm({ ...form, cron_expr: e.target.value === "__custom" ? form.cron_expr : e.target.value })}>
              {PRESETS.map(p => <option key={p.expr} value={p.expr}>{p.label} ({p.expr})</option>)}
              <option value="__custom">Custom…</option>
            </Select>
          </Field>
          {(!PRESETS.some(p => p.expr === form.cron_expr)) && (
            <Field label="Custom cron">
              <input value={form.cron_expr} onChange={e => setForm({ ...form, cron_expr: e.target.value })}
                placeholder="0 2 * * *" className="w-full px-4 py-3 rounded-xl bg-slate-50 dark:bg-white/5 border border-slate-200 dark:border-white/10 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500" />
            </Field>
          )}
          <label className="flex items-center gap-3 cursor-pointer">
            <input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })}
              className="h-5 w-5 rounded accent-indigo-600" />
            <span className="text-sm font-semibold text-slate-700 dark:text-slate-200">Enabled</span>
          </label>
          <div className="flex items-start gap-2 text-xs text-slate-400 bg-slate-50 dark:bg-white/5 rounded-xl p-3">
            <Info className="h-4 w-4 shrink-0 mt-0.5" /> The scheduler runs server-side; scans appear in History when triggered.
          </div>
          <div className="flex justify-end gap-2">
            <Btn variant="ghost" onClick={() => setModal(false)}>Cancel</Btn>
            <Btn onClick={save} disabled={busy || !form.target_id}>{busy ? "Saving…" : "Save schedule"}</Btn>
          </div>
        </div>
      </Modal>

      <Confirm open={!!confirmId} onClose={() => setConfirmId(null)} danger title="Delete schedule" body="Delete this recurring schedule?"
        onYes={() => { if (confirmId) api.schedules.remove(confirmId).then(load).catch(e => alert(e.message)); }} />
    </PageWrap>
  );
}
