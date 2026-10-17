import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Layers, Plus, Pencil, Trash2, Play, Gauge } from "lucide-react";
import { api, SCAN_MODULES } from "../lib/api";
import type { Template } from "../lib/api";
import { PageHeader, PageWrap, Btn, Modal, Field, TextInput, TextArea, Confirm, EmptyState, Spinner } from "../components/ui";

const EMPTY = { name: "", modules: [] as string[], rate_limit: 10, description: "" };

export default function Templates() {
  const nav = useNavigate();
  const [list, setList] = useState<Template[]>([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(false);
  const [editing, setEditing] = useState<Template | null>(null);
  const [form, setForm] = useState(EMPTY);
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = () => api.templates.list().then(setList).catch(() => {}).finally(() => setLoading(false));
  useEffect(() => { load(); }, []);

  const openNew = () => { setEditing(null); setForm(EMPTY); setModal(true); };
  const openEdit = (t: Template) => { setEditing(t); setForm({ name: t.name, modules: [...t.modules], rate_limit: t.rate_limit, description: t.description }); setModal(true); };
  const toggleMod = (m: string) => setForm(f => ({ ...f, modules: f.modules.includes(m) ? f.modules.filter(x => x !== m) : [...f.modules, m] }));
  const save = async () => {
    if (!form.name.trim() || form.modules.length === 0) return;
    setBusy(true);
    try {
      if (editing) await api.templates.update(editing.id, form);
      else await api.templates.create(form);
      setModal(false); load();
    } catch (e: any) { alert(e.message); } finally { setBusy(false); }
  };
  const apply = (t: Template) => nav(`/scan/new?template=${t.id}`);

  return (
    <PageWrap wide>
      <PageHeader icon={<Layers className="h-6 w-6 text-white" />} title="Scan templates" sub="Reusable module sets and rate limits"
        actions={<Btn onClick={openNew}><Plus className="h-4 w-4" /> New template</Btn>} />
      {loading ? <Spinner /> : list.length === 0 ? (
        <EmptyState title="No templates yet" sub="Bundle module selections into reusable templates." action={<Btn onClick={openNew}><Plus className="h-4 w-4" /> New template</Btn>} />
      ) : (
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {list.map(t => (
            <div key={t.id} className="glass card-hover rounded-3xl p-6">
              <div className="font-extrabold text-slate-900 dark:text-white mb-1">{t.name}</div>
              <p className="text-sm text-slate-500 dark:text-slate-400 mb-3 line-clamp-2">{t.description || "No description"}</p>
              <div className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400 mb-3">
                <Gauge className="h-3.5 w-3.5" /> {t.rate_limit} req/s · {t.modules.length} modules
              </div>
              <div className="flex flex-wrap gap-1.5 mb-4">
                {t.modules.slice(0, 6).map(m => (
                  <span key={m} className="text-[11px] font-mono font-bold px-2 py-1 rounded-lg bg-indigo-50 dark:bg-indigo-500/15 text-indigo-700 dark:text-indigo-300">{m}</span>
                ))}
                {t.modules.length > 6 && <span className="text-[11px] font-bold text-slate-400">+{t.modules.length - 6}</span>}
              </div>
              <div className="flex gap-2">
                <Btn variant="primary" className="flex-1 !px-3" onClick={() => apply(t)}><Play className="h-4 w-4" /> Use</Btn>
                <Btn variant="ghost" className="!px-3" onClick={() => openEdit(t)}><Pencil className="h-4 w-4" /></Btn>
                <Btn variant="danger" className="!px-3" onClick={() => setConfirmId(t.id)}><Trash2 className="h-4 w-4" /></Btn>
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal open={modal} onClose={() => setModal(false)} title={editing ? "Edit template" : "New template"} wide>
        <div className="space-y-5">
          <div className="grid sm:grid-cols-2 gap-4">
            <Field label="Name"><TextInput value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Full audit" /></Field>
            <Field label="Rate limit (req/s)"><TextInput type="number" min={1} max={100} value={form.rate_limit} onChange={e => setForm({ ...form, rate_limit: Number(e.target.value) })} /></Field>
          </div>
          <Field label="Description"><TextArea rows={2} value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} placeholder="What is this template for?" /></Field>
          <div>
            <span className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Modules ({form.modules.length} selected)</span>
            <div className="mt-2 flex flex-wrap gap-2">
              {SCAN_MODULES.map(m => (
                <button key={m} onClick={() => toggleMod(m)}
                  className={`px-3 py-1.5 rounded-xl text-xs font-mono font-bold border-2 transition-all ${form.modules.includes(m) ? "bg-indigo-600 border-indigo-600 text-white" : "border-slate-200 dark:border-white/10 text-slate-500 dark:text-slate-400 hover:border-indigo-300"}`}>
                  {m}
                </button>
              ))}
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <Btn variant="ghost" onClick={() => setModal(false)}>Cancel</Btn>
            <Btn onClick={save} disabled={busy || !form.name.trim() || form.modules.length === 0}>{busy ? "Saving…" : "Save template"}</Btn>
          </div>
        </div>
      </Modal>

      <Confirm open={!!confirmId} onClose={() => setConfirmId(null)} danger title="Delete template" body="Delete this template? Existing scans are unaffected."
        onYes={() => { if (confirmId) api.templates.remove(confirmId).then(load).catch(e => alert(e.message)); }} />
    </PageWrap>
  );
}
