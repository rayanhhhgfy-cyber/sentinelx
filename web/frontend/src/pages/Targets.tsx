import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Target as TargetIcon, Plus, Pencil, Trash2, Upload, Zap, Tag as TagIcon } from "lucide-react";
import { api } from "../lib/api";
import type { Target } from "../lib/api";
import { PageHeader, PageWrap, Btn, Modal, Field, TextInput, TextArea, Confirm, EmptyState, Spinner, fmtDateShort } from "../components/ui";

const EMPTY = { url: "", name: "", tags: "", notes: "" };

export default function Targets() {
  const nav = useNavigate();
  const [params] = useSearchParams();
  const [list, setList] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(false);
  const [editing, setEditing] = useState<Target | null>(null);
  const [form, setForm] = useState(EMPTY);
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [csv, setCsv] = useState("");
  const [busy, setBusy] = useState(false);

  const load = () => api.targets.list().then(setList).catch(() => {}).finally(() => setLoading(false));
  useEffect(() => { load(); }, []);
  useEffect(() => { if (params.get("action") === "new") { setEditing(null); setForm(EMPTY); setModal(true); } }, [params]);

  const openNew = () => { setEditing(null); setForm(EMPTY); setModal(true); };
  const openEdit = (t: Target) => { setEditing(t); setForm({ url: t.url, name: t.name, tags: (t.tags || []).join(", "), notes: t.notes || "" }); setModal(true); };
  const save = async () => {
    if (!form.url.trim()) return;
    setBusy(true);
    const body = { url: form.url.trim(), name: form.name.trim() || form.url.trim(), tags: form.tags.split(",").map(s => s.trim()).filter(Boolean), notes: form.notes };
    try {
      if (editing) await api.targets.update(editing.id, body);
      else await api.targets.create(body);
      setModal(false); load();
    } catch (e: any) { alert(e.message); } finally { setBusy(false); }
  };
  const doImport = async () => {
    if (!csv.trim()) return;
    setBusy(true);
    try { const r = await api.targets.importCsv(csv); alert(`Imported ${r.imported} targets`); setImportOpen(false); setCsv(""); load(); }
    catch (e: any) { alert(e.message); } finally { setBusy(false); }
  };
  const scanNow = async (t: Target) => {
    try { const r = await api.startScan({ target: t.url, confirm_own: true }); nav(`/scan/${r.scan_id}`); }
    catch (e: any) { alert(e.message); }
  };

  return (
    <PageWrap wide>
      <PageHeader icon={<TargetIcon className="h-6 w-6 text-white" />} title="Targets" sub={`${list.length} saved targets`}
        actions={<>
          <Btn variant="outline" onClick={() => setImportOpen(true)}><Upload className="h-4 w-4" /> Import CSV</Btn>
          <Btn onClick={openNew}><Plus className="h-4 w-4" /> Add target</Btn>
        </>} />
      {loading ? <Spinner /> : list.length === 0 ? (
        <EmptyState title="No targets yet" sub="Add your first target or import a CSV list." action={<Btn onClick={openNew}><Plus className="h-4 w-4" /> Add target</Btn>} />
      ) : (
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {list.map(t => (
            <div key={t.id} className="glass card-hover rounded-3xl p-6">
              <div className="font-mono text-sm font-bold text-slate-900 dark:text-white truncate mb-1">{t.url}</div>
              <div className="text-sm font-semibold text-slate-600 dark:text-slate-300 mb-3">{t.name}</div>
              {(t.tags || []).length > 0 && (
                <div className="flex flex-wrap gap-1.5 mb-3">
                  {t.tags.map(tag => (
                    <span key={tag} className="inline-flex items-center gap-1 text-[11px] font-bold px-2.5 py-1 rounded-full bg-indigo-50 dark:bg-indigo-500/15 text-indigo-700 dark:text-indigo-300">
                      <TagIcon className="h-3 w-3" />{tag}
                    </span>
                  ))}
                </div>
              )}
              {t.notes && <p className="text-xs text-slate-500 dark:text-slate-400 mb-3 line-clamp-2">{t.notes}</p>}
              <p className="text-[11px] text-slate-400 mb-4">Last scan: {fmtDateShort(t.last_scan_at)}</p>
              <div className="flex gap-2">
                <Btn variant="success" className="flex-1 !px-3" onClick={() => scanNow(t)}><Zap className="h-4 w-4" /> Scan now</Btn>
                <Btn variant="ghost" className="!px-3" onClick={() => openEdit(t)}><Pencil className="h-4 w-4" /></Btn>
                <Btn variant="danger" className="!px-3" onClick={() => setConfirmId(t.id)}><Trash2 className="h-4 w-4" /></Btn>
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal open={modal} onClose={() => setModal(false)} title={editing ? "Edit target" : "Add target"}>
        <div className="space-y-4">
          <Field label="URL"><TextInput value={form.url} onChange={e => setForm({ ...form, url: e.target.value })} placeholder="https://example.com" /></Field>
          <Field label="Name"><TextInput value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Production site" /></Field>
          <Field label="Tags" hint="Comma-separated"><TextInput value={form.tags} onChange={e => setForm({ ...form, tags: e.target.value })} placeholder="prod, external" /></Field>
          <Field label="Notes"><TextArea rows={3} value={form.notes} onChange={e => setForm({ ...form, notes: e.target.value })} placeholder="Scope notes…" /></Field>
          <div className="flex justify-end gap-2">
            <Btn variant="ghost" onClick={() => setModal(false)}>Cancel</Btn>
            <Btn onClick={save} disabled={busy || !form.url.trim()}>{busy ? "Saving…" : "Save"}</Btn>
          </div>
        </div>
      </Modal>

      <Modal open={importOpen} onClose={() => setImportOpen(false)} title="Import targets from CSV">
        <div className="space-y-4">
          <p className="text-sm text-slate-500 dark:text-slate-400">One per line: <code className="font-mono text-xs bg-slate-100 dark:bg-white/10 px-1.5 py-0.5 rounded">url, name, tag1;tag2</code></p>
          <Field label="CSV">
            <TextArea rows={6} value={csv} onChange={e => setCsv(e.target.value)} placeholder={"https://a.com, Site A, prod\nhttps://b.com, Site B, staging"} className="font-mono" />
          </Field>
          <div className="flex justify-end gap-2">
            <Btn variant="ghost" onClick={() => setImportOpen(false)}>Cancel</Btn>
            <Btn onClick={doImport} disabled={busy || !csv.trim()}><Upload className="h-4 w-4" /> Import</Btn>
          </div>
        </div>
      </Modal>

      <Confirm open={!!confirmId} onClose={() => setConfirmId(null)} danger title="Delete target" body="Delete this target? Scheduled scans referencing it will stop working."
        onYes={() => { if (confirmId) api.targets.remove(confirmId).then(load).catch(e => alert(e.message)); }} />
    </PageWrap>
  );
}
