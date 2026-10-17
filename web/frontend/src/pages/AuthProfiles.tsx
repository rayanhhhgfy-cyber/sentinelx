import { useEffect, useState } from "react";
import { KeyRound, Plus, Pencil, Trash2, Eye, EyeOff } from "lucide-react";
import { api } from "../lib/api";
import type { AuthProfile } from "../lib/api";
import { PageHeader, PageWrap, Btn, Modal, Field, TextInput, Confirm, EmptyState, Spinner } from "../components/ui";

const EMPTY = { name: "", login_url: "", username_field: "username", password_field: "password", username: "", password: "" };

export default function AuthProfiles() {
  const [list, setList] = useState<AuthProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(false);
  const [editing, setEditing] = useState<AuthProfile | null>(null);
  const [form, setForm] = useState(EMPTY);
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [showPw, setShowPw] = useState(false);

  const load = () => api.authProfiles.list().then(setList).catch(() => {}).finally(() => setLoading(false));
  useEffect(() => { load(); }, []);

  const openNew = () => { setEditing(null); setForm(EMPTY); setShowPw(false); setModal(true); };
  const openEdit = (p: AuthProfile) => {
    setEditing(p);
    setForm({ name: p.name, login_url: p.login_url, username_field: p.username_field, password_field: p.password_field, username: p.username, password: "" });
    setShowPw(false); setModal(true);
  };
  const save = async () => {
    if (!form.name.trim() || !form.login_url.trim() || !form.username.trim()) return;
    if (!editing && !form.password) { alert("Password is required for a new profile"); return; }
    setBusy(true);
    try {
      const body: any = { ...form };
      if (editing && !form.password) delete body.password;
      if (editing) await api.authProfiles.update(editing.id, body);
      else await api.authProfiles.create(body);
      setModal(false); load();
    } catch (e: any) { alert(e.message); } finally { setBusy(false); }
  };

  return (
    <PageWrap>
      <PageHeader icon={<KeyRound className="h-6 w-6 text-white" />} title="Auth profiles" sub="Stored login credentials for authenticated scans"
        actions={<Btn onClick={openNew}><Plus className="h-4 w-4" /> New profile</Btn>} />
      {loading ? <Spinner /> : list.length === 0 ? (
        <EmptyState title="No auth profiles" sub="Save logins so scans can test behind authentication." action={<Btn onClick={openNew}><Plus className="h-4 w-4" /> New profile</Btn>} />
      ) : (
        <div className="space-y-3">
          {list.map(p => (
            <div key={p.id} className="glass card-hover rounded-2xl p-5 flex flex-wrap items-center gap-3">
              <div className="min-w-0 flex-1">
                <div className="font-bold text-slate-900 dark:text-white">{p.name}</div>
                <div className="text-xs text-slate-500 dark:text-slate-400 font-mono truncate">{p.login_url}</div>
                <div className="text-xs text-slate-400 mt-1">User: <span className="font-mono">{p.username}</span> · fields: <span className="font-mono">{p.username_field}/{p.password_field}</span> · password: ••••••••</div>
              </div>
              <div className="flex gap-1.5">
                <Btn variant="ghost" className="!px-3 !py-2" onClick={() => openEdit(p)}><Pencil className="h-4 w-4" /></Btn>
                <Btn variant="danger" className="!px-3 !py-2" onClick={() => setConfirmId(p.id)}><Trash2 className="h-4 w-4" /></Btn>
              </div>
            </div>
          ))}
        </div>
      )}

      <Modal open={modal} onClose={() => setModal(false)} title={editing ? "Edit auth profile" : "New auth profile"}>
        <div className="space-y-4">
          <Field label="Profile name"><TextInput value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Client staging login" /></Field>
          <Field label="Login URL"><TextInput value={form.login_url} onChange={e => setForm({ ...form, login_url: e.target.value })} placeholder="https://app.example.com/login" className="font-mono" /></Field>
          <div className="grid grid-cols-2 gap-4">
            <Field label="Username field"><TextInput value={form.username_field} onChange={e => setForm({ ...form, username_field: e.target.value })} className="font-mono" /></Field>
            <Field label="Password field"><TextInput value={form.password_field} onChange={e => setForm({ ...form, password_field: e.target.value })} className="font-mono" /></Field>
          </div>
          <Field label="Username"><TextInput value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} autoComplete="off" /></Field>
          <Field label={editing ? "New password (leave blank to keep)" : "Password"}>
            <div className="relative">
              <TextInput type={showPw ? "text" : "password"} value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} autoComplete="new-password" className="pr-12" />
              <button type="button" onClick={() => setShowPw(!showPw)} className="absolute right-3 top-1/2 -translate-y-1/2 p-1 text-slate-400 hover:text-slate-600">
                {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </Field>
          <div className="flex justify-end gap-2">
            <Btn variant="ghost" onClick={() => setModal(false)}>Cancel</Btn>
            <Btn onClick={save} disabled={busy}>{busy ? "Saving…" : "Save profile"}</Btn>
          </div>
        </div>
      </Modal>

      <Confirm open={!!confirmId} onClose={() => setConfirmId(null)} danger title="Delete profile" body="Delete this auth profile? Credentials are removed from the server."
        onYes={() => { if (confirmId) api.authProfiles.remove(confirmId).then(load).catch(e => alert(e.message)); }} />
    </PageWrap>
  );
}
