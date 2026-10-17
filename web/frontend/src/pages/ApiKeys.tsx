import { useEffect, useState } from "react";
import { Key, Plus, Trash2, Copy, Check, AlertTriangle } from "lucide-react";
import { api } from "../lib/api";
import type { ApiKey } from "../lib/api";
import { PageHeader, PageWrap, Btn, Modal, Field, TextInput, Confirm, EmptyState, Spinner, fmtDate } from "../components/ui";

export default function ApiKeys() {
  const [list, setList] = useState<ApiKey[]>([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(false);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [revokeId, setRevokeId] = useState<string | null>(null);

  const load = () => api.apiKeys.list().then(setList).catch(() => {}).finally(() => setLoading(false));
  useEffect(() => { load(); }, []);

  const create = async () => {
    if (!name.trim()) return;
    setBusy(true);
    try {
      const k = await api.apiKeys.create(name.trim());
      setNewKey(k.key || null); setName(""); setModal(false); load();
    } catch (e: any) { alert(e.message); } finally { setBusy(false); }
  };
  const copy = () => { if (newKey) { navigator.clipboard.writeText(newKey); setCopied(true); setTimeout(() => setCopied(false), 1500); } };

  return (
    <PageWrap>
      <PageHeader icon={<Key className="h-6 w-6 text-white" />} title="API keys" sub="Programmatic access to the SentinelX API"
        actions={<Btn onClick={() => setModal(true)}><Plus className="h-4 w-4" /> New key</Btn>} />

      {newKey && (
        <div className="mb-5 rounded-3xl border-2 border-amber-300 dark:border-amber-500/40 bg-amber-50 dark:bg-amber-500/10 p-6">
          <div className="flex items-start gap-3 mb-3">
            <AlertTriangle className="h-5 w-5 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
            <p className="text-sm font-semibold text-amber-800 dark:text-amber-200">Copy this key now — it will never be shown again.</p>
          </div>
          <div className="flex gap-2">
            <code className="flex-1 font-mono text-sm bg-white dark:bg-black/30 border border-amber-200 dark:border-amber-500/30 rounded-xl px-4 py-3 break-all text-slate-800 dark:text-slate-100">{newKey}</code>
            <Btn variant="outline" onClick={copy}>{copied ? <Check className="h-4 w-4 text-emerald-500" /> : <Copy className="h-4 w-4" />}</Btn>
          </div>
          <Btn variant="ghost" className="mt-3" onClick={() => setNewKey(null)}>I've saved it</Btn>
        </div>
      )}

      {loading ? <Spinner /> : list.length === 0 ? (
        <EmptyState title="No API keys" sub="Create a key to drive scans from scripts and CI." action={<Btn onClick={() => setModal(true)}><Plus className="h-4 w-4" /> New key</Btn>} />
      ) : (
        <div className="space-y-3">
          {list.map(k => (
            <div key={k.id} className="glass rounded-2xl p-5 flex flex-wrap items-center gap-3">
              <div className="p-2.5 rounded-xl bg-violet-50 dark:bg-violet-500/15"><Key className="h-5 w-5 text-violet-600 dark:text-violet-400" /></div>
              <div className="min-w-0 flex-1">
                <div className="font-bold text-slate-900 dark:text-white">{k.name}</div>
                <div className="text-xs text-slate-500 dark:text-slate-400 font-mono">{k.prefix}•••••••• · created {fmtDate(k.created_at)}</div>
              </div>
              <Btn variant="danger" className="!px-3 !py-2" onClick={() => setRevokeId(k.id)}><Trash2 className="h-4 w-4" /> Revoke</Btn>
            </div>
          ))}
        </div>
      )}

      <div className="mt-6 glass rounded-2xl p-5 text-sm text-slate-500 dark:text-slate-400">
        <span className="font-bold text-slate-700 dark:text-slate-200">Usage:</span>{" "}
        <code className="font-mono text-xs bg-slate-100 dark:bg-white/10 px-2 py-1 rounded">curl -H "Authorization: Bearer YOUR_KEY" /api/scans</code>
      </div>

      <Modal open={modal} onClose={() => setModal(false)} title="Create API key">
        <div className="space-y-4">
          <Field label="Key name" hint="e.g. CI pipeline, personal scripts">
            <TextInput value={name} onChange={e => setName(e.target.value)} placeholder="My integration" onKeyDown={e => e.key === "Enter" && create()} />
          </Field>
          <div className="flex justify-end gap-2">
            <Btn variant="ghost" onClick={() => setModal(false)}>Cancel</Btn>
            <Btn onClick={create} disabled={busy || !name.trim()}>{busy ? "Creating…" : "Create key"}</Btn>
          </div>
        </div>
      </Modal>

      <Confirm open={!!revokeId} onClose={() => setRevokeId(null)} danger title="Revoke API key" body="Revoke this key? Integrations using it will stop working immediately."
        onYes={() => { if (revokeId) api.apiKeys.revoke(revokeId).then(load).catch(e => alert(e.message)); }} />
    </PageWrap>
  );
}
