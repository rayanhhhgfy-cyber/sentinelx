import { useEffect, useState } from "react";
import { Bell, Plus, Pencil, Trash2, Send, Webhook, Mail, MessageSquare } from "lucide-react";
import { api, CHANNEL_EVENTS } from "../lib/api";
import type { Channel } from "../lib/api";
import { PageHeader, PageWrap, Btn, Modal, Field, TextInput, TextArea, Select, Confirm, EmptyState, Spinner } from "../components/ui";

const TYPES = [
  { id: "webhook", label: "Webhook", icon: Webhook, fields: [{ k: "url", label: "Webhook URL", ph: "https://hooks.example.com/…" }] },
  { id: "email", label: "Email", icon: Mail, fields: [{ k: "to", label: "Recipient", ph: "alerts@example.com" }] },
  { id: "slack", label: "Slack", icon: MessageSquare, fields: [{ k: "webhook_url", label: "Slack webhook URL", ph: "https://hooks.slack.com/…" }] },
  { id: "discord", label: "Discord", icon: MessageSquare, fields: [{ k: "webhook_url", label: "Discord webhook URL", ph: "https://discord.com/api/webhooks/…" }] },
];

export default function Notifications() {
  const [list, setList] = useState<Channel[]>([]);
  const [loading, setLoading] = useState(true);
  const [modal, setModal] = useState(false);
  const [editing, setEditing] = useState<Channel | null>(null);
  const [type, setType] = useState("webhook");
  const [cfg, setCfg] = useState<Record<string, string>>({});
  const [events, setEvents] = useState<string[]>([...CHANNEL_EVENTS]);
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [testing, setTesting] = useState("");

  const load = () => api.channels.list().then(setList).catch(() => {}).finally(() => setLoading(false));
  useEffect(() => { load(); }, []);

  const tdef = TYPES.find(t => t.id === type)!;
  const openNew = () => { setEditing(null); setType("webhook"); setCfg({}); setEvents([...CHANNEL_EVENTS]); setModal(true); };
  const openEdit = (c: Channel) => {
    setEditing(c); setType(c.type);
    setCfg(Object.fromEntries(Object.entries(c.config).map(([k, v]) => [k, String(v)])));
    setEvents([...c.events]); setModal(true);
  };
  const toggleEv = (e: string) => setEvents(p => p.includes(e) ? p.filter(x => x !== e) : [...p, e]);
  const save = async () => {
    setBusy(true);
    try {
      const body = { type, config: cfg, events };
      if (editing) await api.channels.update(editing.id, body);
      else await api.channels.create(body);
      setModal(false); load();
    } catch (e: any) { alert(e.message); } finally { setBusy(false); }
  };
  const test = async (id: string) => {
    setTesting(id);
    try { const r = await api.channels.test(id); alert(r.ok ? "Test notification sent ✓" : "Test failed"); }
    catch (e: any) { alert("Test failed: " + e.message); } finally { setTesting(""); }
  };

  return (
    <PageWrap>
      <PageHeader icon={<Bell className="h-6 w-6 text-white" />} title="Notifications" sub="Alert channels for scan events"
        actions={<Btn onClick={openNew}><Plus className="h-4 w-4" /> New channel</Btn>} />
      {loading ? <Spinner /> : list.length === 0 ? (
        <EmptyState title="No channels yet" sub="Get alerted when scans finish or critical findings appear." action={<Btn onClick={openNew}><Plus className="h-4 w-4" /> New channel</Btn>} />
      ) : (
        <div className="space-y-3">
          {list.map(c => {
            const td = TYPES.find(t => t.id === c.type);
            return (
              <div key={c.id} className="glass card-hover rounded-2xl p-5 flex flex-wrap items-center gap-3">
                <div className="p-2.5 rounded-xl bg-indigo-50 dark:bg-indigo-500/15">
                  {td ? <td.icon className="h-5 w-5 text-indigo-600 dark:text-indigo-400" /> : <Bell className="h-5 w-5 text-indigo-600" />}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="font-bold text-slate-900 dark:text-white capitalize">{c.type}</div>
                  <div className="text-xs text-slate-500 dark:text-slate-400 truncate">{Object.values(c.config).map(String).join(" · ")}</div>
                  <div className="flex flex-wrap gap-1.5 mt-2">
                    {c.events.map(e => (
                      <span key={e} className="text-[10px] font-bold uppercase tracking-wide px-2 py-0.5 rounded-full bg-emerald-50 dark:bg-emerald-500/10 text-emerald-700 dark:text-emerald-300">{e.replace(/_/g, " ")}</span>
                    ))}
                  </div>
                </div>
                <div className="flex gap-1.5">
                  <Btn variant="outline" className="!px-3 !py-2" onClick={() => test(c.id)} disabled={testing === c.id}>
                    <Send className="h-4 w-4" /> {testing === c.id ? "…" : "Test"}
                  </Btn>
                  <Btn variant="ghost" className="!px-3 !py-2" onClick={() => openEdit(c)}><Pencil className="h-4 w-4" /></Btn>
                  <Btn variant="danger" className="!px-3 !py-2" onClick={() => setConfirmId(c.id)}><Trash2 className="h-4 w-4" /></Btn>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <Modal open={modal} onClose={() => setModal(false)} title={editing ? "Edit channel" : "New notification channel"}>
        <div className="space-y-4">
          <Field label="Channel type">
            <Select value={type} onChange={e => { setType(e.target.value); setCfg({}); }}>
              {TYPES.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
            </Select>
          </Field>
          {tdef.fields.map(f => (
            <Field key={f.k} label={f.label}>
              {f.k === "url" || f.k.includes("webhook") ? (
                <TextArea rows={2} value={cfg[f.k] || ""} onChange={e => setCfg({ ...cfg, [f.k]: e.target.value })} placeholder={f.ph} className="font-mono" />
              ) : (
                <TextInput value={cfg[f.k] || ""} onChange={e => setCfg({ ...cfg, [f.k]: e.target.value })} placeholder={f.ph} />
              )}
            </Field>
          ))}
          <div>
            <span className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Events</span>
            <div className="mt-2 flex flex-wrap gap-2">
              {CHANNEL_EVENTS.map(e => (
                <button key={e} onClick={() => toggleEv(e)}
                  className={`px-3 py-1.5 rounded-xl text-xs font-bold border-2 transition-all ${events.includes(e) ? "bg-indigo-600 border-indigo-600 text-white" : "border-slate-200 dark:border-white/10 text-slate-500 dark:text-slate-400"}`}>
                  {e.replace(/_/g, " ")}
                </button>
              ))}
            </div>
          </div>
          <div className="flex justify-end gap-2">
            <Btn variant="ghost" onClick={() => setModal(false)}>Cancel</Btn>
            <Btn onClick={save} disabled={busy}>{busy ? "Saving…" : "Save channel"}</Btn>
          </div>
        </div>
      </Modal>

      <Confirm open={!!confirmId} onClose={() => setConfirmId(null)} danger title="Delete channel" body="Delete this notification channel?"
        onYes={() => { if (confirmId) api.channels.remove(confirmId).then(load).catch(e => alert(e.message)); }} />
    </PageWrap>
  );
}
