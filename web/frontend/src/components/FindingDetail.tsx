import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { X, Copy, Check, MessageSquare, Send, UserPlus, Tags, ShieldAlert, CalendarClock } from "lucide-react";
import { api, FINDING_STATUSES } from "../lib/api";
import type { Finding, FindingNote, Tag } from "../lib/api";
import { Btn, Field, TextInput, TextArea, Select, Modal, SevBadge, StatusBadge } from "./ui";

export default function FindingDetail({ finding, onClose, onChanged }: {
  finding: Finding; onClose: () => void; onChanged?: () => void;
}) {
  const [copied, setCopied] = useState("");
  const [notes, setNotes] = useState<FindingNote[]>([]);
  const [noteText, setNoteText] = useState("");
  const [tags, setTags] = useState<Tag[]>([]);
  const [assignee, setAssignee] = useState(finding.assignee || "");
  const [status, setStatus] = useState(finding.status || "open");
  const [selTags, setSelTags] = useState<string[]>(finding.tags || []);
  const [riskOpen, setRiskOpen] = useState(false);
  const [riskReason, setRiskReason] = useState("");
  const [riskExpiry, setRiskExpiry] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api.findingNotes(finding.id).then(setNotes).catch(() => {});
    api.tags.list().then(setTags).catch(() => {});
  }, [finding.id]);

  const copy = (label: string, text: string) => { navigator.clipboard.writeText(text); setCopied(label); setTimeout(() => setCopied(""), 1500); };
  const refresh = () => onChanged?.();

  const addNote = async () => {
    if (!noteText.trim()) return;
    setBusy(true);
    try { const n = await api.addFindingNote(finding.id, noteText.trim()); setNotes(p => [...p, n]); setNoteText(""); refresh(); }
    catch (e: any) { alert(e.message); } finally { setBusy(false); }
  };
  const changeStatus = async (s: string) => {
    setStatus(s);
    try { await api.setFindingStatus(finding.id, s); refresh(); } catch (e: any) { alert(e.message); }
  };
  const saveAssignee = async () => {
    try { await api.setFindingAssignee(finding.id, assignee.trim()); refresh(); alert("Assignee updated"); }
    catch (e: any) { alert(e.message); }
  };
  const toggleTag = async (tagId: string) => {
    const next = selTags.includes(tagId) ? selTags.filter(t => t !== tagId) : [...selTags, tagId];
    setSelTags(next);
    try { await api.setFindingTags(finding.id, next); refresh(); } catch (e: any) { alert(e.message); }
  };
  const doAcceptRisk = async () => {
    if (!riskReason.trim() || !riskExpiry) return;
    try { await api.acceptRisk(finding.id, riskReason.trim(), riskExpiry); setRiskOpen(false); setStatus("accepted_risk"); refresh(); }
    catch (e: any) { alert(e.message); }
  };

  return (
    <>
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        onClick={onClose} className="fixed inset-0 z-40 bg-slate-900/30 dark:bg-black/60 backdrop-blur-sm" />
      <motion.aside initial={{ x: "100%" }} animate={{ x: 0 }} exit={{ x: "100%" }}
        transition={{ type: "spring", damping: 30, stiffness: 300 }}
        className="fixed top-0 right-0 bottom-0 z-50 w-full max-w-xl bg-white dark:bg-slate-900 shadow-2xl overflow-y-auto">
        <div className="sticky top-0 bg-white/90 dark:bg-slate-900/90 backdrop-blur-xl border-b border-slate-100 dark:border-white/5 px-6 py-5 flex items-center gap-3 z-10">
          <SevBadge sev={finding.severity} />
          <h2 className="flex-1 text-lg font-extrabold text-slate-900 dark:text-white truncate">{finding.type}</h2>
          <button onClick={onClose} className="p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-white/10 transition-colors" aria-label="Close">
            <X className="h-5 w-5 text-slate-500" />
          </button>
        </div>

        <div className="p-6">
          <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed bg-slate-50 dark:bg-white/5 border border-slate-100 dark:border-white/5 rounded-2xl p-4 mb-4">{finding.evidence.proof}</p>
          <div className="flex flex-wrap gap-2 mb-6 text-xs">
            <StatusBadge status={status} />
            <span className="px-3 py-1.5 rounded-full bg-slate-100 dark:bg-white/10 font-mono text-slate-600 dark:text-slate-300">{finding.cwe}</span>
            <span className="px-3 py-1.5 rounded-full bg-slate-100 dark:bg-white/10 font-mono text-slate-600 dark:text-slate-300">{finding.owasp}</span>
            <span className="px-3 py-1.5 rounded-full bg-indigo-50 dark:bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 font-mono">{finding.cvss_vector || "n/a"}</span>
            {selTags.map(tid => { const t = tags.find(x => x.id === tid); return t ? (
              <span key={tid} className="px-3 py-1.5 rounded-full font-semibold text-white" style={{ background: t.color }}>{t.name}</span>
            ) : null; })}
          </div>

          {/* triage controls */}
          <div className="glass rounded-2xl p-5 mb-6 space-y-4">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Triage</h4>
            <Field label="Status">
              <Select value={status} onChange={e => changeStatus(e.target.value)}>
                {FINDING_STATUSES.map(s => <option key={s} value={s}>{s.replace(/_/g, " ")}</option>)}
              </Select>
            </Field>
            <div className="flex gap-2">
              <div className="flex-1">
                <Field label="Assignee (email)">
                  <TextInput value={assignee} onChange={e => setAssignee(e.target.value)} placeholder="analyst@example.com" />
                </Field>
              </div>
              <div className="flex items-end">
                <Btn variant="outline" onClick={saveAssignee}><UserPlus className="h-4 w-4" /></Btn>
              </div>
            </div>
            <div>
              <span className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 flex items-center gap-1.5 mb-2">
                <Tags className="h-3.5 w-3.5" /> Tags
              </span>
              <div className="flex flex-wrap gap-2">
                {tags.map(t => (
                  <button key={t.id} onClick={() => toggleTag(t.id)}
                    className={`px-3 py-1.5 rounded-full text-xs font-bold border-2 transition-all ${selTags.includes(t.id) ? "text-white border-transparent" : "border-slate-200 dark:border-white/10 text-slate-500 dark:text-slate-400 hover:border-slate-300"}`}
                    style={selTags.includes(t.id) ? { background: t.color } : {}}>
                    {t.name}
                  </button>
                ))}
                {tags.length === 0 && <span className="text-xs text-slate-400">No tags yet — create some on the Findings page.</span>}
              </div>
            </div>
            <Btn variant="ghost" onClick={() => setRiskOpen(true)} className="w-full">
              <ShieldAlert className="h-4 w-4" /> Accept risk…
            </Btn>
          </div>

          {/* notes */}
          <div className="mb-6">
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-3 flex items-center gap-1.5">
              <MessageSquare className="h-3.5 w-3.5" /> Notes ({notes.length})
            </h4>
            <div className="space-y-2.5 mb-3">
              {notes.map(n => (
                <div key={n.id} className="bg-slate-50 dark:bg-white/5 border border-slate-100 dark:border-white/5 rounded-2xl p-4">
                  <p className="text-sm text-slate-700 dark:text-slate-200 leading-relaxed">{n.text}</p>
                  <p className="text-[11px] text-slate-400 mt-2">{n.author} · {new Date(n.created_at * 1000).toLocaleString()}</p>
                </div>
              ))}
              {notes.length === 0 && <p className="text-sm text-slate-400">No notes yet.</p>}
            </div>
            <div className="flex gap-2">
              <TextInput value={noteText} onChange={e => setNoteText(e.target.value)}
                placeholder="Add a note…" onKeyDown={e => e.key === "Enter" && addNote()} />
              <Btn onClick={addNote} disabled={busy || !noteText.trim()}><Send className="h-4 w-4" /></Btn>
            </div>
          </div>

          {/* evidence */}
          {([["Payload", finding.payload], ["Request", finding.evidence.request_raw], ["Response", finding.evidence.response_raw], ["Reproduce", finding.curl_command]] as const).map(([t, c]) => (
            <div key={t} className="mb-5">
              <div className="flex items-center justify-between mb-2">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">{t}</h4>
                <button onClick={() => copy(t, c)}
                  className="inline-flex items-center gap-1.5 text-xs font-semibold text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 px-3 py-1.5 rounded-lg hover:bg-indigo-50 dark:hover:bg-indigo-500/10 transition-colors">
                  {copied === t ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
                  {copied === t ? "Copied!" : "Copy"}
                </button>
              </div>
              <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-all rounded-2xl bg-slate-900 text-slate-200 p-4 font-mono text-xs leading-relaxed">{c || "—"}</pre>
            </div>
          ))}
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2">Remediation</h4>
          <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed bg-emerald-50/60 dark:bg-emerald-500/10 border border-emerald-100 dark:border-emerald-500/20 rounded-2xl p-4">{finding.remediation}</p>
        </div>
      </motion.aside>

      <Modal open={riskOpen} onClose={() => setRiskOpen(false)} title="Accept risk">
        <div className="space-y-4">
          <p className="text-sm text-slate-500 dark:text-slate-400">Mark this finding as an accepted risk with an expiry. It will move to <b>accepted_risk</b> status.</p>
          <Field label="Reason">
            <TextArea rows={3} value={riskReason} onChange={e => setRiskReason(e.target.value)} placeholder="Why is this risk acceptable?" />
          </Field>
          <Field label="Expires at" hint="The finding returns to open after this date.">
            <div className="relative">
              <CalendarClock className="absolute left-4 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-400" />
              <TextInput type="date" value={riskExpiry} onChange={e => setRiskExpiry(e.target.value)} className="pl-11" />
            </div>
          </Field>
          <div className="flex justify-end gap-2">
            <Btn variant="ghost" onClick={() => setRiskOpen(false)}>Cancel</Btn>
            <Btn onClick={doAcceptRisk} disabled={!riskReason.trim() || !riskExpiry}>Accept risk</Btn>
          </div>
        </div>
      </Modal>
    </>
  );
}
