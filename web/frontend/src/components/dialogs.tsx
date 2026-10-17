import { useEffect, useState } from "react";
import { Share2, Download, Eye, MessageSquare, Send, FileJson, FileText, FileSpreadsheet, ShieldCheck } from "lucide-react";
import { api, dlUrl } from "../lib/api";
import type { ScanComment } from "../lib/api";
import { Modal, Btn, TextInput, TextArea, Spinner, fmtDate } from "./ui";

/* ---------- share scan ---------- */
export function ShareDialog({ scanId, open, onClose }: { scanId: string; open: boolean; onClose: () => void }) {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState("");
  const share = async () => {
    if (!email.includes("@")) return;
    setBusy(true);
    try { await api.shareScan(scanId, email.trim()); setDone(email.trim()); setEmail(""); }
    catch (e: any) { alert(e.message); } finally { setBusy(false); }
  };
  return (
    <Modal open={open} onClose={onClose} title="Share scan">
      <div className="flex items-center gap-3 mb-5 text-sm text-slate-500 dark:text-slate-400">
        <Share2 className="h-5 w-5 text-indigo-500" /> The recipient gets read access to this scan and its findings.
      </div>
      {done && <p className="mb-4 text-sm font-semibold text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-200 dark:border-emerald-500/20 rounded-xl px-4 py-3">Shared with {done}</p>}
      <div className="flex gap-2">
        <TextInput value={email} onChange={e => setEmail(e.target.value)} placeholder="colleague@example.com"
          onKeyDown={e => e.key === "Enter" && share()} />
        <Btn onClick={share} disabled={busy || !email.includes("@")}>{busy ? "Sharing…" : "Share"}</Btn>
      </div>
    </Modal>
  );
}

/* ---------- export center modal ---------- */
const FORMATS = [
  { id: "json", label: "JSON", icon: FileJson, desc: "Raw machine-readable findings" },
  { id: "html", label: "HTML", icon: FileText, desc: "Styled human-readable report" },
  { id: "csv", label: "CSV", icon: FileSpreadsheet, desc: "Spreadsheet-friendly rows" },
  { id: "pdf", label: "PDF", icon: FileText, desc: "Printable executive report" },
  { id: "sarif", label: "SARIF", icon: ShieldCheck, desc: "Static-analysis interchange format" },
];

export function ExportModal({ scanId, target, open, onClose }: { scanId: string; target: string; open: boolean; onClose: () => void }) {
  const [preview, setPreview] = useState<string | null>(null);
  const [previewFmt, setPreviewFmt] = useState("");
  const doPreview = async (fmt: string) => {
    if (fmt === "pdf" || fmt === "html") { setPreview(null); setPreviewFmt(""); return; }
    try {
      const r = await fetch(dlUrl(`/api/scans/${scanId}/export/${fmt}`), { headers: { Authorization: "Bearer " + localStorage.getItem("sx_token") } });
      const t = await r.text();
      setPreview(t.slice(0, 4000)); setPreviewFmt(fmt);
    } catch (e: any) { alert(e.message); }
  };
  return (
    <Modal open={open} onClose={onClose} title="Export scan report" wide>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-5 font-mono truncate">{target}</p>
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 mb-6">
        {FORMATS.map(f => (
          <div key={f.id} className="glass rounded-2xl p-4 text-center">
            <f.icon className="mx-auto h-7 w-7 text-indigo-500 mb-2" />
            <div className="font-extrabold text-sm text-slate-900 dark:text-white">{f.label}</div>
            <div className="text-[11px] text-slate-400 mt-1 mb-3 leading-snug">{f.desc}</div>
            <div className="flex gap-1.5 justify-center">
              {(f.id === "json" || f.id === "csv" || f.id === "sarif") && (
                <button onClick={() => doPreview(f.id)} title="Preview"
                  className="p-2 rounded-lg text-slate-500 hover:bg-indigo-50 dark:hover:bg-indigo-500/15 hover:text-indigo-600 transition-colors">
                  <Eye className="h-4 w-4" />
                </button>
              )}
              <a href={dlUrl(`/api/scans/${scanId}/export/${f.id}`)} download title="Download"
                className="p-2 rounded-lg text-slate-500 hover:bg-emerald-50 dark:hover:bg-emerald-500/15 hover:text-emerald-600 transition-colors">
                <Download className="h-4 w-4" />
              </a>
            </div>
          </div>
        ))}
      </div>
      {preview && (
        <div>
          <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2">Preview — {previewFmt.toUpperCase()}</h4>
          <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all rounded-2xl bg-slate-900 text-slate-200 p-4 font-mono text-xs leading-relaxed">{preview}</pre>
        </div>
      )}
    </Modal>
  );
}

/* ---------- scan comments ---------- */
export function ScanComments({ scanId }: { scanId: string }) {
  const [list, setList] = useState<ScanComment[]>([]);
  const [text, setText] = useState("");
  const [loading, setLoading] = useState(true);
  const load = () => api.scanComments(scanId).then(setList).catch(() => {}).finally(() => setLoading(false));
  useEffect(() => { load(); }, [scanId]);
  const send = async () => {
    if (!text.trim()) return;
    try { const c = await api.addScanComment(scanId, text.trim()); setList(p => [...p, c]); setText(""); }
    catch (e: any) { alert(e.message); }
  };
  return (
    <div className="glass rounded-3xl p-6 sm:p-8">
      <h3 className="text-lg font-extrabold text-slate-900 dark:text-white mb-1 flex items-center gap-2">
        <MessageSquare className="h-5 w-5 text-indigo-500" /> Discussion
      </h3>
      <p className="text-sm text-slate-500 dark:text-slate-400 mb-5">Coordinate with your team on this scan.</p>
      {loading ? <Spinner /> : (
        <div className="space-y-3 mb-4 max-h-80 overflow-y-auto">
          {list.map(c => (
            <div key={c.id} className="bg-slate-50 dark:bg-white/5 border border-slate-100 dark:border-white/5 rounded-2xl p-4">
              <p className="text-sm text-slate-700 dark:text-slate-200 leading-relaxed">{c.text}</p>
              <p className="text-[11px] text-slate-400 mt-2">{c.author} · {fmtDate(c.created_at)}</p>
            </div>
          ))}
          {list.length === 0 && <p className="text-sm text-slate-400">No comments yet — start the conversation.</p>}
        </div>
      )}
      <div className="flex gap-2">
        <TextArea rows={2} value={text} onChange={e => setText(e.target.value)} placeholder="Write a comment…" />
      </div>
      <div className="flex justify-end mt-2">
        <Btn onClick={send} disabled={!text.trim()}><Send className="h-4 w-4" /> Post</Btn>
      </div>
    </div>
  );
}
