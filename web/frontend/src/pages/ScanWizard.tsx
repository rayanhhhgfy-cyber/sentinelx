import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Globe, Layers, KeyRound, SlidersHorizontal, ClipboardCheck, ArrowLeft, ArrowRight, Check, Rocket, Loader2 } from "lucide-react";
import { api, SCAN_MODULES } from "../lib/api";
import type { Template, Target, AuthProfile } from "../lib/api";
import { PageWrap, Btn, Field, TextInput, TextArea, Select, Spinner } from "../components/ui";

const STEPS = [
  { id: 0, label: "Target", icon: Globe },
  { id: 1, label: "Template", icon: Layers },
  { id: 2, label: "Auth", icon: KeyRound },
  { id: 3, label: "Advanced", icon: SlidersHorizontal },
  { id: 4, label: "Review", icon: ClipboardCheck },
];

export default function ScanWizard() {
  const nav = useNavigate();
  const [params] = useSearchParams();
  const [step, setStep] = useState(0);
  const [loading, setLoading] = useState(true);
  const [targets, setTargets] = useState<Target[]>([]);
  const [templates, setTemplates] = useState<Template[]>([]);
  const [profiles, setProfiles] = useState<AuthProfile[]>([]);
  const [busy, setBusy] = useState(false);

  const [target, setTarget] = useState("");
  const [confirmOwn, setConfirmOwn] = useState(false);
  const [templateId, setTemplateId] = useState("");
  const [modules, setModules] = useState<string[]>([...SCAN_MODULES]);
  const [authProfileId, setAuthProfileId] = useState("");
  const [rate, setRate] = useState(10);
  const [concurrency, setConcurrency] = useState(30);
  const [userAgent, setUserAgent] = useState("");
  const [customHeaders, setCustomHeaders] = useState("");
  const [customCookies, setCustomCookies] = useState("");
  const [excludePaths, setExcludePaths] = useState("");

  useEffect(() => {
    Promise.all([api.targets.list(), api.templates.list(), api.authProfiles.list()])
      .then(([t, tm, ap]) => {
        setTargets(t); setTemplates(tm); setProfiles(ap);
        const tpl = params.get("template");
        if (tpl) { setTemplateId(tpl); const found = tm.find(x => x.id === tpl); if (found) { setModules([...found.modules]); setRate(found.rate_limit); } }
      })
      .catch(() => {}).finally(() => setLoading(false));
  }, []);

  const tpl = templates.find(t => t.id === templateId);
  const pickTemplate = (id: string) => {
    setTemplateId(id);
    if (!id) { setModules([...SCAN_MODULES]); return; }
    const f = templates.find(t => t.id === id);
    if (f) { setModules([...f.modules]); setRate(f.rate_limit); }
  };
  const toggleMod = (m: string) => setModules(p => p.includes(m) ? p.filter(x => x !== m) : [...p, m]);

  const parseKV = (s: string) => {
    const o: Record<string, string> = {};
    s.split("\n").forEach(l => { const i = l.indexOf(":"); if (i > 0) o[l.slice(0, i).trim()] = l.slice(i + 1).trim(); });
    return o;
  };

  const launch = async () => {
    if (!target.trim() || !confirmOwn) return;
    setBusy(true);
    try {
      const r = await api.startScan({
        target: target.trim(), confirm_own: true, modules,
        rate_limit: rate, concurrency,
        ...(templateId ? { template_id: templateId } : {}),
        ...(authProfileId ? { auth_profile_id: authProfileId } : {}),
        ...(userAgent.trim() ? { user_agent: userAgent.trim() } : {}),
        custom_headers: parseKV(customHeaders), custom_cookies: parseKV(customCookies),
        exclude_paths: excludePaths.split("\n").map(s => s.trim()).filter(Boolean),
        rate_limit_profile: "default",
      });
      nav(`/scan/${r.scan_id}`);
    } catch (e: any) { alert("Failed: " + e.message); setBusy(false); }
  };

  const canNext = step === 0 ? target.trim() && confirmOwn : step === 1 ? modules.length > 0 : true;

  if (loading) return <PageWrap><Spinner label="Loading wizard…" /></PageWrap>;

  return (
    <PageWrap>
      <div className="mx-auto max-w-3xl">
        <div className="text-center mb-8">
          <h1 className="text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight">New scan</h1>
          <p className="text-slate-500 dark:text-slate-400 text-sm mt-1">Configure every detail before launch.</p>
        </div>

        <div className="flex items-center justify-between mb-8 px-1">
          {STEPS.map((s, i) => (
            <div key={s.id} className="flex flex-col items-center gap-1.5 flex-1">
              <button onClick={() => i < step && setStep(i)}
                className={`flex h-10 w-10 items-center justify-center rounded-2xl transition-all ${i < step ? "bg-emerald-500 text-white" : i === step ? "bg-gradient-to-br from-indigo-500 to-violet-500 text-white shadow-lg shadow-indigo-500/25" : "bg-slate-100 dark:bg-white/10 text-slate-400"}`}>
                {i < step ? <Check className="h-5 w-5" /> : <s.icon className="h-5 w-5" />}
              </button>
              <span className={`text-[10px] font-bold uppercase tracking-wide ${i === step ? "text-indigo-600 dark:text-indigo-400" : "text-slate-400"}`}>{s.label}</span>
            </div>
          ))}
        </div>

        <AnimatePresence mode="wait">
          <motion.div key={step} initial={{ opacity: 0, x: 24 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -24 }}
            transition={{ duration: 0.22 }} className="glass rounded-[1.75rem] p-6 sm:p-9">

            {step === 0 && (
              <div className="space-y-5">
                <Field label="Target URL">
                  <TextInput value={target} onChange={e => setTarget(e.target.value)} placeholder="https://example.com" className="font-mono !py-4 !text-base" />
                </Field>
                {targets.length > 0 && (
                  <Field label="Or pick a saved target">
                    <Select value="" onChange={e => { const t = targets.find(x => x.id === e.target.value); if (t) setTarget(t.url); }}>
                      <option value="">Saved targets…</option>
                      {targets.map(t => <option key={t.id} value={t.id}>{t.name} — {t.url}</option>)}
                    </Select>
                  </Field>
                )}
                <label className="flex items-start gap-3 cursor-pointer bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/20 rounded-2xl p-4">
                  <input type="checkbox" checked={confirmOwn} onChange={e => setConfirmOwn(e.target.checked)} className="mt-1 h-5 w-5 rounded accent-indigo-600" />
                  <span className="text-sm text-slate-600 dark:text-slate-300">I confirm I own this target or have <b>explicit written permission</b> to test it.</span>
                </label>
              </div>
            )}

            {step === 1 && (
              <div className="space-y-5">
                <Field label="Template (optional)">
                  <Select value={templateId} onChange={e => pickTemplate(e.target.value)}>
                    <option value="">Custom — pick modules manually</option>
                    {templates.map(t => <option key={t.id} value={t.id}>{t.name} ({t.modules.length} modules)</option>)}
                  </Select>
                </Field>
                <div>
                  <span className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400">Modules ({modules.length})</span>
                  <div className="mt-2.5 flex flex-wrap gap-2">
                    {SCAN_MODULES.map(m => (
                      <button key={m} onClick={() => toggleMod(m)}
                        className={`px-3.5 py-2 rounded-xl text-xs font-mono font-bold border-2 transition-all ${modules.includes(m) ? "bg-indigo-600 border-indigo-600 text-white shadow-md shadow-indigo-600/20" : "border-slate-200 dark:border-white/10 text-slate-500 dark:text-slate-400 hover:border-indigo-300"}`}>
                        {m}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {step === 2 && (
              <div className="space-y-5">
                <Field label="Auth profile (optional)" hint="Scan authenticated areas of the app">
                  <Select value={authProfileId} onChange={e => setAuthProfileId(e.target.value)}>
                    <option value="">No authentication</option>
                    {profiles.map(p => <option key={p.id} value={p.id}>{p.name} ({p.username})</option>)}
                  </Select>
                </Field>
                {profiles.length === 0 && <p className="text-sm text-slate-400">No auth profiles yet — create one under Manage → Auth profiles.</p>}
              </div>
            )}

            {step === 3 && (
              <div className="space-y-5">
                <div className="grid sm:grid-cols-2 gap-4">
                  <Field label="Rate limit (req/s)"><TextInput type="number" min={1} max={100} value={rate} onChange={e => setRate(Number(e.target.value))} /></Field>
                  <Field label="Concurrency"><TextInput type="number" min={1} max={100} value={concurrency} onChange={e => setConcurrency(Number(e.target.value))} /></Field>
                </div>
                <Field label="User agent" hint="Blank = default SentinelX UA"><TextInput value={userAgent} onChange={e => setUserAgent(e.target.value)} placeholder="Mozilla/5.0 …" className="font-mono" /></Field>
                <div className="grid sm:grid-cols-2 gap-4">
                  <Field label="Custom headers" hint="One per line: Name: value"><TextArea rows={3} value={customHeaders} onChange={e => setCustomHeaders(e.target.value)} placeholder={"X-Api-Key: abc\nX-Debug: 1"} className="font-mono" /></Field>
                  <Field label="Custom cookies" hint="One per line: name: value"><TextArea rows={3} value={customCookies} onChange={e => setCustomCookies(e.target.value)} placeholder={"session: xyz"} className="font-mono" /></Field>
                </div>
                <Field label="Exclude paths" hint="One prefix per line — never requested"><TextArea rows={2} value={excludePaths} onChange={e => setExcludePaths(e.target.value)} placeholder={"/logout\n/admin/delete"} className="font-mono" /></Field>
              </div>
            )}

            {step === 4 && (
              <div className="space-y-3 text-sm">
                {[
                  ["Target", target], ["Modules", `${modules.length} selected`], ["Template", tpl?.name || "Custom"],
                  ["Auth", profiles.find(p => p.id === authProfileId)?.name || "None"],
                  ["Rate", `${rate}/s · ${concurrency} concurrent`],
                  ["User-Agent", userAgent || "default"],
                  ["Excluded paths", excludePaths.split("\n").filter(Boolean).length || "none"],
                ].map(([k, v]) => (
                  <div key={k} className="flex justify-between gap-4 px-4 py-3 rounded-2xl bg-slate-50 dark:bg-white/5">
                    <span className="font-bold text-slate-500 dark:text-slate-400 uppercase text-xs tracking-wider pt-0.5">{k}</span>
                    <span className="font-mono text-slate-800 dark:text-slate-100 text-right break-all">{v}</span>
                  </div>
                ))}
              </div>
            )}
          </motion.div>
        </AnimatePresence>

        <div className="flex justify-between mt-6">
          <Btn variant="ghost" onClick={() => step > 0 ? setStep(step - 1) : nav("/dashboard")}>
            <ArrowLeft className="h-4 w-4" /> {step > 0 ? "Back" : "Cancel"}
          </Btn>
          {step < 4 ? (
            <Btn onClick={() => setStep(step + 1)} disabled={!canNext}>Next <ArrowRight className="h-4 w-4" /></Btn>
          ) : (
            <Btn onClick={launch} disabled={busy || !canNext} className="!px-8 !py-3.5">
              {busy ? <Loader2 className="h-5 w-5 animate-spin" /> : <Rocket className="h-5 w-5" />}
              {busy ? "Launching…" : "Launch scan"}
            </Btn>
          )}
        </div>
      </div>
    </PageWrap>
  );
}
