import { useState } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Settings as SettingsIcon, KeyRound, Gauge, Check, Bell, Key, Moon, Sun, ChevronRight } from "lucide-react";
import { useTheme } from "../context/ThemeContext";
import { PageHeader, PageWrap, Btn, Field, TextInput } from "../components/ui";

export default function Settings() {
  const { theme, toggle } = useTheme();
  const [saved, setSaved] = useState("");
  const [rate, setRate] = useState(() => Number(localStorage.getItem("sx_def_rate") || 10));
  const [conc, setConc] = useState(() => Number(localStorage.getItem("sx_def_conc") || 30));
  const [depth, setDepth] = useState(() => Number(localStorage.getItem("sx_def_depth") || 2));

  const save = () => {
    localStorage.setItem("sx_def_rate", String(rate));
    localStorage.setItem("sx_def_conc", String(conc));
    localStorage.setItem("sx_def_depth", String(depth));
    setSaved("Saved ✓"); setTimeout(() => setSaved(""), 2000);
  };

  const links = [
    { to: "/notifications", icon: Bell, tint: "bg-amber-100 dark:bg-amber-500/15", tc: "text-amber-600 dark:text-amber-400", label: "Notification channels", desc: "Webhooks, email, Slack, Discord" },
    { to: "/api-keys", icon: Key, tint: "bg-violet-100 dark:bg-violet-500/15", tc: "text-violet-600 dark:text-violet-400", label: "API keys", desc: "Programmatic access tokens" },
    { to: "/auth-profiles", icon: KeyRound, tint: "bg-blue-100 dark:bg-blue-500/15", tc: "text-blue-600 dark:text-blue-400", label: "Auth profiles", desc: "Stored logins for scans" },
  ];

  return (
    <PageWrap>
      <PageHeader icon={<SettingsIcon className="h-6 w-6 text-white" />} title="Settings" sub="Tune SentinelX to your workflow" />

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
        className="glass rounded-[1.75rem] p-7 mb-5">
        <div className="flex items-center gap-3 mb-1">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-indigo-100 dark:bg-indigo-500/15">
            {theme === "dark" ? <Moon className="h-5 w-5 text-indigo-600 dark:text-indigo-400" /> : <Sun className="h-5 w-5 text-indigo-600" />}
          </div>
          <h3 className="text-lg font-bold text-slate-900 dark:text-white">Appearance</h3>
        </div>
        <p className="text-sm text-slate-500 dark:text-slate-400 mb-5 ml-12">Theme is saved on this device.</p>
        <div className="grid grid-cols-2 gap-3 ml-0 sm:ml-12">
          {(["light", "dark"] as const).map(t => (
            <button key={t} onClick={() => theme !== t && toggle()}
              className={`rounded-2xl border-2 p-4 text-left transition-all ${theme === t ? "border-indigo-500 bg-indigo-50/60 dark:bg-indigo-500/10" : "border-slate-200 dark:border-white/10 hover:border-slate-300"}`}>
              <div className={`h-12 rounded-xl mb-2.5 ${t === "light" ? "bg-white border border-slate-200" : "bg-slate-900 border border-white/10"}`} />
              <div className="text-sm font-bold text-slate-800 dark:text-slate-100 capitalize">{t}</div>
            </button>
          ))}
        </div>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 }}
        className="glass rounded-[1.75rem] p-7 mb-5">
        <div className="flex items-center gap-3 mb-5">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-blue-100 dark:bg-blue-500/15"><Gauge className="h-5 w-5 text-blue-600 dark:text-blue-400" /></div>
          <h3 className="text-lg font-bold text-slate-900 dark:text-white">Scan defaults</h3>
        </div>
        <div className="grid sm:grid-cols-3 gap-4 mb-6">
          <Field label="Rate /s"><TextInput type="number" min={1} max={100} value={rate} onChange={e => setRate(Number(e.target.value))} /></Field>
          <Field label="Concurrency"><TextInput type="number" min={1} max={100} value={conc} onChange={e => setConc(Number(e.target.value))} /></Field>
          <Field label="Crawl depth"><TextInput type="number" min={0} max={5} value={depth} onChange={e => setDepth(Number(e.target.value))} /></Field>
        </div>
        <Btn onClick={save}>{saved ? <><Check className="h-5 w-5" />{saved}</> : "Save settings"}</Btn>
      </motion.div>

      <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.14 }}
        className="glass rounded-[1.75rem] p-7">
        <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-4">Integrations</h3>
        <div className="space-y-2.5">
          {links.map(l => (
            <Link key={l.to} to={l.to} className="flex items-center gap-4 p-4 rounded-2xl hover:bg-slate-50 dark:hover:bg-white/5 transition-colors group">
              <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${l.tint}`}><l.icon className={`h-5 w-5 ${l.tc}`} /></div>
              <div className="flex-1 min-w-0">
                <div className="font-bold text-slate-900 dark:text-white text-sm">{l.label}</div>
                <div className="text-xs text-slate-500 dark:text-slate-400">{l.desc}</div>
              </div>
              <ChevronRight className="h-5 w-5 text-slate-300 group-hover:text-indigo-500 group-hover:translate-x-1 transition-all" />
            </Link>
          ))}
        </div>
      </motion.div>
    </PageWrap>
  );
}
