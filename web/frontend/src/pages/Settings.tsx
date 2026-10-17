import { useState } from "react";
import { motion } from "framer-motion";
import { Settings as SettingsIcon, KeyRound, Gauge, Check } from "lucide-react";

export default function Settings() {
  const [saved, setSaved] = useState("");
  const save = () => { setSaved("Saved"); setTimeout(() => setSaved(""), 2000); };

  return (
    <div className="min-h-[calc(100vh-4rem)] px-4 sm:px-6 py-10 bg-slate-50">
      <div className="mx-auto max-w-2xl">
        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="flex items-center gap-3 mb-8">
          <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-500 shadow-lg shadow-indigo-500/25">
            <SettingsIcon className="h-6 w-6 text-white" />
          </div>
          <h1 className="text-3xl font-extrabold text-slate-900 tracking-tight">Settings</h1>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.08 }}
          className="glass rounded-[1.75rem] p-7 mb-5">
          <div className="flex items-center gap-3 mb-1">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-violet-100"><KeyRound className="h-5 w-5 text-violet-600" /></div>
            <h3 className="text-lg font-bold text-slate-900">AI enhancement keys</h3>
          </div>
          <p className="text-sm text-slate-500 mb-5 ml-12">Read from <code className="font-mono text-xs bg-slate-100 px-1.5 py-0.5 rounded">OPENAI_API_KEY</code> / <code className="font-mono text-xs bg-slate-100 px-1.5 py-0.5 rounded">ANTHROPIC_API_KEY</code> on the server.</p>
          <div className="space-y-4">
            <label className="block">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-500">OpenAI key</span>
              <input type="password" placeholder="sk-…" className="mt-1.5 w-full px-4 py-3 rounded-xl bg-slate-50 border border-slate-200 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all" />
            </label>
            <label className="block">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-500">Anthropic key</span>
              <input type="password" placeholder="sk-ant-…" className="mt-1.5 w-full px-4 py-3 rounded-xl bg-slate-50 border border-slate-200 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all" />
            </label>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.14 }}
          className="glass rounded-[1.75rem] p-7">
          <div className="flex items-center gap-3 mb-5">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-blue-100"><Gauge className="h-5 w-5 text-blue-600" /></div>
            <h3 className="text-lg font-bold text-slate-900">Scan defaults</h3>
          </div>
          <div className="grid sm:grid-cols-3 gap-4 mb-6">
            {[["Concurrency", 30], ["Rate /s", 10], ["Depth", 2]].map(([l, v]) => (
              <label key={l as string} className="block">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-500">{l}</span>
                <input type="number" defaultValue={v as number} className="mt-1.5 w-full px-4 py-3 rounded-xl bg-slate-50 border border-slate-200 font-semibold focus:outline-none focus:ring-2 focus:ring-indigo-500 transition-all" />
              </label>
            ))}
          </div>
          <motion.button whileTap={{ scale: 0.98 }} onClick={save}
            className="inline-flex items-center gap-2 px-7 py-3.5 rounded-xl text-white font-semibold bg-gradient-to-r from-indigo-600 to-violet-600 shadow-lg shadow-indigo-600/25 hover:-translate-y-0.5 transition-all">
            {saved ? <><Check className="h-5 w-5" />{saved} ✓</> : "Save settings"}
          </motion.button>
        </motion.div>
      </div>
    </div>
  );
}
