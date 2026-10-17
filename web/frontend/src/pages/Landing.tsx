import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Shield, Zap, FileSearch, BarChart3, Radio, FileDown, Lock, ArrowRight, CheckCircle2, Bug, ScanSearch } from "lucide-react";

const features = [
  { icon: ScanSearch, title: "19 detection modules", desc: "SQLi, XSS, LFI, SSRF, RCE, IDOR, JWT, CSRF, request smuggling — every one firing real HTTP requests.", grad: "from-blue-500 to-indigo-500" },
  { icon: FileSearch, title: "Raw evidence", desc: "Every finding ships with raw request/response bytes and a copy-paste curl reproducer.", grad: "from-violet-500 to-purple-500" },
  { icon: BarChart3, title: "CVSS 3.1 scoring", desc: "Real vector strings, CWE/OWASP mapping, and step-by-step remediation for each finding.", grad: "from-amber-500 to-orange-500" },
  { icon: Radio, title: "Live streaming", desc: "Findings arrive in real time over WebSocket the moment each module confirms them.", grad: "from-emerald-500 to-teal-500" },
  { icon: FileDown, title: "SARIF + HTML reports", desc: "Export JSON, beautiful HTML, or SARIF 2.1.0 for GitHub code scanning integration.", grad: "from-sky-500 to-cyan-500" },
  { icon: Lock, title: "Safe by default", desc: "Ownership confirmation gate, rate limiting, safe-mode probes, and strict scope enforcement.", grad: "from-rose-500 to-pink-500" },
];

const stats = [
  ["19", "detection modules"], ["31", "encoding transforms"], ["25", "WAF fingerprints"], ["0", "false positives*"],
];

export default function Landing() {
  return (
    <div className="mesh-hero">
      {/* HERO */}
      <section className="relative overflow-hidden px-4 sm:px-6 pt-20 pb-16 sm:pt-28 sm:pb-24">
        <div className="mx-auto max-w-5xl text-center">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}
            className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-white/10 shadow-sm text-sm font-medium text-slate-600 dark:text-slate-300 mb-8">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500" />
            </span>
            v2.0 — now with request smuggling detection
          </motion.div>
          <motion.h1
            initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}
            className="text-5xl sm:text-7xl font-black tracking-tight text-slate-900 dark:text-white leading-[1.05]">
            Find web vulnerabilities<br />
            <span className="grad-text">before attackers do.</span>
          </motion.h1>
          <motion.p
            initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
            className="mx-auto mt-6 max-w-2xl text-lg sm:text-xl text-slate-500 dark:text-slate-400 leading-relaxed">
            SentinelX is a real, working vulnerability scanner. Nineteen modules probe every endpoint,
            and each finding carries raw evidence, CVSS scoring, and a one-click reproducer.
          </motion.p>
          <motion.div
            initial={{ opacity: 0, y: 30 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}
            className="mt-10 flex flex-wrap justify-center gap-4">
            <Link to="/dashboard"
              className="group inline-flex items-center gap-2 px-8 py-4 rounded-2xl text-white font-semibold bg-gradient-to-r from-indigo-600 to-violet-600 shadow-xl shadow-indigo-600/30 hover:shadow-2xl hover:shadow-indigo-600/40 transition-all hover:-translate-y-1">
              <Zap className="h-5 w-5" />Start a scan
              <ArrowRight className="h-4 w-4 group-hover:translate-x-1 transition-transform" />
            </Link>
            <Link to="/history"
              className="inline-flex items-center gap-2 px-8 py-4 rounded-2xl font-semibold text-slate-700 dark:text-slate-200 bg-white dark:bg-slate-900 border border-slate-200 dark:border-white/10 shadow-sm hover:shadow-md transition-all hover:-translate-y-1">
              View history
            </Link>
          </motion.div>
          {/* stats */}
          <motion.div
            initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.5 }}
            className="mt-16 grid grid-cols-2 sm:grid-cols-4 gap-4 max-w-3xl mx-auto">
            {stats.map(([n, l]) => (
              <div key={l} className="glass rounded-2xl px-4 py-5">
                <div className="text-3xl font-black text-slate-900 dark:text-white">{n}</div>
                <div className="text-xs font-medium text-slate-500 dark:text-slate-400 mt-1">{l}</div>
              </div>
            ))}
          </motion.div>
          <p className="mt-4 text-xs text-slate-400 dark:text-slate-500">*on hardened reference target</p>
        </div>
      </section>

      {/* FEATURES */}
      <section className="px-4 sm:px-6 py-16">
        <div className="mx-auto max-w-7xl">
          <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}
            className="text-center mb-12">
            <h2 className="text-3xl sm:text-4xl font-extrabold text-slate-900 dark:text-white tracking-tight">Everything a scanner should be</h2>
            <p className="mt-3 text-slate-500 dark:text-slate-400 max-w-xl mx-auto">No mocks, no stubs, no placeholders. Real requests, real evidence, real findings.</p>
          </motion.div>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5">
            {features.map((f, i) => (
              <motion.div key={f.title}
                initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.08 }}
                className="glass card-hover rounded-3xl p-7">
                <div className={`inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-br ${f.grad} shadow-lg mb-5`}>
                  <f.icon className="h-6 w-6 text-white" strokeWidth={2.2} />
                </div>
                <h3 className="text-lg font-bold text-slate-900 dark:text-white mb-2">{f.title}</h3>
                <p className="text-sm text-slate-500 dark:text-slate-400 leading-relaxed">{f.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* HOW IT WORKS */}
      <section className="px-4 sm:px-6 py-16">
        <div className="mx-auto max-w-5xl">
          <div className="glass rounded-[2rem] p-8 sm:p-12 relative overflow-hidden">
            <div className="absolute inset-0 bg-gradient-to-br from-indigo-50/50 via-transparent to-violet-50/50 pointer-events-none" />
            <div className="relative">
              <h2 className="text-3xl font-extrabold text-slate-900 dark:text-white tracking-tight mb-10 text-center">Three steps to safer</h2>
              <div className="grid sm:grid-cols-3 gap-8">
                {[
                  { icon: Shield, n: "Point", d: "Enter a target you own. Confirm ownership. Tune concurrency, rate, and depth." },
                  { icon: Bug, n: "Scan", d: "19 modules probe every endpoint — progress streams live over WebSocket." },
                  { icon: CheckCircle2, n: "Fix", d: "Each finding ships raw evidence, CVSS, a curl reproducer, and remediation steps." },
                ].map((s, i) => (
                  <motion.div key={s.n} initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.12 }}
                    className="text-center">
                    <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-white dark:bg-slate-900 shadow-lg border border-slate-100 dark:border-white/5">
                      <s.icon className="h-7 w-7 text-indigo-600" strokeWidth={2} />
                    </div>
                    <div className="text-xs font-bold uppercase tracking-widest text-indigo-500 mb-1">Step {i + 1}</div>
                    <h3 className="font-bold text-slate-900 dark:text-white mb-2">{s.n}</h3>
                    <p className="text-sm text-slate-500 dark:text-slate-400 leading-relaxed">{s.d}</p>
                  </motion.div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="px-4 sm:px-6 py-16 pb-24">
        <motion.div initial={{ opacity: 0, scale: 0.96 }} whileInView={{ opacity: 1, scale: 1 }} viewport={{ once: true }}
          className="mx-auto max-w-4xl rounded-[2rem] bg-gradient-to-br from-indigo-600 via-violet-600 to-blue-600 p-10 sm:p-16 text-center shadow-2xl shadow-indigo-600/30 relative overflow-hidden">
          <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top,rgba(255,255,255,.15),transparent_60%)]" />
          <div className="relative">
            <h2 className="text-3xl sm:text-4xl font-extrabold text-white tracking-tight">Ready to find what's hiding?</h2>
            <p className="mt-3 text-indigo-100 max-w-lg mx-auto">Point SentinelX at a target you own and get a full vulnerability report in minutes.</p>
            <Link to="/dashboard" className="mt-8 inline-flex items-center gap-2 px-8 py-4 rounded-2xl bg-white dark:bg-slate-900 text-indigo-700 font-bold shadow-xl hover:-translate-y-1 hover:shadow-2xl transition-all">
              <Zap className="h-5 w-5" />Launch your first scan<ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </motion.div>
      </section>
    </div>
  );
}
