import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Radar, Target, FileWarning, X, ArrowRight, ArrowLeft, PartyPopper } from "lucide-react";
import { Btn } from "./ui";

const STEPS = [
  { icon: Radar, title: "Welcome to SentinelX", body: "Launch a full vulnerability scan against any target you own. Every finding ships with raw request/response evidence, CVSS scores, and a curl reproducer." },
  { icon: Target, title: "Organize targets", body: "Save your targets, import them from CSV, and re-scan in one click. Templates let you reuse module sets and rate limits." },
  { icon: FileWarning, title: "Triage findings", body: "Use the kanban board to move findings through open → in progress → resolved → verified. Add notes, assign owners, and track SLA breaches." },
  { icon: PartyPopper, title: "You're set", body: "Press Ctrl+K anytime for the command palette, or ? for keyboard shortcuts. Happy hunting." },
];

export default function OnboardingTour() {
  const nav = useNavigate();
  const [done, setDone] = useState(() => localStorage.getItem("sx_onboarded") === "1");
  const [step, setStep] = useState(0);
  if (done) return null;
  const finish = (to?: string) => { localStorage.setItem("sx_onboarded", "1"); setDone(true); if (to) nav(to); };
  const S = STEPS[step];
  return (
    <AnimatePresence>
      <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
        className="fixed inset-0 z-[80] bg-slate-900/50 dark:bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
        <motion.div initial={{ scale: 0.92, y: 24 }} animate={{ scale: 1, y: 0 }} exit={{ scale: 0.92, y: 24 }}
          transition={{ type: "spring", damping: 26, stiffness: 300 }}
          className="glass rounded-[2rem] p-8 max-w-md w-full relative">
          <button onClick={() => finish()} className="absolute top-5 right-5 p-2 rounded-xl hover:bg-slate-100 dark:hover:bg-white/10" aria-label="Skip tour">
            <X className="h-5 w-5 text-slate-400" />
          </button>
          <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-500 shadow-lg shadow-indigo-500/25 mb-5">
            <S.icon className="h-7 w-7 text-white" />
          </div>
          <div className="text-xs font-bold uppercase tracking-wider text-indigo-500 mb-1.5">Step {step + 1} of {STEPS.length}</div>
          <h2 className="text-2xl font-extrabold text-slate-900 dark:text-white mb-2">{S.title}</h2>
          <p className="text-slate-500 dark:text-slate-400 text-sm leading-relaxed mb-7">{S.body}</p>
          <div className="flex items-center gap-1.5 mb-6">
            {STEPS.map((_, i) => (
              <div key={i} className={`h-1.5 rounded-full transition-all ${i === step ? "w-8 bg-indigo-500" : "w-4 bg-slate-200 dark:bg-white/15"}`} />
            ))}
          </div>
          <div className="flex justify-between">
            <Btn variant="ghost" onClick={() => step > 0 ? setStep(step - 1) : finish()}>
              {step > 0 ? <><ArrowLeft className="h-4 w-4" /> Back</> : "Skip"}
            </Btn>
            {step < STEPS.length - 1 ? (
              <Btn onClick={() => setStep(step + 1)}>Next <ArrowRight className="h-4 w-4" /></Btn>
            ) : (
              <Btn onClick={() => finish("/scan/new")}>Start scanning <ArrowRight className="h-4 w-4" /></Btn>
            )}
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
