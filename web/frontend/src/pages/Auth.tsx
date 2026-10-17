import { useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Shield, Mail, User, KeyRound, ArrowRight, Loader2 } from "lucide-react";
import { useAuth } from "../context/AuthContext";

export default function Auth() {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState(""); const [name, setName] = useState(""); const [pw, setPw] = useState("");
  const [err, setErr] = useState(""); const [busy, setBusy] = useState(false);
  const { login, register } = useAuth(); const nav = useNavigate();

  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setErr(""); setBusy(true);
    try {
      if (mode === "login") await login(email, pw); else await register(email, name, pw);
      nav("/dashboard");
    } catch (ex: any) { setErr(ex.message || "Something went wrong"); } finally { setBusy(false); }
  };

  return (
    <div className="mesh-hero min-h-[calc(100vh-4rem)] flex items-center justify-center px-4 py-12">
      <motion.div
        initial={{ opacity: 0, y: 30, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }}
        className="glass rounded-[2rem] p-8 sm:p-10 w-full max-w-md relative overflow-hidden">
        <div className="absolute top-0 inset-x-0 h-1.5 bg-gradient-to-r from-indigo-500 via-violet-500 to-blue-500" />
        <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-500 shadow-lg shadow-indigo-500/30 mb-6">
          <Shield className="h-7 w-7 text-white" strokeWidth={2.2} />
        </div>
        <h1 className="text-2xl font-extrabold text-slate-900 tracking-tight">
          {mode === "login" ? "Welcome back" : "Create your account"}
        </h1>
        <p className="mt-1.5 text-sm text-slate-500">
          {mode === "login" ? "Sign in to run scans and review findings." : "Join SentinelX and start scanning in seconds."}
        </p>
        <form onSubmit={submit} className="mt-7 space-y-4">
          {mode === "register" && (
            <label className="block">
              <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Name</span>
              <div className="relative mt-1.5">
                <User className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4.5 w-4.5 h-5 w-5 text-slate-400" />
                <input value={name} onChange={e => setName(e.target.value)} required placeholder="Ada Lovelace"
                  className="w-full pl-11 pr-4 py-3 rounded-xl bg-slate-50 border border-slate-200 text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-all" />
              </div>
            </label>
          )}
          <label className="block">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Email</span>
            <div className="relative mt-1.5">
              <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400" />
              <input type="email" value={email} onChange={e => setEmail(e.target.value)} required placeholder="you@example.com"
                className="w-full pl-11 pr-4 py-3 rounded-xl bg-slate-50 border border-slate-200 text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-all" />
            </div>
          </label>
          <label className="block">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Password</span>
            <div className="relative mt-1.5">
              <KeyRound className="absolute left-3.5 top-1/2 -translate-y-1/2 h-5 w-5 text-slate-400" />
              <input type="password" value={pw} onChange={e => setPw(e.target.value)} required minLength={4} placeholder="••••••••"
                className="w-full pl-11 pr-4 py-3 rounded-xl bg-slate-50 border border-slate-200 text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-all" />
            </div>
          </label>
          {err && (
            <motion.p initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="text-sm text-rose-600 bg-rose-50 border border-rose-200 rounded-xl px-4 py-3">{err}</motion.p>
          )}
          <motion.button whileTap={{ scale: 0.98 }} disabled={busy}
            className="w-full inline-flex items-center justify-center gap-2 py-3.5 rounded-xl text-white font-semibold bg-gradient-to-r from-indigo-600 to-violet-600 shadow-lg shadow-indigo-600/25 hover:shadow-xl transition-all disabled:opacity-50">
            {busy ? <Loader2 className="h-5 w-5 animate-spin" /> : <>{mode === "login" ? "Sign in" : "Create account"}<ArrowRight className="h-4 w-4" /></>}
          </motion.button>
        </form>
        <p className="mt-6 text-center text-sm text-slate-500">
          {mode === "login" ? <>No account? <button onClick={() => setMode("register")} className="font-semibold text-indigo-600 hover:text-indigo-700">Register</button></>
            : <>Have an account? <button onClick={() => setMode("login")} className="font-semibold text-indigo-600 hover:text-indigo-700">Sign in</button></>}
        </p>
        <Link to="/" className="mt-3 block text-center text-sm text-slate-400 hover:text-slate-600">← Back home</Link>
      </motion.div>
    </div>
  );
}
