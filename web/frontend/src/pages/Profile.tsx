import { useEffect, useState } from "react";
import { User as UserIcon, KeyRound, Crown, Save, Check } from "lucide-react";
import { api } from "../lib/api";
import { useAuth } from "../context/AuthContext";
import { PageHeader, PageWrap, Btn, Field, TextInput, Spinner } from "../components/ui";

export default function Profile() {
  const { user } = useAuth();
  const [name, setName] = useState("");
  const [oldPw, setOldPw] = useState("");
  const [newPw, setNewPw] = useState("");
  const [newPw2, setNewPw2] = useState("");
  const [msg, setMsg] = useState("");
  const [pwMsg, setPwMsg] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => { if (user) setName(user.name); }, [user]);
  if (!user) return <PageWrap><Spinner /></PageWrap>;

  const saveName = async () => {
    if (!name.trim()) return;
    setBusy(true);
    try { await api.updateProfile(name.trim()); setMsg("Profile updated ✓"); setTimeout(() => setMsg(""), 2500); }
    catch (e: any) { alert(e.message); } finally { setBusy(false); }
  };
  const changePw = async () => {
    if (!oldPw || !newPw) return;
    if (newPw !== newPw2) { setPwMsg("New passwords don't match"); return; }
    if (newPw.length < 8) { setPwMsg("Minimum 8 characters"); return; }
    setBusy(true);
    try { await api.changePassword(oldPw, newPw); setPwMsg("Password changed ✓"); setOldPw(""); setNewPw(""); setNewPw2(""); setTimeout(() => setPwMsg(""), 2500); }
    catch (e: any) { setPwMsg(e.message); } finally { setBusy(false); }
  };

  return (
    <PageWrap>
      <PageHeader icon={<UserIcon className="h-6 w-6 text-white" />} title="Profile" sub={user.email} />
      <div className="grid md:grid-cols-2 gap-5 items-start">
        <div className="glass rounded-[1.75rem] p-7">
          <div className="flex items-center gap-4 mb-6">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-gradient-to-br from-indigo-500 to-violet-500 text-white text-xl font-black">
              {user.name.charAt(0).toUpperCase()}
            </div>
            <div>
              <div className="font-extrabold text-slate-900 dark:text-white">{user.name}</div>
              <div className="text-sm text-slate-500 dark:text-slate-400 font-mono">{user.email}</div>
              <span className={`inline-flex items-center gap-1 mt-1.5 text-[11px] font-extrabold uppercase tracking-wide px-2.5 py-1 rounded-full ${user.role === "admin" ? "bg-amber-100 dark:bg-amber-500/15 text-amber-700 dark:text-amber-300" : "bg-slate-100 dark:bg-white/10 text-slate-500 dark:text-slate-400"}`}>
                {user.role === "admin" && <Crown className="h-3 w-3" />}{user.role || "analyst"}
              </span>
            </div>
          </div>
          <Field label="Display name">
            <TextInput value={name} onChange={e => setName(e.target.value)} />
          </Field>
          <div className="flex items-center gap-3 mt-4">
            <Btn onClick={saveName} disabled={busy || !name.trim()}><Save className="h-4 w-4" /> Save</Btn>
            {msg && <span className="text-sm font-semibold text-emerald-600 dark:text-emerald-400 flex items-center gap-1"><Check className="h-4 w-4" />{msg}</span>}
          </div>
        </div>

        <div className="glass rounded-[1.75rem] p-7">
          <div className="flex items-center gap-3 mb-5">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-violet-100 dark:bg-violet-500/15"><KeyRound className="h-5 w-5 text-violet-600 dark:text-violet-400" /></div>
            <h3 className="text-lg font-bold text-slate-900 dark:text-white">Change password</h3>
          </div>
          <div className="space-y-4">
            <Field label="Current password"><TextInput type="password" value={oldPw} onChange={e => setOldPw(e.target.value)} autoComplete="current-password" /></Field>
            <Field label="New password"><TextInput type="password" value={newPw} onChange={e => setNewPw(e.target.value)} autoComplete="new-password" /></Field>
            <Field label="Confirm new password"><TextInput type="password" value={newPw2} onChange={e => setNewPw2(e.target.value)} autoComplete="new-password" /></Field>
            {pwMsg && <p className={`text-sm font-semibold ${pwMsg.includes("✓") ? "text-emerald-600 dark:text-emerald-400" : "text-rose-600 dark:text-rose-400"}`}>{pwMsg}</p>}
            <Btn onClick={changePw} disabled={busy || !oldPw || !newPw}><KeyRound className="h-4 w-4" /> Change password</Btn>
          </div>
        </div>
      </div>
    </PageWrap>
  );
}
