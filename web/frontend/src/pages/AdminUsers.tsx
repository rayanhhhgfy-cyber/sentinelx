import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { Users, ShieldCheck, Crown } from "lucide-react";
import { api } from "../lib/api";
import type { User } from "../lib/api";
import { useAuth } from "../context/AuthContext";
import { PageHeader, PageWrap, EmptyState, Spinner } from "../components/ui";

export default function AdminUsers() {
  const { user } = useAuth();
  const [list, setList] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [denied, setDenied] = useState(false);

  useEffect(() => {
    api.adminUsers().then(setList).catch(() => setDenied(true)).finally(() => setLoading(false));
  }, []);

  if (user && user.role !== "admin") return <Navigate to="/overview" replace />;

  return (
    <PageWrap>
      <PageHeader icon={<Users className="h-6 w-6 text-white" />} title="User administration" sub="All registered users" />
      {loading ? <Spinner /> : denied ? (
        <EmptyState icon={<ShieldCheck className="mx-auto h-12 w-12" />} title="Access denied" sub="This page requires the admin role." />
      ) : list.length === 0 ? (
        <EmptyState title="No users" sub="No registered users found." />
      ) : (
        <div className="space-y-3">
          {list.map(u => (
            <div key={u.id} className="glass card-hover rounded-2xl p-5 flex flex-wrap items-center gap-3">
              <div className={`p-2.5 rounded-xl ${u.role === "admin" ? "bg-amber-100 dark:bg-amber-500/15" : "bg-slate-100 dark:bg-white/10"}`}>
                {u.role === "admin" ? <Crown className="h-5 w-5 text-amber-600 dark:text-amber-400" /> : <Users className="h-5 w-5 text-slate-500" />}
              </div>
              <div className="min-w-0 flex-1">
                <div className="font-bold text-slate-900 dark:text-white">{u.name}</div>
                <div className="text-xs text-slate-500 dark:text-slate-400 font-mono">{u.email}</div>
              </div>
              <span className={`text-[11px] font-extrabold uppercase tracking-wide px-3 py-1.5 rounded-full ${u.role === "admin" ? "bg-amber-100 dark:bg-amber-500/15 text-amber-700 dark:text-amber-300" : "bg-slate-100 dark:bg-white/10 text-slate-500 dark:text-slate-400"}`}>
                {u.role || "user"}
              </span>
            </div>
          ))}
        </div>
      )}
    </PageWrap>
  );
}
