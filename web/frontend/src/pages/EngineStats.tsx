import { useEffect, useState } from "react";
import { Cpu, Activity, Zap, Bug, Clock } from "lucide-react";
import { api } from "../lib/api";
import type { EngineStats } from "../lib/api";
import { PageHeader, PageWrap, StatCard, Spinner } from "../components/ui";
import { ModuleBars } from "../components/Charts";

export default function EngineStats() {
  const [s, setS] = useState<EngineStats | null>(null);
  const [ver, setVer] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([api.engineStats(), api.version().catch(() => ({ version: "?" }))])
      .then(([st, v]) => { setS(st); setVer(v.version); })
      .catch(() => {}).finally(() => setLoading(false));
  }, []);

  const uptime = s ? `${Math.floor(s.uptime_s / 3600)}h ${Math.floor((s.uptime_s % 3600) / 60)}m` : "—";

  return (
    <PageWrap wide>
      <PageHeader icon={<Cpu className="h-6 w-6 text-white" />} title="Engine stats" sub={`Scanner engine internals${ver ? ` · v${ver}` : ""}`} />
      {loading || !s ? <Spinner /> : (<>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          <StatCard label="Total requests" value={s.total_requests.toLocaleString()} icon={<Zap className="h-5 w-5 text-indigo-600 dark:text-indigo-400" />} tint="bg-indigo-50 dark:bg-indigo-500/15" />
          <StatCard label="Modules" value={s.modules.length} icon={<Cpu className="h-5 w-5 text-violet-600 dark:text-violet-400" />} tint="bg-violet-50 dark:bg-violet-500/15" delay={0.05} />
          <StatCard label="Findings produced" value={s.modules.reduce((a, m) => a + m.findings, 0)} icon={<Bug className="h-5 w-5 text-rose-600 dark:text-rose-400" />} tint="bg-rose-50 dark:bg-rose-500/15" delay={0.1} />
          <StatCard label="Uptime" value={uptime} icon={<Clock className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />} tint="bg-emerald-50 dark:bg-emerald-500/15" delay={0.15} />
        </div>
        <div className="glass rounded-3xl p-6 sm:p-8">
          <div className="flex items-center gap-2 mb-1">
            <Activity className="h-5 w-5 text-indigo-500" />
            <h3 className="text-lg font-extrabold text-slate-900 dark:text-white">Per-module activity</h3>
          </div>
          <p className="text-sm text-slate-500 dark:text-slate-400 mb-6">HTTP requests fired and findings produced by each module.</p>
          <ModuleBars modules={s.modules} />
        </div>
      </>)}
    </PageWrap>
  );
}
