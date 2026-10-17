import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, LineChart, Line, XAxis, YAxis, CartesianGrid, Legend, BarChart, Bar } from "recharts";
import { useTheme } from "../context/ThemeContext";
import type { TrendPoint } from "../lib/api";

const SEV_COLORS: Record<string, string> = {
  critical: "#e11d48", high: "#ea580c", medium: "#ca8a04", low: "#0284c7", info: "#64748b",
};

export function SeverityDonut({ counts }: { counts: Record<string, number> }) {
  const data = ["critical", "high", "medium", "low", "info"]
    .map(k => ({ name: k, value: counts[k] || 0 }))
    .filter(d => d.value > 0);
  const total = data.reduce((a, b) => a + b.value, 0);
  if (total === 0) return <p className="text-center text-sm text-slate-400 py-10">No findings yet.</p>;
  return (
    <div className="relative h-64">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie data={data} dataKey="value" nameKey="name" innerRadius={62} outerRadius={92} paddingAngle={3} strokeWidth={0}>
            {data.map(d => <Cell key={d.name} fill={SEV_COLORS[d.name]} />)}
          </Pie>
          <Tooltip
            contentStyle={{ borderRadius: 14, border: "1px solid rgba(0,0,0,.08)", fontSize: 13 }}
            formatter={(v: any, name: any) => [v, String(name).toUpperCase()]}
          />
        </PieChart>
      </ResponsiveContainer>
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <div className="text-3xl font-black text-slate-900 dark:text-white">{total}</div>
        <div className="text-[11px] font-bold uppercase tracking-wider text-slate-400">findings</div>
      </div>
    </div>
  );
}

export function TrendChart({ data }: { data: TrendPoint[] }) {
  const { theme } = useTheme();
  const tick = theme === "dark" ? "#94a3b8" : "#64748b";
  const grid = theme === "dark" ? "rgba(255,255,255,.06)" : "#f1f5f9";
  if (!data.length) return <p className="text-center text-sm text-slate-400 py-10">No trend data yet.</p>;
  return (
    <div className="h-72">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data} margin={{ top: 8, right: 8, left: -14, bottom: 0 }}>
          <CartesianGrid stroke={grid} strokeDasharray="3 3" vertical={false} />
          <XAxis dataKey="date" tick={{ fill: tick, fontSize: 11 }} tickLine={false} axisLine={false} interval="preserveStartEnd" />
          <YAxis tick={{ fill: tick, fontSize: 11 }} tickLine={false} axisLine={false} allowDecimals={false} />
          <Tooltip contentStyle={{ borderRadius: 14, border: "1px solid rgba(0,0,0,.08)", fontSize: 13 }} />
          <Legend wrapperStyle={{ fontSize: 12 }} />
          {(["critical", "high", "medium", "low"] as const).map(k => (
            <Line key={k} type="monotone" dataKey={k} stroke={SEV_COLORS[k]} strokeWidth={2.5} dot={false} activeDot={{ r: 4 }} />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

export function ModuleBars({ modules }: { modules: { name: string; requests: number; findings: number }[] }) {
  const { theme } = useTheme();
  const tick = theme === "dark" ? "#94a3b8" : "#64748b";
  const data = [...modules].sort((a, b) => b.requests - a.requests).slice(0, 19);
  return (
    <div className="h-96">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 0, right: 12, left: 8, bottom: 0 }}>
          <CartesianGrid stroke={theme === "dark" ? "rgba(255,255,255,.06)" : "#f1f5f9"} horizontal={false} />
          <XAxis type="number" tick={{ fill: tick, fontSize: 11 }} tickLine={false} axisLine={false} />
          <YAxis type="category" dataKey="name" tick={{ fill: tick, fontSize: 11 }} tickLine={false} axisLine={false} width={90} />
          <Tooltip contentStyle={{ borderRadius: 14, fontSize: 13 }} cursor={{ fill: theme === "dark" ? "rgba(255,255,255,.04)" : "#f8fafc" }} />
          <Bar dataKey="requests" fill="#6366f1" radius={[0, 6, 6, 0]} name="Requests" />
          <Bar dataKey="findings" fill="#e11d48" radius={[0, 6, 6, 0]} name="Findings" />
          <Legend wrapperStyle={{ fontSize: 12 }} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
