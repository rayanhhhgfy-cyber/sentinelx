export interface Finding {
  id: string; type: string; subtype: string;
  severity: "critical"|"high"|"medium"|"low"|"info";
  cvss_vector: string; cvss_score: number; confidence: number;
  url: string; method: string; param: string; payload: string;
  evidence: { request_raw: string; response_raw: string; proof: string };
  cwe: string; owasp: string; remediation: string; references: string[];
  curl_command: string; timestamp: number;
}
export interface Scan {
  id: string; target: string; status: string; created_at: number;
  finished_at?: number; counts?: Record<string, number>;
  total_findings?: number; finding_count?: number; findings?: Finding[];
}
export interface User { id: number; email: string; name: string; }

function headers(): HeadersInit {
  const h: Record<string,string> = { "Content-Type": "application/json" };
  const t = localStorage.getItem("sx_token");
  if (t) h["Authorization"] = "Bearer " + t;
  return h;
}
async function req<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const r = await fetch(path, { ...opts, headers: { ...headers(), ...(opts.headers||{}) } });
  if (r.status === 401) { localStorage.removeItem("sx_token"); location.href = "/login"; throw new Error("unauthorized"); }
  if (!r.ok) throw new Error((await r.text()).slice(0,300));
  const ct = r.headers.get("content-type") || "";
  return (ct.includes("json") ? r.json() : r.text()) as T;
}
export const api = {
  register: (email:string,name:string,password:string) => req<{token:string;user:User}>("/api/auth/register",{method:"POST",body:JSON.stringify({email,name,password})}),
  login: (email:string,password:string) => req<{token:string;user:User}>("/api/auth/login",{method:"POST",body:JSON.stringify({email,password})}),
  logout: () => req("/api/auth/logout",{method:"POST"}),
  me: () => req<User>("/api/auth/me"),
  startScan: (cfg: Record<string,unknown>) => req<{scan_id:string}>("/api/scans",{method:"POST",body:JSON.stringify(cfg)}),
  listScans: () => req<Scan[]>("/api/scans"),
  getScan: (id:string) => req<Scan>(`/api/scans/${id}`),
  deleteScan: (id:string) => req(`/api/scans/${id}`,{method:"DELETE"}),
  cancelScan: (id:string) => req(`/api/scans/${id}/cancel`,{method:"POST"}),
  rerunScan: (id:string) => req<{scan_id:string}>(`/api/scans/${id}/rerun`,{method:"POST"}),
  health: () => req<{status:string}>("/api/health"),
  dashboardStats: () => req<{
    total_scans:number; active_scans:number; completed_scans:number;
    open_findings:number; severity_counts:Record<string,number>;
    security_score:number; recent_scans:any[]; recent_findings:any[];
  }>("/api/dashboard/stats"),
};
export function wsUrl(scanId: string): string {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${location.host}/ws/scans/${scanId}?token=${localStorage.getItem("sx_token")||""}`;
}
export const SEVS = ["critical","high","medium","low","info"] as const;
