export interface Finding {
  id: string; type: string; subtype: string;
  severity: "critical"|"high"|"medium"|"low"|"info";
  cvss_vector: string; cvss_score: number; confidence: number;
  url: string; method: string; param: string; payload: string;
  evidence: { request_raw: string; response_raw: string; proof: string };
  cwe: string; owasp: string; remediation: string; references: string[];
  curl_command: string; timestamp: number;
  status?: string; assignee?: string; tags?: string[]; notes_count?: number;
}
export interface Scan {
  id: string; target: string; status: string; created_at: number;
  finished_at?: number; counts?: Record<string, number>;
  total_findings?: number; finding_count?: number; findings?: Finding[];
  shared_with?: string[];
}
export interface User { id: number; email: string; name: string; role?: string; }
export interface Template { id: string; name: string; modules: string[]; rate_limit: number; description: string; }
export interface Target { id: string; url: string; name: string; tags: string[]; notes: string; last_scan_at?: number; }
export interface Schedule { id: string; target_id: string; template_id: string; cron_expr: string; enabled: boolean; next_run_at?: number; }
export interface AuthProfile { id: string; name: string; login_url: string; username_field: string; password_field: string; username: string; }
export interface FindingNote { id: string; text: string; author: string; created_at: number; }
export interface Tag { id: string; name: string; color: string; }
export interface Channel { id: string; type: string; config: Record<string, unknown>; events: string[]; }
export interface ApiKey { id: string; name: string; prefix: string; created_at: number; key?: string; }
export interface AuditEntry { id: string; actor: string; action: string; detail: string; created_at: number; ip?: string; }
export interface ScanComment { id: string; text: string; author: string; created_at: number; }
export interface EngineStats { modules: { name: string; requests: number; findings: number }[]; total_requests: number; uptime_s: number; }
export interface TrendPoint { date: string; critical: number; high: number; medium: number; low: number; info: number; }

function headers(): HeadersInit {
  const h: Record<string,string> = { "Content-Type": "application/json" };
  const t = localStorage.getItem("sx_token");
  if (t) h["Authorization"] = "Bearer " + t;
  return h;
}
/** Base URL for the API. Defaults to same-origin (monorepo deploy);
 * set VITE_API_URL for split frontend/backend hosting. */
export const API_BASE = (import.meta.env.VITE_API_URL as string || "").replace(/\/$/, "");
const u = (path: string) => `${API_BASE}${path}`;
async function req<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const r = await fetch(u(path), { ...opts, headers: { ...headers(), ...(opts.headers||{}) } });
  if (r.status === 401) { localStorage.removeItem("sx_token"); location.href = "/login"; throw new Error("unauthorized"); }
  if (!r.ok) throw new Error((await r.text()).slice(0,300));
  const ct = r.headers.get("content-type") || "";
  return (ct.includes("json") ? r.json() : r.text()) as T;
}
const J = (b: unknown) => JSON.stringify(b);
export const dlUrl = (path: string) => `${API_BASE}${path}?token=${encodeURIComponent(localStorage.getItem("sx_token") || "")}`;

export const api = {
  register: (email:string,name:string,password:string) => req<{token:string;user:User}>("/api/auth/register",{method:"POST",body:J({email,name,password})}),
  login: (email:string,password:string) => req<{token:string;user:User}>("/api/auth/login",{method:"POST",body:J({email,password})}),
  logout: () => req("/api/auth/logout",{method:"POST"}),
  me: () => req<User>("/api/auth/me"),
  changePassword: (old_password:string,new_password:string) => req("/api/auth/password",{method:"POST",body:J({old_password,new_password})}),
  updateProfile: (name:string) => req<User>("/api/auth/profile",{method:"PATCH",body:J({name})}),

  startScan: (cfg: Record<string,unknown>) => req<{scan_id:string}>("/api/scans",{method:"POST",body:J(cfg)}),
  listScans: () => req<Scan[]>("/api/scans"),
  getScan: (id:string) => req<Scan>(`/api/scans/${id}`),
  deleteScan: (id:string) => req(`/api/scans/${id}`,{method:"DELETE"}),
  cancelScan: (id:string) => req(`/api/scans/${id}/cancel`,{method:"POST"}),
  rerunScan: (id:string) => req<{scan_id:string}>(`/api/scans/${id}/rerun`,{method:"POST"}),
  pauseScan: (id:string) => req(`/api/scans/${id}/pause`,{method:"POST"}),
  resumeScan: (id:string) => req(`/api/scans/${id}/resume`,{method:"POST"}),
  compareScans: (ids:string[]) => req<{new:string[];fixed:string[];persisting:string[];scans:Scan[]}>(`/api/scans/compare?ids=${ids.join(",")}`),
  exportConfig: (id:string) => req<Record<string,unknown>>(`/api/scans/${id}/config-export`),
  importConfig: (cfg:Record<string,unknown>) => req<{scan_id:string}>("/api/scans/import-config",{method:"POST",body:J(cfg)}),
  shareScan: (id:string,email:string) => req(`/api/scans/${id}/share`,{method:"POST",body:J({email})}),
  scanComments: (id:string) => req<ScanComment[]>(`/api/scans/${id}/comments`),
  addScanComment: (id:string,text:string) => req<ScanComment>(`/api/scans/${id}/comments`,{method:"POST",body:J({text})}),

  listFindings: (scanId?:string) => req<Finding[]>(scanId?`/api/scans/${scanId}/findings`:"/api/findings"),
  searchFindings: (q:string) => req<Finding[]>(`/api/findings/search?q=${encodeURIComponent(q)}`),
  slaOverdue: () => req<(Finding & {days_overdue:number})[]>("/api/findings/sla-overdue"),
  findingNotes: (id:string) => req<FindingNote[]>(`/api/findings/${id}/notes`),
  addFindingNote: (id:string,text:string) => req<FindingNote>(`/api/findings/${id}/notes`,{method:"POST",body:J({text})}),
  setFindingStatus: (id:string,status:string) => req(`/api/findings/${id}/status`,{method:"PATCH",body:J({status})}),
  setFindingAssignee: (id:string,email:string) => req(`/api/findings/${id}/assignee`,{method:"PATCH",body:J({email})}),
  setFindingTags: (id:string,tag_ids:string[]) => req(`/api/findings/${id}/tags`,{method:"PATCH",body:J({tag_ids})}),
  acceptRisk: (id:string,reason:string,expires_at:string) => req(`/api/findings/${id}/accept-risk`,{method:"POST",body:J({reason,expires_at})}),

  tags: {
    list: () => req<Tag[]>("/api/tags"),
    create: (t:{name:string;color:string}) => req<Tag>("/api/tags",{method:"POST",body:J(t)}),
    update: (id:string,t:{name:string;color:string}) => req<Tag>(`/api/tags/${id}`,{method:"PUT",body:J(t)}),
    remove: (id:string) => req(`/api/tags/${id}`,{method:"DELETE"}),
  },
  templates: {
    list: () => req<Template[]>("/api/templates"),
    get: (id:string) => req<Template>(`/api/templates/${id}`),
    create: (t:{name:string;modules:string[];rate_limit:number;description:string}) => req<Template>("/api/templates",{method:"POST",body:J(t)}),
    update: (id:string,t:Partial<Template>) => req<Template>(`/api/templates/${id}`,{method:"PUT",body:J(t)}),
    remove: (id:string) => req(`/api/templates/${id}`,{method:"DELETE"}),
  },
  targets: {
    list: () => req<Target[]>("/api/targets"),
    get: (id:string) => req<Target>(`/api/targets/${id}`),
    create: (t:{url:string;name:string;tags:string[];notes:string}) => req<Target>("/api/targets",{method:"POST",body:J(t)}),
    update: (id:string,t:Partial<Target>) => req<Target>(`/api/targets/${id}`,{method:"PUT",body:J(t)}),
    remove: (id:string) => req(`/api/targets/${id}`,{method:"DELETE"}),
    importCsv: (csv:string) => req<{imported:number}>("/api/targets/import",{method:"POST",body:J({csv})}),
  },
  schedules: {
    list: () => req<Schedule[]>("/api/schedules"),
    create: (s:{target_id:string;template_id:string;cron_expr:string;enabled:boolean}) => req<Schedule>("/api/schedules",{method:"POST",body:J(s)}),
    update: (id:string,s:Partial<Schedule>) => req<Schedule>(`/api/schedules/${id}`,{method:"PUT",body:J(s)}),
    remove: (id:string) => req(`/api/schedules/${id}`,{method:"DELETE"}),
  },
  authProfiles: {
    list: () => req<AuthProfile[]>("/api/auth-profiles"),
    create: (p:{name:string;login_url:string;username_field:string;password_field:string;username:string;password:string}) => req<AuthProfile>("/api/auth-profiles",{method:"POST",body:J(p)}),
    update: (id:string,p:Partial<AuthProfile>) => req<AuthProfile>(`/api/auth-profiles/${id}`,{method:"PUT",body:J(p)}),
    remove: (id:string) => req(`/api/auth-profiles/${id}`,{method:"DELETE"}),
  },
  channels: {
    list: () => req<Channel[]>("/api/notification-channels"),
    create: (c:{type:string;config:Record<string,unknown>;events:string[]}) => req<Channel>("/api/notification-channels",{method:"POST",body:J(c)}),
    update: (id:string,c:Partial<Channel>) => req<Channel>(`/api/notification-channels/${id}`,{method:"PUT",body:J(c)}),
    remove: (id:string) => req(`/api/notification-channels/${id}`,{method:"DELETE"}),
    test: (id:string) => req<{ok:boolean}>("/api/notification-channels/"+id+"/test",{method:"POST"}),
  },
  apiKeys: {
    list: () => req<ApiKey[]>("/api/api-keys"),
    create: (name:string) => req<ApiKey>("/api/api-keys",{method:"POST",body:J({name})}),
    revoke: (id:string) => req(`/api/api-keys/${id}`,{method:"DELETE"}),
  },
  auditLog: (params?:{action?:string;actor?:string;limit?:number}) => {
    const q = new URLSearchParams();
    if (params?.action) q.set("action", params.action);
    if (params?.actor) q.set("actor", params.actor);
    if (params?.limit) q.set("limit", String(params.limit));
    const qs = q.toString();
    return req<AuditEntry[]>(`/api/audit-log${qs?"?"+qs:""}`);
  },
  adminUsers: () => req<User[]>("/api/admin/users"),
  engineStats: () => req<EngineStats>("/api/engine/stats"),
  version: () => req<{version:string}>("/api/version"),
  health: () => req<{status:string}>("/api/health"),
  trends: (days=30) => req<TrendPoint[]>(`/api/dashboard/trends?days=${days}`),
  dashboardStats: () => req<{
    total_scans:number; active_scans:number; completed_scans:number;
    open_findings:number; severity_counts:Record<string,number>;
    security_score:number; recent_scans:any[]; recent_findings:any[];
  }>("/api/dashboard/stats"),
};
export interface ScanEvent { seq: number; type: string; data: any; created_at: number; }
/** Poll-based live stream (replaces the removed WebSocket endpoint). */
export const scanEvents = (scanId: string, since = 0) =>
  req<{events: ScanEvent[]}>(`/api/scans/${scanId}/events?since=${since}`);
export const continueScan = (scanId: string) =>
  req<{scan_id: string; status: string; chunk: string}>(`/api/scans/${scanId}/continue`, {method: "POST"});
export const SEVS = ["critical","high","medium","low","info"] as const;
export const FINDING_STATUSES = ["open","in_progress","resolved","verified","false_positive","accepted_risk"] as const;
export const CHANNEL_EVENTS = ["scan_finished","critical_finding","scan_failed","sla_breach"] as const;
export const SCAN_MODULES = ["sqli","xss","headers","cookies","cors","methods","redirect","direnum","lfi","ssrf","rce","idor","jwt","csrf","bac","secrets","techfp","graphql","smuggling"] as const;
