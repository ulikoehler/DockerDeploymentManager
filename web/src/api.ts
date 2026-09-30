/** Thin REST/WS client for the ddm backend. */

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

let token = sessionStorage.getItem('ddm_token') || '';

export function setToken(t: string) {
  token = t;
  sessionStorage.setItem('ddm_token', t);
}
export function getToken(): string {
  return token;
}
export function clearToken() {
  token = '';
  sessionStorage.removeItem('ddm_token');
}

export async function api<T = any>(
  path: string,
  opts: { method?: string; body?: unknown; query?: Record<string, string | number | undefined> } = {},
): Promise<T> {
  let url = path;
  if (opts.query) {
    const q = new URLSearchParams();
    for (const [k, v] of Object.entries(opts.query)) {
      if (v !== undefined && v !== '') q.set(k, String(v));
    }
    const s = q.toString();
    if (s) url += `?${s}`;
  }
  const res = await fetch(url, {
    method: opts.method || 'GET',
    headers: {
      ...(opts.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  const json = await res.json().catch(() => ({ success: false, error: `HTTP ${res.status}` }));
  if (!res.ok || json.success === false) {
    if (res.status === 401) clearToken();
    throw new ApiError(res.status, json.error || `HTTP ${res.status}`);
  }
  return (json.data !== undefined ? json.data : json) as T;
}

export function wsUrl(path: string, params: Record<string, string | number | boolean | undefined> = {}): string {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  const q = new URLSearchParams();
  q.set('token', token);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') q.set(k, String(v));
  }
  return `${proto}//${location.host}${path}?${q.toString()}`;
}

// ---------------------------------------------------------------------------
// typed endpoints
// ---------------------------------------------------------------------------

export interface LoginResult {
  token: string;
  name: string;
  roles: string[];
  expires_at: number;
}

export interface ContainerInfo {
  id: string;
  name: string;
  service: string;
  state: string;
  status: string;
  health?: string;
}

export interface ServiceSummary {
  name: string;
  description: string;
  containers: ContainerInfo[];
  running: number;
  total: number;
  unit: { exists: boolean; enabled?: string; active?: string };
  monitor_state?: string;
}

export interface UserView {
  name: string;
  roles: string[];
  access: { type: string; pattern: string; effect: string }[];
  features: Record<string, boolean>;
  compose_policy?: string;
}

export const apiLogin = (name: string, password: string) =>
  api<LoginResult>('/api/auth/login', { method: 'POST', body: { name, password } });
export const apiMe = () => api('/api/auth/me');
export const apiServices = () => api<ServiceSummary[]>('/api/services');
export const apiService = (name: string) => api(`/api/services/${name}`);
export const apiAction = (name: string, action: string) =>
  api(`/api/services/${name}/actions`, { method: 'POST', body: { action } });
export const apiCreateService = (body: unknown) =>
  api('/api/services', { method: 'POST', body });
export const apiDeleteService = (name: string, down = false) =>
  api(`/api/services/${name}`, { method: 'DELETE', query: { down: down ? 'true' : 'false' } });
export const apiGetCompose = (name: string) =>
  api<{ content: string; violations: { path: string; message: string }[] }>(
    `/api/services/${name}/compose`,
  );
export const apiPutCompose = (name: string, content: string, recreate = false) =>
  api(`/api/services/${name}/compose`, { method: 'PUT', body: { content, recreate } });
export const apiGetUnit = (name: string) => api(`/api/services/${name}/unit`);
export const apiPutUnit = (name: string, content: string, restart = false) =>
  api(`/api/services/${name}/unit`, { method: 'PUT', body: { content, restart } });
export const apiCheckUnit = (name: string) => api(`/api/services/${name}/unit/check`);
export const apiRegenUnit = (name: string, enable = true, start = false) =>
  api(`/api/services/${name}/unit/regenerate`, { method: 'POST', body: { enable, start } });
export const apiLogs = (name: string, q: Record<string, string | number | undefined>) =>
  api(`/api/services/${name}/logs`, { query: q });
export const apiBackup = (name: string) => api(`/api/services/${name}/backup`);
export const apiPutBackup = (name: string, cfg: unknown) =>
  api(`/api/services/${name}/backup`, { method: 'PUT', body: cfg });
export const apiBackupCheck = (name: string) => api(`/api/services/${name}/backup/check`);
export const apiBackupProvision = (name: string) =>
  api(`/api/services/${name}/backup/provision`, { method: 'POST', body: {} });
export const apiBackupRun = (name: string) =>
  api(`/api/services/${name}/backup/run`, { method: 'POST', body: {} });
export const apiSnapshots = (name: string) => api(`/api/services/${name}/backup/snapshots`);
export const apiBackupForget = (name: string) =>
  api(`/api/services/${name}/backup/forget`, { method: 'POST', body: {} });
export const apiBackupRestore = (name: string, snapshot: string, target_dir: string) =>
  api(`/api/services/${name}/backup/restore`, { method: 'POST', body: { snapshot, target_dir } });
export const apiFiles = (name: string, path = '') =>
  api(`/api/services/${name}/files`, { query: { path } });
export const apiWriteFile = (name: string, path: string, content: string) =>
  api(`/api/services/${name}/files`, { method: 'PUT', body: { path, content } });
export const apiMkdir = (name: string, path: string) =>
  api(`/api/services/${name}/files/mkdir`, { method: 'POST', body: { path } });
export const apiRename = (name: string, from: string, to: string) =>
  api(`/api/services/${name}/files/rename`, { method: 'POST', body: { from, to } });
export const apiDeleteFile = (name: string, path: string) =>
  api(`/api/services/${name}/files`, { method: 'DELETE', query: { path } });
export const apiGitRepos = (name: string) => api(`/api/services/${name}/git/repos`);
export const apiGitStatus = (name: string, path = '') =>
  api(`/api/services/${name}/git/status`, { query: { path } });
export const apiGitLog = (name: string, path = '', n = 30) =>
  api(`/api/services/${name}/git/log`, { query: { path, n } });
export const apiGitBranches = (name: string, path = '') =>
  api(`/api/services/${name}/git/branches`, { query: { path } });
export const apiGitClone = (name: string, url: string, path = '', branch?: string) =>
  api(`/api/services/${name}/git/clone`, { method: 'POST', body: { url, path, branch } });
export const apiGitAction = (name: string, path: string, op: string, gitRef?: string) =>
  api(`/api/services/${name}/git/action`, { method: 'POST', body: { path, op, git_ref: gitRef } });
export const apiGetMonitoring = (name: string) => api(`/api/services/${name}/monitoring`);
export const apiPutMonitoring = (name: string, cfg: unknown) =>
  api(`/api/services/${name}/monitoring`, { method: 'PUT', body: cfg });
export const apiMonitorStatus = () => api('/api/monitoring/status');
export const apiMonitorEvents = (service?: string, limit = 100) =>
  api('/api/monitoring/events', { query: { service, limit } });
export const apiNotifiers = () => api('/api/monitoring/notifiers');
export const apiCreateNotifier = (body: unknown) =>
  api('/api/monitoring/notifiers', { method: 'POST', body });
export const apiUpdateNotifier = (id: string, body: unknown) =>
  api(`/api/monitoring/notifiers/${id}`, { method: 'PUT', body });
export const apiDeleteNotifier = (id: string) =>
  api(`/api/monitoring/notifiers/${id}`, { method: 'DELETE' });
export const apiNotifierTest = (id: string, message: string) =>
  api(`/api/monitoring/notifiers/${id}/test`, { method: 'POST', body: { message } });
export const apiUsers = () => api<UserView[]>('/api/users');
export const apiCreateUser = (body: unknown) => api('/api/users', { method: 'POST', body });
export const apiUpdateUser = (name: string, body: unknown) =>
  api(`/api/users/${name}`, { method: 'PUT', body });
export const apiDeleteUser = (name: string) => api(`/api/users/${name}`, { method: 'DELETE' });
export const apiSetPassword = (name: string, password: string) =>
  api(`/api/users/${name}/password`, { method: 'PUT', body: { password } });
export const apiSetAccess = (name: string, rules: unknown) =>
  api(`/api/users/${name}/access`, { method: 'PUT', body: rules });
export const apiCommands = () => api('/api/commands');
export const apiRunCommand = (section: number, item: number, params: Record<string, string>) =>
  api(`/api/commands/${section}/${item}`, { method: 'POST', body: { params } });
export const apiExecutions = () => api('/api/executions');
export const apiTemplates = () => api('/api/templates');
export const apiPolicy = () => api('/api/policy');
export const apiConfigStatus = () => api('/api/config/status');
export const apiAudit = () => api('/api/audit');
