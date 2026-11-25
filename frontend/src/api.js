const TOKEN_KEY = "reconforge_token";

export const getToken = () => localStorage.getItem(TOKEN_KEY) || "";
export const setToken = (t) => localStorage.setItem(TOKEN_KEY, t);

async function request(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  const tok = getToken();
  if (tok) headers.Authorization = `Bearer ${tok}`;
  let res;
  try {
    res = await fetch(path, { ...opts, headers, credentials: "same-origin" });
  } catch {
    throw Object.assign(new Error("ReconForge server is not reachable. Is the dashboard still running?"), { status: 0 });
  }
  if (res.status === 401) throw Object.assign(new Error("unauthorized"), { status: 401 });
  if (!res.ok) {
    const txt = await res.text();
    let msg = txt;
    try { msg = JSON.parse(txt).detail || txt; } catch { /* plain text */ }
    if (res.status >= 500 && /^\s*</.test(msg)) msg = `server error (${res.status})`;
    throw Object.assign(new Error(typeof msg === "string" ? msg.slice(0, 600) : JSON.stringify(msg).slice(0, 600)), { status: res.status });
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("json") ? res.json() : res.text();
}

const CACHE = new Map();
function cached(key, ttl, fn) {
  const hit = CACHE.get(key);
  if (hit && Date.now() - hit.at < ttl) return hit.p;
  const p = fn().catch((e) => { CACHE.delete(key); throw e; });
  CACHE.set(key, { at: Date.now(), p });
  if (CACHE.size > 8) CACHE.delete(CACHE.keys().next().value);
  return p;
}
export const dropCache = () => CACHE.clear();

export const api = {
  meta: () => request("/api/meta"),
  overview: (t) => request(`/api/targets/${t}/overview`),
  inventory: (t) => request(`/api/targets/${t}/inventory`),
  assets: (t, params = {}) => request(`/api/targets/${t}/assets?` + new URLSearchParams(params)),
  // Several pages read the same (possibly large) scan summary: keep it for 20 s so switching pages doesn't refetch it.
  reportData: (t, scan) => cached(`report|${t}|${scan || ""}`, 20000, () => request(`/api/targets/${t}/report-data` + (scan ? `?scan_id=${scan}` : ""))),
  asset: (id) => request(`/api/assets/${id}`),
  setFP: (id, fp, reason) => (dropCache(), request(`/api/assets/${id}/false-positive`, { method: "POST", body: JSON.stringify({ false_positive: fp, reason }) })),
  evidence: (id) => request(`/api/evidence/${id}`),
  scans: (t) => request(`/api/scans?target=${t}`),
  scanLog: (id, module) => request(`/api/scans/${id}/log` + (module ? `?module=${encodeURIComponent(module)}` : "")),
  scanReports: (id) => request(`/api/scans/${id}/reports`),
  startScan: (target, profile, incremental) => request(`/api/scans`, { method: "POST", body: JSON.stringify({ target, profile, incremental }) }),
  changes: (t) => request(`/api/targets/${t}/changes`),
  graph: (t, types) => request(`/api/targets/${t}/graph` + (types ? `?types=${types}` : "")),
  ai: (scan) => request(`/api/scans/${scan}/ai`),
  analyze: (scan, provider) => request(`/api/scans/${scan}/analyze` + (provider ? `?provider=${provider}` : ""), { method: "POST" }),
  schedules: () => request(`/api/schedules`),
  addSchedule: (body) => request(`/api/schedules`, { method: "POST", body: JSON.stringify(body) }),
  deleteSchedule: (name) => request(`/api/schedules/${encodeURIComponent(name)}`, { method: "DELETE" }),
  notifications: () => request(`/api/notifications`),
  tools: () => request(`/api/tools`),
  saveTarget: (body) => request(`/api/targets`, { method: "POST", body: JSON.stringify(body) }),
  deleteTarget: (name) => request(`/api/targets/${encodeURIComponent(name)}`, { method: "DELETE" }),
  targetDefinition: (name) => request(`/api/targets/${encodeURIComponent(name)}/definition`),
  runScan: (body) => request(`/api/scans`, { method: "POST", body: JSON.stringify(body) }),
  runs: () => request(`/api/runs`),
  progress: (id) => request(`/api/scans/${id}/progress`),
  cancel: (id) => request(`/api/scans/${id}/cancel`, { method: "POST" }),
  actions: (t) => request(`/api/actions?target=${encodeURIComponent(t)}`),
  runAction: (target, action_id) => request(`/api/actions/run`, { method: "POST", body: JSON.stringify({ target, action_id }) }),
  settings: () => request(`/api/settings`),
  saveSettings: (ai) => request(`/api/settings`, { method: "PUT", body: JSON.stringify({ ai }) }),
  analyzeWith: (scan, body) => request(`/api/scans/${scan}/analyze`, { method: "POST", body: JSON.stringify(body) }),
  aiImport: (scan, answer, label) => request(`/api/scans/${scan}/ai-import`, { method: "POST", body: JSON.stringify({ answer, label }) }),
  bundle: (scan) => request(`/api/scans/${scan}/ai-bundle`),
  installTool: (name) => request(`/api/tools/${encodeURIComponent(name)}/install`, { method: "POST" }),
  installStatus: (jobId) => request(`/api/installs/${jobId}`),
  scanModules: (id) => request(`/api/scans/${id}/modules`),
  moduleOutput: (id, m) => request(`/api/scans/${id}/modules/${encodeURIComponent(m)}`),
  moduleExportUrl: (id, m, fmt) => withToken(`/api/scans/${id}/modules/${encodeURIComponent(m)}/export?format=${fmt}`),
  modulesZipUrl: (id) => withToken(`/api/scans/${id}/modules-export`),
  apiKeys: () => request(`/api/settings/keys`),
  saveApiKeys: (keys, clear = []) => request(`/api/settings/keys`, { method: "PUT", body: JSON.stringify({ keys, clear }) }),
  scanFiles: (id, refresh) => request(`/api/scans/${id}/files` + (refresh ? "?refresh=1" : "")),
  fileHead: (id, path, n = 400) => request(`/api/scans/${id}/files/${path.split("/").map(encodeURIComponent).join("/")}?head=${n}`),
  fileUrl: (id, path, download) => withToken(`/api/scans/${id}/files/${path.split("/").map(encodeURIComponent).join("/")}` + (download ? "?download=1" : "")),
  filesZipUrl: (id) => withToken(`/api/scans/${id}/files-zip`),
  screenshots: (t) => request(`/api/targets/${encodeURIComponent(t)}/screenshots`),
  screenshotsZipUrl: (t) => withToken(`/api/targets/${encodeURIComponent(t)}/screenshots-zip`),
  evidenceImageUrl: (id) => withToken(`/api/evidence/${id}?raw=1`),
  triage: (t) => request(`/api/targets/${encodeURIComponent(t)}/triage`),
  setTriage: (id, status, note, ids) => (dropCache(), request(`/api/assets/${id}/triage`, { method: "POST", body: JSON.stringify({ status, note, ids }) })),
  search: (t, q) => request(`/api/search?target=${encodeURIComponent(t)}&q=${encodeURIComponent(q)}`),
  notifySettings: () => request(`/api/settings/notifications`),
  saveNotify: (body) => request(`/api/settings/notifications`, { method: "PUT", body: JSON.stringify(body) }),
  testNotify: (ch) => request(`/api/settings/notifications/test/${ch}`, { method: "POST" }),
  burpScopeUrl: (t) => withToken(`/api/targets/${encodeURIComponent(t)}/burp-scope`),
  endpoints: (t, params) => request(`/api/targets/${encodeURIComponent(t)}/endpoints?` + qs(params)),
  endpointFacets: (t) => request(`/api/targets/${encodeURIComponent(t)}/endpoints/facets`),
  logLines: (id, params) => request(`/api/scans/${id}/log/lines?` + qs(params)),
  evidenceLines: (id, params) => request(`/api/evidence/${id}/lines?` + qs(params)),
  fileLines: (id, path, params) => request(`/api/scans/${id}/files/${path.split("/").map(encodeURIComponent).join("/")}?` + qs({ lines: -1, ...params })),
  moduleObservations: (id, m, params) => request(`/api/scans/${id}/modules/${encodeURIComponent(m)}/observations?` + qs(params)),
  moduleEvidence: (id, m, params) => request(`/api/scans/${id}/modules/${encodeURIComponent(m)}/evidence?` + qs(params)),
  findingsReportUrl: (t, format, scan) => withToken(`/api/targets/${encodeURIComponent(t)}/findings-report?format=${format}` + (scan ? `&scan_id=${scan}` : "")),
};

// query string without empty values; start=null means "the newest lines" and is left out
export const qs = (params = {}) => new URLSearchParams(Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== "")).toString();

export const withToken = (url) => (getToken() ? `${url}${url.includes("?") ? "&" : "?"}token=${encodeURIComponent(getToken())}` : url);
