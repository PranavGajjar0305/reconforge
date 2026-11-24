import { createContext, useContext, useEffect, useState } from "react";
import { Link, NavLink, Navigate, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { api, setToken } from "./api";
import AssetDrawer from "./components/AssetDrawer";
import { ExportMenu, Loading, PageBoundary, PageHead } from "./components/ui";
import { withToken } from "./api";
import Icon from "./components/icons";
import Overview from "./pages/Overview";
import Inventory from "./pages/Inventory";
import Subdomains from "./pages/Subdomains";
import Ports from "./pages/Ports";
import Technologies from "./pages/Technologies";
import Endpoints from "./pages/Endpoints";
import Security from "./pages/Security";
import Changes from "./pages/Changes";
import Scans from "./pages/Scans";
import GraphPage from "./pages/Graph";
import Priorities from "./pages/Priorities";
import AIAnalysis from "./pages/AIAnalysis";
import Schedules from "./pages/Schedules";
import Coverage from "./pages/Coverage";
import Infrastructure from "./pages/Infrastructure";
import Scanner from "./pages/Scanner";
import Live from "./pages/Live";
import Actions from "./pages/Actions";
import ToolOutput from "./pages/ToolOutput";
import Files from "./pages/Files";
import Screenshots from "./pages/Screenshots";
import Triage from "./pages/Triage";
import Osint from "./pages/Osint";
import Settings from "./pages/Settings";
import Palette from "./components/Palette";

export const Ctx = createContext(null);
export const useApp = () => useContext(Ctx);

const NAV = [
  ["Operate", [["/scanner", "Scanner", "scan"], ["/live", "Live execution", "live"], ["/output", "Tool output", "terminal"],
               ["/files", "Output files", "folder"], ["/actions", "Tools & commands", "tools"]]],
  ["Findings", [["/triage", "Triage board", "triage"], ["/security", "Security observations", "shield"],
                ["/priorities", "Review priorities", "priority"], ["/ai", "AI analysis", "ai"]]],
  ["Surface", [["/", "Overview", "overview"], ["/inventory", "Asset inventory", "inventory"], ["/subdomains", "Subdomains", "subdomains"],
               ["/ports", "Ports & services", "ports"], ["/technologies", "Technologies", "tech"], ["/endpoints", "APIs & endpoints", "api"],
               ["/screenshots", "Screenshots", "image"], ["/infrastructure", "DNS, identity, third parties", "infra"],
               ["/osint", "OSINT & brand", "globe"], ["/graph", "Relationship graph", "graph"]]],
  ["History", [["/changes", "Changes", "changes"], ["/scans", "Executions", "history"], ["/coverage", "Coverage & tool registry", "coverage"],
               ["/schedules", "Schedules & alerts", "clock"]]],
  ["Settings", [["/settings", "API keys & notifications", "key"]]],
];
const FLAT = NAV.flatMap(([, items]) => items);
const BLURB = {
  "/triage": "Every observation ranked by review priority (severity, confidence, host exposure, novelty). Record a decision for each one.",
  "/screenshots": "What every web application looks like. Look-alike default pages can be collapsed; open one for full size.",
  "/osint": "Search-engine and code-search pivots, look-alike domains, published contacts, URL candidate lists and the organisation's IP ranges.",
  "/settings": "API keys for passive sources and external tools, and where scan alerts are sent (Slack, Discord, Telegram, e-mail).",
  "/actions": "Every module and tool, with the exact command it runs against this target. Execute one on its own, or install what is missing.",
  "/inventory": "One correlated record per host: DNS, addresses, web services, ports, technologies, hosting and TLS.",
  "/subdomains": "Every hostname found, where it came from, and whether it resolves.",
  "/ports": "Services answering on authorized addresses, and the web applications behind them.",
  "/technologies": "Software identified on web services, grouped by role, with versions where advertised.",
  "/endpoints": "API routes, documentation, GraphQL and WebSocket references. Inventory only; nothing here is called.",
  "/infrastructure": "Name servers, mail security, virtual hosts, identity providers and the third parties the target depends on.",
  "/graph": "How hosts, addresses, certificates and services connect. Dashed lines are inferred; double-click a node to isolate its neighbourhood.",
  "/security": "Configuration observations and version advisories with the evidence behind each. Verify before reporting.",
  "/priorities": "Where manual review is most likely to pay off, with the reasons for every score.",
  "/ai": "Send the collected evidence to an AI model, or any chat, and get a ranked list of what matters most.",
  "/changes": "What appeared, disappeared or changed between scans.",
  "/scans": "Every run with its modules, commands, logs and reports. Open Tool output to read any module's results.",
  "/coverage": "What the last scan covered, which sources answered, and every tool the registry knows about.",
  "/schedules": "Recurring scans and the alerts they sent.",
};

/* downloadable surfaces per page: [surface id, label, formats?] */
const EXPORTS = {
  "/": [["full", "Complete dataset", ["json"]], ["inventory", "Asset inventory"], ["findings", "Security observations"]],
  "/inventory": [["inventory", "Asset inventory"]],
  "/subdomains": [["subdomains", "Subdomains"]],
  "/ports": [["ports", "Ports & services"], ["web-apps", "Web applications"]],
  "/technologies": [["technologies", "Technologies"]],
  "/endpoints": [["endpoints", "Endpoints"], ["js-files", "JavaScript files"], ["api-hosts", "API hosts"], ["parameters", "Parameters"]],
  "/infrastructure": [["dns", "DNS & mail security"], ["identity", "Identity providers"], ["third-parties", "Third parties"],
                      ["http-profiles", "HTTP profiles"], ["documents", "Public documents"], ["ips", "IP addresses"],
                      ["ip-intelligence", "IP intelligence"], ["certificates", "Certificates"]],
  "/graph": [["graph", "Graph nodes"]],
  "/security": [["findings", "Security observations"], ["cves", "CVE correlations"], ["certificates", "Certificates"], ["cloud", "Cloud resources"]],
  "/priorities": [["priorities", "Review priorities"]],
  "/changes": [["changes", "Changes"]],
  "/scans": [["scans", "Executions"]],
  "/coverage": [["coverage", "Coverage"], ["source-comparison", "Source comparison"]],
  "/actions": [["tools", "Tools & commands"]],
  "/triage": [["findings", "Security observations"], ["cves", "CVE correlations"], ["priorities", "Review priorities"]],
  "/screenshots": [["web-apps", "Web applications"]],
  "/osint": [["dns", "DNS & mail security"], ["third-parties", "Third parties (incl. look-alikes)"]],
};
const EXTRA_EXPORTS = {
  "/graph": (t) => [["Graphviz (.dot)", withToken(`/api/targets/${encodeURIComponent(t)}/graph?format=dot`)],
                    ["GraphML (.graphml)", withToken(`/api/targets/${encodeURIComponent(t)}/graph?format=graphml`)]],
};

const RESULT_PAGES = ["/triage", "/screenshots", "/osint", "/", "/inventory", "/subdomains", "/ports", "/technologies", "/endpoints", "/infrastructure", "/graph",
                      "/security", "/priorities", "/ai", "/changes", "/coverage"];

function PageFrame() {
  const { pathname } = useLocation();
  const { meta, target } = useApp();
  useEffect(() => { window.scrollTo(0, 0); }, [pathname]);
  const base = "/" + (pathname.split("/")[1] || "");
  const item = FLAT.find(([to]) => to === base);
  const runId = meta.running?.[target];
  const banner = runId && RESULT_PAGES.includes(base) && (
    <div className="scanbar mb-4 flex flex-wrap items-center gap-3 rounded-[3px] border border-amber-400/30 bg-amber-400/5 px-3 py-2 text-[12.5px] text-slate-300">
      <span className="radar active" style={{ "--size": "18px" }} />
      A scan of {target} is running. This page shows what has been collected so far; reload it to pick up newer results.
      <Link className="ml-auto font-medium text-amber-300 hover:text-amber-200" to={`/live/${runId}`}>Watch live</Link>
    </div>
  );
  const exportMenu = <ExportMenu target={target} surfaces={EXPORTS[base] || []} extra={EXTRA_EXPORTS[base]?.(target) || []} />;
  if (base === "/") return <>{banner}<div className="relative z-20 -mb-1 flex justify-end">{exportMenu}</div></>;
  if (!item || ["/scanner", "/output", "/files"].includes(base) || pathname.startsWith("/live")) return banner || null;
  return <>{banner}<PageHead title={item[1]} aside={exportMenu}>{BLURB[base]}</PageHead></>;
}

/* /live without an id: open the running scan for this target, or the most recent run. */
function LiveLatest() {
  const { meta, target } = useApp();
  const [dest, setDest] = useState(meta.running?.[target] || Object.values(meta.running || {})[0] || null);
  const [none, setNone] = useState(false);
  useEffect(() => {
    if (dest) return;
    api.runs()
      .then((r) => (r || [])[0]?.scan_id || api.scans(target).then((sc) => (sc || [])[0]?.id))
      .then((id) => (id ? setDest(id) : setNone(true)))
      .catch(() => setNone(true));
  }, [dest]);
  if (dest) return <Navigate to={`/live/${dest}`} replace />;
  if (!none) return <Loading />;
  return (
    <div className="hud p-6">
      <div className="display text-[18px] font-semibold text-slate-100">Nothing is running</div>
      <p className="mt-1.5 text-[13px] text-slate-400">Start a scan or execute a single tool and its live output appears here.</p>
      <div className="mt-4 flex gap-2"><Link className="btn-primary" to="/scanner">Open scanner</Link><Link className="btn" to="/scans">Past executions</Link></div>
    </div>
  );
}

function Wordmark({ live }) {
  return (
    <div className="flex items-center gap-3">
      <div className={`radar ${live ? "active" : "idle"}`} style={{ "--size": "30px" }} />
      <div>
        <div className="display text-[19px] font-bold leading-none tracking-[0.06em] text-slate-50">
          RECON<span className="text-indigo-400">FORGE</span>
        </div>
        <div className="mt-1.5 whitespace-nowrap font-mono text-[10px] leading-none text-slate-500">attack surface console</div>
      </div>
    </div>
  );
}

/* telemetry: UTC clock and API link state */
function Telemetry({ ok }) {
  const [now, setNow] = useState(new Date());
  useEffect(() => { const t = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(t); }, []);
  return (
    <div className="hidden items-center gap-4 font-mono text-[11.5px] text-slate-500 lg:flex">
      <span className="flex items-center gap-1.5"><span className={`diode ${ok ? "ok" : "bad"}`} />{ok ? "uplink" : "no uplink"}</span>
      <span className="tabular text-slate-400">{now.toISOString().slice(11, 19)} <span className="text-slate-600">UTC</span></span>
    </div>
  );
}

function ScopePlate({ meta, target, setTarget }) {
  const t = meta.targets.find((x) => x.name === target);
  if (!meta.targets.length) return <span className="text-[13px] text-slate-400">No scans yet. Create one in Scanner.</span>;
  const all = [...(t?.root_domains || []), ...(t?.ip_targets || [])];
  const summary = all.length > 3 ? `${all.slice(0, 3).join(" ")} +${all.length - 3}` : all.join(" ");
  return (
    <label className="relative flex min-w-0 cursor-pointer items-center gap-3 rounded-[2px] border border-slate-800 bg-slate-900/70 py-1.5 pl-3 pr-8 hover:border-indigo-400/50 focus-within:border-indigo-400">
      <span className={t?.authorized ? "text-emerald-300" : "text-amber-300"} title={t?.authorized ? "authorized" : "passive only"}>
        <Icon name={t?.authorized ? "lock" : "unlock"} size={15} />
      </span>
      <span className="flex min-w-0 flex-col leading-tight">
        <span className="truncate text-[13px] font-medium text-slate-100">{t?.name}</span>
        <span className="truncate font-mono text-[11px] text-slate-500">{summary} · {t?.authorized ? "authorized" : "passive only"}</span>
      </span>
      <svg className="pointer-events-none absolute right-2.5 text-slate-500" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m6 9 6 6 6-6" /></svg>
      <select aria-label="Switch scan" className="absolute inset-0 cursor-pointer opacity-0" value={target} onChange={(e) => setTarget(e.target.value)}>
        {meta.targets.map((x) => <option key={x.name} value={x.name}>{x.name} ({[...x.root_domains, ...(x.ip_targets || [])].length} targets)</option>)}
      </select>
    </label>
  );
}

export default function App() {
  const [meta, setMeta] = useState(null);
  const [target, setTarget] = useState(localStorage.getItem("rf_target") || "");
  const [assetId, setAssetId] = useState(null);
  const [needToken, setNeedToken] = useState(false);
  const [uplink, setUplink] = useState(true);
  const [palette, setPalette] = useState(false);
  const [tok, setTok] = useState("");
  const nav = useNavigate();
  const loc = useLocation();

  const loadMeta = () =>
    api.meta().then((m) => {
      setMeta(m); setUplink(true);
      const names = m.targets.map((t) => t.name);
      if (!names.includes(target) && names.length) setTarget(names[0]);
    }).catch((e) => { if (e.status === 401) setNeedToken(true); else setUplink(false); });

  useEffect(() => { loadMeta(); }, []);
  useEffect(() => {  // keep the running indicator fresh
    const t = setInterval(() => { if (meta) loadMeta(); }, Object.keys(meta?.running || {}).length ? 4000 : 20000);
    return () => clearInterval(t);
  }, [meta]);
  useEffect(() => { if (target) localStorage.setItem("rf_target", target); }, [target]);

  if (needToken)
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="card w-96">
          <div className="display mb-1 text-[18px] font-semibold text-slate-50">API token required</div>
          <p className="mb-3 text-[12.5px] text-slate-400">This ReconForge instance is protected. Paste the value of RECONFORGE_API_TOKEN.</p>
          <input className="input w-full" type="password" value={tok} onChange={(e) => setTok(e.target.value)} placeholder="RECONFORGE_API_TOKEN" />
          <button className="btn-primary mt-3 w-full" onClick={() => { setToken(tok); setNeedToken(false); loadMeta(); }}>Continue</button>
        </div>
      </div>
    );
  if (!meta) return <div className="flex h-screen items-center justify-center"><Loading what="Establishing uplink to ReconForge" /></div>;
  const live = Object.keys(meta.running || {}).length > 0;

  return (
    <Ctx.Provider value={{ meta, target, setTarget, openAsset: setAssetId, reloadMeta: loadMeta }}>
      <div className="flex min-h-screen">
        <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-slate-800 bg-[#040810]/95 md:flex">
          <Link to="/" aria-label="ReconForge home" className="block border-b border-slate-800 px-5 py-4 hover:bg-slate-900/40"><Wordmark live={live} /></Link>
          <nav className="flex-1 overflow-auto px-3 py-3" aria-label="Main">
            {NAV.map(([group, items]) => (
              <div key={group} className="mb-4">
                <div className="flex items-center gap-2 px-2 pb-1.5 font-[family-name:var(--font-display)] text-[12px] font-semibold text-slate-500">
                  <span className="h-px w-3 bg-indigo-400/50" />{group}
                </div>
                {items.map(([to, label, icon]) => (
                  <NavLink key={to} to={to} end={to === "/"}
                    className={({ isActive }) => `relative flex items-center gap-2.5 px-2 py-1.5 text-[13px] transition-colors ${isActive
                      ? "bg-gradient-to-r from-indigo-400/15 to-transparent text-slate-50 before:absolute before:-left-3 before:top-1 before:bottom-1 before:w-[3px] before:bg-indigo-400 before:shadow-[0_0_10px_var(--ion)]"
                      : "text-slate-400 hover:bg-slate-900/70 hover:text-slate-100"}`}>
                    {({ isActive }) => <>
                      <Icon name={icon} size={16} className={`shrink-0 ${isActive ? "text-indigo-300" : "opacity-75"}`} />{label}
                      {to === "/live" && live && <span className="diode live ml-auto" />}
                    </>}
                  </NavLink>
                ))}
              </div>
            ))}
          </nav>
          <div className="border-t border-slate-800 px-5 py-3 text-[11px] leading-relaxed text-slate-500">
            <div className="mb-1 flex items-center gap-1.5 text-slate-400"><Icon name="shield" size={13} className="text-emerald-300" /> Rules of engagement</div>
            Built-in recon sends only GET/HEAD to in-scope hosts. Active modules and Nuclei run only for authorized scans. Third parties are recorded, never probed.
          </div>
        </aside>
        <main className="min-w-0 flex-1">
          <header className={`sticky top-0 z-30 flex items-center gap-3 border-b border-slate-800 bg-slate-950/85 px-6 py-2.5 backdrop-blur ${live ? "scanbar" : ""}`}>
            <ScopePlate meta={meta} target={target} setTarget={setTarget} />
            {Object.entries(meta.running || {}).map(([t, id]) => (
              <button key={id} className="flex items-center gap-2 rounded-[2px] border border-amber-400/40 bg-amber-400/10 py-1 pl-1.5 pr-3 text-[12px] text-amber-200 hover:bg-amber-400/15"
                      onClick={() => nav(`/live/${id}`)}>
                <span className="radar active" style={{ "--size": "20px" }} /> Scanning {t}<span className="ml-1 font-semibold text-amber-100">Watch live</span>
              </button>
            ))}
            <button className="hidden min-w-56 items-center gap-2 rounded-[2px] border border-slate-800 bg-slate-950/70 px-2.5 py-1.5 text-[12.5px] text-slate-500 hover:border-indigo-400/50 hover:text-slate-300 lg:flex"
                    onClick={() => setPalette(true)} aria-label="Search (Ctrl+K)">
              <Icon name="search" size={14} /> Search hosts, findings, pages
              <kbd className="ml-auto rounded-[2px] border border-slate-700 px-1 font-mono text-[10.5px]">⌘K</kbd>
            </button>
            <div className="ml-auto flex items-center gap-4">
              <Telemetry ok={uplink} />
              <select aria-label="Navigate" className="input md:hidden" onChange={(e) => nav(e.target.value)}>
                {FLAT.map(([to, label]) => <option key={to} value={to}>{label}</option>)}
              </select>
              <button className="btn-primary" onClick={() => nav("/scanner")}><Icon name="play" size={14} /> New scan</button>
            </div>
          </header>
          <div className="mx-auto max-w-[1600px] p-6">
            <PageFrame />
            <PageBoundary resetKey={loc.pathname + target}>
            {target ? (
              <Routes>
                <Route path="/scanner" element={<Scanner />} />
                <Route path="/live" element={<LiveLatest />} />
                <Route path="/live/:scanId" element={<Live />} />
                <Route path="/actions" element={<Actions />} />
                <Route path="/output" element={<ToolOutput />} />
                <Route path="/files" element={<Files />} />
                <Route path="/files/:scanId" element={<Files />} />
                <Route path="/triage" element={<Triage />} />
                <Route path="/screenshots" element={<Screenshots />} />
                <Route path="/osint" element={<Osint />} />
                <Route path="/settings" element={<Settings />} />
                <Route path="/output/:scanId" element={<ToolOutput />} />
                <Route path="/" element={<Overview />} />
                <Route path="/inventory" element={<Inventory />} />
                <Route path="/subdomains" element={<Subdomains />} />
                <Route path="/ports" element={<Ports />} />
                <Route path="/technologies" element={<Technologies />} />
                <Route path="/endpoints" element={<Endpoints />} />
                <Route path="/security" element={<Security />} />
                <Route path="/priorities" element={<Priorities />} />
                <Route path="/changes" element={<Changes />} />
                <Route path="/graph" element={<GraphPage />} />
                <Route path="/ai" element={<AIAnalysis />} />
                <Route path="/scans" element={<Scans />} />
                <Route path="/scans/:scanId" element={<Scans />} />
                <Route path="/schedules" element={<Schedules />} />
                <Route path="/infrastructure" element={<Infrastructure />} />
                <Route path="/coverage" element={<Coverage />} />
                <Route path="*" element={<Navigate to="/" />} />
              </Routes>
            ) : <Scanner />}
            </PageBoundary>
          </div>
        </main>
      </div>
      {assetId && <AssetDrawer id={assetId} onClose={() => setAssetId(null)} onNavigate={setAssetId} />}
      <Palette pages={FLAT} target={target} openAsset={setAssetId} open={palette} setOpen={setPalette} />
    </Ctx.Provider>
  );
}
