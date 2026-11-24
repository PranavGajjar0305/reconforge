import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Link, useNavigate } from "react-router-dom";
import { useApp } from "../App";
import { api } from "../api";
import Icon from "../components/icons";
import { Empty, Loading, Section, SEV_COLOR, TIER_STYLE, useLoad, Pending } from "../components/ui";

const SIG = { high: "#ff7a45", medium: "#f0a23a", low: "#5d7397" };
const SEVS = ["critical", "high", "medium", "low", "info"];

function Ledger({ title, rows, to }) {
  return (
    <Link to={to} className="group block px-4 py-3 hover:bg-slate-800/30">
      <div className="mb-2 flex items-center justify-between text-[12px] text-slate-400">
        <span className="display text-[13px] font-semibold text-slate-200">{title}</span>
        <span className="opacity-0 transition-opacity group-hover:opacity-100">open</span>
      </div>
      <dl className="space-y-1">
        {rows.map(([label, value, tone]) => (
          <div key={label} className="flex items-baseline gap-2 text-[13px]">
            <dt className="text-slate-400">{label}</dt>
            <span className="mb-1 flex-1 border-b border-dotted border-slate-700" />
            <dd className={`readout text-[18px] font-semibold ${tone || "text-slate-50"}`}>{value}</dd>
          </div>
        ))}
      </dl>
    </Link>
  );
}

function Spectrum({ counts }) {
  const total = SEVS.reduce((n, s) => n + (counts[s] || 0), 0);
  return (
    <div>
      <div className="flex h-2.5 w-full overflow-hidden rounded-sm bg-slate-800">
        {SEVS.map((s) => counts[s] ? <div key={s} title={`${s}: ${counts[s]}`} style={{ width: `${(counts[s] / total) * 100}%`, background: SEV_COLOR[s] }} /> : null)}
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[12px] text-slate-400">
        {SEVS.map((s) => (
          <span key={s} className="inline-flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-[2px]" style={{ background: SEV_COLOR[s] }} />{s}
            <b className="font-medium tabular-nums text-slate-100">{counts[s] || 0}</b>
          </span>
        ))}
      </div>
    </div>
  );
}

export default function Overview() {
  const { target, openAsset, meta } = useApp();
  const nav = useNavigate();
  const { data, loading, error, reload } = useLoad(() => api.overview(target), [target]);
  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;
  const t = meta.targets.find((x) => x.name === target);
  if (!data?.scan) return (
    <div className="mx-auto mt-16 max-w-lg text-center">
      <div className="radar idle mx-auto" style={{ "--size": "72px" }} />
      <h1 className="display mt-6 text-[24px] font-semibold text-slate-50">Nothing mapped for {target} yet</h1>
      <p className="mt-2 text-[13px] text-slate-400">Run a scan to discover hosts, services and exposures. You can watch every request as it happens.</p>
      <button className="btn-primary mt-5" onClick={() => nav("/scanner")}><Icon name="play" size={14} /> Start a scan</button>
    </div>
  );
  const o = data.overview;
  const running = meta.running?.[target];
  return (
    <div className="space-y-5">
      {/* target header: the radar is the page's one animated element */}
      <div className="flex flex-wrap items-center gap-5 hud px-5 py-4">
        <div className={`radar ${running ? "active" : "idle"}`} style={{ "--size": "64px" }} />
        <div className="min-w-0 flex-1">
          <h1 className="display truncate text-[30px] font-semibold leading-none text-slate-50">{target}</h1>
          <div className="mt-2 font-mono text-[12px] text-slate-400">{[...(t?.root_domains || []), ...(t?.ip_targets || [])].join("  ")}</div>
          <div className="mt-1.5 text-[12px] text-slate-500">
            Last {data.scan.profile} scan finished {data.scan.finished_at?.replace("T", " ").replace("Z", " UTC")} with status {data.scan.status}.{" "}
            <Link className="text-indigo-300 hover:underline" to={`/scans/${data.scan.id}`}>Execution details</Link>
          </div>
        </div>
        <div className="flex gap-2">
          {running
            ? <button className="btn" onClick={() => nav(`/live/${running}`)}><Icon name="live" size={14} /> Watch live run</button>
            : <button className="btn-primary" onClick={() => nav("/scanner")}><Icon name="play" size={14} /> Scan again</button>}
        </div>
      </div>

      <div className="grid divide-slate-800 hud md:grid-cols-2 md:divide-x xl:grid-cols-4">
        <Ledger title="Discovery" to="/subdomains" rows={[["Root domains", o.domains], ...(o.ip_targets ? [["IP targets", o.ip_targets]] : []), ["Subdomains", o.subdomains],
          ["Resolving", o.resolved_hosts, "text-emerald-300"], ["Not resolving", o.unresolved_hosts, "text-slate-400"]]} />
        <Ledger title="Exposure" to="/ports" rows={[["Web services", o.live_web_services], ["Open ports", o.open_ports],
          ["IP addresses", o.ip_addresses], ["Networks (ASN)", o.asns]]} />
        <Ledger title="Application" to="/endpoints" rows={[["Technologies", o.technologies], ["API endpoints", o.api_endpoints],
          ["All endpoints", o.endpoints], ["TLS certificates", o.certificates]]} />
        <Ledger title="Risk & change" to="/security" rows={[["Observations", o.security_observations, "text-indigo-300"],
          ["Version advisories", o.cve_correlations], ["Third parties", o.third_parties], ["Changes in last scan", o.changes]]} />
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        <Section title="Observations by severity" className="lg:col-span-2"
                 right={<Link className="text-[12px] text-indigo-300 hover:underline" to="/triage">Open triage board</Link>}>
          <Spectrum counts={o.findings_by_severity} />
          <p className="mt-3 text-[12px] text-slate-500">Configuration observations and advisory matches. None are confirmed vulnerabilities until verified.</p>
        </Section>
        <Section title="Surface over time" className="lg:col-span-3">
          <div className="h-40">
            <ResponsiveContainer>
              <LineChart data={data.trend} margin={{ left: -18, right: 8, top: 4 }}>
                <CartesianGrid stroke="#1a2a42" vertical={false} />
                <XAxis dataKey="started_at" tick={{ fill: "#5d7397", fontSize: 10 }} tickFormatter={(v) => v?.slice(5, 16).replace("T", " ")} stroke="#1a2a42" />
                <YAxis tick={{ fill: "#5d7397", fontSize: 10 }} stroke="#1a2a42" allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#0b1422", border: "1px solid #27405f", fontSize: 12, borderRadius: 2 }} labelStyle={{ color: "#a6b9d6" }} />
                <Line dataKey="subdomains" name="Subdomains" stroke="#e2ecfa" strokeWidth={1.5} dot={{ r: 2 }} />
                <Line dataKey="web_apps" name="Web services" stroke="#2ee6ff" strokeWidth={1.5} dot={{ r: 2 }} />
                <Line dataKey="findings" name="Observations" stroke="#ff7a3d" strokeWidth={1.5} dot={{ r: 2 }} />
                <Line dataKey="changes" name="Changes" stroke="#5d7397" strokeDasharray="4 3" strokeWidth={1.5} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </Section>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Review these first" right={<Link className="text-[12px] text-indigo-300 hover:underline" to="/priorities">All priorities</Link>}>
          <p className="mb-2 text-[12px] text-slate-500">{data.priority_disclaimer}</p>
          {data.priorities.slice(0, 7).map((p) => (
            <button key={p.asset.id} className="flex w-full items-start gap-3 border-b border-slate-800 py-2 text-left last:border-0 hover:bg-slate-800/30"
                    onClick={() => openAsset(p.asset.id)}>
              <span className={`display w-9 text-[15px] font-semibold ${TIER_STYLE[p.tier]}`}>{p.tier}</span>
              <span className="min-w-0 flex-1">
                <span className="mono block text-slate-100">{p.asset.key}</span>
                <span className="block text-[12px] text-slate-400">{p.factors.filter((f) => f.points > 0)[0]?.reason}</span>
              </span>
              <span className="tabular-nums text-[12px] text-slate-500">{p.score}</span>
            </button>
          ))}
        </Section>
        <Section title="What changed" right={<Link className="text-[12px] text-indigo-300 hover:underline" to="/changes">Full history</Link>}>
          {!data.changes.length && <Empty>The last scan matched the previous one. Nothing new to review.</Empty>}
          {data.changes.slice(0, 9).map((c) => (
            <button key={c.id} className="flex w-full items-start gap-3 border-b border-slate-800 py-2 text-left text-[13px] last:border-0 hover:bg-slate-800/30"
                    onClick={() => c.asset_id && openAsset(c.asset_id)}>
              <span className="mt-1.5 h-2 w-2 shrink-0 rounded-full" style={{ background: SIG[c.significance] }} title={`${c.significance} significance`} />
              <span className="text-slate-200">{c.summary}</span>
            </button>
          ))}
        </Section>
      </div>

      {data.coverage_gaps.length > 0 && (
        <Section title="Not covered by this scan" right={<Link className="text-[12px] text-indigo-300 hover:underline" to="/coverage">Coverage report</Link>}>
          <ul className="grid gap-x-6 gap-y-2 md:grid-cols-2">
            {data.coverage_gaps.slice(0, 10).map((g, i) => (
              <li key={i} className="text-[12px]">
                <span className="font-medium text-slate-200">{g.module}</span> <span className="text-slate-500">{g.status}</span>
                <div className="text-slate-400">{g.reason}</div>
              </li>
            ))}
          </ul>
        </Section>
      )}
    </div>
  );
}
