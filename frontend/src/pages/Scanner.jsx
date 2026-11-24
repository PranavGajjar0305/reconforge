import { useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useApp } from "../App";
import { api } from "../api";
import Icon from "../components/icons";
import { PageHead, Section, useLoad } from "../components/ui";

const EMPTY = { name: "", targets: "", profile: "standard", include: "", exclude: "", ip_allow: "", ports: "", authorized: false };
const lines = (s) => s.split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);

/* Client-side preview only; the server re-validates every entry. */
export function classifyEntry(raw) {
  let v = raw.trim().replace(/^[,;]+|[,;]+$/g, "");
  if (!v) return null;
  if (/^[0-9a-f:.]+\/\d{1,3}$/i.test(v)) {
    const bits = +v.split("/")[1];
    const v6 = v.includes(":");
    const size = 2 ** ((v6 ? 128 : 32) - bits);
    if ((v6 ? bits > 128 : bits > 32)) return { raw, kind: "invalid", value: v, note: "bad prefix length" };
    if (size > 4096) return { raw, kind: "invalid", value: v, note: `${size.toLocaleString()} addresses; max 4,096 per range` };
    return { raw, kind: size === 1 ? "ip" : "range", value: v, note: size > 1 ? `${size} addresses` : "" };
  }
  try { if (/^[a-z]+:\/\//i.test(v)) v = new URL(v).hostname; } catch { /* not a URL */ }
  v = v.replace(/^\[|\]$/g, "").replace(/^\*\./, "").toLowerCase();
  if (/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/.test(v)) {
    const ip = v.split(":")[0];
    return ip.split(".").every((o) => +o <= 255) ? { raw, kind: "ip", value: ip } : { raw, kind: "invalid", value: v, note: "not an IP" };
  }
  if (/^[0-9a-f:]+$/i.test(v) && v.includes(":") && v.split(":").length > 2) return { raw, kind: "ip", value: v };
  v = v.replace(/:\d+$/, "").replace(/\/.*$/, "");
  if (/^(?=.{1,253}$)([a-z0-9_]([a-z0-9-_]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$/.test(v)) return { raw, kind: "domain", value: v };
  return { raw, kind: "invalid", value: v, note: "not a domain, IP or range" };
}
const KIND = { domain: ["domain", "text-indigo-200 border-indigo-400/40"], ip: ["IP", "text-emerald-200 border-emerald-400/40"],
               range: ["range", "text-emerald-200 border-emerald-400/40"], invalid: ["invalid", "text-[#ff8da0] border-[#ff3d71]/50"] };

export function TargetChips({ domains = [], ips = [], max = 8 }) {
  const all = [...domains.map((d) => ["domain", d]), ...ips.map((i) => [i.includes("/") ? "range" : "ip", i])];
  return (
    <div className="flex flex-wrap gap-1">
      {all.slice(0, max).map(([k, v]) => (
        <span key={v} className={`rounded-[2px] border px-1.5 py-0.5 font-mono text-[11px] ${KIND[k][1]}`}>{v}</span>
      ))}
      {all.length > max && <span className="px-1 font-mono text-[11px] text-slate-500">+{all.length - max} more</span>}
    </div>
  );
}

function ScanForm({ initial, profiles, onSaved, onCancel, editing }) {
  const [f, setF] = useState(initial || EMPTY);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [adv, setAdv] = useState(false);
  const set = (k) => (e) => setF({ ...f, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  const parsed = useMemo(() => {
    const seen = new Set();
    return lines(f.targets).map(classifyEntry).filter((x) => x && !seen.has(x.value) && seen.add(x.value));
  }, [f.targets]);
  const counts = parsed.reduce((a, x) => ({ ...a, [x.kind]: (a[x.kind] || 0) + 1 }), {});
  const valid = parsed.filter((x) => x.kind !== "invalid");
  const save = async (andRun) => {
    setErr(""); setBusy(true);
    try {
      const firstName = (valid[0]?.value || "scan").replace(/[^a-zA-Z0-9_.-]/g, "-");
      const body = {
        name: f.name.trim() || (valid.length > 1 ? `${firstName}-and-${valid.length - 1}-more` : firstName),
        targets: valid.map((x) => x.value), profile: f.profile, authorization: { confirmed: f.authorized },
        scope: { include: lines(f.include), exclude: lines(f.exclude), ip_allow: lines(f.ip_allow) },
        ports: f.ports ? lines(f.ports).map(Number) : null,
      };
      const t = await api.saveTarget(body);
      await onSaved(t.name, andRun ? f.profile : null);
    } catch (e) { setErr(e.message); } finally { setBusy(false); }
  };
  return (
    <div className="space-y-4 text-sm">
      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_280px]">
        <label className="block">
          <span className="text-slate-200">Targets</span>
          <span className="ml-2 text-[12px] text-slate-500">one per line or comma-separated: domains, IP addresses, CIDR ranges or URLs</span>
          <textarea className="input mt-1.5 h-40 w-full font-mono text-[12.5px] leading-relaxed" spellCheck={false}
                    placeholder={"example.com\nshop.example.org\n203.0.113.10\n198.51.100.0/28\nhttps://portal.example.net"}
                    value={f.targets} onChange={set("targets")} />
        </label>
        <div className="space-y-3">
          <label className="block text-slate-200">Scan name
            <input className="input mt-1.5 w-full" placeholder="defaults to the first target" value={f.name} onChange={set("name")} disabled={editing} />
          </label>
          <label className="block text-slate-200">Profile
            <select className="input mt-1.5 w-full" value={f.profile} onChange={set("profile")}>
              {Object.entries(profiles).map(([p, v]) => <option key={p} value={p}>{p} — {v.modules.length} modules</option>)}
            </select>
          </label>
          <div className="hud px-3 py-2 text-[12px]">
            <div className="readout text-[22px] text-slate-50">{valid.length}<span className="ml-1.5 text-[12px] text-slate-400">target{valid.length === 1 ? "" : "s"}</span></div>
            <div className="mt-1 text-slate-400">{counts.domain || 0} domain · {counts.ip || 0} IP · {counts.range || 0} range{counts.invalid ? <span className="text-[#ff8da0]"> · {counts.invalid} invalid</span> : ""}</div>
          </div>
        </div>
      </div>
      {parsed.length > 0 && (
        <div className="flex max-h-36 flex-wrap gap-1.5 overflow-auto" aria-label="Parsed targets">
          {parsed.map((x) => (
            <span key={x.value} title={x.note || x.raw} className={`rounded-[2px] border px-2 py-0.5 font-mono text-[11.5px] ${KIND[x.kind][1]}`}>
              <span className="mr-1.5 text-[10.5px] opacity-70">{KIND[x.kind][0]}</span>{x.value}{x.note ? <span className="ml-1.5 opacity-70">{x.note}</span> : null}
            </span>
          ))}
        </div>
      )}
      <p className="text-[12px] leading-relaxed text-slate-500">
        Every module runs against all of these in one execution. Domains include their subdomains. IP addresses and ranges are
        probed directly (ports, HTTP/HTTPS, TLS, fingerprinting); domain-only sources such as certificate logs are skipped for them.
      </p>
      <button className="btn-ghost -ml-2" onClick={() => setAdv(!adv)}>{adv ? "▾" : "▸"} Scope options</button>
      {adv && (
        <div className="grid gap-3 md:grid-cols-2">
          <label>Include patterns<input className="input mt-1 w-full" placeholder="default: each domain and *.domain" value={f.include} onChange={set("include")} /></label>
          <label>Exclude patterns<input className="input mt-1 w-full" placeholder="*.corp.example.com" value={f.exclude} onChange={set("exclude")} /></label>
          <label>Extra IP ranges for active checks<input className="input mt-1 w-full" placeholder="listed IPs are always allowed; empty = public IPs only for resolved hosts" value={f.ip_allow} onChange={set("ip_allow")} /></label>
          <label>Ports for port scanning<input className="input mt-1 w-full" placeholder="default from config (e.g. 22,80,443,8080)" value={f.ports} onChange={set("ports")} /></label>
        </div>
      )}
      <label className={`flex cursor-pointer items-start gap-2.5 rounded-[3px] border p-3 transition-colors ${f.authorized
        ? "border-emerald-400/50 bg-emerald-400/[0.06]" : "border-amber-400/40 bg-amber-400/[0.07]"}`}>
        <input type="checkbox" className="mt-0.5 h-4 w-4" checked={f.authorized} onChange={set("authorized")} />
        <span className="text-[13px] leading-relaxed">
          <b className="text-slate-100">I am authorized to test these targets.</b>{" "}
          <span className="text-slate-400">I own them or have written permission. Without this only passive modules run (no traffic to the targets).</span>
        </span>
      </label>
      {err && <div className="text-[#ff8da0]">{err}</div>}
      <div className="flex flex-wrap gap-2">
        <button className="btn-primary px-5 py-2" disabled={busy || !valid.length} onClick={() => save(true)}>
          <Icon name="play" size={14} />{busy ? "Starting…" : editing ? "Save and run" : "Create and start scan"}
        </button>
        <button className="btn" disabled={busy || !valid.length} onClick={() => save(false)}>{editing ? "Save changes" : "Save without running"}</button>
        {onCancel && <button className="btn" onClick={onCancel}>Cancel</button>}
      </div>
    </div>
  );
}

export default function Scanner() {
  const { meta, target, setTarget, reloadMeta } = useApp();
  const nav = useNavigate();
  const [mode, setMode] = useState(meta.targets.length ? "run" : "new");
  const [editing, setEditing] = useState(null);
  const sel = meta.targets.find((t) => t.name === target);
  const [profile, setProfile] = useState("");
  const [mods, setMods] = useState(null);
  const [custom, setCustom] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const runs = useLoad(() => api.runs(), [meta]);
  const prof = profile || sel?.profile || "standard";
  const profMods = meta.profiles[prof]?.modules || [];
  useEffect(() => { setMods(new Set(profMods)); }, [prof]);
  const modInfo = useMemo(() => Object.fromEntries(meta.modules.map((m) => [m.name, m])), [meta]);
  const activeMods = [...(mods || [])].filter((m) => modInfo[m]?.active);

  const run = async (name = target, profileName = prof) => {
    setErr(""); setBusy(true);
    try {
      const r = await api.runScan({ target: name, profile: profileName, modules: custom ? [...mods] : null });
      reloadMeta();
      nav(`/live/${r.scan_id}`);
    } catch (e) { setErr(e.message); } finally { setBusy(false); }
  };
  const edit = async (name) => {
    const d = await api.targetDefinition(name);
    setEditing({ name: d.name, targets: [...(d.root_domains || []), ...(d.ip_targets || [])].join("\n"), profile: d.profile || "standard",
      include: (d.scope?.include || []).join(", "), exclude: (d.scope?.exclude || []).join(", "), ip_allow: (d.scope?.ip_allow || []).join(", "),
      ports: (d.ports || []).join(", "), authorized: !!d.authorization?.confirmed });
    setMode("edit");
  };

  return (
    <div>
    <PageHead title="Scanner">Create a scan with as many targets as you need (domains, IPs or ranges), pick how deep to go, and run. Every request streams to the live console as it happens.</PageHead>
    <div className="grid gap-5 xl:grid-cols-[340px_1fr]">
      <div className="order-2 space-y-4 xl:order-1">
        <Section title="Scans" right={<button className="btn" onClick={() => { setEditing(null); setMode("new"); }}><Icon name="plus" size={14} /> New scan</button>}>
          {!meta.targets.length && <div className="text-sm text-slate-400">No scans yet. Create one to start.</div>}
          <div className="space-y-2">
            {meta.targets.map((t) => (
              <div key={t.name} onClick={() => { setTarget(t.name); setMode("run"); }}
                   className={`cursor-pointer rounded-[3px] border p-3 transition-colors ${t.name === target ? "border-indigo-400/70 bg-indigo-400/[0.04]" : "border-slate-800 hover:border-slate-700"}`}>
                <div className="flex items-center justify-between">
                  <span className="font-medium text-slate-100">{t.name}</span>
                  <span className={`text-[11px] ${t.authorized ? "text-emerald-300" : "text-amber-300"}`}>{t.authorized ? "authorized" : "passive only"}</span>
                </div>
                <div className="mt-1.5"><TargetChips domains={t.root_domains} ips={t.ip_targets} max={6} /></div>
                <div className="mt-1 flex items-center gap-2 text-[11px] text-slate-500">
                  {t.scans} execution{t.scans === 1 ? "" : "s"} · {(t.root_domains?.length || 0) + (t.ip_targets?.length || 0)} target(s)
                  {meta.running?.[t.name] && <button className="text-amber-300" onClick={(e) => { e.stopPropagation(); nav(`/live/${meta.running[t.name]}`); }}>● running — view</button>}
                  {t.source === "dashboard" && <>
                    <button className="ml-auto text-indigo-300" onClick={(e) => { e.stopPropagation(); edit(t.name); }}>edit</button>
                    <button className="text-[#ffb3c0]" onClick={async (e) => { e.stopPropagation(); if (confirm(`Remove scan ${t.name}? Its execution history is kept.`)) { await api.deleteTarget(t.name); reloadMeta(); } }}>remove</button>
                  </>}
                </div>
              </div>
            ))}
          </div>
        </Section>
        <Section title="Recent runs in this session">
          {(runs.data || []).slice(0, 8).map((r) => (
            <div key={r.scan_id} className="flex cursor-pointer justify-between border-b border-slate-800 py-1 text-xs hover:bg-slate-800/40" onClick={() => nav(`/live/${r.scan_id}`)}>
              <span>{r.target} · {r.label}</span><span className={r.status === "running" ? "text-amber-300" : r.status === "failed" ? "text-[#ff8da0]" : "text-slate-400"}>{r.status}</span>
            </div>
          ))}
          {!runs.data?.length && <div className="text-xs text-slate-500">No runs started from the dashboard yet.</div>}
        </Section>
      </div>

      <div className="order-1 space-y-4 xl:order-2">
        {(mode === "new" || mode === "edit") && (
          <Section title={mode === "new" ? "New scan" : `Edit ${editing?.name}`}>
            <ScanForm key={mode + (editing?.name || "")} initial={mode === "edit" ? editing : null} profiles={meta.profiles} editing={mode === "edit"}
                      onSaved={async (name, runProfile) => {
                        await reloadMeta(); setTarget(name); setMode("run");
                        if (runProfile) await run(name, runProfile);
                      }}
                      onCancel={meta.targets.length ? () => setMode("run") : null} />
          </Section>
        )}
        {mode === "run" && sel && (
          <Section title={`Run ${sel.name}`} right={sel.source === "dashboard" && <button className="btn-ghost" onClick={() => edit(sel.name)}>Edit targets</button>}>
            <div className="space-y-4 text-sm">
              <div className="space-y-2 text-[12px]">
                <TargetChips domains={sel.root_domains} ips={sel.ip_targets} max={40} />
                <span className={`block ${sel.authorized ? "text-emerald-300" : "text-amber-300"}`}>
                  {sel.authorized ? "Authorized — every profile can run" : "Not marked as authorized — only the passive profile can run"}
                </span>
              </div>
              {!sel.runnable && <div className="text-amber-300">This scan only exists in execution history; re-create it to run it again.</div>}
              <div className="grid gap-2 md:grid-cols-4">
                {Object.entries(meta.profiles).map(([name, p]) => (
                  <button key={name} onClick={() => setProfile(name)}
                          aria-pressed={prof === name}
                          className={`rounded-[3px] border p-3 text-left transition-colors ${prof === name ? "border-indigo-400 bg-indigo-400/[0.06]" : "border-slate-800 hover:border-slate-600"}`}>
                    <div className="display text-[15px] font-semibold capitalize text-slate-100">{name}</div>
                    <div className="text-[11px] text-slate-400">{p.description}</div>
                    <div className="mt-1 text-[11px] text-slate-500">{p.modules.length} modules</div>
                  </button>
                ))}
              </div>
              <label className="flex items-center gap-2 text-xs"><input type="checkbox" checked={custom} onChange={(e) => setCustom(e.target.checked)} /> Customise modules for this run</label>
              {custom && mods && (
                <div className="grid gap-1 md:grid-cols-3">
                  {meta.modules.map((m) => (
                    <label key={m.name} className="flex items-start gap-2 rounded border border-slate-800 p-2 text-xs" title={m.description}>
                      <input type="checkbox" checked={mods.has(m.name)} onChange={() => { const n = new Set(mods); n.has(m.name) ? n.delete(m.name) : n.add(m.name); setMods(n); }} />
                      <span><span className="text-slate-200">{m.name}</span> <span className={m.active ? "text-amber-300" : "text-slate-500"}>{m.active ? "active" : "passive"}</span>
                        <div className="text-slate-500">{m.description}</div></span>
                    </label>
                  ))}
                </div>
              )}
              {!sel.authorized && activeMods.length > 0 && (
                <div className="rounded-[3px] border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-100">
                  This scan is not marked as authorized, so active modules ({activeMods.join(", ")}) cannot run. {sel.source === "dashboard" ? "Edit the scan and tick “I am authorized to test these targets”" : "Set authorization.confirmed: true in the config file"}, or choose the passive profile.
                </div>
              )}
              {meta.offline && <div className="text-xs text-slate-400">Config has network.offline = true: public-internet sources are skipped.</div>}
              {err && <div className="text-[#ff8da0]">{err}</div>}
              <div className="flex items-center gap-3">
                <button className="btn-primary px-6 py-2 text-base" disabled={busy || !sel.runnable || !!meta.running?.[sel.name]} onClick={() => run()}>
                  <Icon name="play" size={15} />{busy ? "Starting" : meta.running?.[sel.name] ? "Running" : "Run scan"}
                </button>
                <span className="text-xs text-slate-500">Runs every selected module, then correlation, change detection, prioritisation, reports{meta.offline ? "" : " and notifications (if enabled)"}.</span>
              </div>
            </div>
          </Section>
        )}
      </div>
    </div>
    </div>
  );
}
