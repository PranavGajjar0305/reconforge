import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import Icon from "../components/icons";
import { Pending, Section, useLoad } from "../components/ui";

const SOURCE = {
  dashboard: ["saved here", "text-emerald-300 border-emerald-400/40"],
  environment: ["from environment", "text-indigo-200 border-indigo-400/40"],
};

function KeyRow({ row, onSaved }) {
  const [val, setVal] = useState("");
  const [show, setShow] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const save = async (clear) => {
    setBusy(true); setErr("");
    try { onSaved(await api.saveApiKeys(clear ? {} : { [row.env]: val }, clear ? [row.env] : [])); setVal(""); }
    catch (e) { setErr(e.message); } finally { setBusy(false); }
  };
  const [label, cls] = SOURCE[row.source] || ["not set", "text-slate-500 border-slate-700"];
  return (
    <tr>
      <td className="align-middle">
        <div className="font-medium text-slate-100">{row.service}</div>
        <div className="font-mono text-[11px] text-slate-500">{row.env}</div>
      </td>
      <td className="max-w-[260px] align-middle text-[12px] text-slate-400">{row.used_by || "custom key"}</td>
      <td className="align-middle"><span className={`rounded-[2px] border px-1.5 py-0.5 font-mono text-[11px] ${cls}`}>{label}</span></td>
      <td className="align-middle">
        <form className="flex items-center gap-1.5" onSubmit={(e) => { e.preventDefault(); if (val.trim()) save(false); }}>
          <input className="input w-64 font-mono text-[12px]" type={show ? "text" : "password"} autoComplete="off" spellCheck={false}
                 placeholder={row.set ? "•••••••• (enter a new value to replace)" : "paste key"} value={val} onChange={(e) => setVal(e.target.value)}
                 aria-label={`${row.service} API key`} />
          <button type="button" className="btn-ghost px-1.5" onClick={() => setShow(!show)} aria-label={show ? "Hide value" : "Show value"}>
            {show ? "hide" : "show"}
          </button>
          <button className="btn px-2.5 py-1 text-[12px]" disabled={busy || !val.trim()}>Save</button>
          {row.source === "dashboard" && <button type="button" className="btn-ghost text-[#ffb3c0]" disabled={busy} onClick={() => save(true)}>Remove</button>}
          {row.url && <a className="btn-ghost" href={row.url} target="_blank" rel="noreferrer noopener">Get key</a>}
        </form>
        {err && <div className="mt-1 text-[12px] text-[#ff8da0]">{err}</div>}
      </td>
    </tr>
  );
}

const CHANNELS = [
  { id: "slack", label: "Slack", secret: "Incoming webhook URL", hint: "https://hooks.slack.com/services/…" },
  { id: "discord", label: "Discord", secret: "Webhook URL", hint: "https://discord.com/api/webhooks/…" },
  { id: "telegram", label: "Telegram", secret: "Bot token", hint: "123456:ABC…", fields: [["chat_id", "Chat ID", "-1001234567890"]] },
  { id: "email", label: "E-mail (SMTP)", secret: "SMTP password", hint: "password",
    fields: [["smtp_host", "SMTP host", "smtp.example.com"], ["smtp_port", "Port", "587"], ["username", "Username", "alerts@example.com"],
             ["from", "From", "reconforge@example.com"], ["to", "To (comma separated)", "secops@example.com"]] },
];

function ChannelCard({ ch, state, onSaved }) {
  const [form, setForm] = useState({});
  const [secret, setSecret] = useState("");
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);
  const val = (k) => (k in form ? form[k] : Array.isArray(state[k]) ? state[k].join(", ") : state[k] ?? "");
  const run = async (fn, ok) => {
    setBusy(true); setMsg(null);
    try { const r = await fn(); if (r && r.channels) onSaved(r); setMsg(["ok", ok]); }
    catch (e) { setMsg(["err", e.message]); } finally { setBusy(false); }
  };
  const save = (extra = {}) => run(() => api.saveNotify({ channels: { [ch.id]: { ...form, ...(secret ? { secret } : {}), ...extra } } }), "Saved.")
    .then(() => { setSecret(""); setForm({}); });
  return (
    <div className="rounded-[3px] border border-slate-800 p-3">
      <div className="mb-2 flex items-center gap-2">
        <span className="text-[13.5px] font-semibold text-slate-100">{ch.label}</span>
        <span className={`rounded-[2px] border px-1.5 py-0.5 font-mono text-[10.5px] ${state.secret_set ? "border-emerald-400/40 text-emerald-300" : "border-slate-700 text-slate-500"}`}>
          {state.secret_set ? `${ch.secret.toLowerCase()} set` : `no ${ch.secret.toLowerCase()}`}</span>
        <label className="ml-auto flex items-center gap-1.5 text-[12.5px] text-slate-300">
          <input type="checkbox" checked={!!state.enabled} disabled={busy} onChange={(e) => save({ enabled: e.target.checked })} /> Send scan alerts
        </label>
      </div>
      <form className="grid gap-2 sm:grid-cols-2" onSubmit={(e) => { e.preventDefault(); save(); }}>
        <label className="text-[11.5px] text-slate-400 sm:col-span-2">{ch.secret}
          <input className="input mt-0.5 w-full font-mono text-[12px]" type="password" autoComplete="off" spellCheck={false}
                 placeholder={state.secret_set ? "•••••••• (enter a new value to replace)" : ch.hint} value={secret} onChange={(e) => setSecret(e.target.value)} />
        </label>
        {(ch.fields || []).map(([k, label, ph]) => (
          <label key={k} className="text-[11.5px] text-slate-400">{label}
            <input className="input mt-0.5 w-full font-mono text-[12px]" placeholder={ph} value={val(k)}
                   onChange={(e) => setForm({ ...form, [k]: k === "smtp_port" ? e.target.value.replace(/\D/g, "") : e.target.value })} />
          </label>
        ))}
        {ch.id === "email" && (
          <label className="flex items-center gap-1.5 self-end text-[12px] text-slate-300">
            <input type="checkbox" checked={"starttls" in form ? form.starttls : state.starttls !== false}
                   onChange={(e) => setForm({ ...form, starttls: e.target.checked })} /> STARTTLS
          </label>
        )}
        <div className="flex flex-wrap items-center gap-2 sm:col-span-2">
          <button className="btn px-2.5 py-1 text-[12px]" disabled={busy || (!secret && !Object.keys(form).length)}>Save</button>
          <button type="button" className="btn-ghost" disabled={busy || !state.secret_set} onClick={() => run(() => api.testNotify(ch.id), "Test message sent.")}>Send test</button>
          {state.secret_set && <button type="button" className="btn-ghost text-[#ffb3c0]" disabled={busy} onClick={() => save({ clear_secret: true, enabled: false })}>Remove {ch.secret.toLowerCase()}</button>}
          {msg && <span className={`text-[12px] ${msg[0] === "ok" ? "text-emerald-300" : "text-[#ff8da0]"}`}>{msg[1]}</span>}
        </div>
      </form>
    </div>
  );
}

function Notifications() {
  const { data, error, loading, reload } = useLoad(() => api.notifySettings(), []);
  const [state, setState] = useState(null);
  const [err, setErr] = useState("");
  const cur = state || data;
  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;
  const update = async (body) => { setErr(""); try { setState(await api.saveNotify(body)); } catch (e) { setErr(e.message); } };
  return (
    <Section title="Notifications" right={
      <div className="flex items-center gap-3 text-[12.5px] text-slate-300">
        <label className="flex items-center gap-1.5"><input type="checkbox" checked={cur.enabled} onChange={(e) => update({ enabled: e.target.checked })} /> Notify after every scan</label>
        <label className="flex items-center gap-1.5">Minimum significance
          <select className="input py-0.5" value={cur.min_significance} onChange={(e) => update({ min_significance: e.target.value })}>
            {["low", "medium", "high"].map((x) => <option key={x}>{x}</option>)}
          </select>
        </label>
      </div>}>
      <p className="mb-3 text-[12.5px] text-slate-400">
        After each scan ReconForge sends one summary of new attack-surface changes (new hosts, ports, findings, certificate changes) to every enabled
        channel; identical changes are not repeated within a week. Webhook URLs, tokens and passwords are stored like API keys and never shown again.
      </p>
      {err && <div className="mb-2 text-[12.5px] text-[#ff8da0]">{err}</div>}
      <div className="grid gap-3 xl:grid-cols-2">
        {CHANNELS.map((ch) => <ChannelCard key={ch.id} ch={ch} state={cur.channels[ch.id]} onSaved={setState} />)}
      </div>
    </Section>
  );
}

export default function Settings() {
  const { data, error, loading, reload } = useLoad(() => api.apiKeys(), []);
  const [rows, setRows] = useState(null);
  const [q, setQ] = useState("");
  const [custom, setCustom] = useState({ env: "", value: "" });
  const [cerr, setCerr] = useState("");
  const list = rows || data;
  const shown = useMemo(() => (list || []).filter((r) => !q || JSON.stringify(r).toLowerCase().includes(q.toLowerCase())), [list, q]);
  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;
  const setCount = list.filter((r) => r.set).length;
  const addCustom = async (e) => {
    e.preventDefault(); setCerr("");
    try { setRows(await api.saveApiKeys({ [custom.env.trim().toUpperCase()]: custom.value })); setCustom({ env: "", value: "" }); }
    catch (x) { setCerr(x.message); }
  };
  return (
    <div className="space-y-4">
      <div className="grid gap-3 md:grid-cols-3">
        <div className="hud px-4 py-3">
          <div className="readout text-[26px] text-slate-50">{setCount}<span className="ml-1.5 text-[13px] text-slate-400">of {list.length} keys set</span></div>
          <div className="mt-1 text-[12px] text-slate-400">More keys mean more passive sources: more subdomains, URLs and IP context.</div>
        </div>
        <div className="hud px-4 py-3 text-[12.5px] leading-relaxed text-slate-400 md:col-span-2">
          <div className="mb-1 flex items-center gap-1.5 text-slate-200"><Icon name="lock" size={14} className="text-emerald-300" /> How keys are handled</div>
          Saved in <span className="font-mono text-slate-300">data/settings.json</span> (file mode 600, git-ignored) and exported to the scan process,
          so built-in providers and external tools (subfinder, chaos, github-subdomains, …) use them. Values are never sent back to the browser.
          AI provider keys live on the <Link className="text-indigo-300 hover:underline" to="/ai">AI analysis</Link> page.
        </div>
      </div>
      <Section title="API keys" right={<input className="input w-56" placeholder="Filter services" value={q} onChange={(e) => setQ(e.target.value)} />}>
        <div className="overflow-auto">
          <table className="tbl">
            <thead><tr><th>Service</th><th>Used by</th><th>Status</th><th>Value</th></tr></thead>
            <tbody>{shown.map((r) => <KeyRow key={r.env} row={r} onSaved={setRows} />)}</tbody>
          </table>
        </div>
      </Section>
      <Notifications />
      <Section title="Add another key">
        <form className="flex flex-wrap items-center gap-2" onSubmit={addCustom}>
          <input className="input w-72 font-mono text-[12px]" placeholder="VARIABLE_NAME_API_KEY" value={custom.env}
                 onChange={(e) => setCustom({ ...custom, env: e.target.value })} aria-label="Environment variable name" />
          <input className="input w-80 font-mono text-[12px]" type="password" autoComplete="off" placeholder="value" value={custom.value}
                 onChange={(e) => setCustom({ ...custom, value: e.target.value })} aria-label="Key value" />
          <button className="btn-primary" disabled={!custom.env.trim() || !custom.value.trim()}>Save key</button>
          <span className="text-[12px] text-slate-500">For tools that read a key from the environment. Names must end in _API_KEY, _KEY, _TOKEN or _SECRET.</span>
        </form>
        {cerr && <div className="mt-2 text-[12.5px] text-[#ff8da0]">{cerr}</div>}
      </Section>
    </div>
  );
}
