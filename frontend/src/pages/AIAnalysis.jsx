import { useEffect, useState } from "react";
import { useApp } from "../App";
import { api, withToken } from "../api";
import { EvidenceLink, Loading, Section, useLoad, Pending } from "../components/ui";

const TITLES = {
  executive_summary: "Executive summary", asset_relationships: "Asset relationships", technology_stack: "Technology stack",
  interesting_assets: "Potentially interesting assets", unusual_changes: "Unusual infrastructure changes",
  security_observations: "Security configuration observations", cve_intelligence: "CVE intelligence",
  manual_investigation: "Recommended manual investigation", coverage_gaps: "Reconnaissance coverage gaps",
};
const PRIO = { critical: "bg-red-600 text-white", high: "bg-red-500/25 text-red-200", medium: "bg-orange-500/25 text-orange-200", low: "bg-slate-600/40 text-slate-200" };

function Ref({ id, openAsset }) {
  if (id.startsWith("ev_")) return <EvidenceLink id={id} />;
  if (id.startsWith("ast_")) return <button className="mono text-indigo-300 hover:underline" onClick={() => openAsset(id)}>{id}</button>;
  return <span className="mono text-slate-400">{id}</span>;
}

function ProviderSettings({ settings, onSaved }) {
  const [ai, setAi] = useState(settings.ai);
  const [key, setKey] = useState("");
  const [msg, setMsg] = useState("");
  useEffect(() => setAi(settings.ai), [settings]);
  const info = settings.providers[ai.provider] || {};
  const set = (k) => (e) => setAi({ ...ai, [k]: e.target.value });
  const save = async () => {
    setMsg("");
    try { await onSaved({ provider: ai.provider, model: ai.model, base_url: ai.base_url, effort: ai.effort, api_key_env: ai.api_key_env, ...(key ? { api_key: key } : {}) }); setKey(""); setMsg("Saved."); }
    catch (e) { setMsg(e.message); }
  };
  return (
    <div className="grid gap-3 text-sm md:grid-cols-2">
      <label className="md:col-span-2">Provider
        <select className="input mt-1 w-full" value={ai.provider} onChange={set("provider")}>
          {Object.entries(settings.providers).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
        </select></label>
      {ai.provider !== "heuristic" && <>
        <label>Model<input className="input mt-1 w-full" value={ai.model} onChange={set("model")}
          placeholder={info.default_model || (ai.provider === "openai" ? "the OpenAI model you have access to" : "e.g. llama3.1, qwen2.5, mistral")} /></label>
        {ai.provider !== "anthropic" && <label>Base URL<input className="input mt-1 w-full" value={ai.base_url} onChange={set("base_url")} placeholder={info.default_base_url} /></label>}
        {ai.provider === "anthropic" && <label>Effort<select className="input mt-1 w-full" value={ai.effort} onChange={set("effort")}>
          {["low", "medium", "high", "xhigh", "max"].map((e) => <option key={e}>{e}</option>)}</select></label>}
        <label>API key {settings.ai.api_key_set ? <span className="text-emerald-300">(set)</span> : <span className="text-slate-500">(not set)</span>}
          <input className="input mt-1 w-full" type="password" value={key} onChange={(e) => setKey(e.target.value)} placeholder={info.key_env ? `or set ${info.key_env} in the environment` : "optional"} /></label>
        <label>…or environment variable name<input className="input mt-1 w-full" value={ai.api_key_env} onChange={set("api_key_env")} placeholder={info.key_env || "MY_LLM_KEY"} /></label>
      </>}
      <div className="flex items-center gap-2 md:col-span-2">
        <button className="btn-primary" onClick={save}>Save provider settings</button>
        {settings.ai.api_key && <button className="btn" onClick={() => onSaved({ clear_api_key: true })}>Forget stored key</button>}
        <span className="text-xs text-slate-400">{msg}</span>
      </div>
      <p className="text-[11px] text-slate-500 md:col-span-2">Keys typed here are stored locally in settings.json (file mode 600) and never sent back to the browser. Environment variables are preferred.</p>
    </div>
  );
}

export default function AIAnalysis() {
  const { target, openAsset } = useApp();
  const overview = useLoad(() => api.overview(target), [target]);
  const settings = useLoad(() => api.settings(), []);
  const scanId = overview.data?.scan?.id;
  const ai = useLoad(() => (scanId ? api.ai(scanId) : Promise.resolve(null)), [scanId]);
  const [busy, setBusy] = useState(false);
  const [consent, setConsent] = useState(false);
  const [err, setErr] = useState("");
  const [answer, setAnswer] = useState("");
  const [copied, setCopied] = useState(false);
  if (overview.loading || ai.loading || settings.loading || overview.error || settings.error)
    return <Pending loading={overview.loading || ai.loading || settings.loading} error={overview.error || settings.error} reload={overview.reload} />;
  if (!scanId) return <div className="text-sm text-slate-500">No completed scans yet for this target.</div>;
  const prov = settings.data.ai.provider;
  const external = prov !== "heuristic";
  const run = async (provider) => {
    setErr(""); setBusy(true);
    try { await api.analyzeWith(scanId, { provider, consent }); ai.reload(); }
    catch (e) { setErr(e.message); } finally { setBusy(false); }
  };
  const copyPrompt = async () => {
    const b = await api.bundle(scanId);
    await navigator.clipboard.writeText(b.prompt);
    setCopied(true); setTimeout(() => setCopied(false), 2500);
  };
  const doImport = async () => {
    setErr("");
    try { await api.aiImport(scanId, answer, "pasted answer"); setAnswer(""); ai.reload(); } catch (e) { setErr(e.message); }
  };
  const a = ai.data;
  const top = a?.result?.top_priorities || [];
  return (
    <div className="space-y-4">
      <div className="grid gap-4 xl:grid-cols-2">
        <Section title="AI provider">
          <ProviderSettings settings={settings.data} onSaved={async (s) => { await api.saveSettings(s); settings.reload(); }} />
        </Section>
        <Section title={`Analyse scan ${scanId}`}>
          <p className="text-xs text-slate-400">
            The model receives only an evidence pack built from this scan. Every statement must cite asset/evidence IDs; an evidence guard rejects
            statements with unknown IDs or hosts, IPs, ports or CVEs that were not collected. <span className="text-emerald-300">fact</span> = restates evidence,
            <span className="text-orange-300"> hypothesis</span> = interpretation to verify.
          </p>
          {external && (
            <label className="mt-3 flex items-start gap-2 rounded border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-100">
              <input type="checkbox" className="mt-0.5" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
              <span>I understand this sends the reconnaissance evidence for <b>{target}</b> to <b>{settings.data.providers[prov]?.label}</b>{settings.data.ai.base_url ? ` (${settings.data.ai.base_url})` : ""}.</span>
            </label>
          )}
          <div className="mt-3 flex flex-wrap gap-2">
            <button className="btn-primary" disabled={busy || (external && !consent)} onClick={() => run(prov)}>{busy ? "Analysing…" : `Analyse with ${prov}`}</button>
            {external && <button className="btn" disabled={busy} onClick={() => run("heuristic")}>Offline analyst</button>}
          </div>
          {err && <div className="mt-2 text-sm text-[#ff8da0]">{err}</div>}
          <div className="mt-4 border-t border-slate-800 pt-3 text-xs">
            <div className="mb-2 font-semibold text-slate-200">Use any AI chat (ChatGPT, Claude.ai, Gemini, local LLM UI)</div>
            <div className="flex flex-wrap gap-2">
              <button className="btn" onClick={copyPrompt}>{copied ? "Copied ✓" : "Copy full prompt"}</button>
              <a className="btn" href={withToken(`/api/scans/${scanId}/ai-bundle?format=prompt`)}>Download prompt (.txt)</a>
              <a className="btn" href={withToken(`/api/scans/${scanId}/ai-bundle`)}>Download bundle (.json)</a>
            </div>
            <textarea className="input mt-2 h-24 w-full font-mono text-[11px]" placeholder="Paste the AI's JSON answer here to import it through the evidence guard"
                      value={answer} onChange={(e) => setAnswer(e.target.value)} />
            <button className="btn mt-1" disabled={!answer.trim()} onClick={doImport}>Import answer</button>
          </div>
        </Section>
      </div>

      {a && a.status !== "none" && (
        <div className="text-xs text-slate-400">Latest analysis: {a.provider} / {a.model} · {a.status} · {a.created_at} · {a.rejected.length} statement(s) rejected by the guard
          {a.error && <span className="ml-2 text-amber-300">{a.error}</span>}</div>
      )}
      {top.length > 0 && (
        <Section title="Most crucial — review in this order">
          <ol className="space-y-2">
            {top.map((it, i) => (
              <li key={i} className="flex gap-3 hud p-3">
                <div className="w-6 text-right text-lg font-bold text-slate-500">{i + 1}</div>
                <div className="flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`rounded px-2 py-0.5 text-[11px] font-bold uppercase ${PRIO[it.priority] || PRIO.low}`}>{it.priority}</span>
                    <span className={`text-[10px] uppercase ${it.kind === "hypothesis" ? "text-orange-300" : "text-emerald-300"}`}>{it.kind}</span>
                    <span className="text-sm text-slate-100">{it.statement}</span>
                  </div>
                  {it.rationale && <div className="mt-1 text-xs text-slate-400">Why: {it.rationale}</div>}
                  <div className="mt-1 flex flex-wrap gap-2 text-[11px]">{it.refs.map((r) => <Ref key={r} id={r} openAsset={openAsset} />)}</div>
                </div>
              </li>
            ))}
          </ol>
          <p className="mt-2 text-[11px] text-slate-500">Priority = urgency of manual review, not a confirmed vulnerability severity.</p>
        </Section>
      )}
      {a?.result && Object.entries(TITLES).map(([k, title]) => (a.result[k] || []).length > 0 && (
        <Section key={k} title={title}>
          {a.result[k].map((it, i) => (
            <div key={i} className={`mb-2 rounded-[3px] border-l-4 p-2 text-sm ${it.kind === "hypothesis" ? "border-orange-400 bg-orange-500/5" : "border-emerald-400 bg-emerald-500/5"}`}>
              <span className={`mr-2 text-[10px] font-semibold uppercase ${it.kind === "hypothesis" ? "text-orange-300" : "text-emerald-300"}`}>{it.kind}</span>
              {it.statement}
              <div className="mt-1 flex flex-wrap gap-2 text-[11px]">{it.refs.map((r) => <Ref key={r} id={r} openAsset={openAsset} />)}</div>
            </div>
          ))}
        </Section>
      ))}
      {a?.rejected?.length > 0 && (
        <Section title="Rejected by evidence guard (audit)">
          {a.rejected.map((r, i) => <div key={i} className="mb-1 text-xs text-slate-400"><span className="text-[#ffb3c0]">{r.reason}</span> — {String(r.item?.statement).slice(0, 200)}</div>)}
        </Section>
      )}
    </div>
  );
}
