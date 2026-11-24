import { useMemo } from "react";
import { Link } from "react-router-dom";
import { useApp } from "../App";
import { api } from "../api";
import { Empty, Pending, Section, useLoad } from "../components/ui";

const GF_INFO = { xss: "reflected input", sqli: "database-backed parameters", ssrf: "server-side fetch targets", redirect: "redirect targets",
  lfi: "file/path parameters", rce: "command-like parameters", idor: "object identifiers", debug: "debug switches",
  interesting_files: "backup/config/data files", parameters: "any URL with parameters", secrets_in_url: "credentials in URLs" };

export default function Osint() {
  const { target, openAsset } = useApp();
  const { data, error, loading, reload } = useLoad(() => api.assets(target, { type: "domain,asn,third_party" }), [target]);
  const v = useMemo(() => {
    const rows = data || [];
    const domains = rows.filter((a) => a.type === "domain");
    return {
      domains,
      lookalikes: rows.filter((a) => a.type === "third_party" && a.attributes.category === "lookalike-domain"),
      asns: rows.filter((a) => a.type === "asn" && (a.attributes.announced_prefixes || []).length),
      social: rows.filter((a) => a.type === "third_party" && a.attributes.category === "social"),
    };
  }, [data]);
  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;
  const patterns = Object.assign({}, ...v.domains.map((d) => d.attributes.url_patterns || {}));
  const params = [...new Set(v.domains.flatMap((d) => d.attributes.top_parameters || []))];
  const contacts = v.domains.map((d) => d.attributes.contacts).filter(Boolean);
  return (
    <div className="space-y-4">
      <Section title="OSINT pivots" right={<span className="text-[12px] text-slate-500">Open in a new tab. ReconForge sends nothing to these sites.</span>}>
        {v.domains.every((d) => !(d.attributes.dorks || []).length) && <Empty>Run a scan with dork_builder (passive, standard and comprehensive profiles).</Empty>}
        {v.domains.filter((d) => (d.attributes.dorks || []).length).map((d) => {
          const by = {};
          d.attributes.dorks.forEach((x) => (by[x.engine] = by[x.engine] || []).push(x));
          return (
            <div key={d.id} className="mb-4">
              <div className="mb-2 font-mono text-[13px] text-indigo-200">{d.key}</div>
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                {Object.entries(by).map(([engine, list]) => (
                  <div key={engine} className="rounded-[3px] border border-slate-800 p-2.5">
                    <div className="mb-1 text-[12px] font-semibold text-slate-200">{engine}</div>
                    {list.map((x) => (
                      <a key={x.url + x.title} className="block truncate py-0.5 text-[12.5px] text-slate-300 hover:text-indigo-200" href={x.url}
                         target="_blank" rel="noreferrer noopener" title={x.query}>{x.title}</a>
                    ))}
                  </div>
                ))}
              </div>
            </div>
          );
        })}
      </Section>
      <div className="grid gap-4 xl:grid-cols-2">
        <Section title={`Look-alike domains (${v.lookalikes.length})`}>
          {!v.lookalikes.length ? <Empty>No registered look-alikes recorded (lookalike_domains module).</Empty> : (
            <div className="max-h-96 overflow-auto">
              <table className="tbl"><thead><tr><th>Domain</th><th>Technique</th><th>A</th><th>MX</th></tr></thead>
                <tbody>{v.lookalikes.map((a) => (
                  <tr key={a.id} className="cursor-pointer" onClick={() => openAsset(a.id)}>
                    <td className="font-mono text-[12px] text-slate-100">{a.key}</td><td className="text-[12px] text-slate-400">{a.attributes.technique}</td>
                    <td className="font-mono text-[11px] text-slate-400">{(a.attributes.dns?.A || []).slice(0, 2).join(", ")}</td>
                    <td className={`font-mono text-[11px] ${(a.attributes.dns?.MX || []).length ? "text-amber-300" : "text-slate-500"}`}>{(a.attributes.dns?.MX || []).slice(0, 1).join(", ") || "–"}</td>
                  </tr>))}
                </tbody></table>
            </div>
          )}
        </Section>
        <Section title="URL candidate lists (gf-style)" right={<Link className="btn-ghost" to="/files">Open the lists in Output files</Link>}>
          {!Object.keys(patterns).length ? <Empty>No URL classification yet (url_patterns module).</Empty> : (
            <div className="grid gap-1.5 sm:grid-cols-2">
              {Object.entries(patterns).sort((a, b) => b[1] - a[1]).map(([k, n]) => (
                <div key={k} className="flex items-baseline gap-2 border-b border-dotted border-slate-800 py-1 text-[13px]">
                  <span className="font-mono text-slate-200">{k}</span><span className="text-[11.5px] text-slate-500">{GF_INFO[k]}</span>
                  <span className="readout ml-auto text-[15px] text-slate-50">{n}</span>
                </div>
              ))}
            </div>
          )}
          {params.length > 0 && <div className="mt-3"><div className="mb-1 text-[12px] text-slate-400">Most common parameters</div>
            <div className="flex flex-wrap">{params.slice(0, 40).map((p) => <span key={p} className="pill">{p}</span>)}</div></div>}
        </Section>
        <Section title="Published contacts">
          {!contacts.length && !v.social.length ? <Empty>No e-mail addresses or social profiles collected (contact_intel module).</Empty> : (
            <div className="space-y-3 text-[13px]">
              {contacts.map((c, i) => (
                <div key={i}>
                  {(c.role_accounts || []).length > 0 && <div className="mb-1 text-[12px] text-slate-400">Role accounts: <span className="font-mono text-slate-200">{c.role_accounts.join(", ")}</span></div>}
                  <div className="flex flex-wrap">{(c.emails || []).slice(0, 80).map((e) => <span key={e} className="pill">{e}</span>)}</div>
                  <div className="mt-1 flex flex-wrap">{(c.social_profiles || []).slice(0, 40).map((s) => (
                    <a key={s} className="pill text-indigo-200 hover:underline" href={s} target="_blank" rel="noreferrer noopener">{s.replace(/^https?:\/\//, "")}</a>))}</div>
                </div>
              ))}
            </div>
          )}
        </Section>
        <Section title="Network ranges announced by the organisation">
          {!v.asns.length ? <Empty>No organisation-owned ASN prefixes (asn_prefixes skips shared cloud and CDN networks).</Empty> : v.asns.map((a) => (
            <div key={a.id} className="mb-3">
              <div className="mb-1 text-[13px] text-slate-200">{a.key} <span className="text-slate-500">{a.attributes.name}</span> · {a.attributes.prefix_count} prefixes</div>
              <div className="flex max-h-32 flex-wrap overflow-auto">{a.attributes.announced_prefixes.slice(0, 200).map((p) => <span key={p} className="pill">{p}</span>)}</div>
              <div className="mt-1 text-[11.5px] text-slate-500">{a.attributes.prefix_note}</div>
            </div>
          ))}
        </Section>
      </div>
    </div>
  );
}
