import { useApp } from "../App";
import { api } from "../api";
import { EvidenceLink, Loading, Pills, Section, Sev, useLoad, Pending, useStep } from "../components/ui";

export default function Infrastructure() {
  const { target, openAsset } = useApp();
  const { data: d, loading, error, reload } = useLoad(() => api.reportData(target), [target]);
  // big scans have thousands of these; render them in steps
  const [profiles, moreProfiles] = useStep(d?.http_profiles, 100);
  const [byIp, moreByIp] = useStep(d ? Object.entries(d.vhost_inventory.applications_by_ip) : null, 100);
  const [intel, moreIntel] = useStep(d?.ip_intelligence, 50);
  const [params, moreParams] = useStep(d?.parameter_inventory, 100);
  const [docs, moreDocs] = useStep(d?.documents, 100);
  const [dnsObs, moreDnsObs] = useStep(d ? [...d.email_findings, ...d.findings.filter((f) => f.attributes.category === "dns")] : null, 100);
  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;
  return (
    <div className="space-y-4">
      <Section title="DNS & mail infrastructure">
        {d.dns_infrastructure.map((x) => (
          <div key={x.domain} className="grid gap-3 text-xs md:grid-cols-3">
            <div><div className="text-slate-500">Nameservers</div>{x.nameservers.map((n) => <div key={n.host} className="mono">{n.host} <span className="text-slate-500">{n.provider || ""} {n.ips.join(", ")}</span></div>)}
              <div className="mt-2 text-slate-500">Registration</div><div>{x.registration?.registrar} · {JSON.stringify(x.registration?.events || {})}</div></div>
            <div><div className="text-slate-500">DNSSEC / CAA</div><div>{x.dnssec} · CAA: {x.caa.join(", ") || "none"}</div>
              <div className="mt-2 text-slate-500">MX</div>{x.mx.map((m) => <div key={m} className="mono">{m}</div>)}</div>
            <div><div className="text-slate-500">Email authentication</div>
              <div>SPF: <span className="mono">{x.spf.join(" | ") || "none"}</span> ({x.spf_dns_lookups} lookups)</div>
              <div>DMARC policy: {x.dmarc_policy || "none"}</div><div>DKIM selectors found: {x.dkim_selectors_found.join(", ") || "none"}</div>
              <div>MTA-STS {String(x.mta_sts)} · TLS-RPT {String(x.tls_rpt)} · BIMI {String(x.bimi)}</div></div>
          </div>
        ))}
        <div className="mt-3 text-xs text-slate-400">Email & DNS observations</div>
        {dnsObs.map((f) => (
          <div key={f.id} className="cursor-pointer text-sm" onClick={() => openAsset(f.id)}><Sev s={f.attributes.severity} /> {f.attributes.title} <span className="text-slate-500">{f.attributes.subject}</span></div>
        ))}{moreDnsObs}
      </Section>
      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Virtual hosts & application grouping">
          {byIp.map(([ip, apps]) => <div key={ip} className="mb-2 text-xs"><span className="mono text-slate-200">{ip}</span> <Pills items={apps} /></div>)}{moreByIp}
          <div className="text-xs text-slate-500">Shared certificates</div>
          {Object.entries(d.vhost_inventory.shared_certificates).map(([c, apps]) => <div key={c} className="text-xs">{c}: <Pills items={apps} /></div>)}
          <div className="mt-2 text-xs text-slate-500">Hosts answering only with the server default vhost</div><Pills items={d.vhost_inventory.default_vhost_only_hosts} />
          <div className="mt-2 text-xs text-slate-500">Visually similar applications</div>
          {d.screenshot_groups.map((g, i) => <div key={i}><Pills items={g} /></div>)}
          <div className="text-[11px] text-slate-500">Near-blank renders: {(d.screenshot_near_blank || []).join(", ") || "none"}</div>
        </Section>
        <Section title="Authentication & identity (inventory only)">
          {!d.identity.length && <div className="text-xs text-slate-500">No authentication infrastructure identified.</div>}
          {d.identity.map((i) => (
            <div key={i.app} className="mb-2 text-xs">
              <div className="mono text-slate-100">{i.app}</div>
              <div>Login: <Pills items={i.login_pages} /></div><div>Registration: <Pills items={i.registration} /></div>
              <div>Password reset: <Pills items={i.password_reset} /></div><div>Providers: <Pills items={i.providers} /></div>
              {i.oidc.map((o) => <div key={o.url}>OIDC issuer {o.issuer}</div>)}{i.saml.map((o) => <div key={o.url}>SAML entity {o.entity_id}</div>)}
            </div>
          ))}
        </Section>
      </div>
      <Section title="Third-party dependency inventory (referenced, not owned)">
        <div className="grid gap-2 md:grid-cols-3">
          {Object.entries(d.third_party_inventory).map(([cat, items]) => (
            <div key={cat} className="rounded-[3px] border border-slate-800 p-2 text-xs"><div className="mb-1 font-semibold text-slate-200">{cat.replaceAll("_", " ")}</div>
              {items.map((t) => <div key={t.domain}><span className="mono">{t.domain}</span> <span className="text-slate-500">{t.service}</span></div>)}</div>
          ))}
        </div>
      </Section>
      <Section title="HTTP/HTTPS intelligence">
        <table className="tbl"><thead><tr><th>Application</th><th>Redirect chain</th><th>HTTP/2</th><th>HTTP/3 adv.</th><th>Compression</th><th>HSTS</th><th>CSP</th><th>Default page</th></tr></thead><tbody>
          {profiles.map((p) => (
            <tr key={p.app}><td className="mono">{p.app}</td><td className="text-[11px]">{(p.redirect_chain || []).map((c, i) => <div key={i}>{c.status ?? "—"} {c.url}</div>)}</td>
              <td>{String(p.http2 ?? "n/a")}</td><td>{String(p.http3_advertised)}</td><td>{p.compression || "—"}</td>
              <td>{p.hsts ? `${p.hsts.max_age}s${p.hsts.include_subdomains ? " +sub" : ""}` : "none"}</td>
              <td className="text-[11px]">{p.csp ? p.csp.directives.join(" ") : "none"}</td><td>{p.default_page || ""}</td></tr>
          ))}
        </tbody></table>{moreProfiles}
      </Section>
      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="Endpoint categories & parameter inventory">
          <Pills items={Object.entries(d.endpoint_categories).map(([k, v]) => `${k}: ${v}`)} />
          <div className="mt-1 text-[11px] text-slate-500">Categories describe function, not weakness.</div>
          <table className="tbl mt-2"><thead><tr><th>Parameter</th><th>Endpoints</th><th>Examples</th></tr></thead><tbody>
            {params.map((p) => <tr key={p.name}><td className="mono">{p.name}</td><td>{p.endpoints}</td><td className="mono text-[11px]">{p.examples.join(", ")}</td></tr>)}
          </tbody></table>{moreParams}
        </Section>
        <Section title="Exposure intelligence, documents & secrets">
          {intel.map((x) => <div key={x.ip} className="mb-2 text-xs"><span className="mono text-slate-200">{x.ip}</span><pre className="mono whitespace-pre-wrap text-slate-400">{JSON.stringify(Object.fromEntries(Object.entries(x).filter(([k]) => k !== "ip")), null, 1).slice(0, 800)}</pre></div>)}{moreIntel}
          <div className="text-xs text-slate-500">Public documents (HEAD metadata only)</div>
          {docs.map((e) => <div key={e.id} className="mono text-[11px]">{e.key} · {e.attributes.content_type} · {e.attributes.size} B</div>)}{moreDocs}
          <div className="mt-2 text-xs text-slate-500">Potential secret exposure (redacted, never used or validated)</div>
          {d.secret_exposures.map((x, i) => <div key={i} className="text-[11px]"><span className="mono">{x.location}</span> · {x.pattern} · <EvidenceLink id={x.evidence} /></div>)}
        </Section>
      </div>
    </div>
  );
}
