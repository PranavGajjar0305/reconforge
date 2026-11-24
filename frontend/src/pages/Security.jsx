import { useApp } from "../App";
import { api } from "../api";
import Icon from "../components/icons";
import { DataTable, EvidenceLink, Loading, Pills, Section, Sev, useLoad, Pending } from "../components/ui";

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export default function Security() {
  const { target, openAsset } = useApp();
  const { data, loading, error, reload } = useLoad(() => api.reportData(target), [target]);
  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;
  const tls = data.findings.filter((f) => f.attributes.category === "tls");
  const total = data.findings.length + data.cve_findings.length;
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-[3px] border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-100">
        <span className="max-w-3xl">These are configuration observations and intelligence correlations, not confirmed vulnerabilities. Each links to the evidence it was derived from; verify manually and mark false positives from the asset panel.</span>
        <div className="flex shrink-0 gap-2">
          <a className="btn" href={api.burpScopeUrl(target)} title="Target scope as a Burp Suite project-options file (Settings > Project > Scope > Load)"><Icon name="download" size={13} /> Burp scope</a>
          <a className="btn" href={api.findingsReportUrl(target, "html")} target="_blank" rel="noreferrer" title="Open a shareable findings report"><Icon name="overview" size={13} /> HTML report</a>
          <a className="btn-primary" href={api.findingsReportUrl(target, "pdf")} title={`Download all ${total} findings as PDF`}><Icon name="download" size={13} /> PDF report</a>
        </div>
      </div>
      <Section title={`Security configuration observations (${data.findings.length})`}>
        <DataTable
          rows={data.findings}
          onRowClick={(r) => openAsset(r.id)}
          filters={[
            { key: "sev", label: "Severity", get: (r) => r.attributes.severity },
            { key: "cat", label: "Category", get: (r) => r.attributes.category },
          ]}
          columns={[
            { key: "sev", label: "Severity", render: (r) => <Sev s={r.attributes.severity} />, sort: (r) => SEV_RANK[r.attributes.severity] },
            { key: "title", label: "Observation", render: (r) => r.attributes.title, sort: (r) => r.attributes.title },
            { key: "cat", label: "Category", render: (r) => r.attributes.category },
            { key: "subject", label: "Subject", className: "min-w-[200px]", render: (r) => <span className="mono">{r.attributes.subject}</span> },
            { key: "desc", label: "Details", render: (r) => <span className="text-xs text-slate-400">{r.attributes.description}</span> },
            { key: "confidence", label: "Conf.", sort: (r) => r.confidence },
            { key: "evidence", label: "Evidence", render: (r) => <EvidenceLink id={r.evidence} /> },
          ]}
        />
      </Section>
      <div className="grid gap-4 lg:grid-cols-2">
        <Section title="TLS issues">
          {tls.map((f) => <div key={f.id} className="mb-1 cursor-pointer text-sm" onClick={() => openAsset(f.id)}><Sev s={f.attributes.severity} /> {f.attributes.title} <span className="mono text-slate-400">{f.attributes.subject}</span></div>)}
          <div className="mt-3 text-xs text-slate-400">Certificates</div>
          {data.certificates.map((c) => (
            <div key={c.id} className="mt-1 cursor-pointer text-xs" onClick={() => openAsset(c.id)}>
              <span className="text-slate-200">{c.subject_cn}</span> · {c.issuer_cn} · expires {c.not_after?.slice(0, 10)} ({c.days_remaining}d) · {c.trusted ? "trusted" : "untrusted"} · <Pills items={c.sans} />
            </div>
          ))}
        </Section>
        <Section title="Cloud & exposed-information references">
          {data.cloud.map((c) => (
            <div key={c.id} className="mb-1 cursor-pointer text-sm" onClick={() => openAsset(c.id)}>
              <span className="pill">{c.attributes.provider}</span><span className="pill">{c.attributes.service}</span>
              <span className="mono">{c.attributes.name}</span> <span className="text-xs text-slate-500">ownership {c.attributes.ownership}</span>
            </div>
          ))}
          <div className="mt-3 text-xs text-slate-400">Third parties referenced (reference ≠ ownership)</div>
          {data.third_parties.map((t) => (
            <div key={t.id} className="mt-1 text-xs"><span className="mono text-slate-200">{t.key}</span> <span className="text-slate-500">{t.attributes.service || t.attributes.category}</span></div>
          ))}
        </Section>
      </div>
      <Section title={`CVE intelligence (${data.cve_findings.length}) — version correlation only`}>
        <DataTable
          rows={data.cve_findings}
          onRowClick={(r) => openAsset(r.id)}
          filters={[{ key: "prod", label: "Product", get: (r) => r.attributes.product }]}
          columns={[
            { key: "cve", label: "CVE", render: (r) => r.attributes.cves.map((c) => <a key={c} className="mono text-indigo-300" href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noreferrer" onClick={(e) => e.stopPropagation()}>{c} </a>) },
            { key: "product", label: "Product", render: (r) => `${r.attributes.product} ${r.attributes.version}` },
            { key: "subject", label: "Asset", render: (r) => <span className="mono">{r.attributes.subject}</span> },
            { key: "desc", label: "Summary", render: (r) => <span className="text-xs text-slate-400">{r.attributes.description}</span> },
            { key: "confidence", label: "Conf." },
            { key: "evidence", label: "Evidence", render: (r) => <EvidenceLink id={r.evidence} /> },
          ]}
        />
      </Section>
    </div>
  );
}
