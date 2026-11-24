import { useApp } from "../App";
import { api } from "../api";
import { DataTable, EvidenceLink, Loading, Pills, Section, useLoad, Pending } from "../components/ui";

export default function Subdomains() {
  const { target, openAsset } = useApp();
  const { data, loading, error, reload } = useLoad(() => api.reportData(target), [target]);
  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;
  return (
    <Section title={`Subdomain explorer (${data.hosts.length})`}>
      <DataTable
        rows={data.hosts}
        onRowClick={(r) => openAsset(r.id)}
        filters={[
          { key: "res", label: "DNS", get: (r) => (r.resolved ? "resolves" : "unresolved") },
          { key: "src", label: "Source", get: (r) => r.discovered_via.join("|") },
          { key: "scope", label: "Scope", get: (r) => r.scope },
        ]}
        columns={[
          { key: "key", label: "Hostname", render: (r) => <span className="mono text-slate-100">{r.key}</span> },
          { key: "resolved", label: "DNS", render: (r) => (r.resolved ? <span className="text-emerald-300">resolves</span> : <span className="text-slate-500">{r.attributes.dns_status || "unresolved"}</span>) },
          { key: "ips", label: "IPs", render: (r) => <span className="mono">{r.ips.join(", ")}</span> },
          { key: "cname", label: "CNAME", render: (r) => <span className="mono">{r.cname.join(", ")}</span> },
          { key: "discovered_via", label: "Discovery source", render: (r) => <Pills items={r.discovered_via} /> },
          { key: "first_seen", label: "First seen", className: "text-xs whitespace-nowrap" },
          { key: "last_seen", label: "Last seen", className: "text-xs whitespace-nowrap" },
          { key: "scope", label: "Scope" },
          { key: "confidence", label: "Conf.", sort: (r) => r.confidence },
          { key: "evidence", label: "Evidence", render: (r) => <EvidenceLink id={r.evidence} /> },
        ]}
      />
    </Section>
  );
}
