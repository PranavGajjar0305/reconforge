import { useApp } from "../App";
import { api } from "../api";
import { DataTable, Loading, Pills, Section, useLoad, Pending } from "../components/ui";

export default function Inventory() {
  const { target, openAsset } = useApp();
  const { data, loading, error, reload } = useLoad(() => api.inventory(target), [target]);
  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;
  return (
    <Section title="Asset inventory — one correlated record per host">
      <DataTable
        rows={data}
        onRowClick={(r) => openAsset(r.id)}
        filters={[
          { key: "resolved", label: "Resolved", get: (r) => (r.resolved ? "yes" : "no") },
          { key: "scope", label: "Scope", get: (r) => r.scope },
          { key: "tech", label: "Technology", get: (r) => r.technologies.map((t) => t.split(" ")[0]).join("|") },
          { key: "hosting", label: "Hosting", get: (r) => r.hosting.join("|") },
        ]}
        columns={[
          { key: "domain", label: "Domain" },
          { key: "host", label: "Subdomain", render: (r) => <span className="mono text-slate-100">{r.host}</span> },
          { key: "ips", label: "IP address", render: (r) => <span className="mono">{r.ips.join(", ") || <span className="text-slate-600">unresolved</span>}</span> },
          { key: "http_status", label: "HTTP status", render: (r) => r.http_status.map((s) => <div key={s} className="mono text-[11px]">{s}</div>) },
          { key: "open_ports", label: "Open ports", render: (r) => <Pills items={r.open_ports} /> },
          { key: "technologies", label: "Technologies", render: (r) => <Pills items={r.technologies} /> },
          { key: "hosting", label: "Hosting / ASN", render: (r) => <span className="text-xs">{r.hosting.join(", ")} {r.asn.join(", ")}</span> },
          { key: "cdn_waf", label: "CDN/WAF", render: (r) => <Pills items={r.cdn_waf} /> },
          { key: "tls", label: "TLS", render: (r) => r.tls.map((t) => <div key={t.app} className="text-[11px]">{t.version} · {t.issuer_cn} · {t.trusted ? "trusted" : "untrusted"} · exp {t.not_after?.slice(0, 10)}</div>) },
          { key: "last_seen", label: "Last observed", className: "whitespace-nowrap text-xs" },
        ]}
      />
    </Section>
  );
}
