import { useApp } from "../App";
import { api } from "../api";
import { DataTable, EvidenceLink, Loading, Pills, Section, Stat, useLoad, Pending } from "../components/ui";

const API_KINDS = ["api", "graphql", "openapi", "websocket", "api_documentation", "oidc_metadata"];

export default function Endpoints() {
  const { target, openAsset } = useApp();
  const { data, loading, error, reload } = useLoad(() => api.reportData(target), [target]);
  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;
  const eps = data.endpoints;
  const count = (k) => eps.filter((e) => e.kind === k).length;
  const versions = [...new Set(eps.map((e) => e.api_version).filter(Boolean))];
  return (
    <div className="space-y-4">
      <div className="rounded-[3px] border border-indigo-500/30 bg-indigo-500/10 p-3 text-xs text-indigo-200">
        Inventory only. Documented methods come from specifications, HTML forms or JavaScript; ReconForge issues GET/HEAD requests exclusively and the dashboard never sends requests to these endpoints.
      </div>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-6">
        <Stat label="API hosts" value={data.api_hosts.length} />
        <Stat label="API endpoints" value={eps.filter((e) => API_KINDS.includes(e.kind)).length} />
        <Stat label="OpenAPI / Swagger docs" value={count("openapi") + count("api_documentation")} />
        <Stat label="GraphQL" value={count("graphql")} />
        <Stat label="WebSocket" value={count("websocket")} />
        <Stat label="API versions" value={versions.length} sub={versions.join(", ")} />
      </div>
      <Section title="API hosts"><Pills items={data.api_hosts} /></Section>
      <Section title={`Endpoints (${eps.length})`}>
        <DataTable
          rows={eps}
          onRowClick={(r) => openAsset(r.id)}
          filters={[
            { key: "kind", label: "Kind", get: (r) => r.kind },
            { key: "host", label: "Host", get: (r) => r.host },
            { key: "src", label: "Source", get: (r) => r.discovered_via.join("|") },
          ]}
          columns={[
            { key: "key", label: "Endpoint", render: (r) => <span className="mono text-slate-100">{r.key}</span> },
            { key: "kind", label: "Kind" },
            { key: "methods_documented", label: "Documented methods", render: (r) => <Pills items={r.methods_documented} /> },
            { key: "methods_observed", label: "Observed", render: (r) => <Pills items={r.methods_observed} /> },
            { key: "api_version", label: "Version" },
            { key: "status", label: "Status" },
            { key: "discovered_via", label: "Source", render: (r) => <Pills items={r.discovered_via} /> },
            { key: "evidence", label: "Evidence", render: (r) => <EvidenceLink id={r.evidence} /> },
          ]}
        />
      </Section>
      <Section title={`JavaScript files (${data.js_files.length})`}>
        <DataTable rows={data.js_files} onRowClick={(r) => openAsset(r.id)} search={false} columns={[
          { key: "key", label: "File", render: (r) => <span className="mono">{r.key}</span> },
          { key: "size", label: "Size" },
          { key: "endpoints_found", label: "API refs" },
          { key: "third_parties", label: "Third parties", render: (r) => <Pills items={r.third_parties} /> },
          { key: "secret_patterns", label: "Secret-like patterns" },
          { key: "sourcemap", label: "Source map", render: (r) => <span className="mono text-[11px]">{r.sourcemap}</span> },
        ]} />
      </Section>
    </div>
  );
}
