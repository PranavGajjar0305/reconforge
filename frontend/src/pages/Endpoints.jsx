import { useCallback, useEffect, useState } from "react";
import { useApp } from "../App";
import { api } from "../api";
import { DataTable, EvidenceLink, ExportMenu, Pending, Pills, Section, ServerTable, Stat, useLoad } from "../components/ui";

const ORIGINS = [["live", "Live (crawled, probed, JS)"], ["archive", "Archive (Wayback etc.)"]];

export default function Endpoints() {
  const { target, openAsset } = useApp();
  const { data, loading, error, reload } = useLoad(() => api.reportData(target), [target]);
  const [facets, setFacets] = useState(null);
  useEffect(() => { setFacets(null); api.endpointFacets(target).then(setFacets).catch(() => setFacets(null)); }, [target]);
  const fetchPage = useCallback(({ offset, limit, q, filters, desc }) =>
    api.endpoints(target, { offset, limit, q, desc: desc || undefined, ...filters }), [target]);
  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;
  const summ = data.endpoint_summary || { total: data.endpoints.length, by_kind: {}, api: 0, historical: 0 };
  const k = summ.by_kind || {};
  const versions = [...new Set(data.endpoints.map((e) => e.api_version).filter(Boolean))];
  return (
    <div className="space-y-4">
      <div className="rounded-[3px] border border-indigo-500/30 bg-indigo-500/10 p-3 text-xs text-indigo-200">
        Inventory only. Documented methods come from specifications, HTML forms or JavaScript; ReconForge issues GET/HEAD requests exclusively and the dashboard never sends requests to these endpoints.
      </div>
      <div className="grid grid-cols-2 gap-3 md:grid-cols-6">
        <Stat label="Endpoints" value={summ.total.toLocaleString()} sub={summ.historical ? `${summ.historical.toLocaleString()} from archives` : undefined} />
        <Stat label="API endpoints" value={summ.api.toLocaleString()} />
        <Stat label="API hosts" value={data.api_hosts.length} />
        <Stat label="OpenAPI / Swagger docs" value={(k.openapi || 0) + (k.api_documentation || 0)} />
        <Stat label="GraphQL" value={k.graphql || 0} />
        <Stat label="API versions" value={versions.length} sub={versions.slice(0, 6).join(", ")} />
      </div>
      <Section title="API hosts"><Pills items={data.api_hosts} /></Section>
      <Section title={`Endpoints (${summ.total.toLocaleString()})`}
               right={<ExportMenu target={target} surfaces={[["endpoints", "All endpoints"]]} label="Download all" />}>
        <ServerTable
          fetchPage={fetchPage}
          resetKey={target}
          onRowClick={(r) => openAsset(r.id)}
          searchPlaceholder="Search URLs…"
          sortLabel="URL"
          filters={[
            { key: "kind", label: "Kind", options: Object.entries(facets?.by_kind || k).map(([v, n]) => [v === "unknown" ? "" : v, `${v} (${n.toLocaleString()})`]).filter(([v]) => v) },
            { key: "origin", label: "Origin", options: ORIGINS },
            { key: "host", label: "Host", options: (facets?.hosts || []).map(([h, n]) => [h, `${h} (${n.toLocaleString()})`]) },
          ]}
          columns={[
            { key: "key", label: "Endpoint", className: "max-w-[560px]", render: (r) => <span className="mono break-all text-slate-100">{r.key}</span> },
            { key: "kind", label: "Kind" },
            { key: "status", label: "Status", render: (r) => r.status ?? (r.archived_status ? <span className="text-slate-500">{r.archived_status} (archived)</span> : "") },
            { key: "methods_documented", label: "Documented methods", render: (r) => <Pills items={r.methods_documented} /> },
            { key: "methods_observed", label: "Observed", render: (r) => <Pills items={r.methods_observed} /> },
            { key: "api_version", label: "Version" },
            { key: "discovered_via", label: "Source", render: (r) => <Pills items={r.discovered_via} /> },
            { key: "evidence", label: "Evidence", render: (r) => <EvidenceLink id={r.evidence} /> },
          ]}
          empty="No endpoints match."
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
