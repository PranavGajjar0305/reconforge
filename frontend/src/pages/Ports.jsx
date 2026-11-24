import { useApp } from "../App";
import { api } from "../api";
import { DataTable, EvidenceLink, Loading, Section, useLoad, Pending } from "../components/ui";

export default function Ports() {
  const { target, openAsset } = useApp();
  const { data, loading, error, reload } = useLoad(() => api.reportData(target), [target]);
  if (loading || error) return <Pending loading={loading} error={error} reload={reload} />;
  return (
    <div className="space-y-4">
      <Section title={`Port and service explorer (${data.services.length})`}>
        <DataTable
          rows={data.services}
          onRowClick={(r) => openAsset(r.id)}
          filters={[{ key: "svc", label: "Service", get: (r) => r.service }]}
          columns={[
            { key: "hosts", label: "Hostname(s)", render: (r) => <span className="mono">{(r.hosts || []).join(", ")}</span> },
            { key: "ip", label: "IP", render: (r) => <span className="mono">{r.ip}</span> },
            { key: "port", label: "Port", sort: (r) => r.port },
            { key: "proto", label: "Protocol" },
            { key: "service", label: "Service" },
            { key: "product", label: "Version", render: (r) => `${r.product || ""} ${r.version || ""}` },
            { key: "banner", label: "Banner", render: (r) => <span className="mono text-[11px] text-slate-400">{r.banner}</span> },
            { key: "first_seen", label: "Discovered", className: "text-xs whitespace-nowrap" },
            { key: "evidence", label: "Evidence", render: (r) => <EvidenceLink id={r.evidence} /> },
          ]}
        />
      </Section>
      <Section title={`Web services (${data.web_apps.length})`}>
        <DataTable
          rows={data.web_apps}
          onRowClick={(r) => openAsset(r.id)}
          columns={[
            { key: "key", label: "URL", render: (r) => <span className="mono text-slate-100">{r.key}</span> },
            { key: "status", label: "Status", sort: (r) => r.status },
            { key: "title", label: "Title" },
            { key: "server", label: "Server" },
            { key: "ip", label: "IP", render: (r) => <span className="mono">{r.ip}</span> },
            { key: "screenshot", label: "Screenshot", render: (r) => <EvidenceLink id={r.screenshot}>{r.screenshot ? "view" : ""}</EvidenceLink> },
          ]}
        />
      </Section>
    </div>
  );
}
