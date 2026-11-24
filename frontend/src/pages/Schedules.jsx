import { useState } from "react";
import { useApp } from "../App";
import { api } from "../api";
import { Loading, Section, useLoad } from "../components/ui";

export default function Schedules() {
  const { target, meta } = useApp();
  const sch = useLoad(() => api.schedules(), []);
  const notes = useLoad(() => api.notifications(), []);
  const [form, setForm] = useState({ name: "", frequency: "daily", at: "02:00", day: "", cron: "", profile: "continuous", incremental: true });
  const [err, setErr] = useState("");
  if (sch.loading || notes.loading) return <Loading />;
  const save = async () => {
    setErr("");
    try {
      await api.addSchedule({ ...form, target, day: form.day || null, cron: form.cron || null, name: form.name || `${target}-${form.frequency}` });
      sch.reload();
    } catch (e) { setErr(e.message); }
  };
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });
  return (
    <div className="space-y-4">
      <Section title="Scan schedules (UTC)">
        <table className="tbl">
          <thead><tr><th>Name</th><th>Target</th><th>Frequency</th><th>Cron</th><th>Profile</th><th>Incremental</th><th>Enabled</th><th>Next run</th><th>Last run</th><th>Last status</th><th /></tr></thead>
          <tbody>
            {sch.data.map((s) => (
              <tr key={s.id}>
                <td>{s.name}</td><td>{s.target}</td><td>{s.frequency}</td><td className="mono">{s.cron}</td><td>{s.profile}</td>
                <td>{s.incremental ? "yes" : "no"}</td><td>{s.enabled ? "yes" : "no"}</td><td className="text-xs">{s.next_run_at}</td>
                <td className="text-xs">{s.last_run_at}</td><td>{s.last_status}</td>
                <td><button className="btn" onClick={async () => { await api.deleteSchedule(s.name); sch.reload(); }}>Delete</button></td>
              </tr>
            ))}
          </tbody>
        </table>
        {meta.configured_targets.includes(target) && (
          <div className="mt-4 flex flex-wrap items-end gap-2 text-xs">
            <label>Name<br /><input className="input" value={form.name} onChange={set("name")} placeholder={`${target}-${form.frequency}`} /></label>
            <label>Frequency<br /><select className="input" value={form.frequency} onChange={set("frequency")}>
              {["once", "hourly", "daily", "weekly", "monthly", "cron"].map((f) => <option key={f}>{f}</option>)}</select></label>
            <label>At (HH:MM)<br /><input className="input w-24" value={form.at} onChange={set("at")} /></label>
            <label>Day<br /><input className="input w-24" value={form.day} onChange={set("day")} placeholder="mon / 1" /></label>
            <label>Cron<br /><input className="input w-36" value={form.cron} onChange={set("cron")} placeholder="0 3 * * 1-5" /></label>
            <label>Profile<br /><select className="input" value={form.profile} onChange={set("profile")}>{Object.keys(meta.profiles).map((p) => <option key={p}>{p}</option>)}</select></label>
            <label className="flex items-center gap-1"><input type="checkbox" checked={form.incremental} onChange={set("incremental")} /> incremental</label>
            <button className="btn-primary" onClick={save}>Add / update schedule</button>
            {err && <span className="text-[#ff8da0]">{err}</span>}
          </div>
        )}
        <p className="mt-3 text-[11px] text-slate-500">Schedules run when the scheduler is active: <code>reconforge serve --with-scheduler</code>, <code>reconforge scheduler run</code>, or <code>reconforge scheduler tick</code> from system cron.</p>
      </Section>
      <Section title="Notification log">
        <table className="tbl">
          <thead><tr><th>Sent</th><th>Scan</th><th>Channel</th><th>Status</th><th>Changes</th><th>Preview / error</th></tr></thead>
          <tbody>
            {notes.data.map((n) => (
              <tr key={n.id}>
                <td className="text-xs whitespace-nowrap">{n.sent_at}</td><td className="mono">{n.scan_id}</td><td>{n.channel}</td>
                <td className={n.status === "sent" ? "text-emerald-300" : n.status === "failed" ? "text-[#ff8da0]" : "text-slate-400"}>{n.status}</td>
                <td>{n.changes}</td><td><pre className="mono max-h-24 overflow-auto whitespace-pre-wrap text-[11px] text-slate-400">{n.error || n.preview}</pre></td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>
    </div>
  );
}
