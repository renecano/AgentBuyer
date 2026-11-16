import { useCallback, useEffect, useState } from "react";
import { ApiError, request } from "../lib/api";
import { useAuth } from "../lib/AuthProvider";
import { auditTypeLabel, displayName, localizedText, verdictLabel } from "../lib/presentation";

type AuditEvent = { event_id: string; timestamp: string; type: string; mandate_id: string; verdict?: "APPROVE" | "ESCALATE" | "REJECT"; summary: string };

function formatDate(timestamp: string) {
  return new Intl.DateTimeFormat("en-US", { dateStyle: "medium", timeStyle: "medium" }).format(new Date(timestamp));
}

export default function AuditView() {
  // P-04 (4.1): el backend devuelve los eventos de TUS mandatos; un admin, todos.
  // El rol del token es solo para el texto: quién ve qué lo decide el servidor.
  const { session } = useAuth();
  const isAdmin = session?.role === "admin";
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const loadAudit = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setEvents(await request<AuditEvent[]>("/audit"));
    } catch (caught) {
      if (caught instanceof ApiError) setError("Couldn't load the audit trail.");
      else setError(caught instanceof Error ? caught.message : "No connection to the system.");
    } finally { setLoading(false); }
  }, []);

  useEffect(() => { void loadAudit(); }, [loadAudit]);
  const verdictCounts = events.reduce((counts, event) => {
    if (event.verdict === "APPROVE") counts.approve += 1;
    if (event.verdict === "ESCALATE") counts.escalate += 1;
    if (event.verdict === "REJECT") counts.reject += 1;
    return counts;
  }, { approve: 0, escalate: 0, reject: 0 });
  return (
    <main className="reading-shell">
      <section className="reading-page">
        <header className="reading-header"><div><p className="mission-kicker">AUDIT / APPEND-ONLY TRAIL</p><h1>{isAdmin ? "Complete system record" : "Your permissions' record"}</h1><p>{isAdmin ? "The verifiable history of every mandate, decision, and outcome." : "The verifiable history of every decision made under your permissions."}</p></div><button className="refresh-button" onClick={() => void loadAudit()} disabled={loading} type="button">{loading ? "REFRESHING…" : "↻ REFRESH"}</button></header>
        {error && <div className="connection-error" role="alert"><strong>No connection to the system.</strong> {error}</div>}
        <div className="verdict-summary" aria-label="Trail verdict summary"><span className="summary-approve">{verdictCounts.approve} approved</span><span className="summary-escalate">{verdictCounts.escalate} need approval</span><span className="summary-reject">{verdictCounts.reject} rejected</span></div>
        <section className="audit-panel"><div className="panel-title"><span>EVENTS · NEWEST FIRST</span><small>{events.length} RECORDS</small></div>
          {loading ? <p className="empty-copy">Querying the audit trail…</p> : events.length ? <div className="audit-table-wrap"><table className="audit-table"><thead><tr><th>Date & time</th><th>Type</th><th>Mandate</th><th>Verdict</th><th>Summary</th></tr></thead><tbody>{events.map((event) => <tr className={`audit-row-${event.verdict?.toLowerCase() ?? "neutral"}`} key={event.event_id}><td>{formatDate(event.timestamp)}</td><td><span className="event-type">{auditTypeLabel(event.type)}</span></td><td><code>{displayName(event.mandate_id)}</code></td><td>{event.verdict ? <span className={`verdict-tag verdict-${event.verdict.toLowerCase()}`}>{verdictLabel(event.verdict)}</span> : <span className="neutral-tag">—</span>}</td><td>{localizedText(event.summary)}</td></tr>)}</tbody></table></div> : <p className="empty-copy">No activity yet — run Saturday to get started.</p>}
        </section>
      </section>
    </main>
  );
}
