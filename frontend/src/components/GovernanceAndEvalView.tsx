import React, { useEffect, useState } from "react";
import { CheckCircle2, XCircle, RotateCcw, Search, ShieldCheck, BarChart3 } from "lucide-react";
import { api } from "../api";
import { ApprovalGateItem, AuditEvent, KnowledgeItem } from "../types";

export const HitlGatesView: React.FC<{
  projectId: string;
  gates: ApprovalGateItem[];
  activeRole: string;
  actorName: string;
  mfaVerified: boolean;
  onRefresh: () => Promise<void>;
  onError: (msg: string) => void;
}> = ({ projectId, gates, activeRole, actorName, mfaVerified, onRefresh, onError }) => {
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [busyGate, setBusyGate] = useState<string | null>(null);

  const act = async (gateId: string, decision: string) => {
    setBusyGate(gateId);
    try {
      await api.decideGate(projectId, gateId, {
        decision,
        reviewer_role: activeRole,
        reviewer_name: actorName,
        mfa_verified: mfaVerified,
        notes: notes[gateId] || `Decision '${decision}' recorded by ${activeRole}`,
      });
      await onRefresh();
    } catch (err) {
      onError((err as Error).message);
    } finally {
      setBusyGate(null);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
      <div className="banner banner-info">
        <strong>Human-in-the-Loop Governance (RBAC + MFA Enforced):</strong> Active role{" "}
        <code>{activeRole}</code> (MFA: <strong>{mfaVerified ? "Verified" : "Unverified"}</strong>). Only authorized
        stakeholder roles listed on each gate can sign off.
      </div>
      {gates.map((g) => (
        <div key={g.gate_id} className="card">
          <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
            <div>
              <strong>
                {g.gate_id}: {g.title}
              </strong>
              <div style={{ fontSize: "0.82rem", color: "var(--text-muted)", marginTop: 4 }}>{g.summary}</div>
            </div>
            <span
              className={`badge ${
                g.status.includes("APPROVED")
                  ? "badge-success"
                  : g.status === "REJECTED"
                  ? "badge-danger"
                  : "badge-warn"
              }`}
            >
              {g.status}
            </span>
          </div>
          <div style={{ marginTop: 8, display: "flex", flexWrap: "wrap", gap: 6, alignItems: "center" }}>
            <span style={{ fontSize: "0.76rem", color: "var(--text-muted)" }}>Authorized Approvers:</span>
            {g.required_approver_roles.map((r) => (
              <span key={r} className={`badge ${r === activeRole ? "badge-success" : "badge-info"}`}>
                {r}
              </span>
            ))}
          </div>
          {g.decision_notes && (
            <div style={{ marginTop: 8, fontSize: "0.78rem", color: "#a7f3d0" }}>
              Last Decision ({g.reviewer_role} / {g.reviewer_name}): {g.decision_notes}
            </div>
          )}
          <div style={{ marginTop: 10, display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
            <input
              style={{ flex: 1, minWidth: 220 }}
              placeholder="Reviewer rationale / sign-off comments..."
              value={notes[g.gate_id] || ""}
              onChange={(e) => setNotes({ ...notes, [g.gate_id]: e.target.value })}
            />
            <button className="btn btn-success" disabled={busyGate === g.gate_id} onClick={() => act(g.gate_id, "accept")}>
              <CheckCircle2 size={14} /> Accept
            </button>
            <button className="btn btn-warn" disabled={busyGate === g.gate_id} onClick={() => act(g.gate_id, "regenerate")}>
              <RotateCcw size={14} /> Regenerate
            </button>
            <button className="btn btn-danger" disabled={busyGate === g.gate_id} onClick={() => act(g.gate_id, "reject")}>
              <XCircle size={14} /> Reject
            </button>
          </div>
        </div>
      ))}
    </div>
  );
};

export const KnowledgeAndAuditView: React.FC<{ projectId: string }> = ({ projectId }) => {
  const [kbItems, setKbItems] = useState<KnowledgeItem[]>([]);
  const [query, setQuery] = useState("");
  const [audit, setAudit] = useState<{
    chain_integrity: { valid: boolean; checked: number; broken_at: string | null };
    events: AuditEvent[];
  } | null>(null);

  useEffect(() => {
    api.listKB(true).then((d) => setKbItems(d.items)).catch(() => {});
    api.getAudit(projectId).then(setAudit).catch(() => {});
  }, [projectId]);

  const filtered = kbItems.filter(
    (k) =>
      !query.trim() ||
      k.kb_id.toLowerCase().includes(query.toLowerCase()) ||
      k.title.toLowerCase().includes(query.toLowerCase()) ||
      k.content.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div className="grid-2">
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8, marginBottom: 10 }}>
          <h3 style={{ margin: 0 }}>Version-Controlled Financial Knowledge Base</h3>
          <span className="badge badge-info">{kbItems.filter((i) => i.approved).length} Allowlisted</span>
        </div>
        <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
          <Search size={16} style={{ alignSelf: "center", color: "var(--text-muted)" }} />
          <input
            style={{ flex: 1 }}
            placeholder="Search RBI, NPCI, DPDP, PMLA, CERT-In, PCI-DSS..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <div style={{ maxHeight: 540, overflowY: "auto", display: "flex", flexDirection: "column", gap: 8 }}>
          {filtered.map((item) => (
            <div key={item.kb_id} className="card-elevated">
              <div style={{ display: "flex", justifyContent: "space-between", gap: 6, flexWrap: "wrap" }}>
                <strong>
                  {item.kb_id}: {item.title}
                </strong>
                <span className={`badge ${item.approved ? "badge-success" : "badge-danger"}`}>
                  {item.approved ? `Allowlisted v${item.version}` : "UNAPPROVED (Blocked from RAG)"}
                </span>
              </div>
              <div style={{ fontSize: "0.75rem", color: "#7dd3fc", marginTop: 3 }}>
                {item.source} • {item.jurisdiction} • Effective {item.effective_date}
              </div>
              <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: 5 }}>{item.content}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
          <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: 6 }}>
            <ShieldCheck size={18} color="#10b981" /> Immutable SHA-256 Audit Ledger
          </h3>
          {audit && (
            <span className={`badge ${audit.chain_integrity.valid ? "badge-success" : "badge-danger"}`}>
              Chain {audit.chain_integrity.valid ? "VALID" : "TAMPERED"} ({audit.chain_integrity.checked} entries)
            </span>
          )}
        </div>
        <div style={{ maxHeight: 580, overflowY: "auto", display: "flex", flexDirection: "column", gap: 8 }}>
          {audit?.events.map((ev) => (
            <div key={ev.event_id} className="card-elevated">
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.76rem" }}>
                <strong>
                  {ev.action} • {ev.agent_name}
                </strong>
                <span style={{ color: "var(--text-muted)" }}>{ev.timestamp}</span>
              </div>
              <div style={{ fontSize: "0.8rem", marginTop: 4 }}>
                Actor: <code>{ev.actor_role}</code> ({ev.actor_name}) • Target: <code>{ev.target_id}</code>
              </div>
              <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginTop: 3 }}>{ev.input_summary}</div>
              <div style={{ fontSize: "0.68rem", color: "#64748b", marginTop: 4, fontFamily: "monospace" }}>
                hash: {ev.event_hash.slice(0, 24)}... | prev: {ev.prev_hash.slice(0, 16)}...
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export const EvaluationView: React.FC = () => {
  const [report, setReport] = useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = useState(false);

  const runEval = async () => {
    setLoading(true);
    try {
      const res = await api.runEvaluation();
      setReport(res);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    runEval();
  }, []);

  const metrics = (report?.metrics || {}) as Record<string, number>;
  const comparison = (report?.comparison_vs_manual || []) as { metric: string; manual_re: string; finreq_ai: string }[];
  const cases = (report?.case_results || []) as Record<string, unknown>[];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="card" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10 }}>
        <div>
          <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: 8 }}>
            <BarChart3 size={18} color="#38bdf8" /> Automated Evaluation Benchmark vs. Conventional RE
          </h3>
          <div className="brand-sub">
            Evaluates Precision, Recall, F1, Hallucination Rate, Citation Correctness, Conflict/Ambiguity Detection, and SDLC Accuracy across 3 Indian Payment &amp; Fraud Case Studies.
          </div>
        </div>
        <button className="btn btn-primary" disabled={loading} onClick={runEval}>
          {loading ? "Running Benchmark..." : "Re-Run Evaluation Suite"}
        </button>
      </div>

      {report && (
        <>
          <div className="grid-4">
            <div className="card">
              <div className="kpi-label">Extraction F1 (P / R)</div>
              <div className="kpi-value" style={{ color: "#6ee7b7" }}>{metrics.f1_score}</div>
              <div className="brand-sub">P: {metrics.precision} | R: {metrics.recall}</div>
            </div>
            <div className="card">
              <div className="kpi-label">Hallucination / Citation</div>
              <div className="kpi-value" style={{ color: "#7dd3fc" }}>{metrics.hallucination_rate_pct}%</div>
              <div className="brand-sub">{metrics.citation_correctness_pct}% citations verified • {metrics.unapproved_kb_leak_count} leaks</div>
            </div>
            <div className="card">
              <div className="kpi-label">SDLC &amp; Quality Accuracy</div>
              <div className="kpi-value" style={{ color: "#ddd6fe" }}>{metrics.sdlc_top2_accuracy_pct}%</div>
              <div className="brand-sub">Top-1: {metrics.sdlc_top1_accuracy_pct}% | Conflicts: {metrics.conflict_detection_accuracy_pct}%</div>
            </div>
            <div className="card">
              <div className="kpi-label">Time Saved vs Manual RE</div>
              <div className="kpi-value" style={{ color: "#fcd34d" }}>{metrics.time_saved_vs_manual_pct}%</div>
              <div className="brand-sub">Avg AI latency: {metrics.avg_processing_time_ms} ms + HITL review</div>
            </div>
          </div>

          <div className="grid-2">
            <div className="card">
              <h4 style={{ margin: "0 0 10px" }}>FinReq AI vs. Conventional Manual RE</h4>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Metric</th>
                      <th>Manual RE Baseline</th>
                      <th>FinReq AI + HITL</th>
                    </tr>
                  </thead>
                  <tbody>
                    {comparison.map((row) => (
                      <tr key={row.metric}>
                        <td>{row.metric}</td>
                        <td style={{ color: "var(--text-muted)" }}>{row.manual_re}</td>
                        <td style={{ color: "#6ee7b7", fontWeight: 600 }}>{row.finreq_ai}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="card">
              <h4 style={{ margin: "0 0 10px" }}>Benchmark Case Study Results</h4>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Case Study</th>
                      <th>Reqs / Conflicts</th>
                      <th>Concepts</th>
                      <th>SDLC Chosen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {cases.map((c) => (
                      <tr key={String(c.case_id)}>
                        <td>
                          <strong>{String(c.case_id)}</strong>
                          <div className="brand-sub">{String(c.name)}</div>
                        </td>
                        <td>{String(c.requirements_extracted)} / {String(c.conflicts_detected)}</td>
                        <td><span className="badge badge-success">{String(c.expected_concepts_matched)}</span></td>
                        <td>
                          <strong>{String(c.recommended_sdlc)}</strong> ({String(c.sdlc_score_pct)}%)
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
};
