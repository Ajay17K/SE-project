import React, { useState } from "react";
import { MessageSquare, ShieldAlert, FilePlus2, Sparkles } from "lucide-react";
import { api } from "../api";
import { InterviewMessage, StakeholderInputRecord } from "../types";

interface Props {
  projectId: string;
  activeRole: string;
  actorName: string;
  inputs: StakeholderInputRecord[];
  interviews: InterviewMessage[];
  sourceTypes: string[];
  rolesMeta: { role: string; label: string; interview_focus: string; starter_questions: string[] }[];
  onRefresh: () => Promise<void>;
  onError: (msg: string) => void;
}

export const ElicitationView: React.FC<Props> = ({
  projectId,
  activeRole,
  actorName,
  inputs,
  interviews,
  sourceTypes,
  rolesMeta,
  onRefresh,
  onError,
}) => {
  const [sourceType, setSourceType] = useState(sourceTypes[0] || "stakeholder_conversation");
  const [title, setTitle] = useState("UPI Fraud & Payment SLA Note");
  const [content, setContent] = useState(
    "Transactions above INR 25,000 from new device rahul@okicici (PAN ABCDE1234F, +91 9876543210) must trigger step-up AFA within <=120ms p99."
  );
  const [scanResult, setScanResult] = useState<Record<string, unknown> | null>(null);
  const [busy, setBusy] = useState(false);

  const [sessionId] = useState("session-1");
  const [answer, setAnswer] = useState("");
  const [plannerInfo, setPlannerInfo] = useState<Record<string, unknown> | null>(null);

  const currentRoleMeta = rolesMeta.find((r) => r.role === activeRole);
  const sessionMsgs = interviews.filter((m) => m.session_id === sessionId);
  const lastAgentMsg = [...sessionMsgs].reverse().find((m) => m.sender === "agent");

  const handleScanPreview = async () => {
    try {
      const res = await api.scanPreview(content);
      setScanResult(res);
    } catch (e) {
      onError((e as Error).message);
    }
  };

  const handleIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true);
    try {
      await api.addInput(projectId, {
        source_type: sourceType,
        stakeholder_role: activeRole,
        title,
        content,
        actor_name: actorName,
      });
      setScanResult(null);
      await onRefresh();
    } catch (err) {
      onError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const handleStartOrReplyInterview = async (sendAnswer: boolean) => {
    setBusy(true);
    try {
      const res = await api.advanceInterview(projectId, {
        session_id: sessionId,
        stakeholder_role: activeRole,
        topic: sendAnswer && lastAgentMsg ? lastAgentMsg.topic : undefined,
        answer: sendAnswer ? answer : undefined,
        actor_name: actorName,
      });
      setPlannerInfo(res.planner as Record<string, unknown>);
      if (sendAnswer) setAnswer("");
      await onRefresh();
    } catch (err) {
      onError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="grid-2">
      {/* Adaptive Interview Console */}
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
          <div>
            <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: 8 }}>
              <MessageSquare size={18} color="#38bdf8" /> Adaptive Stakeholder Interview Agent
            </h3>
            <div className="brand-sub">
              Role Template: <strong>{currentRoleMeta?.label || activeRole}</strong> — {currentRoleMeta?.interview_focus}
            </div>
          </div>
          <button className="btn btn-primary" disabled={busy} onClick={() => handleStartOrReplyInterview(false)}>
            <Sparkles size={14} /> {sessionMsgs.length === 0 ? "Start Interview" : "Next Topic"}
          </button>
        </div>

        {plannerInfo && (
          <div className="banner banner-info" style={{ marginBottom: 10 }}>
            Topic coverage: <strong>{String(plannerInfo.topics_covered)}/{String(plannerInfo.total_topics)}</strong>
            {Boolean(plannerInfo.is_followup) && " — Clarification follow-up triggered for vague/incomplete answer."}
          </div>
        )}

        <div
          style={{
            maxHeight: 330,
            overflowY: "auto",
            display: "flex",
            flexDirection: "column",
            gap: 8,
            padding: 10,
            background: "#090e1a",
            borderRadius: 10,
            border: "1px solid var(--border)",
            marginBottom: 12,
          }}
        >
          {sessionMsgs.length === 0 ? (
            <div style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
              Click <strong>Start Interview</strong> to launch the 13-topic adaptive elicitation for{" "}
              <code>{activeRole}</code>. Try giving a vague answer like <em>"It must be fast and secure"</em> to observe
              automatic follow-up probing.
            </div>
          ) : (
            sessionMsgs.map((m) => (
              <div
                key={m.message_id}
                className="card-elevated"
                style={{
                  borderLeft: `3px solid ${m.sender === "agent" ? "var(--accent)" : "var(--success)"}`,
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.75rem", color: "var(--text-muted)" }}>
                  <span>
                    {m.sender === "agent" ? "StakeholderInteractionAgent" : `${m.stakeholder_role}`} •{" "}
                    <code>{m.topic}</code>
                  </span>
                </div>
                <div style={{ marginTop: 4, fontSize: "0.86rem" }}>{m.content}</div>
                {m.follow_up_reasons.length > 0 && (
                  <div style={{ marginTop: 6, fontSize: "0.76rem", color: "#fcd34d" }}>
                    Why probed: {m.follow_up_reasons.join(" ")}
                  </div>
                )}
              </div>
            ))
          )}
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <textarea
            rows={3}
            placeholder="Enter stakeholder response (PII/PCI entities will be masked automatically before reaching agents)..."
            value={answer}
            onChange={(e) => setAnswer(e.target.value)}
          />
          <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
            <button
              className="btn btn-success"
              disabled={busy || !answer.trim()}
              onClick={() => handleStartOrReplyInterview(true)}
            >
              Submit Answer &amp; Evaluate
            </button>
          </div>
        </div>
      </div>

      {/* Multi-Source Ingestion & Live PII Masking */}
      <div className="card">
        <h3 style={{ margin: "0 0 8px", display: "flex", alignItems: "center", gap: 8 }}>
          <FilePlus2 size={18} color="#38bdf8" /> Multi-Source Input &amp; Pre-LLM Security Gateway
        </h3>
        <form onSubmit={handleIngest} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <select value={sourceType} onChange={(e) => setSourceType(e.target.value)} style={{ flex: 1 }}>
              {sourceTypes.map((st) => (
                <option key={st} value={st}>
                  {st.replace(/_/g, " ")}
                </option>
              ))}
            </select>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Document / input title"
              style={{ flex: 1.4 }}
              required
            />
          </div>
          <textarea
            rows={4}
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="Paste interview transcript, banking policy, RBI circular, API/DB spec, or audit finding..."
            required
          />
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button type="button" className="btn" onClick={handleScanPreview}>
              <ShieldAlert size={14} /> Preview PII/PCI Masking &amp; Injection Scan
            </button>
            <button type="submit" className="btn btn-primary" disabled={busy}>
              Mask &amp; Store Input Source
            </button>
          </div>
        </form>

        {scanResult && (
          <div className="card-elevated" style={{ marginTop: 12 }}>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              <span className="badge badge-warn">Sensitivity: {String(scanResult.sensitivity_level)}</span>
              {Boolean(scanResult.injection_detected) && (
                <span className="badge badge-danger">
                  Prompt Injection Detected: {(scanResult.injection_signals as string[]).join(", ")}
                </span>
              )}
              {Boolean(scanResult.blocked) && <span className="badge badge-danger">BLOCKED</span>}
            </div>
            <div style={{ marginTop: 8, fontSize: "0.8rem", color: "#a7f3d0" }}>
              <strong>Masked LLM-Safe Text:</strong> {String(scanResult.masked_text)}
            </div>
          </div>
        )}

        <h4 style={{ margin: "16px 0 8px" }}>Ingested Masked Sources ({inputs.length})</h4>
        <div style={{ maxHeight: 240, overflowY: "auto", display: "flex", flexDirection: "column", gap: 8 }}>
          {inputs.map((inp) => (
            <div key={inp.input_id} className="card-elevated">
              <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 6 }}>
                <strong>
                  {inp.input_id}: {inp.title}
                </strong>
                <div style={{ display: "flex", gap: 6 }}>
                  <span className="badge badge-info">{inp.stakeholder_role}</span>
                  <span className="badge badge-warn">{inp.sensitivity_level}</span>
                </div>
              </div>
              <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginTop: 4 }}>
                {inp.masked_content}
              </div>
              {inp.masking_findings.length > 0 && (
                <div style={{ fontSize: "0.72rem", color: "#fcd34d", marginTop: 4 }}>
                  Masked entities: {inp.masking_findings.map((f) => `${f.entity_type} (${f.count})`).join(", ")}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
