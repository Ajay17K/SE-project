import React, { useState } from "react";
import { Download, Layers, FileText } from "lucide-react";
import { ArtifactDoc, SDLCRecommendation } from "../types";

export const SdlcView: React.FC<{ sdlc: SDLCRecommendation | null }> = ({ sdlc }) => {
  if (!sdlc) {
    return <div className="card">Run the 13-agent pipeline to compute SDLC factor scores, ranked recommendations, and workflow phases.</div>;
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div className="card">
        <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
          <div>
            <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: 8 }}>
              <Layers size={18} color="#38bdf8" /> Hybrid SDLC Selection Engine (Rules + MCDA + LLM)
            </h3>
            <p style={{ margin: "6px 0 0", color: "var(--text-muted)", fontSize: "0.86rem" }}>
              {sdlc.llm_justification}
            </p>
          </div>
          <div style={{ textAlign: "right" }}>
            <span className="badge badge-success" style={{ fontSize: "0.85rem", padding: "5px 12px" }}>
              Top Match: {sdlc.recommended_model} ({sdlc.rankings[0]?.score_pct}%)
            </span>
            <div className="brand-sub" style={{ marginTop: 4 }}>
              Approval Status: <strong>{sdlc.approval_status}</strong>
            </div>
          </div>
        </div>

        <div className="grid-2" style={{ marginTop: 16 }}>
          <div>
            <h4 style={{ margin: "0 0 10px" }}>Ranked SDLC Suitability Scores</h4>
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {sdlc.rankings.map((r, i) => (
                <div key={r.model} className="card-elevated">
                  <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                    <strong>
                      #{i + 1} {r.model}
                    </strong>
                    <span style={{ fontWeight: 700, color: i === 0 ? "#6ee7b7" : "#7dd3fc" }}>{r.score_pct}%</span>
                  </div>
                  <div className="progress-track">
                    <div className="progress-fill" style={{ width: `${r.score_pct}%` }} />
                  </div>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: 5 }}>
                    {r.explanation}
                  </div>
                  {r.matched_rules.length > 0 && (
                    <div style={{ fontSize: "0.72rem", color: "#fcd34d", marginTop: 4 }}>
                      {r.matched_rules.join(" | ")}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          <div>
            <h4 style={{ margin: "0 0 10px" }}>13 Derived Decision Factors (Scale 1–5)</h4>
            <div style={{ display: "flex", flexDirection: "column", gap: 8, maxHeight: 520, overflowY: "auto" }}>
              {sdlc.factors.map((f) => (
                <div key={f.factor_key} className="card-elevated">
                  <div style={{ display: "flex", justifyContent: "space-between" }}>
                    <strong style={{ fontSize: "0.83rem" }}>{f.factor_name}</strong>
                    <span className="badge badge-info">{f.score} / 5.0</span>
                  </div>
                  <div className="progress-track" style={{ margin: "5px 0", height: 7 }}>
                    <div className="progress-fill" style={{ width: `${(f.score / 5) * 100}%` }} />
                  </div>
                  <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{f.rationale}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="card">
        <h3 style={{ margin: "0 0 12px" }}>Project-Specific Customized SDLC Workflow ({sdlc.recommended_model})</h3>
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {sdlc.workflow.map((p) => (
            <div key={p.order} className="card-elevated">
              <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
                <strong>{p.phase_name}</strong>
                <div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}>
                  {p.responsible_roles.map((role) => (
                    <span key={role} className="badge badge-purple">
                      {role}
                    </span>
                  ))}
                </div>
              </div>
              <div style={{ fontSize: "0.82rem", color: "var(--text-muted)", margin: "4px 0 8px" }}>{p.objective}</div>
              <div className="grid-4" style={{ fontSize: "0.77rem" }}>
                <div>
                  <strong>Activities</strong>
                  <ul style={{ margin: "4px 0", paddingLeft: 16 }}>
                    {p.activities.map((a) => (
                      <li key={a}>{a}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <strong>Security &amp; Testing</strong>
                  <ul style={{ margin: "4px 0", paddingLeft: 16 }}>
                    {[...p.security_activities, ...p.testing_requirements].map((s) => (
                      <li key={s}>{s}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <strong>Compliance &amp; Gates</strong>
                  <ul style={{ margin: "4px 0", paddingLeft: 16 }}>
                    {[...p.compliance_checkpoints, ...p.human_approval_gates].map((c) => (
                      <li key={c}>{c}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <strong>Deliverables &amp; Traceability</strong>
                  <ul style={{ margin: "4px 0", paddingLeft: 16 }}>
                    {[...p.deliverables, ...p.traceability_requirements].map((d) => (
                      <li key={d}>{d}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export const ArtifactsView: React.FC<{ artifacts: ArtifactDoc[] }> = ({ artifacts }) => {
  const [selectedKey, setSelectedKey] = useState<string>(artifacts[0]?.artifact_key || "srs");
  const active = artifacts.find((a) => a.artifact_key === selectedKey) || artifacts[0];

  const downloadFile = (filename: string, text: string, mime: string) => {
    const blob = new Blob([text], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!artifacts.length) {
    return <div className="card">No generated artifacts yet. Run the multi-agent pipeline first.</div>;
  }

  return (
    <div style={{ display: "grid", gridTemplateColumns: "280px 1fr", gap: 16 }}>
      <div className="card" style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <h4 style={{ margin: "0 0 8px", display: "flex", alignItems: "center", gap: 6 }}>
          <FileText size={16} color="#38bdf8" /> 11 Deliverable Artifacts
        </h4>
        {artifacts.map((art) => (
          <button
            key={art.artifact_key}
            className={`nav-tab ${art.artifact_key === active?.artifact_key ? "active" : ""}`}
            style={{ justifyContent: "flex-start", textAlign: "left" }}
            onClick={() => setSelectedKey(art.artifact_key)}
          >
            {art.title}
          </button>
        ))}
      </div>
      {active && (
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, flexWrap: "wrap", gap: 8 }}>
            <h3 style={{ margin: 0 }}>{active.title}</h3>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="btn"
                onClick={() => downloadFile(`${active.artifact_key}.md`, active.content_md, "text/markdown")}
              >
                <Download size={14} /> Export Markdown
              </button>
              <button
                className="btn"
                onClick={() =>
                  downloadFile(
                    `${active.artifact_key}.json`,
                    JSON.stringify(active.structured, null, 2),
                    "application/json"
                  )
                }
              >
                <Download size={14} /> Export JSON
              </button>
            </div>
          </div>
          <div className="markdown-box">{active.content_md}</div>
        </div>
      )}
    </div>
  );
};
