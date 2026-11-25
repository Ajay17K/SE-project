import React, { useCallback, useEffect, useState } from "react";
import {
  Activity,
  Bot,
  FileCode2,
  GitBranch,
  Play,
  Plus,
  Scale,
  Settings,
  Shield,
} from "lucide-react";
import { api } from "./api";
import { ProjectSummary, ProjectWorkspace } from "./types";
import { ElicitationView } from "./components/ElicitationView";
import { SdlcView } from "./components/SdlcAndArtifactsView";

type TabKey = "elicitation" | "requirements" | "compliance" | "sdlc";

export default function App() {
  const [projects, setProjects] = useState<ProjectSummary[]>([]);
  const [selectedPid, setSelectedPid] = useState<string>("proj-upi-fraud-india");
  const [workspace, setWorkspace] = useState<ProjectWorkspace | null>(null);
  const [meta, setMeta] = useState<Record<string, unknown> | null>(null);
  const [llmSettings, setLlmSettings] = useState<Record<string, unknown>>({});

  const [activeRole, setActiveRole] = useState<string>("business_analyst");
  const [actorName, setActorName] = useState<string>("Priya Nair (Lead BA)");
  const [tab, setTab] = useState<TabKey>("elicitation");
  const [showAgentTrace, setShowAgentTrace] = useState<boolean>(false);
  const [busy, setBusy] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [catFilter, setCatFilter] = useState<string>("ALL");

  const [showNewProj, setShowNewProj] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");

  const [showSettings, setShowSettings] = useState(false);
  const [providerForm, setProviderForm] = useState({
    provider: "fallback",
    model: "deterministic-grounded-v1",
    gemini_api_key: "",
    openai_api_key: "",
    ollama_base_url: "http://localhost:11434",
    advisory_mode: true,
  });

  const loadMetaAndProjects = useCallback(async () => {
    try {
      const [m, projs, llm] = await Promise.all([api.meta(), api.listProjects(), api.getLLMSettings()]);
      setMeta(m);
      setProjects(projs);
      setLlmSettings(llm);
      setProviderForm((prev) => ({
        ...prev,
        provider: String(llm.provider || "fallback"),
        model: String(llm.model || "deterministic-grounded-v1"),
        ollama_base_url: String(llm.ollama_base_url || "http://localhost:11434"),
        advisory_mode: Boolean(llm.advisory_mode ?? true),
      }));
      if (projs.length && !projs.some((p) => p.project_id === selectedPid)) {
        setSelectedPid(projs[0].project_id);
      }
    } catch (e) {
      setError((e as Error).message);
    }
  }, [selectedPid]);

  const loadWorkspace = useCallback(async () => {
    if (!selectedPid) return;
    try {
      const ws = await api.getWorkspace(selectedPid);
      setWorkspace(ws);
    } catch (e) {
      setError((e as Error).message);
    }
  }, [selectedPid]);

  useEffect(() => {
    loadMetaAndProjects();
  }, [loadMetaAndProjects]);

  useEffect(() => {
    loadWorkspace();
  }, [loadWorkspace]);

  const handleRunPipeline = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.runAnalysis(selectedPid, activeRole, actorName, true);
      await Promise.all([loadWorkspace(), loadMetaAndProjects()]);
      setShowAgentTrace(true);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const handleCreateProject = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const created = await api.createProject({ name: newName, description: newDesc, advisory_mode: true });
      setShowNewProj(false);
      setNewName("");
      setNewDesc("");
      await loadMetaAndProjects();
      setSelectedPid(created.project_id);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleSaveLLM = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const updated = await api.updateLLMSettings(providerForm);
      setLlmSettings(updated);
      setShowSettings(false);
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const handleReqDecision = async (reqId: string, decision: string, modifiedStatement?: string) => {
    try {
      await api.decideRequirement(selectedPid, reqId, {
        decision,
        reviewer_role: activeRole,
        reviewer_name: actorName,
        mfa_verified: true,
        notes: `${decision} from Requirements Workbench`,
        modified_statement: modifiedStatement,
      });
      await loadWorkspace();
    } catch (err) {
      setError((err as Error).message);
    }
  };

  const rolesMeta = (meta?.stakeholder_roles || []) as {
    role: string;
    label: string;
    interview_focus: string;
    starter_questions: string[];
  }[];
  const sourceTypes = (meta?.input_source_types || []) as string[];

  const filteredReqs =
    workspace?.requirements.filter((r) => catFilter === "ALL" || r.categories.includes(catFilter)) || [];
  const functionalCount =
    workspace?.requirements.filter((r) => r.categories.includes("Functional")).length || 0;
  const nonFunctionalCount =
    workspace?.requirements.filter((r) => r.categories.includes("Non-Functional")).length || 0;

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <Shield size={24} color="#38bdf8" />
          <div>
            <div className="brand-title">FinReq AI — Payment &amp; Fraud Engineering Studio</div>
            <div className="brand-sub">
              Agentic Elicitation, Requirements, Compliance &amp; Risk, and SDLC • India (RBI, NPCI/UPI, DPDP, PMLA, CERT-In)
            </div>
          </div>
        </div>

        <div className="controls-row">
          <select value={selectedPid} onChange={(e) => setSelectedPid(e.target.value)} aria-label="Select Project">
            {projects.map((p) => (
              <option key={p.project_id} value={p.project_id}>
                {p.name}
              </option>
            ))}
          </select>
          <button className="btn" onClick={() => setShowNewProj(true)}>
            <Plus size={14} /> New Project
          </button>

          <select
            value={activeRole}
            onChange={(e) => {
              const r = e.target.value;
              setActiveRole(r);
              setActorName(`${r.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase())} User`);
            }}
            aria-label="Stakeholder Persona"
          >
            {rolesMeta.map((r) => (
              <option key={r.role} value={r.role}>
                Role: {r.label}
              </option>
            ))}
          </select>

          <button className="btn" onClick={() => setShowSettings(true)}>
            <Settings size={14} /> LLM: {String(llmSettings.provider || "fallback")}
          </button>

          <button className="btn btn-primary" disabled={busy} onClick={handleRunPipeline}>
            <Play size={14} /> {busy ? "Running Agents..." : "Run Agent Pipeline"}
          </button>
        </div>
      </header>

      <nav className="nav-tabs">
        {[
          { key: "elicitation", label: "Elicitation & Interviews", icon: Bot },
          { key: "requirements", label: `Requirements (${workspace?.requirements.length || 0})`, icon: FileCode2 },
          { key: "compliance", label: "Compliance & Risk", icon: Scale },
          { key: "sdlc", label: "SDLC", icon: GitBranch },
        ].map((item) => {
          const Icon = item.icon;
          return (
            <button
              key={item.key}
              className={`nav-tab ${tab === item.key ? "active" : ""}`}
              onClick={() => setTab(item.key as TabKey)}
            >
              <Icon size={15} /> {item.label}
            </button>
          );
        })}
      </nav>

      <main className="main-content">
        {error && (
          <div className="banner banner-error" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span>{error}</span>
            <button className="btn" onClick={() => setError(null)}>
              Dismiss
            </button>
          </div>
        )}

        {tab === "elicitation" && workspace && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div className="grid-4">
              <div className="card">
                <div className="kpi-label">Extracted Requirements</div>
                <div className="kpi-value">{workspace.requirements.length}</div>
                <div className="brand-sub">
                  {functionalCount} Functional • {nonFunctionalCount} Non-Functional
                </div>
              </div>
              <div className="card">
                <div className="kpi-label">Detected Conflicts</div>
                <div className="kpi-value" style={{ color: workspace.conflicts.length ? "#fcd34d" : "#6ee7b7" }}>
                  {workspace.conflicts.length}
                </div>
                <div className="brand-sub">Cross-stakeholder &amp; policy checks</div>
              </div>
              <div className="card">
                <div className="kpi-label">Compliance &amp; Risks</div>
                <div className="kpi-value" style={{ color: "#7dd3fc" }}>
                  {workspace.compliance_mappings.length} / {workspace.risks.length}
                </div>
                <div className="brand-sub">RBI / NPCI / DPDP / PMLA / CERT-In</div>
              </div>
              <div className="card">
                <div className="kpi-label">Recommended SDLC</div>
                <div className="kpi-value" style={{ fontSize: "1.1rem", color: "#6ee7b7" }}>
                  {workspace.sdlc?.recommended_model || "Pending"}
                </div>
                <div className="brand-sub">
                  {workspace.sdlc?.rankings[0] ? `${workspace.sdlc.rankings[0].score_pct}% fit score` : "Run Agent Pipeline"}
                </div>
              </div>
            </div>

            <ElicitationView
              projectId={selectedPid}
              activeRole={activeRole}
              actorName={actorName}
              inputs={workspace.inputs}
              interviews={workspace.interviews}
              sourceTypes={sourceTypes}
              rolesMeta={rolesMeta}
              onRefresh={loadWorkspace}
              onError={setError}
            />

            <div className="card">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 8 }}>
                <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: 8 }}>
                  <Activity size={18} color="#38bdf8" /> Agent Orchestrator Trace ({workspace.traces.length} steps)
                </h3>
                <button className="btn" onClick={() => setShowAgentTrace((v) => !v)}>
                  {showAgentTrace ? "Hide Agent Trace" : "Show Agent Trace"}
                </button>
              </div>
              {showAgentTrace && (
                <div className="table-wrap" style={{ marginTop: 12 }}>
                  <table>
                    <thead>
                      <tr>
                        <th>Step</th>
                        <th>Agent</th>
                        <th>Action</th>
                        <th>Summary</th>
                        <th>Time</th>
                      </tr>
                    </thead>
                    <tbody>
                      {workspace.traces.map((t) => (
                        <tr key={`${t.step_order}-${t.agent_name}`}>
                          <td>#{t.step_order}</td>
                          <td>
                            <strong>{t.agent_name}</strong>
                          </td>
                          <td>
                            <code>{t.action}</code>
                          </td>
                          <td>{t.summary}</td>
                          <td>{t.duration_ms} ms</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {tab === "requirements" && workspace && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            {workspace.conflicts.length > 0 && (
              <div className="card" style={{ borderColor: "rgba(245, 158, 11, 0.5)" }}>
                <h3 style={{ margin: "0 0 8px", color: "#fcd34d" }}>
                  ConflictDetectionAgent Findings ({workspace.conflicts.length})
                </h3>
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {workspace.conflicts.map((c) => (
                    <div key={c.conflict_id} className="card-elevated">
                      <div style={{ display: "flex", justifyContent: "space-between" }}>
                        <strong>
                          {c.conflict_id} ({c.conflict_type}) — {c.req_ids.join(" vs ")}
                        </strong>
                        <span className="badge badge-danger">{c.severity}</span>
                      </div>
                      <div style={{ fontSize: "0.82rem", marginTop: 4 }}>{c.description}</div>
                      <div style={{ fontSize: "0.79rem", color: "#6ee7b7", marginTop: 4 }}>
                        Recommendation: {c.recommendation}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="card">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, marginBottom: 12 }}>
                <h3 style={{ margin: 0 }}>Structured Requirements (Functional &amp; Non-Functional)</h3>
                <select value={catFilter} onChange={(e) => setCatFilter(e.target.value)}>
                  <option value="ALL">All Requirements ({workspace.requirements.length})</option>
                  <option value="Functional">Functional ({functionalCount})</option>
                  <option value="Non-Functional">Non-Functional ({nonFunctionalCount})</option>
                </select>
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                {filteredReqs.map((r) => (
                  <div key={r.req_id} className="card-elevated">
                    <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
                      <div>
                        <strong>
                          {r.req_id}: {r.title}
                        </strong>
                        <div style={{ display: "flex", gap: 5, flexWrap: "wrap", marginTop: 5 }}>
                          {r.categories.map((c) => (
                            <span key={c} className={`badge ${c === "Functional" ? "badge-info" : "badge-purple"}`}>
                              {c}
                            </span>
                          ))}
                          <span className="badge badge-warn">Priority: {r.priority}</span>
                          <span className="badge">Risk: {r.risk_level}</span>
                          <span className="badge">Confidence: {(r.confidence_score * 100).toFixed(0)}%</span>
                        </div>
                      </div>
                      <span
                        className={`badge ${
                          r.approval_status.includes("APPROVED")
                            ? "badge-success"
                            : r.approval_status === "NEEDS_CLARIFICATION"
                            ? "badge-danger"
                            : "badge-warn"
                        }`}
                      >
                        {r.approval_status}
                      </span>
                    </div>

                    <p style={{ margin: "10px 0 6px", fontSize: "0.9rem" }}>{r.statement}</p>
                    <div style={{ fontSize: "0.77rem", color: "var(--text-muted)" }}>
                      Source: <code>{r.source_stakeholder}</code> ({r.source_artifact_id}) — "{r.source_quote}"
                    </div>

                    {r.acceptance_criteria.length > 0 && (
                      <div style={{ marginTop: 8, fontSize: "0.78rem", color: "#cbd5e1" }}>
                        <strong>Acceptance Criteria:</strong>
                        <ul style={{ margin: "4px 0 0", paddingLeft: 18 }}>
                          {r.acceptance_criteria.map((ac, idx) => (
                            <li key={idx}>{ac}</li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {r.citations.length > 0 && (
                      <div style={{ marginTop: 6, display: "flex", gap: 6, flexWrap: "wrap" }}>
                        {r.citations.map((c) => (
                          <span key={c.kb_id} className={`badge ${c.verified ? "badge-success" : "badge-danger"}`}>
                            {c.kb_id} (sim {c.similarity_score})
                          </span>
                        ))}
                      </div>
                    )}

                    {r.quality_issues.length > 0 && (
                      <div style={{ marginTop: 8, padding: 8, background: "rgba(239,68,68,0.08)", borderRadius: 8 }}>
                        <strong style={{ fontSize: "0.76rem", color: "#fca5a5" }}>Quality / Clarification Flags:</strong>
                        {r.quality_issues.map((q, idx) => (
                          <div key={idx} style={{ fontSize: "0.76rem", marginTop: 3 }}>
                            [{q.severity} • {q.issue_type}] {q.description} <em>({q.suggested_clarification})</em>
                          </div>
                        ))}
                      </div>
                    )}

                    <div style={{ marginTop: 10, display: "flex", gap: 8, flexWrap: "wrap" }}>
                      <button className="btn btn-success" onClick={() => handleReqDecision(r.req_id, "accept")}>
                        Accept
                      </button>
                      <button
                        className="btn"
                        onClick={() => {
                          const edited = window.prompt("Modify requirement statement:", r.statement);
                          if (edited) handleReqDecision(r.req_id, "modify", edited);
                        }}
                      >
                        Modify &amp; Approve
                      </button>
                      <button className="btn btn-warn" onClick={() => handleReqDecision(r.req_id, "regenerate")}>
                        Regenerate
                      </button>
                      <button className="btn btn-danger" onClick={() => handleReqDecision(r.req_id, "reject")}>
                        Reject
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {tab === "compliance" && workspace && (
          <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div className="banner banner-info">
              <strong>Advisory Compliance Notice:</strong> Automated mappings cite RBI, NPCI/UPI, DPDP Act 2023, PMLA,
              CERT-In, and PCI-DSS controls. High-impact regulatory interpretations remain subject to Compliance/Legal sign-off.
            </div>
            <div className="card">
              <h3 style={{ margin: "0 0 10px" }}>RAG Compliance-Control Matrix ({workspace.compliance_mappings.length})</h3>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Mapping</th>
                      <th>Req ID</th>
                      <th>KB / Regulation</th>
                      <th>Required Control</th>
                      <th>Gap / Retention Obligation</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {workspace.compliance_mappings.map((m) => (
                      <tr key={m.mapping_id}>
                        <td>{m.mapping_id}</td>
                        <td>
                          <code>{m.req_id}</code>
                        </td>
                        <td>
                          <span className="badge badge-success">{m.kb_id}</span>
                          <div className="brand-sub">{m.jurisdiction}</div>
                        </td>
                        <td>{m.required_control}</td>
                        <td>
                          <div>{m.compliance_gap}</div>
                          <div className="brand-sub">{m.retention_reporting_obligation}</div>
                        </td>
                        <td>
                          <span className="badge badge-warn">{m.approval_status}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="card">
              <h3 style={{ margin: "0 0 10px" }}>Threat &amp; Risk Register ({workspace.risks.length})</h3>
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Risk ID</th>
                      <th>Category</th>
                      <th>Req</th>
                      <th>Inherent (LxI)</th>
                      <th>Residual</th>
                      <th>Owner</th>
                      <th>Mitigation Controls</th>
                    </tr>
                  </thead>
                  <tbody>
                    {workspace.risks.map((rk) => (
                      <tr key={rk.risk_id}>
                        <td>
                          <strong>{rk.risk_id}</strong>
                        </td>
                        <td>
                          <span className="badge badge-warn">{rk.category}</span>
                        </td>
                        <td>
                          <code>{rk.req_id}</code>
                        </td>
                        <td>
                          {rk.inherent_score} ({rk.likelihood}x{rk.impact})
                        </td>
                        <td>{rk.residual_score}</td>
                        <td>{rk.owner_role}</td>
                        <td>{rk.mitigation_controls.join(" ")}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {tab === "sdlc" && <SdlcView sdlc={workspace?.sdlc || null} />}
      </main>

      {showNewProj && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <h3 style={{ marginTop: 0 }}>Create Payment / Fraud Project</h3>
            <form onSubmit={handleCreateProject} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <input
                placeholder="Project name (e.g., IMPS Mule Detection Gateway)"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                required
              />
              <textarea
                rows={3}
                placeholder="Scope, payment rails, regulatory goals..."
                value={newDesc}
                onChange={(e) => setNewDesc(e.target.value)}
                required
              />
              <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
                <button type="button" className="btn" onClick={() => setShowNewProj(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Create Project
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {showSettings && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <h3 style={{ marginTop: 0 }}>Pluggable LLM Provider Settings</h3>
            <form onSubmit={handleSaveLLM} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <label style={{ fontSize: "0.8rem" }}>
                Provider
                <select
                  style={{ width: "100%", marginTop: 4 }}
                  value={providerForm.provider}
                  onChange={(e) => setProviderForm({ ...providerForm, provider: e.target.value })}
                >
                  <option value="fallback">Deterministic Grounded Fallback (Offline)</option>
                  <option value="gemini">Google Gemini API</option>
                  <option value="openai">OpenAI API</option>
                  <option value="ollama">Local Ollama</option>
                </select>
              </label>
              <label style={{ fontSize: "0.8rem" }}>
                Model Name
                <input
                  style={{ width: "100%", marginTop: 4 }}
                  value={providerForm.model}
                  onChange={(e) => setProviderForm({ ...providerForm, model: e.target.value })}
                />
              </label>
              {providerForm.provider === "gemini" && (
                <input
                  type="password"
                  placeholder="Gemini API Key"
                  value={providerForm.gemini_api_key}
                  onChange={(e) => setProviderForm({ ...providerForm, gemini_api_key: e.target.value })}
                />
              )}
              {providerForm.provider === "openai" && (
                <input
                  type="password"
                  placeholder="OpenAI API Key"
                  value={providerForm.openai_api_key}
                  onChange={(e) => setProviderForm({ ...providerForm, openai_api_key: e.target.value })}
                />
              )}
              {providerForm.provider === "ollama" && (
                <input
                  placeholder="Ollama Base URL (http://localhost:11434)"
                  value={providerForm.ollama_base_url}
                  onChange={(e) => setProviderForm({ ...providerForm, ollama_base_url: e.target.value })}
                />
              )}
              <label style={{ display: "flex", alignItems: "center", gap: 8, fontSize: "0.82rem" }}>
                <input
                  type="checkbox"
                  checked={providerForm.advisory_mode}
                  onChange={(e) => setProviderForm({ ...providerForm, advisory_mode: e.target.checked })}
                />
                Advisory Mode (require human approval for compliance &amp; SDLC adoption)
              </label>
              <div style={{ display: "flex", justifyContent: "flex-end", gap: 8 }}>
                <button type="button" className="btn" onClick={() => setShowSettings(false)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary">
                  Save Provider Settings
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
