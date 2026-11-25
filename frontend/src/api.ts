const API_BASE = "";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...(init?.headers || {}) },
    ...init,
  });
  if (!res.ok) {
    let msg = `HTTP ${res.status}`;
    try {
      const data = await res.json();
      msg = data.detail || msg;
    } catch {
      // ignore
    }
    throw new Error(msg);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => request<Record<string, unknown>>("/api/health"),
  meta: () => request<Record<string, unknown>>("/api/meta/roles-and-security"),
  listProjects: () => request<import("./types").ProjectSummary[]>("/api/projects"),
  createProject: (payload: { name: string; description: string; advisory_mode: boolean }) =>
    request<import("./types").ProjectSummary>("/api/projects", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getWorkspace: (pid: string) => request<import("./types").ProjectWorkspace>(`/api/projects/${pid}/workspace`),
  scanPreview: (text: string) =>
    request<Record<string, unknown>>("/api/security/scan", {
      method: "POST",
      body: JSON.stringify({ text }),
    }),
  addInput: (
    pid: string,
    payload: { source_type: string; stakeholder_role: string; title: string; content: string; actor_name: string }
  ) =>
    request<import("./types").StakeholderInputRecord>(`/api/projects/${pid}/inputs`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  advanceInterview: (
    pid: string,
    payload: { session_id: string; stakeholder_role: string; topic?: string; answer?: string; actor_name: string }
  ) =>
    request<Record<string, unknown>>(`/api/projects/${pid}/interview`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  runAnalysis: (pid: string, actorRole: string, actorName: string, mfaVerified: boolean) =>
    request<Record<string, unknown>>(
      `/api/projects/${pid}/analyze?actor_role=${encodeURIComponent(actorRole)}&actor_name=${encodeURIComponent(actorName)}`,
      {
        method: "POST",
        headers: { "x-mfa-verified": String(mfaVerified) },
      }
    ),
  decideRequirement: (
    pid: string,
    reqId: string,
    payload: {
      decision: string;
      reviewer_role: string;
      reviewer_name: string;
      mfa_verified: boolean;
      notes: string;
      modified_statement?: string;
    }
  ) =>
    request<import("./types").RequirementItem>(`/api/projects/${pid}/requirements/${reqId}/decision`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  decideGate: (
    pid: string,
    gateId: string,
    payload: {
      decision: string;
      reviewer_role: string;
      reviewer_name: string;
      mfa_verified: boolean;
      notes: string;
    }
  ) =>
    request<import("./types").ApprovalGateItem>(`/api/projects/${pid}/gates/${gateId}/decision`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  listKB: (includeUnapproved = false) =>
    request<{ count: number; allowlisted_count: number; items: import("./types").KnowledgeItem[] }>(
      `/api/kb?include_unapproved=${includeUnapproved}`
    ),
  searchKB: (q: string) =>
    request<{ query: string; results: import("./types").CitationRecord[] }>(
      `/api/kb/search?q=${encodeURIComponent(q)}`
    ),
  getLLMSettings: () => request<Record<string, unknown>>("/api/settings/llm"),
  updateLLMSettings: (payload: Record<string, unknown>) =>
    request<Record<string, unknown>>("/api/settings/llm", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  runEvaluation: () => request<Record<string, unknown>>("/api/evaluation/run", { method: "POST" }),
  getAudit: (pid?: string) =>
    request<{ chain_integrity: { valid: boolean; checked: number; broken_at: string | null }; events: import("./types").AuditEvent[] }>(
      pid ? `/api/audit?project_id=${encodeURIComponent(pid)}` : "/api/audit"
    ),
};
