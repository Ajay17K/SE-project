export interface ProjectSummary {
  project_id: string;
  name: string;
  domain: string;
  jurisdiction: string;
  description: string;
  advisory_mode: boolean;
  created_at: string;
  updated_at: string;
  requirement_count: number;
  pending_approvals: number;
  recommended_sdlc?: string | null;
}

export interface CitationRecord {
  kb_id: string;
  title: string;
  source: string;
  jurisdiction: string;
  version: string;
  effective_date: string;
  similarity_score: number;
  verified: boolean;
  excerpt: string;
}

export interface QualityIssue {
  issue_type: string;
  severity: string;
  description: string;
  suggested_clarification: string;
}

export interface RequirementItem {
  req_id: string;
  title: string;
  statement: string;
  categories: string[];
  source_stakeholder: string;
  source_artifact_id: string;
  source_quote: string;
  business_justification: string;
  priority: string;
  dependencies: string[];
  assumptions: string[];
  acceptance_criteria: string[];
  applicable_regulations: string[];
  risk_level: string;
  confidence_score: number;
  citations: CitationRecord[];
  quality_issues: QualityIssue[];
  approval_status: string;
  escalation_reason?: string | null;
}

export interface ConflictRecord {
  conflict_id: string;
  req_ids: string[];
  conflict_type: string;
  severity: string;
  description: string;
  recommendation: string;
  resolved: boolean;
}

export interface ComplianceMapping {
  mapping_id: string;
  req_id: string;
  jurisdiction: string;
  regulation: string;
  kb_id: string;
  required_control: string;
  supporting_evidence: string;
  compliance_gap: string;
  mandatory_checkpoint: string;
  retention_reporting_obligation: string;
  legal_review_required: boolean;
  confidence_score: number;
  approval_status: string;
}

export interface RiskItem {
  risk_id: string;
  req_id: string;
  category: string;
  title: string;
  description: string;
  likelihood: number;
  impact: number;
  inherent_score: number;
  mitigation_controls: string[];
  residual_score: number;
  owner_role: string;
}

export interface SDLCFactorScore {
  factor_key: string;
  factor_name: string;
  score: number;
  rationale: string;
  evidence_refs: string[];
}

export interface SDLCRankingItem {
  model: string;
  score_pct: number;
  mcda_score: number;
  rule_adjustment: number;
  matched_rules: string[];
  explanation: string;
  strengths: string[];
  cautions: string[];
}

export interface SDLCWorkflowPhase {
  order: number;
  phase_name: string;
  objective: string;
  activities: string[];
  responsible_roles: string[];
  deliverables: string[];
  security_activities: string[];
  testing_requirements: string[];
  compliance_checkpoints: string[];
  human_approval_gates: string[];
  entry_criteria: string[];
  exit_criteria: string[];
  traceability_requirements: string[];
}

export interface SDLCRecommendation {
  project_id: string;
  recommended_model: string;
  factors: SDLCFactorScore[];
  rankings: SDLCRankingItem[];
  workflow: SDLCWorkflowPhase[];
  llm_justification: string;
  approval_status: string;
  required_approvers: string[];
}

export interface ApprovalGateItem {
  gate_id: string;
  project_id: string;
  gate_type: string;
  target_id: string;
  title: string;
  summary: string;
  required_approver_roles: string[];
  status: string;
  reviewer_role?: string | null;
  reviewer_name?: string | null;
  decision_notes?: string | null;
  updated_at: string;
}

export interface StakeholderInputRecord {
  input_id: string;
  project_id: string;
  source_type: string;
  stakeholder_role: string;
  title: string;
  masked_content: string;
  sensitivity_level: string;
  masking_findings: { entity_type: string; token: string; preview_masked: string; count: number }[];
  injection_detected: boolean;
  created_at: string;
}

export interface InterviewMessage {
  message_id: string;
  session_id: string;
  sender: string;
  stakeholder_role: string;
  topic: string;
  content: string;
  follow_up_reasons: string[];
  created_at: string;
}

export interface ArtifactDoc {
  artifact_key: string;
  title: string;
  content_md: string;
  structured: unknown;
  updated_at: string;
}

export interface AgentTrace {
  step_order: number;
  agent_name: string;
  action: string;
  status: string;
  summary: string;
  retrieved_kb_ids: string[];
  confidence_score?: number | null;
  duration_ms: number;
}

export interface ProjectWorkspace {
  project: ProjectSummary;
  inputs: StakeholderInputRecord[];
  interviews: InterviewMessage[];
  requirements: RequirementItem[];
  conflicts: ConflictRecord[];
  compliance_mappings: ComplianceMapping[];
  risks: RiskItem[];
  sdlc: SDLCRecommendation | null;
  gates: ApprovalGateItem[];
  artifacts: ArtifactDoc[];
  traces: AgentTrace[];
}

export interface KnowledgeItem {
  kb_id: string;
  title: string;
  domain: string;
  category: string;
  source: string;
  jurisdiction: string;
  effective_date: string;
  version: string;
  applicability: string[];
  approved: boolean;
  mandatory_controls: string[];
  content: string;
}

export interface AuditEvent {
  event_id: string;
  project_id: string;
  timestamp: string;
  actor_role: string;
  actor_name: string;
  action: string;
  agent_name: string;
  target_id: string;
  input_summary: string;
  retrieved_kb_ids: string[];
  confidence_score?: number | null;
  prev_hash: string;
  event_hash: string;
}
