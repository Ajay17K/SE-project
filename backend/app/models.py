from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class StakeholderRole(str, Enum):
    CUSTOMER_END_USER = "customer_end_user"
    BUSINESS_ANALYST = "business_analyst"
    PRODUCT_OWNER = "product_owner"
    ARCHITECT_DEVELOPER = "architect_developer"
    INFOSEC_TEAM = "infosec_team"
    COMPLIANCE_LEGAL = "compliance_legal"
    RISK_MANAGEMENT = "risk_management"
    OPERATIONS = "operations"
    AUDITOR_REGULATOR = "auditor_regulator"


class RequirementCategory(str, Enum):
    FUNCTIONAL = "Functional"
    NON_FUNCTIONAL = "Non-Functional"


class InputSourceType(str, Enum):
    STAKEHOLDER_CONVERSATION = "stakeholder_conversation"
    INTERVIEW_TRANSCRIPT = "interview_transcript"
    QUESTIONNAIRE = "questionnaire"
    EMAIL_MEETING_NOTE = "email_meeting_note"
    EXISTING_REQUIREMENT_DOC = "existing_requirement_doc"
    BANKING_POLICY = "banking_policy"
    REGULATORY_CIRCULAR = "regulatory_circular"
    API_DB_SPEC = "api_db_spec"
    LEGACY_SYSTEM_DOC = "legacy_system_doc"
    INCIDENT_AUDIT_REPORT = "incident_audit_report"


class SensitivityLevel(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED_PII_PCI = "RESTRICTED_PII_PCI"


class ApprovalStatus(str, Enum):
    DRAFT = "DRAFT"
    NEEDS_CLARIFICATION = "NEEDS_CLARIFICATION"
    PENDING_HUMAN_APPROVAL = "PENDING_HUMAN_APPROVAL"
    APPROVED = "APPROVED"
    MODIFIED_APPROVED = "MODIFIED_APPROVED"
    REJECTED = "REJECTED"
    REGENERATE_REQUESTED = "REGENERATE_REQUESTED"


class GateType(str, Enum):
    FINAL_REQUIREMENT_BASELINE = "final_requirement_baseline"
    REGULATORY_INTERPRETATION = "regulatory_interpretation"
    HIGH_RISK_SECURITY = "high_risk_security"
    CONFLICTING_STAKEHOLDER_DECISION = "conflicting_stakeholder_decision"
    ARCHITECTURE_CRITICAL_REQUIREMENT = "architecture_critical_requirement"
    SDLC_SELECTION = "sdlc_selection"
    APPROVED_REQUIREMENT_CHANGE = "approved_requirement_change"
    PRODUCTION_READINESS = "production_readiness"


class SDLCModel(str, Enum):
    AGILE_DEVSECOPS_HYBRID = "Agile-DevSecOps Hybrid"
    AGILE_V_MODEL_HYBRID = "Agile-V-Model Hybrid"
    DEVSECOPS = "DevSecOps"
    V_MODEL = "V-Model"
    SPIRAL = "Spiral"
    AGILE = "Agile"
    WATERFALL = "Waterfall"


class QualityIssueType(str, Enum):
    AMBIGUITY = "ambiguity"
    INCOMPLETENESS = "incompleteness"
    INCONSISTENCY = "inconsistency"
    DUPLICATION = "duplication"
    INFEASIBILITY = "infeasibility"
    LACK_OF_TESTABILITY = "lack_of_testability"
    MISSING_SOURCE = "missing_source"
    UNDEFINED_TERMINOLOGY = "undefined_terminology"
    CONFLICTING_STAKEHOLDER = "conflicting_stakeholder"
    MISSING_SECURITY_COMPLIANCE = "missing_security_compliance"


class CitationRecord(BaseModel):
    kb_id: str
    title: str
    source: str
    jurisdiction: str
    version: str
    effective_date: str
    similarity_score: float
    verified: bool = True
    excerpt: str = ""


class QualityIssue(BaseModel):
    issue_type: QualityIssueType
    severity: str  # High, Medium, Low
    description: str
    suggested_clarification: str


class RequirementItem(BaseModel):
    req_id: str
    title: str
    statement: str
    categories: List[RequirementCategory]
    source_stakeholder: StakeholderRole
    source_artifact_id: str
    source_quote: str
    business_justification: str
    priority: str  # Critical, High, Medium, Low
    dependencies: List[str] = Field(default_factory=list)
    assumptions: List[str] = Field(default_factory=list)
    acceptance_criteria: List[str] = Field(default_factory=list)
    applicable_regulations: List[str] = Field(default_factory=list)
    risk_level: str = "Medium"  # Critical, High, Medium, Low
    confidence_score: float = 0.85
    citations: List[CitationRecord] = Field(default_factory=list)
    quality_issues: List[QualityIssue] = Field(default_factory=list)
    approval_status: ApprovalStatus = ApprovalStatus.DRAFT
    escalation_reason: Optional[str] = None

    @field_validator("categories", mode="before")
    @classmethod
    def _normalize_categories(cls, v: Any) -> List[RequirementCategory]:
        if not v:
            return [RequirementCategory.FUNCTIONAL]
        items = v if isinstance(v, list) else [v]
        normalized: List[RequirementCategory] = []
        for item in items:
            val = item.value if isinstance(item, RequirementCategory) else str(item)
            if val == "Functional":
                normalized.append(RequirementCategory.FUNCTIONAL)
            else:
                normalized.append(RequirementCategory.NON_FUNCTIONAL)
        # Keep strictly one primary classification (Functional or Non-Functional)
        if RequirementCategory.NON_FUNCTIONAL in normalized and RequirementCategory.FUNCTIONAL not in normalized:
            return [RequirementCategory.NON_FUNCTIONAL]
        return [RequirementCategory.FUNCTIONAL] if RequirementCategory.FUNCTIONAL in normalized else [RequirementCategory.NON_FUNCTIONAL]


class ConflictRecord(BaseModel):
    conflict_id: str
    req_ids: List[str]
    conflict_type: str  # Contradiction, Duplication, StakeholderConflict, PolicyConflict
    severity: str
    description: str
    recommendation: str
    resolved: bool = False
    resolution_notes: Optional[str] = None


class ComplianceMapping(BaseModel):
    mapping_id: str
    req_id: str
    jurisdiction: str
    regulation: str
    kb_id: str
    required_control: str
    supporting_evidence: str
    compliance_gap: str
    mandatory_checkpoint: str
    retention_reporting_obligation: str
    legal_review_required: bool = True
    confidence_score: float = 0.85
    approval_status: ApprovalStatus = ApprovalStatus.PENDING_HUMAN_APPROVAL


class RiskItem(BaseModel):
    risk_id: str
    req_id: str
    category: str  # Business, Technical, Fraud, Security, Compliance
    title: str
    description: str
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    inherent_score: int
    mitigation_controls: List[str]
    residual_score: int
    owner_role: StakeholderRole


class SDLCFactorScore(BaseModel):
    factor_key: str
    factor_name: str
    score: float = Field(ge=1.0, le=5.0)
    rationale: str
    evidence_refs: List[str] = Field(default_factory=list)


class SDLCRankingItem(BaseModel):
    model: SDLCModel
    score_pct: float
    mcda_score: float
    rule_adjustment: float
    matched_rules: List[str] = Field(default_factory=list)
    explanation: str
    strengths: List[str] = Field(default_factory=list)
    cautions: List[str] = Field(default_factory=list)


class SDLCWorkflowPhase(BaseModel):
    order: int
    phase_name: str
    objective: str
    activities: List[str]
    responsible_roles: List[StakeholderRole]
    deliverables: List[str]
    security_activities: List[str]
    testing_requirements: List[str]
    compliance_checkpoints: List[str]
    human_approval_gates: List[str]
    entry_criteria: List[str]
    exit_criteria: List[str]
    traceability_requirements: List[str]


class SDLCRecommendation(BaseModel):
    project_id: str
    recommended_model: SDLCModel
    factors: List[SDLCFactorScore]
    rankings: List[SDLCRankingItem]
    workflow: List[SDLCWorkflowPhase]
    llm_justification: str
    approval_status: ApprovalStatus = ApprovalStatus.PENDING_HUMAN_APPROVAL
    required_approvers: List[StakeholderRole] = Field(
        default_factory=lambda: [
            StakeholderRole.PRODUCT_OWNER,
            StakeholderRole.ARCHITECT_DEVELOPER,
            StakeholderRole.INFOSEC_TEAM,
            StakeholderRole.COMPLIANCE_LEGAL,
        ]
    )


class ApprovalGateItem(BaseModel):
    gate_id: str
    project_id: str
    gate_type: GateType
    target_id: str
    title: str
    summary: str
    required_approver_roles: List[StakeholderRole]
    status: ApprovalStatus = ApprovalStatus.PENDING_HUMAN_APPROVAL
    reviewer_role: Optional[StakeholderRole] = None
    reviewer_name: Optional[str] = None
    decision_notes: Optional[str] = None
    updated_at: str = Field(default_factory=utc_now)


class MaskingFinding(BaseModel):
    entity_type: str
    token: str
    preview_masked: str
    count: int


class SecurityScanResult(BaseModel):
    sensitivity_level: SensitivityLevel
    masked_text: str
    findings: List[MaskingFinding] = Field(default_factory=list)
    injection_detected: bool = False
    injection_signals: List[str] = Field(default_factory=list)
    blocked: bool = False
    block_reason: Optional[str] = None


class StakeholderInputRecord(BaseModel):
    input_id: str
    project_id: str
    source_type: InputSourceType
    stakeholder_role: StakeholderRole
    title: str
    masked_content: str
    sensitivity_level: SensitivityLevel
    masking_findings: List[MaskingFinding] = Field(default_factory=list)
    injection_detected: bool = False
    created_at: str = Field(default_factory=utc_now)


class InterviewMessage(BaseModel):
    message_id: str
    session_id: str
    sender: str  # "agent" or "stakeholder"
    stakeholder_role: StakeholderRole
    topic: str
    content: str
    follow_up_reasons: List[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=utc_now)


class AgentTraceEvent(BaseModel):
    step_order: int
    agent_name: str
    action: str
    status: str
    summary: str
    retrieved_kb_ids: List[str] = Field(default_factory=list)
    confidence_score: Optional[float] = None
    duration_ms: int = 0


class AuditEvent(BaseModel):
    event_id: str
    project_id: str
    timestamp: str = Field(default_factory=utc_now)
    actor_role: str
    actor_name: str
    action: str
    agent_name: str
    target_id: str
    input_summary: str
    retrieved_kb_ids: List[str] = Field(default_factory=list)
    confidence_score: Optional[float] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    prev_hash: str
    event_hash: str


class KnowledgeItem(BaseModel):
    kb_id: str
    title: str
    domain: str
    category: str
    source: str
    jurisdiction: str
    effective_date: str
    version: str
    applicability: List[str]
    approved: bool = True
    mandatory_controls: List[str] = Field(default_factory=list)
    content: str


class ProjectSummary(BaseModel):
    project_id: str
    name: str
    domain: str
    jurisdiction: str
    description: str
    advisory_mode: bool = True
    created_at: str = Field(default_factory=utc_now)
    updated_at: str = Field(default_factory=utc_now)
    requirement_count: int = 0
    pending_approvals: int = 0
    recommended_sdlc: Optional[str] = None
