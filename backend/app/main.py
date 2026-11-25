from __future__ import annotations

from pathlib import Path
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from backend.agents.interviews import (
    INQUIRY_TOPICS,
    ROLE_INTERVIEW_TEMPLATES,
    next_interview_question,
)
from backend.agents.pipeline import MultiAgentOrchestrator
from backend.app.db import Database
from backend.app.demo_seed import seed_demo_data
from backend.app.llm import PluggableLLMClient
from backend.app.models import (
    ApprovalStatus,
    InputSourceType,
    InterviewMessage,
    StakeholderInputRecord,
    StakeholderRole,
    utc_now,
)
from backend.app.rag import HybridKBRetriever
from backend.app.security import (
    AGENT_PERMISSIONS,
    ROLE_PERMISSIONS,
    check_rbac,
    scan_and_mask_input,
)
from backend.evaluation.benchmark import run_evaluation_suite
from backend.knowledge_base.kb_data import INITIAL_KNOWLEDGE_BASE


app = FastAPI(
    title="FinReq AI — Agentic Financial Requirement Engineering & SDLC Platform",
    version="1.0.0",
    description="Multi-agent RAG platform for Payment Processing & Fraud Detection (India: RBI, NPCI/UPI, DPDP 2023, PMLA, CERT-In, PCI-DSS).",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db = Database()
db.seed_knowledge_base(INITIAL_KNOWLEDGE_BASE)
retriever = HybridKBRetriever(db.list_knowledge_base(approved_only=True))
llm_client = PluggableLLMClient()
orchestrator = MultiAgentOrchestrator(db=db, retriever=retriever, llm=llm_client)
seed_demo_data(db, orchestrator)


# --- Request Schemas ---
class CreateProjectRequest(BaseModel):
    name: str
    description: str
    domain: str = "Payment Processing & Fraud Detection"
    jurisdiction: str = "India (RBI, NPCI/UPI, DPDP 2023, PMLA, CERT-In)"
    advisory_mode: bool = True


class SecurityScanRequest(BaseModel):
    text: str


class AddInputRequest(BaseModel):
    source_type: InputSourceType
    stakeholder_role: StakeholderRole
    title: str
    content: str
    actor_name: str = "Stakeholder User"


class InterviewTurnRequest(BaseModel):
    session_id: str = "default-session"
    stakeholder_role: StakeholderRole
    topic: Optional[str] = None
    answer: Optional[str] = None
    actor_name: str = "Stakeholder User"


class HITLDecisionRequest(BaseModel):
    decision: str = Field(pattern="^(accept|reject|modify|regenerate)$")
    reviewer_role: StakeholderRole
    reviewer_name: str = "Authorized Reviewer"
    mfa_verified: bool = True
    notes: str = ""
    modified_statement: Optional[str] = None


class LLMSettingsRequest(BaseModel):
    provider: Optional[str] = None
    model: Optional[str] = None
    gemini_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None
    ollama_base_url: Optional[str] = None
    advisory_mode: Optional[bool] = None


# --- Helpers ---
def _enforce_rbac(role: StakeholderRole, permission: str, mfa_verified: bool = True) -> None:
    ok, reason = check_rbac(role, permission, mfa_verified=mfa_verified)
    if not ok:
        raise HTTPException(status_code=403, detail=reason)


# --- Routes ---
@app.get("/api/health")
def health() -> Dict[str, Any]:
    return {
        "status": "ok",
        "domain_scope": "Payment Processing & Fraud Detection",
        "jurisdiction": "India (RBI, NPCI/UPI, DPDP 2023, PMLA, CERT-In, PCI-DSS)",
        "llm_provider": llm_client.config.provider,
        "llm_model": llm_client.config.model,
        "advisory_mode": llm_client.config.advisory_mode,
        "approved_kb_items": len(retriever.items),
    }


@app.get("/api/meta/roles-and-security")
def get_roles_and_security() -> Dict[str, Any]:
    return {
        "stakeholder_roles": [
            {
                "role": role.value,
                "label": role.value.replace("_", " ").title(),
                "permissions": sorted(ROLE_PERMISSIONS[role]),
                "interview_focus": ROLE_INTERVIEW_TEMPLATES[role]["focus"],
                "starter_questions": ROLE_INTERVIEW_TEMPLATES[role]["starter_questions"],
            }
            for role in StakeholderRole
        ],
        "inquiry_topics": INQUIRY_TOPICS,
        "agent_permissions": {k: sorted(v) for k, v in AGENT_PERMISSIONS.items()},
        "input_source_types": [s.value for s in InputSourceType],
    }


@app.get("/api/settings/llm")
def get_llm_settings() -> Dict[str, Any]:
    cfg = llm_client.config
    return {
        "provider": cfg.provider,
        "model": cfg.model,
        "ollama_base_url": cfg.ollama_base_url,
        "advisory_mode": cfg.advisory_mode,
        "confidence_escalation_threshold": cfg.confidence_escalation_threshold,
        "gemini_configured": bool(cfg.gemini_api_key),
        "openai_configured": bool(cfg.openai_api_key),
    }


@app.post("/api/settings/llm")
def update_llm_settings(req: LLMSettingsRequest) -> Dict[str, Any]:
    cfg = llm_client.update_config(
        provider=req.provider,
        model=req.model,
        gemini_api_key=req.gemini_api_key,
        openai_api_key=req.openai_api_key,
        ollama_base_url=req.ollama_base_url,
        advisory_mode=req.advisory_mode,
    )
    return {
        "provider": cfg.provider,
        "model": cfg.model,
        "ollama_base_url": cfg.ollama_base_url,
        "advisory_mode": cfg.advisory_mode,
        "gemini_configured": bool(cfg.gemini_api_key),
        "openai_configured": bool(cfg.openai_api_key),
    }


@app.post("/api/security/scan")
def security_scan_preview(req: SecurityScanRequest) -> Dict[str, Any]:
    res = scan_and_mask_input(req.text)
    return res.model_dump()


@app.get("/api/kb")
def list_kb(include_unapproved: bool = False) -> Dict[str, Any]:
    items = db.list_knowledge_base(approved_only=not include_unapproved)
    return {
        "count": len(items),
        "allowlisted_count": len(retriever.items),
        "items": [i.model_dump() for i in items],
    }


@app.get("/api/kb/search")
def search_kb(q: str = Query(..., min_length=2), top_k: int = 5) -> Dict[str, Any]:
    hits = retriever.retrieve(q, top_k=top_k, min_score=0.05)
    return {"query": q, "results": [h.model_dump() for h in hits]}


@app.get("/api/projects")
def list_projects() -> List[Dict[str, Any]]:
    return [p.model_dump() for p in db.list_projects()]


@app.post("/api/projects")
def create_project(req: CreateProjectRequest) -> Dict[str, Any]:
    pid = f"proj-{uuid.uuid4().hex[:8]}"
    proj = db.upsert_project(
        project_id=pid,
        name=req.name,
        domain=req.domain,
        jurisdiction=req.jurisdiction,
        description=req.description,
        advisory_mode=req.advisory_mode,
    )
    db.append_audit_event(
        event_id=f"AUD-{uuid.uuid4().hex[:10].upper()}",
        project_id=pid,
        actor_role="business_analyst",
        actor_name="Workspace User",
        action="PROJECT_CREATED",
        agent_name="CoordinatorAgent",
        target_id=pid,
        input_summary=req.name,
    )
    return proj.model_dump()


@app.get("/api/projects/{project_id}/workspace")
def get_project_workspace(project_id: str) -> Dict[str, Any]:
    proj = db.get_project(project_id)
    if not proj:
        raise HTTPException(status_code=404, detail="Project not found")
    return {
        "project": proj.model_dump(),
        "inputs": [i.model_dump() for i in db.list_inputs(project_id)],
        "interviews": [m.model_dump() for m in db.list_interview_messages(project_id)],
        "requirements": [r.model_dump() for r in db.list_requirements(project_id)],
        "conflicts": [c.model_dump() for c in db.list_conflicts(project_id)],
        "compliance_mappings": [m.model_dump() for m in db.list_compliance_mappings(project_id)],
        "risks": [r.model_dump() for r in db.list_risks(project_id)],
        "sdlc": db.get_sdlc(project_id).model_dump() if db.get_sdlc(project_id) else None,
        "gates": [g.model_dump() for g in db.list_approval_gates(project_id)],
        "artifacts": db.list_artifacts(project_id),
        "traces": db.list_agent_traces(project_id),
    }


@app.post("/api/projects/{project_id}/inputs")
def add_stakeholder_input(project_id: str, req: AddInputRequest) -> Dict[str, Any]:
    if not db.get_project(project_id):
        raise HTTPException(status_code=404, detail="Project not found")
    _enforce_rbac(req.stakeholder_role, "submit_input", mfa_verified=True)

    scan = scan_and_mask_input(req.content)
    if scan.blocked:
        db.append_audit_event(
            event_id=f"AUD-{uuid.uuid4().hex[:10].upper()}",
            project_id=project_id,
            actor_role=req.stakeholder_role.value,
            actor_name=req.actor_name,
            action="INPUT_BLOCKED_INJECTION",
            agent_name="SecurityGateway",
            target_id=req.title,
            input_summary=scan.block_reason or "Prompt injection blocked",
            details={"signals": scan.injection_signals},
        )
        raise HTTPException(status_code=400, detail=scan.block_reason)

    record = StakeholderInputRecord(
        input_id=f"INP-{uuid.uuid4().hex[:6].upper()}",
        project_id=project_id,
        source_type=req.source_type,
        stakeholder_role=req.stakeholder_role,
        title=req.title,
        masked_content=scan.masked_text,
        sensitivity_level=scan.sensitivity_level,
        masking_findings=scan.findings,
        injection_detected=scan.injection_detected,
    )
    db.save_input(record)
    db.append_audit_event(
        event_id=f"AUD-{uuid.uuid4().hex[:10].upper()}",
        project_id=project_id,
        actor_role=req.stakeholder_role.value,
        actor_name=req.actor_name,
        action="INPUT_INGESTED_AND_MASKED",
        agent_name="SecurityGateway",
        target_id=record.input_id,
        input_summary=f"{req.title} ({scan.sensitivity_level.value}, masked={len(scan.findings)} types)",
        details={"masking_findings": [f.model_dump() for f in scan.findings], "injection_detected": scan.injection_detected},
    )
    return record.model_dump()


@app.post("/api/projects/{project_id}/interview")
def advance_interview(project_id: str, req: InterviewTurnRequest) -> Dict[str, Any]:
    if not db.get_project(project_id):
        raise HTTPException(status_code=404, detail="Project not found")
    _enforce_rbac(req.stakeholder_role, "participate_interview", mfa_verified=True)

    if req.answer:
        scan = scan_and_mask_input(req.answer)
        if scan.blocked:
            raise HTTPException(status_code=400, detail=scan.block_reason)
        stakeholder_msg = InterviewMessage(
            message_id=f"MSG-{uuid.uuid4().hex[:8].upper()}",
            session_id=req.session_id,
            sender="stakeholder",
            stakeholder_role=req.stakeholder_role,
            topic=req.topic or "business_objectives",
            content=scan.masked_text,
        )
        db.save_interview_message(project_id, stakeholder_msg)

    history = [
        {"sender": m.sender, "topic": m.topic, "content": m.content}
        for m in db.list_interview_messages(project_id, session_id=req.session_id)
    ]
    next_q = next_interview_question(req.stakeholder_role, history, llm_client)
    agent_msg = InterviewMessage(
        message_id=f"MSG-{uuid.uuid4().hex[:8].upper()}",
        session_id=req.session_id,
        sender="agent",
        stakeholder_role=req.stakeholder_role,
        topic=str(next_q["topic"]),
        content=str(next_q["question"]),
        follow_up_reasons=list(next_q.get("follow_up_reasons", [])),  # type: ignore[arg-type]
    )
    db.save_interview_message(project_id, agent_msg)
    return {
        "agent_message": agent_msg.model_dump(),
        "planner": next_q,
        "history": [m.model_dump() for m in db.list_interview_messages(project_id, session_id=req.session_id)],
    }


@app.post("/api/projects/{project_id}/analyze")
def run_multi_agent_analysis(
    project_id: str,
    actor_role: StakeholderRole = StakeholderRole.BUSINESS_ANALYST,
    actor_name: str = "Lead Analyst",
    x_mfa_verified: bool = Header(default=True),
) -> Dict[str, Any]:
    _enforce_rbac(actor_role, "run_agents", mfa_verified=x_mfa_verified)
    try:
        result = orchestrator.run_pipeline(project_id, actor_role=actor_role, actor_name=actor_name)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {
        "run_id": result["run_id"],
        "validation": result["validation"],
        "recommended_sdlc": result["sdlc"].recommended_model.value,
        "sdlc_top_score": result["sdlc"].rankings[0].score_pct,
        "traces": [t.model_dump() for t in result["traces"]],
    }


@app.post("/api/projects/{project_id}/requirements/{req_id}/decision")
def decide_requirement(project_id: str, req_id: str, req: HITLDecisionRequest) -> Dict[str, Any]:
    reqs = db.list_requirements(project_id)
    target = next((r for r in reqs if r.req_id == req_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Requirement not found")

    _enforce_rbac(req.reviewer_role, "view_requirements", mfa_verified=req.mfa_verified)
    if req.decision in {"accept", "modify"} and target.risk_level in {"Critical", "High"}:
        if req.reviewer_role not in {
            StakeholderRole.PRODUCT_OWNER,
            StakeholderRole.COMPLIANCE_LEGAL,
            StakeholderRole.INFOSEC_TEAM,
            StakeholderRole.ARCHITECT_DEVELOPER,
            StakeholderRole.BUSINESS_ANALYST,
        }:
            raise HTTPException(status_code=403, detail="Unauthorized role for high-risk requirement sign-off.")

    if req.decision == "accept":
        target.approval_status = ApprovalStatus.APPROVED
        target.escalation_reason = None
    elif req.decision == "modify":
        if not req.modified_statement:
            raise HTTPException(status_code=400, detail="modified_statement required when decision='modify'")
        scan = scan_and_mask_input(req.modified_statement)
        target.statement = scan.masked_text
        target.approval_status = ApprovalStatus.MODIFIED_APPROVED
        target.escalation_reason = None
    elif req.decision == "reject":
        target.approval_status = ApprovalStatus.REJECTED
    elif req.decision == "regenerate":
        target.approval_status = ApprovalStatus.REGENERATE_REQUESTED
        target.escalation_reason = f"Regeneration requested by {req.reviewer_role.value}: {req.notes}"

    db.upsert_requirement(project_id, target)
    db.append_audit_event(
        event_id=f"AUD-{uuid.uuid4().hex[:10].upper()}",
        project_id=project_id,
        actor_role=req.reviewer_role.value,
        actor_name=req.reviewer_name,
        action=f"HITL_REQ_{req.decision.upper()}",
        agent_name="HumanApprovalAgent",
        target_id=req_id,
        input_summary=req.notes or req.decision,
        confidence_score=target.confidence_score,
    )
    return target.model_dump()


@app.post("/api/projects/{project_id}/gates/{gate_id}/decision")
def decide_approval_gate(project_id: str, gate_id: str, req: HITLDecisionRequest) -> Dict[str, Any]:
    gates = db.list_approval_gates(project_id)
    gate = next((g for g in gates if g.gate_id == gate_id), None)
    if not gate:
        raise HTTPException(status_code=404, detail="Approval gate not found")
    if not req.mfa_verified:
        raise HTTPException(status_code=403, detail="MFA verification required for governance gates.")
    if req.reviewer_role not in gate.required_approver_roles:
        allowed = ", ".join(r.value for r in gate.required_approver_roles)
        raise HTTPException(
            status_code=403,
            detail=f"Role '{req.reviewer_role.value}' is not authorized for this gate. Required: {allowed}.",
        )

    status_map = {
        "accept": ApprovalStatus.APPROVED,
        "modify": ApprovalStatus.MODIFIED_APPROVED,
        "reject": ApprovalStatus.REJECTED,
        "regenerate": ApprovalStatus.REGENERATE_REQUESTED,
    }
    gate.status = status_map[req.decision]
    gate.reviewer_role = req.reviewer_role
    gate.reviewer_name = req.reviewer_name
    gate.decision_notes = req.notes
    gate.updated_at = utc_now()
    db.upsert_approval_gate(gate)

    if gate.gate_type.value == "sdlc_selection":
        sdlc = db.get_sdlc(project_id)
        if sdlc:
            sdlc.approval_status = gate.status
            db.save_sdlc(sdlc)

    db.append_audit_event(
        event_id=f"AUD-{uuid.uuid4().hex[:10].upper()}",
        project_id=project_id,
        actor_role=req.reviewer_role.value,
        actor_name=req.reviewer_name,
        action=f"HITL_GATE_{req.decision.upper()}",
        agent_name="HumanApprovalAgent",
        target_id=gate_id,
        input_summary=f"{gate.title} -> {gate.status.value}",
        details={"notes": req.notes},
    )
    return gate.model_dump()


@app.post("/api/evaluation/run")
def execute_evaluation() -> Dict[str, Any]:
    return run_evaluation_suite(llm_client)


@app.get("/api/audit")
def get_audit_events(project_id: Optional[str] = None, limit: int = 150) -> Dict[str, Any]:
    events = db.list_audit_events(project_id=project_id, limit=limit)
    chain = db.verify_audit_chain()
    return {
        "chain_integrity": chain,
        "events": [e.model_dump() for e in events],
    }


_FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
if _FRONTEND_DIST.is_dir():
    app.mount("/", StaticFiles(directory=str(_FRONTEND_DIST), html=True), name="frontend")
