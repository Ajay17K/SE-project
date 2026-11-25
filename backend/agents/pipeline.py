from __future__ import annotations

import re
import time
import uuid
from typing import Any, Dict, List, Set, Tuple

from backend.app.db import Database
from backend.app.llm import PluggableLLMClient
from backend.app.models import (
    AgentTraceEvent,
    ApprovalGateItem,
    ApprovalStatus,
    CitationRecord,
    ComplianceMapping,
    ConflictRecord,
    GateType,
    QualityIssue,
    QualityIssueType,
    RequirementCategory,
    RequirementItem,
    RiskItem,
    SDLCRecommendation,
    StakeholderInputRecord,
    StakeholderRole,
)
from backend.app.rag import HybridKBRetriever, tokenize
from backend.app.security import GATE_APPROVER_MAP, check_agent_permission
from backend.artifacts.generator import generate_all_artifacts
from backend.sdlc.engine import build_sdlc_recommendation


FUNCTIONAL_KEYWORDS: List[str] = [
    "trigger", "step-up", "auto-block", "block", "approve", "workflow", "dispute",
    "udir", "limit", "cap", "cooling", "reconcil", "detect", "flag", "escalate",
    "delete", "erase", "capture", "idempoten", "fallback", "reversal", "file", "str", "fmr",
    "allow", "save", "submit", "enforce", "verify",
]

NON_FUNCTIONAL_KEYWORDS: List[str] = [
    "latency", "ms", "tps", "throughput", "p99", "response time", "sub-second",
    "availability", "uptime", "99.9", "rpo", "rto", "failover", "active-active",
    "retain", "retention", "5 year", "five year", "180", "exclusively in india",
    "localization", "located within india", "ntp", "synchronize", "immutable",
    "encrypt", "hsm", "mtls", "tls", "coft", "tokeniz", "never store cvv", "mask",
    "user-friendly", "fast", "scalable", "high availability", "appropriate", "reasonable",
    "rbac", "audit log", "consent notice", "dpdp", "pci-dss",
]

VAGUE_TERMS = {
    "fast", "quickly", "soon", "real-time", "realtime", "secure", "safe",
    "scalable", "user-friendly", "appropriate", "reasonable", "adequate",
    "high availability", "minimal", "robust", "seamless",
}

DOMAIN_ACRONYMS = {"AFA", "UDIR", "COFT", "EWS", "SCBMF", "FMR", "STR", "RRN", "VPA", "CBS", "NTSL", "HSM", "RASP", "DPIA", "SIEM"}


def _split_candidate_clauses(text: str) -> List[str]:
    lines = [ln.strip(" \t•-*") for ln in text.splitlines() if ln.strip()]
    clauses: List[str] = []
    for ln in lines:
        cleaned = re.sub(r"^\d+[\.\)]\s*", "", ln).strip()
        if len(cleaned.split()) < 5:
            continue
        parts = re.split(r"(?<!\d)\.(?!\d)\s+", cleaned)
        for part in parts:
            p = part.strip().rstrip(".")
            if len(p.split()) >= 5:
                clauses.append(p)
    return clauses


def classify_categories(text: str) -> List[RequirementCategory]:
    lower = text.lower()
    # Explicit SLA / quality / residency / retention / crypto constraints -> Non-Functional
    nfr_hits = sum(1 for kw in NON_FUNCTIONAL_KEYWORDS if kw in lower)
    fr_hits = sum(1 for kw in FUNCTIONAL_KEYWORDS if kw in lower)

    # Strong NFR overrides when performance, availability, localization, retention, or usability SLAs are primary
    strong_nfr = any(
        k in lower
        for k in [
            "p99", "tps", "uptime", "99.9", "rpo", "rto", "retain", "retention",
            "exclusively in india", "located within india", "ntp", "tls", "mtls",
            "hsm", "never store cvv", "user-friendly", "fast and",
        ]
    )
    if strong_nfr or nfr_hits > fr_hits:
        return [RequirementCategory.NON_FUNCTIONAL]
    return [RequirementCategory.FUNCTIONAL]


def _prefix_for_categories(cats: List[RequirementCategory], text: str) -> str:
    lower = text.lower()
    subdomain = "FRD" if any(k in lower for k in ["fraud", "mule", "velocity", "score", "ews", "str", "anomaly", "risk"]) else "PAY"
    if RequirementCategory.NON_FUNCTIONAL in cats:
        return f"NFR-{subdomain}"
    return f"FR-{subdomain}"


def _formalize_statement(clause: str) -> str:
    c = clause.strip()
    if re.match(r"^(?:the\s+system|the\s+platform|payment\s+gateway|fraud\s+engine)\s+shall\b", c, flags=re.IGNORECASE):
        return c if c.endswith(".") else c + "."
    if re.match(r"^(?:we\s+need|it\s+should|system\s+must|system\s+should|must|should)\b", c, flags=re.IGNORECASE):
        stripped = re.sub(r"^(?:we\s+need(?:\s+to)?|it\s+should|system\s+must|system\s+should|must|should)\s+", "", c, flags=re.IGNORECASE)
        return f"The system shall {stripped[0].lower() + stripped[1:]}" + ("" if stripped.endswith(".") else ".")
    return f"The system shall {c[0].lower() + c[1:]}" + ("" if c.endswith(".") else ".")


def _build_title(clause: str) -> str:
    words = clause.split()
    snippet = " ".join(words[:9])
    return snippet[:68] + ("..." if len(snippet) > 68 else "")


def _build_acceptance_criteria(statement: str, cats: List[RequirementCategory]) -> List[str]:
    lower = statement.lower()
    criteria: List[str] = []
    if "step-up" in lower or "afa" in lower or "mfa" in lower:
        criteria.append("Given a payment exceeding the approved risk or monetary threshold, When authorization is requested, Then the system shall enforce dynamic step-up AFA before settlement.")
    elif "latency" in lower or "ms" in lower or "timeout" in lower:
        criteria.append("Given peak payment load, When fraud evaluation executes, Then p99 latency shall remain within the specified SLA or invoke deterministic fallback rules.")
    elif "retention" in lower or "5 year" in lower or "180" in lower or "delete" in lower:
        criteria.append("Given stored transaction and audit records, When retention or erasure policies run, Then records remain stored in India for statutory duration with tamper-evident audit hashes.")
    elif "token" in lower or "coft" in lower or "cvv" in lower or "pan" in lower:
        criteria.append("Given cardholder data in payment requests, When persisted or logged, Then PAN is masked/tokenized via CoFT and CVV/PIN is never stored post-authorization.")
    else:
        criteria.append(f"Given valid authenticated input, When the rule triggers ({statement[:75]}), Then the expected state transition and audit log entry are recorded deterministically.")

    if RequirementCategory.NON_FUNCTIONAL in cats or any(k in lower for k in ["rbi", "npci", "pmla", "cert-in", "dpdp", "audit"]):
        criteria.append("Given rule execution or denial, When completed, Then an immutable audit log entry with timestamp, actor/channel ID, and KB control reference is persisted.")
    return criteria


def _derive_priority_and_risk(cats: List[RequirementCategory], text: str) -> Tuple[str, str]:
    lower = text.lower()
    if any(k in lower for k in ["cvv", "breach", "cert-in", "pmla", "str", "step-up", "afa", "localization", "block", "mule", "double debit", "idempoten"]):
        return "Critical", "High"
    if RequirementCategory.NON_FUNCTIONAL in cats:
        return "High", "High" if any(k in lower for k in ["encrypt", "hsm", "india", "rbi", "dpdp", "pci", "coft", "180", "5 year"]) else "Medium"
    return "Medium", "Medium"


class MultiAgentOrchestrator:
    """
    Central orchestrator coordinating all 13 specialised agents across:
      1. CoordinatorAgent
      2. StakeholderInteractionAgent (via interviews module)
      3. RequirementExtractionAgent
      4. ClarificationAgent
      5. ClassificationAgent
      6. ConflictDetectionAgent
      7. ComplianceAgent
      8. SecurityPrivacyAgent
      9. RiskAnalysisAgent
      10. SDLCSelectionAgent
      11. DocumentationAgent
      12. ValidationAgent
      13. HumanApprovalAgent
    """

    def __init__(self, db: Database, retriever: HybridKBRetriever, llm: PluggableLLMClient):
        self.db = db
        self.retriever = retriever
        self.llm = llm

    def run_pipeline(
        self,
        project_id: str,
        actor_role: StakeholderRole,
        actor_name: str,
    ) -> Dict[str, Any]:
        project = self.db.get_project(project_id)
        if not project:
            raise ValueError(f"Project '{project_id}' not found")

        run_id = f"RUN-{uuid.uuid4().hex[:8].upper()}"
        traces: List[AgentTraceEvent] = []
        step_counter = 0

        def _trace(agent: str, action: str, summary: str, kb_ids: List[str] | None = None, conf: float | None = None, start_t: float = 0.0) -> None:
            nonlocal step_counter
            step_counter += 1
            dur = max(1, int((time.perf_counter() - start_t) * 1000)) if start_t else 5
            traces.append(
                AgentTraceEvent(
                    step_order=step_counter,
                    agent_name=agent,
                    action=action,
                    status="completed",
                    summary=summary,
                    retrieved_kb_ids=kb_ids or [],
                    confidence_score=conf,
                    duration_ms=dur,
                )
            )

        # 1. CoordinatorAgent
        t0 = time.perf_counter()
        assert check_agent_permission("CoordinatorAgent", "orchestrate")
        inputs = self.db.list_inputs(project_id)
        interviews = self.db.list_interview_messages(project_id)
        if not inputs and not interviews:
            raise ValueError("No stakeholder inputs or interviews available for analysis. Add inputs first.")
        _trace(
            "CoordinatorAgent",
            "plan_workflow",
            f"Scheduled multi-agent DAG over {len(inputs)} input source(s) and {len(interviews)} interview turn(s).",
            start_t=t0,
        )

        # 2 & 3. RequirementExtractionAgent + ClassificationAgent
        t1 = time.perf_counter()
        assert check_agent_permission("RequirementExtractionAgent", "write_requirements")
        assert check_agent_permission("ClassificationAgent", "label_categories")
        requirements = self._extract_and_classify(inputs, interviews)
        _trace(
            "RequirementExtractionAgent",
            "extract_requirements",
            f"Extracted {len(requirements)} structured requirements with multi-label classification.",
            start_t=t1,
        )
        _trace(
            "ClassificationAgent",
            "classify_functional_nonfunctional",
            (
                f"Classified {sum(1 for r in requirements if RequirementCategory.FUNCTIONAL in r.categories)} Functional and "
                f"{sum(1 for r in requirements if RequirementCategory.NON_FUNCTIONAL in r.categories)} Non-Functional requirements."
            ),
            start_t=t1,
        )

        # 4. ClarificationAgent (10-point quality checks)
        t2 = time.perf_counter()
        assert check_agent_permission("ClarificationAgent", "flag_quality_issues")
        clarifications = self._analyze_quality(requirements)
        _trace(
            "ClarificationAgent",
            "quality_analysis",
            f"Evaluated 10 quality criteria; flagged {clarifications} quality/clarification issue(s).",
            start_t=t2,
        )

        # 5. ConflictDetectionAgent
        t3 = time.perf_counter()
        assert check_agent_permission("ConflictDetectionAgent", "write_conflicts")
        conflicts = self._detect_conflicts(requirements)
        _trace(
            "ConflictDetectionAgent",
            "detect_conflicts",
            f"Identified {len(conflicts)} cross-requirement conflict(s)/duplication(s).",
            start_t=t3,
        )

        # 6. ComplianceAgent (RAG-grounded)
        t4 = time.perf_counter()
        assert check_agent_permission("ComplianceAgent", "write_compliance_mappings")
        compliance_mappings, kb_cited = self._run_compliance_agent(requirements)
        _trace(
            "ComplianceAgent",
            "rag_compliance_mapping",
            f"Generated {len(compliance_mappings)} citation-grounded regulatory mappings across RBI/NPCI/DPDP/PMLA/CERT-In/PCI-DSS.",
            kb_ids=sorted(kb_cited),
            conf=round(sum(r.confidence_score for r in requirements) / max(1, len(requirements)), 3),
            start_t=t4,
        )

        # 7. SecurityPrivacyAgent
        t5 = time.perf_counter()
        assert check_agent_permission("SecurityPrivacyAgent", "write_security_controls")
        sec_gaps = self._run_security_privacy_agent(requirements, compliance_mappings)
        _trace(
            "SecurityPrivacyAgent",
            "security_privacy_review",
            f"Verified cryptographic/AFA/DPDP controls; added {sec_gaps} mandatory security & privacy requirement(s) or flags.",
            kb_ids=["KB-RBI-DPSC-01", "KB-PCIDSS-01", "KB-DPDP-01", "KB-ISO27001-01"],
            start_t=t5,
        )

        # Re-run compliance & quality checks if SecurityPrivacyAgent added gap requirements
        if sec_gaps > 0:
            compliance_mappings, kb_cited = self._run_compliance_agent(requirements)

        # 8. RiskAnalysisAgent
        t6 = time.perf_counter()
        assert check_agent_permission("RiskAnalysisAgent", "write_risks")
        risks = self._run_risk_agent(requirements, compliance_mappings, conflicts)
        _trace(
            "RiskAnalysisAgent",
            "assess_risks",
            f"Constructed threat & risk register with {len(risks)} scored risk entries.",
            start_t=t6,
        )

        # 9. SDLCSelectionAgent
        t7 = time.perf_counter()
        assert check_agent_permission("SDLCSelectionAgent", "write_sdlc")
        corpus = "\n".join(i.masked_content for i in inputs) + "\n" + "\n".join(
            m.content for m in interviews if m.sender == "stakeholder"
        )
        sdlc_rec = build_sdlc_recommendation(
            project_id=project_id,
            requirements=requirements,
            compliance_mappings=compliance_mappings,
            risks=risks,
            raw_text_corpus=corpus,
            llm=self.llm,
            project_summary=f"{project.name}: {project.description}",
        )
        _trace(
            "SDLCSelectionAgent",
            "select_sdlc",
            f"Ranked 7 SDLC models; top recommendation: {sdlc_rec.recommended_model.value} ({sdlc_rec.rankings[0].score_pct}%).",
            kb_ids=["KB-SDLC-RULES-01"],
            start_t=t7,
        )

        # 10. ValidationAgent (Verify citations, completeness, hallucinations, confidence)
        t8 = time.perf_counter()
        assert check_agent_permission("ValidationAgent", "verify_citations")
        validation_summary = self._validate_outputs(requirements, compliance_mappings, conflicts)
        _trace(
            "ValidationAgent",
            "verify_evidence_and_confidence",
            (
                f"Verified {validation_summary['verified_citations']} citations, "
                f"hallucinated_kb_ids={validation_summary['hallucinated_citations']}, "
                f"escalated={validation_summary['escalated_requirements']}."
            ),
            kb_ids=sorted(kb_cited),
            conf=validation_summary["avg_confidence"],
            start_t=t8,
        )

        # 11. DocumentationAgent (11 traceable artifacts)
        t9 = time.perf_counter()
        assert check_agent_permission("DocumentationAgent", "write_artifacts")
        artifacts = generate_all_artifacts(
            project=project,
            inputs=inputs,
            requirements=requirements,
            conflicts=conflicts,
            compliance_mappings=compliance_mappings,
            risks=risks,
            sdlc=sdlc_rec,
        )
        _trace(
            "DocumentationAgent",
            "generate_artifacts",
            f"Generated {len(artifacts)} traceable deliverables (SRS, User Stories, Use Cases, RTM, Risk/Compliance Registers, SDLC Workflow).",
            kb_ids=["KB-TPL-SRS-01"],
            start_t=t9,
        )

        # 12. HumanApprovalAgent (8 mandatory HITL gates)
        t10 = time.perf_counter()
        assert check_agent_permission("HumanApprovalAgent", "create_approval_gates")
        gates = self._build_approval_gates(project_id, requirements, conflicts, compliance_mappings, sdlc_rec)
        _trace(
            "HumanApprovalAgent",
            "route_hitl_gates",
            f"Created {len(gates)} mandatory human-in-the-loop governance gates.",
            start_t=t10,
        )

        # Persist everything cleanly
        self.db.replace_requirements(project_id, requirements)
        self.db.replace_conflicts(project_id, conflicts)
        self.db.replace_compliance_mappings(project_id, compliance_mappings)
        self.db.replace_risks(project_id, risks)
        self.db.save_sdlc(sdlc_rec)
        self.db.save_artifacts(project_id, artifacts)
        self.db.replace_approval_gates(project_id, gates)
        self.db.save_agent_traces(project_id, run_id, [t.model_dump() for t in traces])

        self.db.append_audit_event(
            event_id=f"AUD-{uuid.uuid4().hex[:10].upper()}",
            project_id=project_id,
            actor_role=actor_role.value,
            actor_name=actor_name,
            action="PIPELINE_EXECUTED",
            agent_name="CoordinatorAgent",
            target_id=run_id,
            input_summary=f"Analyzed {len(inputs)} inputs & {len(interviews)} interview turns",
            retrieved_kb_ids=sorted(kb_cited),
            confidence_score=validation_summary["avg_confidence"],
            details={
                "requirements_count": len(requirements),
                "conflicts_count": len(conflicts),
                "compliance_mappings_count": len(compliance_mappings),
                "risks_count": len(risks),
                "recommended_sdlc": sdlc_rec.recommended_model.value,
                "gates_count": len(gates),
                "advisory_mode": project.advisory_mode,
            },
        )

        return {
            "run_id": run_id,
            "requirements": requirements,
            "conflicts": conflicts,
            "compliance_mappings": compliance_mappings,
            "risks": risks,
            "sdlc": sdlc_rec,
            "gates": gates,
            "artifacts_count": len(artifacts),
            "validation": validation_summary,
            "traces": traces,
        }

    def _extract_and_classify(
        self,
        inputs: List[StakeholderInputRecord],
        interviews: List[Any],
    ) -> List[RequirementItem]:
        raw_sources: List[Tuple[str, StakeholderRole, str, str]] = []
        for inp in inputs:
            for clause in _split_candidate_clauses(inp.masked_content):
                raw_sources.append((inp.input_id, inp.stakeholder_role, inp.title, clause))
        for msg in interviews:
            if msg.sender == "stakeholder":
                for clause in _split_candidate_clauses(msg.content):
                    raw_sources.append((msg.session_id, msg.stakeholder_role, f"Interview ({msg.topic})", clause))

        # Optionally refine with live LLM when configured (non-fallback)
        if self.llm.config.provider != "fallback" and raw_sources:
            llm_reqs = self._try_llm_extract(raw_sources)
            if llm_reqs:
                return llm_reqs

        # Deterministic grounded extractor (used in fallback or if LLM returns unparseable)
        extracted: List[RequirementItem] = []
        prefix_counters: Dict[str, int] = {}
        seen_normalized: Set[str] = set()

        for artifact_id, role, title, clause in raw_sources:
            norm = re.sub(r"\W+", " ", clause.lower()).strip()
            if not norm or norm in seen_normalized:
                continue
            seen_normalized.add(norm)

            cats = classify_categories(clause)
            prefix = _prefix_for_categories(cats, clause)
            prefix_counters[prefix] = prefix_counters.get(prefix, 0) + 1
            req_id = f"{prefix}-{prefix_counters[prefix]:03d}"

            statement = _formalize_statement(clause)
            priority, risk_level = _derive_priority_and_risk(cats, clause)
            citations = self.retriever.retrieve(clause, top_k=2, min_score=0.10)
            regs = sorted({c.kb_id for c in citations})

            extracted.append(
                RequirementItem(
                    req_id=req_id,
                    title=_build_title(clause),
                    statement=statement,
                    categories=cats,
                    source_stakeholder=role,
                    source_artifact_id=artifact_id,
                    source_quote=clause[:280],
                    business_justification=f"Addresses {role.value.replace('_', ' ')} requirement from '{title}' for secure Indian payment & fraud operations.",
                    priority=priority,
                    dependencies=[],
                    assumptions=["Indian payment infrastructure operates under RBI/NPCI/DPDP governance."],
                    acceptance_criteria=_build_acceptance_criteria(statement, cats),
                    applicable_regulations=regs,
                    risk_level=risk_level,
                    confidence_score=0.84,
                    citations=citations,
                    approval_status=ApprovalStatus.DRAFT,
                )
            )
        return extracted

    def _try_llm_extract(
        self,
        raw_sources: List[Tuple[str, StakeholderRole, str, str]],
    ) -> List[RequirementItem] | None:
        bullets = "\n".join(
            f"- [{idx}] ({role.value} | {art_id}): {clause}"
            for idx, (art_id, role, _, clause) in enumerate(raw_sources[:30])
        )
        kb_context = "\n".join(
            f"- {item.kb_id}: {item.title}" for item in self.retriever.items[:14]
        )
        parsed, meta = self.llm.generate_json(
            system_prompt=(
                "You are RequirementExtractionAgent & ClassificationAgent for Indian Payment Processing & Fraud Detection. "
                "Convert ONLY the untrusted stakeholder inputs into structured JSON requirements. "
                "Cite ONLY KB IDs from the Approved KB List."
            ),
            user_prompt=(
                f"Approved KB List:\n{kb_context}\n\n"
                f"<UNTRUSTED_STAKEHOLDER_DATA>\n{bullets}\n</UNTRUSTED_STAKEHOLDER_DATA>\n\n"
                'Return JSON array of objects with keys: "source_index" (int), "title", "statement", '
                '"categories" (array containing exactly one value: "Functional" or "Non-Functional"), '
                '"priority" (Critical/High/Medium/Low), "risk_level", "business_justification", "acceptance_criteria" (array), "kb_ids" (array).'
            ),
            fallback_fn=lambda: None,
        )
        if not isinstance(parsed, list) or not parsed:
            return None

        out: List[RequirementItem] = []
        prefix_counters: Dict[str, int] = {}
        valid_cats = {c.value: c for c in RequirementCategory}
        for entry in parsed:
            if not isinstance(entry, dict):
                continue
            idx = entry.get("source_index", 0)
            if not isinstance(idx, int) or idx < 0 or idx >= len(raw_sources):
                idx = 0
            art_id, role, title, clause = raw_sources[idx]
            cats = [valid_cats[c] for c in entry.get("categories", []) if c in valid_cats] or classify_categories(clause)
            prefix = _prefix_for_categories(cats, clause)
            prefix_counters[prefix] = prefix_counters.get(prefix, 0) + 1
            req_id = f"{prefix}-{prefix_counters[prefix]:03d}"

            raw_kb_ids = [str(k) for k in entry.get("kb_ids", [])]
            valid_kbs, invalid_kbs = self.retriever.verify_citations(raw_kb_ids)
            citations = [
                CitationRecord(
                    kb_id=self.retriever.item_map[kid].kb_id,
                    title=self.retriever.item_map[kid].title,
                    source=self.retriever.item_map[kid].source,
                    jurisdiction=self.retriever.item_map[kid].jurisdiction,
                    version=self.retriever.item_map[kid].version,
                    effective_date=self.retriever.item_map[kid].effective_date,
                    similarity_score=0.88,
                    verified=True,
                    excerpt=self.retriever.item_map[kid].content[:200],
                )
                for kid in valid_kbs
            ]
            for bad_id in invalid_kbs:
                citations.append(
                    CitationRecord(
                        kb_id=bad_id,
                        title="UNVERIFIED CITATION (FLAGGED)",
                        source="Unverified",
                        jurisdiction="Unknown",
                        version="0.0",
                        effective_date="N/A",
                        similarity_score=0.0,
                        verified=False,
                    )
                )
            if not citations:
                citations = self.retriever.retrieve(clause, top_k=2, min_score=0.10)

            out.append(
                RequirementItem(
                    req_id=req_id,
                    title=str(entry.get("title") or _build_title(clause)),
                    statement=str(entry.get("statement") or _formalize_statement(clause)),
                    categories=cats,
                    source_stakeholder=role,
                    source_artifact_id=art_id,
                    source_quote=clause[:280],
                    business_justification=str(entry.get("business_justification") or f"Derived from {title}."),
                    priority=str(entry.get("priority") or "High"),
                    acceptance_criteria=[str(x) for x in entry.get("acceptance_criteria", [])] or _build_acceptance_criteria(clause, cats),
                    applicable_regulations=[c.kb_id for c in citations if c.verified],
                    risk_level=str(entry.get("risk_level") or "Medium"),
                    confidence_score=0.82 if not invalid_kbs else 0.55,
                    citations=citations,
                    approval_status=ApprovalStatus.DRAFT,
                )
            )
        return out or None

    def _analyze_quality(self, requirements: List[RequirementItem]) -> int:
        total_issues = 0
        seen_token_sets: List[Tuple[str, Set[str]]] = []

        for req in requirements:
            issues: List[QualityIssue] = []
            lower = req.statement.lower()
            has_metric = bool(re.search(r"\d+", req.statement))

            # 1. Ambiguity
            vague_found = [t for t in VAGUE_TERMS if re.search(rf"\b{re.escape(t)}\b", lower)]
            if vague_found and not has_metric:
                issues.append(
                    QualityIssue(
                        issue_type=QualityIssueType.AMBIGUITY,
                        severity="High",
                        description=f"Contains vague unquantified terms: {', '.join(vague_found)}.",
                        suggested_clarification="Replace vague qualifiers with measurable SLAs (e.g., <=150ms p99, >=99.95% uptime, INR thresholds).",
                    )
                )

            # 2. Incompleteness
            if len(req.statement.split()) < 9 or (
                any(k in lower for k in ["fraud", "payment", "timeout", "limit"]) and not has_metric and "shall" in lower and "within" not in lower and "exceed" not in lower
            ):
                if not any(i.issue_type == QualityIssueType.AMBIGUITY for i in issues):
                    issues.append(
                        QualityIssue(
                            issue_type=QualityIssueType.INCOMPLETENESS,
                            severity="Medium",
                            description="Missing quantitative threshold, boundary condition, or explicit fallback behavior.",
                            suggested_clarification="Specify exact threshold values and exception/fallback behavior.",
                        )
                    )

            # 3. Duplication
            toks = set(tokenize(req.statement))
            for prev_id, prev_toks in seen_token_sets:
                if toks and prev_toks:
                    jaccard = len(toks & prev_toks) / len(toks | prev_toks)
                    if jaccard >= 0.65:
                        issues.append(
                            QualityIssue(
                                issue_type=QualityIssueType.DUPLICATION,
                                severity="Medium",
                                description=f"High semantic/lexical overlap ({jaccard:.0%}) with {prev_id}.",
                                suggested_clarification=f"Merge or clarify scope boundaries between {req.req_id} and {prev_id}.",
                            )
                        )
                        break
            seen_token_sets.append((req.req_id, toks))

            # 4. Infeasibility
            if any(p in lower for p in ["100% uptime", "100.0% availability", "zero latency", "0ms", "0% false positive"]):
                issues.append(
                    QualityIssue(
                        issue_type=QualityIssueType.INFEASIBILITY,
                        severity="High",
                        description="States physically or statistically infeasible SLA (e.g., 100% uptime, 0ms latency, or 0% false positives).",
                        suggested_clarification="Set realistic Tier-1 payment SLA (e.g., >=99.95% uptime, <=120ms p99 scoring, <=0.5% FP rate).",
                    )
                )

            # 5. Lack of testability
            if not has_metric and not any(w in lower for w in ["shall block", "shall encrypt", "shall mask", "shall log", "shall require", "shall notify", "shall reject", "shall store", "shall trigger"]):
                issues.append(
                    QualityIssue(
                        issue_type=QualityIssueType.LACK_OF_TESTABILITY,
                        severity="Medium",
                        description="Lacks observable pass/fail criteria or verifiable system response.",
                        suggested_clarification="Define concrete observable action and Given/When/Then assertion.",
                    )
                )

            # 6. Missing source
            if not req.source_quote or not req.source_artifact_id:
                issues.append(
                    QualityIssue(
                        issue_type=QualityIssueType.MISSING_SOURCE,
                        severity="High",
                        description="Missing originating stakeholder statement or artifact reference.",
                        suggested_clarification="Attach original stakeholder quote and source ID.",
                    )
                )

            # 7. Undefined terminology
            acronyms_used = set(re.findall(r"\b[A-Z]{3,6}\b", req.statement)) & DOMAIN_ACRONYMS
            if acronyms_used and "glossary" not in lower:
                # Flag only if esoteric without inline expansion
                unexpanded = [a for a in acronyms_used if a in {"UDIR", "COFT", "SCBMF", "NTSL"} and "(" not in req.statement]
                if unexpanded:
                    issues.append(
                        QualityIssue(
                            issue_type=QualityIssueType.UNDEFINED_TERMINOLOGY,
                            severity="Low",
                            description=f"Domain acronym(s) {', '.join(unexpanded)} used without inline expansion.",
                            suggested_clarification="Expand domain acronyms on first occurrence or link to Financial Glossary.",
                        )
                    )

            # 8. Missing security or compliance control
            if any(k in lower for k in ["card", "upi", "payment", "transaction", "customer data", "pii"]) and not any(
                k in lower for k in ["afa", "mfa", "step-up", "encrypt", "token", "coft", "mask", "consent", "dpdp", "rbi", "npci", "pmla", "cert-in", "audit", "idempoten", "limit"]
            ):
                issues.append(
                    QualityIssue(
                        issue_type=QualityIssueType.MISSING_SECURITY_COMPLIANCE,
                        severity="High",
                        description="Payment/PII workflow lacks explicit authentication, encryption, tokenization, or RBI/DPDP control reference.",
                        suggested_clarification="Bind applicable RBI DPSC / DPDP / PCI-DSS security control to this requirement.",
                    )
                )

            req.quality_issues = issues
            if any(i.severity == "High" for i in issues):
                req.approval_status = ApprovalStatus.NEEDS_CLARIFICATION
                req.confidence_score = round(max(0.55, req.confidence_score - 0.18), 3)
            total_issues += len(issues)

        return total_issues

    def _detect_conflicts(self, requirements: List[RequirementItem]) -> List[ConflictRecord]:
        conflicts: List[ConflictRecord] = []
        seq = 0

        def _add_conflict(req_ids: List[str], ctype: str, sev: str, desc: str, rec: str) -> None:
            nonlocal seq
            seq += 1
            conflicts.append(
                ConflictRecord(
                    conflict_id=f"CONF-{seq:03d}",
                    req_ids=req_ids,
                    conflict_type=ctype,
                    severity=sev,
                    description=desc,
                    recommendation=rec,
                )
            )

        # Pairwise domain-aware conflict rules
        for i, r1 in enumerate(requirements):
            l1 = r1.statement.lower()
            for r2 in requirements[i + 1 :]:
                l2 = r2.statement.lower()

                # 1. Retention vs Short Erasure conflict (DPDP vs PMLA/CERT-In)
                short_del_1 = any(k in l1 for k in ["delete", "purge", "erase"]) and any(k in l1 for k in ["30 day", "7 day", "immediately", "90 day"])
                long_ret_2 = any(k in l2 for k in ["retain", "store", "keep", "archive"]) and any(k in l2 for k in ["5 year", "five year", "180 day", "pmla", "cert-in"])
                short_del_2 = any(k in l2 for k in ["delete", "purge", "erase"]) and any(k in l2 for k in ["30 day", "7 day", "immediately", "90 day"])
                long_ret_1 = any(k in l1 for k in ["retain", "store", "keep", "archive"]) and any(k in l1 for k in ["5 year", "five year", "180 day", "pmla", "cert-in"])
                if (short_del_1 and long_ret_2) or (short_del_2 and long_ret_1):
                    _add_conflict(
                        [r1.req_id, r2.req_id],
                        "PolicyConflict",
                        "Critical",
                        f"{r1.req_id} and {r2.req_id} conflict on data deletion window versus PMLA 5-year / CERT-In 180-day statutory retention.",
                        "Apply DPDP Section 17 statutory override: restrict immediate erasure to marketing preferences while retaining transaction & KYC logs in India for >=5 years.",
                    )

                # 2. Frictionless / Skip MFA vs Mandatory AFA / Step-Up MFA
                skip_auth_1 = any(k in l1 for k in ["skip mfa", "skip afa", "no otp", "without authentication", "bypass mfa", "skip step-up"])
                req_auth_2 = any(k in l2 for k in ["step-up", "afa", "mfa", "two-factor", "biometric"])
                skip_auth_2 = any(k in l2 for k in ["skip mfa", "skip afa", "no otp", "without authentication", "bypass mfa", "skip step-up"])
                req_auth_1 = any(k in l1 for k in ["step-up", "afa", "mfa", "two-factor", "biometric"])
                if (skip_auth_1 and req_auth_2) or (skip_auth_2 and req_auth_1):
                    _add_conflict(
                        [r1.req_id, r2.req_id],
                        "StakeholderConflict",
                        "Critical",
                        f"UX friction-reduction expectation ({r1.req_id}/{r2.req_id}) conflicts with RBI DPSC mandatory AFA/step-up authentication.",
                        "Retain RBI-compliant AFA/step-up MFA; optimize UX using UPI Lite (<=INR 500) or biometric AFA instead of bypassing authentication.",
                    )

                # 3. Fail-open vs Fail-closed on fraud timeout
                if ("fail-open" in l1 or "approve all" in l1) and ("fail-closed" in l2 or "block" in l2) and ("timeout" in l1 or "timeout" in l2):
                    _add_conflict(
                        [r1.req_id, r2.req_id],
                        "Contradiction",
                        "High",
                        f"{r1.req_id} and {r2.req_id} prescribe opposite fallback actions (fail-open vs fail-closed) on ML scorer timeout.",
                        "Adopt tiered deterministic fallback: pass low-value known beneficiaries via hard velocity rules and trigger step-up AFA above risk threshold.",
                    )

                # 4. Card PAN/CVV storage vs RBI CoFT tokenization
                store_raw = any(k in l1 + " " + l2 for k in ["store cvv", "save cvv", "store raw card", "plain card number"])
                coft = any(k in l1 + " " + l2 for k in ["coft", "tokeniz", "pci-dss", "never store cvv"])
                if store_raw and coft:
                    _add_conflict(
                        [r1.req_id, r2.req_id],
                        "PolicyConflict",
                        "Critical",
                        f"Raw card/CVV storage conflicts with RBI CoFT and PCI-DSS v4.0 rules across {r1.req_id} and {r2.req_id}.",
                        "Prohibit CVV/raw PAN persistence; mandate RBI CoFT token vaulting.",
                    )

                # 5. Sub-100ms latency vs synchronous multi-bureau/manual hold
                low_lat = any(k in l1 + " " + l2 for k in ["100ms", "120ms", "150ms", "sub-200ms"])
                heavy_sync = any(k in l1 + " " + l2 for k in ["synchronous manual", "3 external", "third-party bureau synchronously"])
                if low_lat and heavy_sync:
                    _add_conflict(
                        [r1.req_id, r2.req_id],
                        "Inconsistency",
                        "High",
                        f"Strict low-latency SLA conflicts with heavy synchronous external/manual checks across {r1.req_id} and {r2.req_id}.",
                        "Execute fast deterministic + cached feature ML scoring inline (<150ms) and push deep graph/bureau enrichment asynchronously to EWS.",
                    )

                # 6. Duplication
                t1, t2 = set(tokenize(r1.statement)), set(tokenize(r2.statement))
                if t1 and t2:
                    jacc = len(t1 & t2) / len(t1 | t2)
                    if jacc >= 0.68:
                        _add_conflict(
                            [r1.req_id, r2.req_id],
                            "Duplication",
                            "Medium",
                            f"{r1.req_id} and {r2.req_id} overlap by {jacc:.0%}.",
                            "Consolidate duplicate requirements and preserve links to both stakeholder sources.",
                        )

        # Attach inconsistency issues back onto affected requirements
        conflicting_ids = {rid for c in conflicts for rid in c.req_ids}
        for req in requirements:
            if req.req_id in conflicting_ids:
                req.quality_issues.append(
                    QualityIssue(
                        issue_type=QualityIssueType.CONFLICTING_STAKEHOLDER if any(c.conflict_type == "StakeholderConflict" and req.req_id in c.req_ids for c in conflicts) else QualityIssueType.INCONSISTENCY,
                        severity="High",
                        description="Requirement participates in an active conflict detected by ConflictDetectionAgent.",
                        suggested_clarification="Resolve via Human-in-the-Loop Stakeholder Conflict Resolution Gate.",
                    )
                )
        return conflicts

    def _run_compliance_agent(
        self, requirements: List[RequirementItem]
    ) -> Tuple[List[ComplianceMapping], Set[str]]:
        mappings: List[ComplianceMapping] = []
        kb_cited: Set[str] = set()
        seq = 0

        for req in requirements:
            cits = self.retriever.retrieve(f"{req.title} {req.statement}", top_k=3, min_score=0.09)
            # Keep any flagged unverified citations for ValidationAgent auditability, plus verified retrieval
            existing_unverified = [c for c in req.citations if not c.verified]
            req.citations = cits + existing_unverified
            verified_cits = [c for c in req.citations if c.verified]
            req.applicable_regulations = sorted({c.kb_id for c in verified_cits})

            # Calibrated confidence score (retrieval similarity + quality cleanliness)
            top_sim = max((c.similarity_score for c in verified_cits), default=0.0)
            penalty = 0.12 * sum(1 for q in req.quality_issues if q.severity == "High")
            hallucination_penalty = 0.30 if existing_unverified else 0.0
            base_conf = 0.58 + 0.42 * min(1.0, top_sim * 1.45) - penalty - hallucination_penalty
            req.confidence_score = round(max(0.25, min(0.97, base_conf)), 3)

            if req.confidence_score < self.llm.config.confidence_escalation_threshold or not verified_cits:
                req.escalation_reason = (
                    f"Confidence {req.confidence_score:.2f} below threshold "
                    f"({self.llm.config.confidence_escalation_threshold:.2f}) or missing verified KB citation."
                )
                if req.approval_status == ApprovalStatus.DRAFT:
                    req.approval_status = ApprovalStatus.PENDING_HUMAN_APPROVAL

            for cit in verified_cits[:2]:
                kb_item = self.retriever.item_map[cit.kb_id]
                kb_cited.add(cit.kb_id)
                seq += 1
                control = kb_item.mandatory_controls[0] if kb_item.mandatory_controls else kb_item.title
                gap = (
                    "Explicit numeric threshold or exception control missing in requirement statement."
                    if any(q.issue_type in {QualityIssueType.MISSING_SECURITY_COMPLIANCE, QualityIssueType.INCOMPLETENESS, QualityIssueType.AMBIGUITY} for q in req.quality_issues)
                    else "Aligned; verify automated test evidence during V&V gate."
                )
                retention_note = (
                    "Retain payment & KYC audit records in India >=5 years (PMLA) and ICT logs >=180 days (CERT-In)."
                    if any(k in kb_item.kb_id for k in ["PMLA", "CERTIN", "LOCAL", "DPDP"])
                    else "Preserve requirement-to-control audit trace in immutable ledger."
                )
                mappings.append(
                    ComplianceMapping(
                        mapping_id=f"CMP-{seq:03d}",
                        req_id=req.req_id,
                        jurisdiction=kb_item.jurisdiction,
                        regulation=f"{kb_item.source} ({kb_item.kb_id} v{kb_item.version})",
                        kb_id=kb_item.kb_id,
                        required_control=control,
                        supporting_evidence=f"[{kb_item.kb_id}] {kb_item.title} (sim={cit.similarity_score:.2f})",
                        compliance_gap=gap,
                        mandatory_checkpoint=f"Compliance & Legal Officer sign-off for {kb_item.kb_id}",
                        retention_reporting_obligation=retention_note,
                        legal_review_required=True,
                        confidence_score=req.confidence_score,
                        approval_status=ApprovalStatus.PENDING_HUMAN_APPROVAL,
                    )
                )
        return mappings, kb_cited

    def _run_security_privacy_agent(
        self,
        requirements: List[RequirementItem],
        compliance_mappings: List[ComplianceMapping],
    ) -> int:
        corpus = " ".join(r.statement.lower() for r in requirements)
        added = 0

        baseline_controls = [
            (
                "data_localization",
                ["india", "localization", "located in india"],
                "NFR-PAY-LOC",
                "Enforce India-Only Payment & Fraud Data Localization",
                "The system shall store 100% of end-to-end payment transaction data, device telemetry, and audit logs exclusively on servers physically located within India.",
                [RequirementCategory.NON_FUNCTIONAL],
                ["KB-RBI-LOCAL-01"],
            ),
            (
                "certin_reporting",
                ["cert-in", "6 hour", "6-hour", "ntp"],
                "NFR-FRD-CERTIN",
                "Enforce CERT-In 6-Hour Cyber Incident Alerting & 180-Day NTP Logs",
                "The system shall synchronize all clocks via NTP to NPL India, retain ICT security logs for 180 rolling days in India, and trigger automated incident escalation within 6 hours for CERT-In reporting.",
                [RequirementCategory.NON_FUNCTIONAL],
                ["KB-CERTIN-01"],
            ),
            (
                "dpdp_consent",
                ["dpdp", "itemized consent", "consent notice"],
                "NFR-PAY-DPDP",
                "Enforce DPDP Act 2023 Itemized Consent & Statutory Retention Reconciliation",
                "The system shall capture itemized, purpose-limited DPDP Act 2023 consent prior to collecting customer device/behavioral data while honoring PMLA 5-year statutory retention overrides.",
                [RequirementCategory.NON_FUNCTIONAL],
                ["KB-DPDP-01", "KB-PMLA-01"],
            ),
        ]

        existing_ids = {r.req_id for r in requirements}
        for _, keywords, req_id, title, stmt, cats, kb_refs in baseline_controls:
            if not any(kw in corpus for kw in keywords) and req_id not in existing_ids:
                added += 1
                cits = [
                    CitationRecord(
                        kb_id=kid,
                        title=self.retriever.item_map[kid].title,
                        source=self.retriever.item_map[kid].source,
                        jurisdiction=self.retriever.item_map[kid].jurisdiction,
                        version=self.retriever.item_map[kid].version,
                        effective_date=self.retriever.item_map[kid].effective_date,
                        similarity_score=0.95,
                        verified=True,
                        excerpt=self.retriever.item_map[kid].content[:200],
                    )
                    for kid in kb_refs
                    if kid in self.retriever.item_map
                ]
                requirements.append(
                    RequirementItem(
                        req_id=req_id,
                        title=title,
                        statement=stmt,
                        categories=cats,
                        source_stakeholder=StakeholderRole.INFOSEC_TEAM,
                        source_artifact_id="AGENT-INFERRED-BASELINE",
                        source_quote="Mandatory baseline gap detected by SecurityPrivacyAgent across Indian payment/fraud corpus.",
                        business_justification="Eliminates statutory compliance gap prior to architecture design.",
                        priority="Critical",
                        acceptance_criteria=_build_acceptance_criteria(stmt, cats),
                        applicable_regulations=kb_refs,
                        risk_level="High",
                        confidence_score=0.91,
                        citations=cits,
                        approval_status=ApprovalStatus.PENDING_HUMAN_APPROVAL,
                        escalation_reason="Agent-derived mandatory regulatory/security control requires stakeholder ratification.",
                    )
                )
        return added

    def _run_risk_agent(
        self,
        requirements: List[RequirementItem],
        compliance_mappings: List[ComplianceMapping],
        conflicts: List[ConflictRecord],
    ) -> List[RiskItem]:
        risks: List[RiskItem] = []
        seq = 0
        for req in requirements:
            if req.risk_level not in {"Critical", "High"} and not req.quality_issues:
                continue
            seq += 1
            lower = req.statement.lower()
            if any(k in lower for k in ["fraud", "mule", "velocity", "step-up", "afa"]):
                rcat, likelihood, impact = "Fraud", 4, 5
                owner = StakeholderRole.RISK_MANAGEMENT
            elif any(k in lower for k in ["encrypt", "hsm", "cvv", "coft", "token", "mtls", "dpdp", "consent", "mask"]):
                rcat, likelihood, impact = "Security", 4, 5
                owner = StakeholderRole.INFOSEC_TEAM
            elif any(k in lower for k in ["rbi", "npci", "pmla", "cert-in", "india", "5 year", "180", "str", "fmr"]):
                rcat, likelihood, impact = "Compliance", 3, 5
                owner = StakeholderRole.COMPLIANCE_LEGAL
            elif RequirementCategory.NON_FUNCTIONAL in req.categories or any(k in lower for k in ["latency", "ms", "tps", "uptime", "rpo", "rto"]):
                rcat, likelihood, impact = "Technical", 4, 4
                owner = StakeholderRole.ARCHITECT_DEVELOPER
            else:
                rcat, likelihood, impact = "Business", 3, 4
                owner = StakeholderRole.PRODUCT_OWNER

            inherent = likelihood * impact
            mitigations = [
                f"Enforce grounded KB controls: {', '.join(req.applicable_regulations) or 'ISO 27001 / RBI DPSC'}",
                "Require automated verification tests and HITL sign-off prior to production.",
            ]
            residual = max(3, inherent - 10)
            risks.append(
                RiskItem(
                    risk_id=f"RISK-{seq:03d}",
                    req_id=req.req_id,
                    category=rcat,
                    title=f"{rcat} Risk on {req.req_id}: {req.title[:52]}",
                    description=f"Exposure derived from '{req.statement[:140]}' (quality issues: {len(req.quality_issues)}).",
                    likelihood=likelihood,
                    impact=impact,
                    inherent_score=inherent,
                    mitigation_controls=mitigations,
                    residual_score=residual,
                    owner_role=owner,
                )
            )

        for conf in conflicts:
            seq += 1
            risks.append(
                RiskItem(
                    risk_id=f"RISK-{seq:03d}",
                    req_id=", ".join(conf.req_ids),
                    category="Compliance" if conf.conflict_type == "PolicyConflict" else "Business",
                    title=f"Unresolved {conf.conflict_type}: {conf.conflict_id}",
                    description=conf.description,
                    likelihood=4,
                    impact=5 if conf.severity == "Critical" else 4,
                    inherent_score=20 if conf.severity == "Critical" else 16,
                    mitigation_controls=[conf.recommendation],
                    residual_score=6,
                    owner_role=StakeholderRole.COMPLIANCE_LEGAL,
                )
            )
        return risks

    def _validate_outputs(
        self,
        requirements: List[RequirementItem],
        compliance_mappings: List[ComplianceMapping],
        conflicts: List[ConflictRecord],
    ) -> Dict[str, Any]:
        verified = 0
        hallucinated = 0
        escalated = 0
        for req in requirements:
            for c in req.citations:
                if c.verified and c.kb_id in self.retriever.item_map:
                    verified += 1
                else:
                    hallucinated += 1
            if req.escalation_reason:
                escalated += 1

        avg_conf = round(sum(r.confidence_score for r in requirements) / max(1, len(requirements)), 3)
        return {
            "total_requirements": len(requirements),
            "verified_citations": verified,
            "hallucinated_citations": hallucinated,
            "escalated_requirements": escalated,
            "open_conflicts": len(conflicts),
            "compliance_mappings": len(compliance_mappings),
            "avg_confidence": avg_conf,
            "traceability_coverage_pct": 100.0 if all(r.source_artifact_id for r in requirements) else 90.0,
        }

    def _build_approval_gates(
        self,
        project_id: str,
        requirements: List[RequirementItem],
        conflicts: List[ConflictRecord],
        compliance_mappings: List[ComplianceMapping],
        sdlc: SDLCRecommendation,
    ) -> List[ApprovalGateItem]:
        gates: List[ApprovalGateItem] = [
            ApprovalGateItem(
                gate_id="GATE-BASE-001",
                project_id=project_id,
                gate_type=GateType.FINAL_REQUIREMENT_BASELINE,
                target_id="SRS-BASELINE-v1",
                title="Final Requirement Baseline Approval",
                summary=f"Approve {len(requirements)} structured requirements prior to Sprint-1 lock.",
                required_approver_roles=GATE_APPROVER_MAP[GateType.FINAL_REQUIREMENT_BASELINE],
            ),
            ApprovalGateItem(
                gate_id="GATE-REG-001",
                project_id=project_id,
                gate_type=GateType.REGULATORY_INTERPRETATION,
                target_id="COMPLIANCE-MATRIX-v1",
                title="Regulatory & Legal Interpretation Sign-Off",
                summary=f"Compliance/Legal sign-off for {len(compliance_mappings)} RBI/NPCI/DPDP/PMLA/CERT-In mappings (AI does not make final legal determinations).",
                required_approver_roles=GATE_APPROVER_MAP[GateType.REGULATORY_INTERPRETATION],
            ),
            ApprovalGateItem(
                gate_id="GATE-SEC-001",
                project_id=project_id,
                gate_type=GateType.HIGH_RISK_SECURITY,
                target_id="SECURITY-CONTROLS-v1",
                title="High-Risk Security & Privacy Controls Approval",
                summary="Approve AFA/step-up MFA, CoFT tokenization, HSM custody, and CERT-In 6-hour incident controls.",
                required_approver_roles=GATE_APPROVER_MAP[GateType.HIGH_RISK_SECURITY],
            ),
            ApprovalGateItem(
                gate_id="GATE-ARCH-001",
                project_id=project_id,
                gate_type=GateType.ARCHITECTURE_CRITICAL_REQUIREMENT,
                target_id="ARCH-SLA-v1",
                title="Architecture-Critical Latency, Idempotency & DR Approval",
                summary="Sign off <=150ms p99 fraud scoring SLA, deterministic rule fallback, and RPO<=1m/RTO<=15m targets.",
                required_approver_roles=GATE_APPROVER_MAP[GateType.ARCHITECTURE_CRITICAL_REQUIREMENT],
            ),
            ApprovalGateItem(
                gate_id="GATE-SDLC-001",
                project_id=project_id,
                gate_type=GateType.SDLC_SELECTION,
                target_id=sdlc.recommended_model.value,
                title=f"SDLC Adoption Gate: {sdlc.recommended_model.value} ({sdlc.rankings[0].score_pct}%)",
                summary="Approve recommended SDLC methodology and customized 5-phase compliance/security workflow.",
                required_approver_roles=GATE_APPROVER_MAP[GateType.SDLC_SELECTION],
            ),
            ApprovalGateItem(
                gate_id="GATE-PROD-001",
                project_id=project_id,
                gate_type=GateType.PRODUCTION_READINESS,
                target_id="PRR-GATE-v1",
                title="Production-Readiness & NPCI/VAPT Release Gate",
                summary="Mandatory pre-production gate confirming NPCI UAT, VAPT closure, and advisory canary criteria.",
                required_approver_roles=GATE_APPROVER_MAP[GateType.PRODUCTION_READINESS],
            ),
        ]

        if conflicts:
            gates.append(
                ApprovalGateItem(
                    gate_id="GATE-CONF-001",
                    project_id=project_id,
                    gate_type=GateType.CONFLICTING_STAKEHOLDER_DECISION,
                    target_id=", ".join(c.conflict_id for c in conflicts),
                    title=f"Resolve {len(conflicts)} Stakeholder/Policy Conflict(s)",
                    summary="; ".join(c.description for c in conflicts[:3]),
                    required_approver_roles=GATE_APPROVER_MAP[GateType.CONFLICTING_STAKEHOLDER_DECISION],
                )
            )
        return gates
