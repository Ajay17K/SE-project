from __future__ import annotations

from typing import Dict, List, Tuple

from backend.app.llm import PluggableLLMClient
from backend.app.models import (
    ApprovalStatus,
    ComplianceMapping,
    RequirementCategory,
    RequirementItem,
    RiskItem,
    SDLCFactorScore,
    SDLCModel,
    SDLCRankingItem,
    SDLCRecommendation,
    SDLCWorkflowPhase,
    StakeholderRole,
)


# Ideal profile (1-5) for each SDLC model across the 13 Item-13 decision factors
MODEL_FACTOR_PROFILES: Dict[SDLCModel, Dict[str, float]] = {
    SDLCModel.AGILE_DEVSECOPS_HYBRID: {
        "requirement_stability": 2.4,
        "regulatory_criticality": 4.7,
        "security_risk": 4.8,
        "project_complexity": 4.4,
        "system_size": 4.2,
        "legacy_dependence": 3.6,
        "change_frequency": 4.6,
        "continuous_delivery": 4.7,
        "stakeholder_availability": 4.0,
        "testing_doc_rigor": 4.5,
        "schedule_budget_pressure": 4.0,
        "formal_verification": 3.9,
        "failure_consequence": 4.8,
    },
    SDLCModel.AGILE_V_MODEL_HYBRID: {
        "requirement_stability": 3.1,
        "regulatory_criticality": 4.9,
        "security_risk": 4.7,
        "project_complexity": 4.3,
        "system_size": 4.3,
        "legacy_dependence": 4.2,
        "change_frequency": 3.4,
        "continuous_delivery": 3.2,
        "stakeholder_availability": 3.6,
        "testing_doc_rigor": 4.9,
        "schedule_budget_pressure": 3.4,
        "formal_verification": 4.7,
        "failure_consequence": 4.9,
    },
    SDLCModel.DEVSECOPS: {
        "requirement_stability": 2.0,
        "regulatory_criticality": 3.6,
        "security_risk": 4.5,
        "project_complexity": 3.8,
        "system_size": 3.6,
        "legacy_dependence": 2.6,
        "change_frequency": 4.9,
        "continuous_delivery": 5.0,
        "stakeholder_availability": 4.2,
        "testing_doc_rigor": 3.7,
        "schedule_budget_pressure": 4.5,
        "formal_verification": 2.8,
        "failure_consequence": 4.0,
    },
    SDLCModel.V_MODEL: {
        "requirement_stability": 4.6,
        "regulatory_criticality": 5.0,
        "security_risk": 4.6,
        "project_complexity": 4.0,
        "system_size": 4.2,
        "legacy_dependence": 4.3,
        "change_frequency": 1.7,
        "continuous_delivery": 1.6,
        "stakeholder_availability": 2.7,
        "testing_doc_rigor": 5.0,
        "schedule_budget_pressure": 2.4,
        "formal_verification": 5.0,
        "failure_consequence": 5.0,
    },
    SDLCModel.SPIRAL: {
        "requirement_stability": 2.1,
        "regulatory_criticality": 4.1,
        "security_risk": 4.6,
        "project_complexity": 4.8,
        "system_size": 4.5,
        "legacy_dependence": 3.8,
        "change_frequency": 3.6,
        "continuous_delivery": 2.8,
        "stakeholder_availability": 3.4,
        "testing_doc_rigor": 4.1,
        "schedule_budget_pressure": 2.5,
        "formal_verification": 4.0,
        "failure_consequence": 4.6,
    },
    SDLCModel.AGILE: {
        "requirement_stability": 1.8,
        "regulatory_criticality": 2.1,
        "security_risk": 2.4,
        "project_complexity": 3.2,
        "system_size": 3.0,
        "legacy_dependence": 2.3,
        "change_frequency": 4.9,
        "continuous_delivery": 4.6,
        "stakeholder_availability": 4.8,
        "testing_doc_rigor": 2.4,
        "schedule_budget_pressure": 4.6,
        "formal_verification": 1.8,
        "failure_consequence": 2.3,
    },
    SDLCModel.WATERFALL: {
        "requirement_stability": 4.9,
        "regulatory_criticality": 4.2,
        "security_risk": 3.4,
        "project_complexity": 3.0,
        "system_size": 3.5,
        "legacy_dependence": 4.4,
        "change_frequency": 1.2,
        "continuous_delivery": 1.2,
        "stakeholder_availability": 2.0,
        "testing_doc_rigor": 4.2,
        "schedule_budget_pressure": 2.2,
        "formal_verification": 4.0,
        "failure_consequence": 3.9,
    },
}

FACTOR_WEIGHTS: Dict[str, float] = {
    "requirement_stability": 1.1,
    "regulatory_criticality": 1.5,
    "security_risk": 1.4,
    "project_complexity": 1.0,
    "system_size": 0.8,
    "legacy_dependence": 1.0,
    "change_frequency": 1.3,
    "continuous_delivery": 1.2,
    "stakeholder_availability": 0.9,
    "testing_doc_rigor": 1.3,
    "schedule_budget_pressure": 0.9,
    "formal_verification": 1.1,
    "failure_consequence": 1.4,
}


def extract_sdlc_factors(
    requirements: List[RequirementItem],
    compliance_mappings: List[ComplianceMapping],
    risks: List[RiskItem],
    raw_text_corpus: str,
) -> List[SDLCFactorScore]:
    lower = raw_text_corpus.lower()
    req_count = max(1, len(requirements))

    reg_reqs = sum(1 for r in requirements if r.applicable_regulations or any(k in r.statement.lower() for k in ["rbi", "npci", "dpdp", "pmla", "cert-in", "pci", "india"]))
    sec_reqs = sum(1 for r in requirements if any(k in r.statement.lower() for k in ["afa", "mfa", "step-up", "token", "coft", "cvv", "hsm", "encrypt", "mtls", "dpdp", "consent", "mask"]))
    int_reqs = sum(1 for r in requirements if any(k in r.statement.lower() for k in ["api", "switch", "npci", "cbs", "iso 8583", "webhook", "siem", "rrn"]))
    perf_reqs = sum(1 for r in requirements if RequirementCategory.NON_FUNCTIONAL in r.categories and any(k in r.statement.lower() for k in ["latency", "ms", "tps", "uptime", "rpo", "rto"]))
    high_risks = sum(1 for r in risks if r.inherent_score >= 15)
    unresolved_issues = sum(len(r.quality_issues) for r in requirements)

    # 1. Requirement stability (lower if fraud rules/ML evolve or many open issues)
    evolve_hits = sum(1 for k in ["fraud rule", "ml model", "evolving", "dynamic", "sprint", "frequent", "new typology", "tune"] if k in lower)
    frozen_hits = sum(1 for k in ["frozen", "fixed scope", "unchanged", "static specification"] if k in lower)
    stability = max(1.2, min(4.8, 3.6 - 0.35 * evolve_hits - 0.1 * min(6, unresolved_issues) + 0.6 * frozen_hits))

    # 2. Regulatory criticality
    reg_ratio = reg_reqs / req_count
    reg_score = max(2.0, min(5.0, 2.5 + 1.8 * reg_ratio + 0.15 * min(6, len(compliance_mappings))))

    # 3. Security risk
    sec_ratio = sec_reqs / req_count
    sec_score = max(2.0, min(5.0, 2.6 + 1.6 * sec_ratio + 0.25 * min(5, high_risks)))

    # 4. Project complexity
    comp_keywords = sum(1 for k in ["upi", "npci", "mule", "graph", "iso 8583", "coft", "hsm", "udir", "siem", "ml"] if k in lower)
    comp_score = max(2.2, min(5.0, 2.4 + 0.26 * comp_keywords + 0.08 * min(10, req_count)))

    # 5. System size
    size_score = max(2.0, min(5.0, 2.3 + 0.18 * min(15, req_count)))

    # 6. Legacy-system dependence
    legacy_hits = sum(1 for k in ["legacy", "cbs", "core banking", "iso 8583", "mainframe", "soap", "switch", "npci"] if k in lower)
    legacy_score = max(1.5, min(5.0, 2.0 + 0.45 * legacy_hits + 0.25 * min(4, int_reqs)))

    # 7. Frequency of expected changes
    change_freq = max(1.5, min(5.0, 2.5 + 0.45 * evolve_hits + (0.6 if "fraud" in lower else 0.0) - 0.7 * frozen_hits))

    # 8. Need for continuous delivery
    cd_hits = sum(1 for k in ["continuous", "ci/cd", "canary", "shadow mode", "hotfix", "real-time", "deploy"] if k in lower)
    cd_score = max(1.5, min(5.0, 2.4 + 0.42 * cd_hits + (0.6 if "fraud" in lower else 0.0)))

    # 9. Availability of stakeholders
    stakeholders_represented = len({r.source_stakeholder for r in requirements})
    stake_avail = max(2.2, min(5.0, 2.5 + 0.38 * stakeholders_represented))

    # 10. Testing & documentation rigor
    test_rigor = max(2.5, min(5.0, 2.9 + 0.35 * (reg_score - 2.0) + 0.2 * min(4, perf_reqs)))

    # 11. Budget & schedule constraints
    sched_hits = sum(1 for k in ["tight", "quarter", "weeks", "deadline", "budget", "mvp", "phase 1", "phase-1"] if k in lower)
    sched_score = max(2.0, min(4.8, 2.8 + 0.4 * sched_hits))

    # 12. Need for formal verification
    formal_hits = sum(1 for k in ["npci certification", "uat", "qsa", "audit", "idempoten", "reconciliation", "fmr", "str"] if k in lower)
    formal_score = max(2.2, min(5.0, 2.7 + 0.35 * formal_hits + 0.25 * (reg_score - 2.5)))

    # 13. Consequences of system failure
    fail_hits = sum(1 for k in ["double debit", "breach", "cert-in", "settlement", "availability", "99.95", "fraud loss"] if k in lower)
    fail_score = max(2.5, min(5.0, 3.2 + 0.3 * fail_hits + 0.15 * min(5, high_risks)))

    return [
        SDLCFactorScore(
            factor_key="requirement_stability",
            factor_name="Requirement Stability",
            score=round(stability, 2),
            rationale=f"Derived from {unresolved_issues} open quality clarifications and {evolve_hits} dynamic rule/ML evolution signals.",
            evidence_refs=[r.req_id for r in requirements[:3]],
        ),
        SDLCFactorScore(
            factor_key="regulatory_criticality",
            factor_name="Regulatory Criticality",
            score=round(reg_score, 2),
            rationale=f"{reg_reqs}/{req_count} requirements carry regulatory mandates ({len(compliance_mappings)} RBI/NPCI/DPDP/PMLA/CERT-In mappings).",
            evidence_refs=[m.kb_id for m in compliance_mappings[:4]],
        ),
        SDLCFactorScore(
            factor_key="security_risk",
            factor_name="Security & Privacy Risk",
            score=round(sec_score, 2),
            rationale=f"{sec_reqs}/{req_count} requirements involve security/privacy controls with {high_risks} critical/high inherent risks.",
            evidence_refs=[r.risk_id for r in risks[:3]],
        ),
        SDLCFactorScore(
            factor_key="project_complexity",
            factor_name="Project & Algorithmic Complexity",
            score=round(comp_score, 2),
            rationale="Reflects multi-rail payment orchestration, low-latency scoring, and graph/velocity fraud detection complexity.",
            evidence_refs=[r.req_id for r in requirements[:2]],
        ),
        SDLCFactorScore(
            factor_key="system_size",
            factor_name="System Scope & Size",
            score=round(size_score, 2),
            rationale=f"Derived from {len(requirements)} structured requirements across multiple stakeholder dimensions.",
            evidence_refs=[r.req_id for r in requirements[:3]],
        ),
        SDLCFactorScore(
            factor_key="legacy_dependence",
            factor_name="Legacy-System Dependence",
            score=round(legacy_score, 2),
            rationale=f"Integration coupling across {int_reqs} integration requirements (NPCI switch, CBS/ISO 8583, HSM/SIEM).",
            evidence_refs=[r.req_id for r in requirements if any(k in r.statement.lower() for k in ["api", "switch", "npci", "cbs", "iso 8583", "siem"])][:3],
        ),
        SDLCFactorScore(
            factor_key="change_frequency",
            factor_name="Expected Frequency of Change",
            score=round(change_freq, 2),
            rationale="Adversarial fraud typologies and NPCI limit circulars require frequent policy/model updates.",
            evidence_refs=["KB-RBI-FRM-01", "KB-NPCI-UPI-01"],
        ),
        SDLCFactorScore(
            factor_key="continuous_delivery",
            factor_name="Need for Continuous Secure Delivery",
            score=round(cd_score, 2),
            rationale="Fraud rule tuning, shadow-mode ML deployment, and security patching demand automated CI/CD pipelines.",
            evidence_refs=["KB-REF-PROJ-01", "KB-SDLC-RULES-01"],
        ),
        SDLCFactorScore(
            factor_key="stakeholder_availability",
            factor_name="Stakeholder Availability",
            score=round(stake_avail, 2),
            rationale=f"{stakeholders_represented} distinct stakeholder role(s) actively engaged in elicitation.",
            evidence_refs=[],
        ),
        SDLCFactorScore(
            factor_key="testing_doc_rigor",
            factor_name="Testing & Documentation Rigor",
            score=round(test_rigor, 2),
            rationale="High compliance, transaction-integrity, and auditability obligations require formal V&V evidence.",
            evidence_refs=["KB-NPCI-UPI-02", "KB-RE-GUIDE-01"],
        ),
        SDLCFactorScore(
            factor_key="schedule_budget_pressure",
            factor_name="Schedule & Budget Constraints",
            score=round(sched_score, 2),
            rationale="Balances phased time-to-market delivery against mandatory regulatory pre-go-live gates.",
            evidence_refs=[],
        ),
        SDLCFactorScore(
            factor_key="formal_verification",
            factor_name="Need for Formal Verification & Sign-Off",
            score=round(formal_score, 2),
            rationale="NPCI UAT certification, PCI-DSS/CoFT checks, and PMLA/CERT-In verification require formal gates.",
            evidence_refs=["KB-NPCI-UPI-02", "KB-PCIDSS-01"],
        ),
        SDLCFactorScore(
            factor_key="failure_consequence",
            factor_name="Consequences of System Failure",
            score=round(fail_score, 2),
            rationale="Double debits, fraud leakage, or downtime directly cause financial loss and RBI/CERT-In escalation.",
            evidence_refs=["KB-CERTIN-01", "KB-ISO27001-01"],
        ),
    ]


def rank_sdlc_models(
    factors: List[SDLCFactorScore],
    llm: PluggableLLMClient,
    project_summary: str,
) -> Tuple[List[SDLCRankingItem], str]:
    f_map = {f.factor_key: f.score for f in factors}
    total_w = sum(FACTOR_WEIGHTS.values())

    rankings: List[SDLCRankingItem] = []

    for model, profile in MODEL_FACTOR_PROFILES.items():
        # Weighted normalized closeness (0..100)
        weighted_closeness = 0.0
        for key, weight in FACTOR_WEIGHTS.items():
            diff = abs(f_map.get(key, 3.0) - profile[key])
            closeness = max(0.0, 1.0 - (diff / 4.0))
            weighted_closeness += weight * closeness
        mcda_pct = (weighted_closeness / total_w) * 100.0

        # Deterministic financial rule adjustments (Item 14)
        adj = 0.0
        matched_rules: List[str] = []

        if f_map["regulatory_criticality"] >= 3.8 and f_map["change_frequency"] >= 3.4:
            if model == SDLCModel.AGILE_DEVSECOPS_HYBRID:
                adj += 6.5
                matched_rules.append("RULE-HYBRID-01: High regulation + evolving fraud/payment needs favors Agile-DevSecOps Hybrid")
            elif model == SDLCModel.AGILE_V_MODEL_HYBRID:
                adj += 4.5
                matched_rules.append("RULE-HYBRID-02: High regulation + strict verification favors Agile-V-Model Hybrid")
            elif model == SDLCModel.AGILE:
                adj -= 12.0
                matched_rules.append("RULE-PENALTY-01: Pure Agile penalized under strict RBI/NPCI/DPDP governance")
            elif model == SDLCModel.WATERFALL:
                adj -= 9.0
                matched_rules.append("RULE-PENALTY-02: Pure Waterfall penalized due to frequent fraud/rule iteration")

        if f_map["continuous_delivery"] >= 3.8 and f_map["security_risk"] >= 4.0:
            if model in {SDLCModel.AGILE_DEVSECOPS_HYBRID, SDLCModel.DEVSECOPS}:
                adj += 3.0
                matched_rules.append("RULE-SEC-01: Automated SAST/DAST & continuous fraud deployment bonus")

        if f_map["formal_verification"] >= 4.0 and f_map["requirement_stability"] >= 3.8:
            if model in {SDLCModel.V_MODEL, SDLCModel.AGILE_V_MODEL_HYBRID}:
                adj += 5.0
                matched_rules.append("RULE-VV-01: Strict formal verification and certification gate bonus")

        if f_map["project_complexity"] >= 4.2 and f_map["requirement_stability"] <= 2.6:
            if model == SDLCModel.SPIRAL:
                adj += 3.5
                matched_rules.append("RULE-RISK-01: High algorithmic uncertainty favors Spiral prototyping iterations")

        final_pct = round(max(15.0, min(98.0, mcda_pct + adj)), 1)

        strengths, cautions = _model_tradeoffs(model)
        explanation = (
            f"MCDA fit {mcda_pct:.1f}% with deterministic policy adjustment {adj:+.1f}% -> {final_pct:.1f}%."
        )
        rankings.append(
            SDLCRankingItem(
                model=model,
                score_pct=final_pct,
                mcda_score=round(mcda_pct, 1),
                rule_adjustment=round(adj, 1),
                matched_rules=matched_rules,
                explanation=explanation,
                strengths=strengths,
                cautions=cautions,
            )
        )

    rankings.sort(key=lambda r: r.score_pct, reverse=True)
    top = rankings[0]

    def _fallback_justification() -> str:
        second = rankings[1]
        return (
            f"Recommended SDLC: {top.model.value} ({top.score_pct}%), followed by {second.model.value} ({second.score_pct}%). "
            f"Driven by Regulatory Criticality ({f_map['regulatory_criticality']}/5), Security Risk ({f_map['security_risk']}/5), "
            f"Failure Consequence ({f_map['failure_consequence']}/5), and Change Frequency ({f_map['change_frequency']}/5). "
            f"Pure Agile ({next(r.score_pct for r in rankings if r.model == SDLCModel.AGILE)}%) and Waterfall "
            f"({next(r.score_pct for r in rankings if r.model == SDLCModel.WATERFALL)}%) are insufficient alone because Indian "
            f"payment/fraud platforms require both rapid adversarial rule iteration and mandatory RBI/NPCI/CERT-In/DPDP approval gates. "
            f"Final SDLC adoption requires sign-off from Product Owner, Architect, InfoSec, and Compliance Officer."
        )

    llm_justification, _ = llm.generate_text(
        system_prompt=(
            "You are FinReq SDLCSelectionAgent. Explain why the top-ranked SDLC fits this Indian payment/fraud "
            "project based strictly on the provided factor scores and rules."
        ),
        user_prompt=(
            f"Project: {project_summary}\n"
            f"Top 3 Rankings: {[(r.model.value, r.score_pct) for r in rankings[:3]]}\n"
            f"Factors: {[(f.factor_name, f.score) for f in factors]}\n"
            "Provide a concise 3-4 sentence executive justification."
        ),
        fallback_fn=_fallback_justification,
    )
    return rankings, llm_justification


def _model_tradeoffs(model: SDLCModel) -> Tuple[List[str], List[str]]:
    mapping = {
        SDLCModel.AGILE_DEVSECOPS_HYBRID: (
            ["Iterative sprint delivery with embedded SAST/DAST, threat modeling & compliance gates", "Supports continuous fraud rule/ML tuning in shadow mode"],
            ["Requires disciplined automated compliance evidence in CI/CD"],
        ),
        SDLCModel.AGILE_V_MODEL_HYBRID: (
            ["Pairs iterative feature increments with formal V-Model verification & NPCI/RBI traceability", "Strong audit readiness for certification cycles"],
            ["Slower release cadence for experimental fraud models"],
        ),
        SDLCModel.DEVSECOPS: (
            ["Fast automated security scanning and continuous deployment"],
            ["Needs explicit RBI/NPCI human governance gates layered onto pipeline"],
        ),
        SDLCModel.V_MODEL: (
            ["Maximum formal verification, traceability, and test discipline"],
            ["Rigid when fraud typologies or UX specs evolve mid-project"],
        ),
        SDLCModel.SPIRAL: (
            ["Strong risk-driven prototyping for high-uncertainty fraud ML R&D"],
            ["Higher governance overhead and less suited to continuous production rule ops"],
        ),
        SDLCModel.AGILE: (
            ["Fast stakeholder feedback and sprint adaptability"],
            ["Lacks mandatory regulatory, audit, and formal verification checkpoints"],
        ),
        SDLCModel.WATERFALL: (
            ["Predictable upfront sign-off when legacy specs are completely frozen"],
            ["Poor fit for evolving payment fraud threats and iterative threshold tuning"],
        ),
    }
    return mapping[model]


def generate_sdlc_workflow(model: SDLCModel) -> List[SDLCWorkflowPhase]:
    """Generates a customized, financial-grade SDLC workflow (Item 15)."""
    return [
        SDLCWorkflowPhase(
            order=1,
            phase_name="1. Regulatory Discovery & Requirement Baseline",
            objective="Finalize masked stakeholder requirements, compliance mappings, and ambiguity-free SRS baseline.",
            activities=[
                "Complete adaptive stakeholder interviews across Business, Risk, InfoSec, Compliance, Ops",
                "Map requirements to RBI DPSC, Data Localization, NPCI/UPI limits, DPDP Act 2023, PMLA, CERT-In",
                "Resolve all quality issues, contradictions, and open questions",
            ],
            responsible_roles=[StakeholderRole.BUSINESS_ANALYST, StakeholderRole.PRODUCT_OWNER, StakeholderRole.COMPLIANCE_LEGAL],
            deliverables=["Approved SRS v1.0", "Compliance-Control Matrix", "Requirements Traceability Matrix (RTM)"],
            security_activities=["PII/PCI classification & masking audit on ingested artifacts", "Define DPDP consent & purpose matrix"],
            testing_requirements=["Review Gherkin acceptance criteria testability", "Verify numeric SLA & fraud threshold specs"],
            compliance_checkpoints=["RBI DPSC applicability sign-off", "DPDP Data Fiduciary purpose review"],
            human_approval_gates=["Gate: Final Requirement Baseline Approval", "Gate: Regulatory Interpretation Sign-Off"],
            entry_criteria=["Project charter & stakeholder roster confirmed"],
            exit_criteria=["100% critical requirements free of unresolved quality conflicts", "Compliance & PO baseline signed"],
            traceability_requirements=["Every SRS ID linked to Stakeholder Source Quote and KB Citation ID"],
        ),
        SDLCWorkflowPhase(
            order=2,
            phase_name="2. Secure Architecture & Threat Modeling",
            objective="Design low-latency payment/fraud architecture with HSM custody, data localization, and resilience.",
            activities=[
                "Design idempotent payment orchestrator and <150ms p99 dual-stage fraud pipeline",
                "Define India-only data residency topology, NTP sync, and CBS/NPCI switch contracts",
                "Design maker-checker workflows for fraud rule & limit changes",
            ],
            responsible_roles=[StakeholderRole.ARCHITECT_DEVELOPER, StakeholderRole.INFOSEC_TEAM, StakeholderRole.RISK_MANAGEMENT],
            deliverables=["HLD/LLD Architecture Blueprint", "STRIDE Threat Model", "API/DB & ISO 8583 Interface Contracts"],
            security_activities=["STRIDE threat modeling on UPI/Card/Fraud flows", "CoFT tokenization & FIPS 140-3 HSM key design", "mTLS & mobile RASP specification"],
            testing_requirements=["Architecture latency budget simulation (<150ms scoring inside 30s NPCI SLA)", "DR/BCP failover tabletop"],
            compliance_checkpoints=["RBI Data Localization topology verification", "DPDP DPIA completion (if SDF)"],
            human_approval_gates=["Gate: Architecture-Critical Requirement Approval", "Gate: High-Risk Security Design Approval"],
            entry_criteria=["Approved SRS Baseline"],
            exit_criteria=["Zero unmitigated Critical STRIDE threats", "InfoSec & Architect sign-off"],
            traceability_requirements=["Link Threat Model mitigations and HLD components back to SEC-* & REG-* IDs"],
        ),
        SDLCWorkflowPhase(
            order=3,
            phase_name=f"3. Iterative Build & Embedded DevSecOps ({model.value})",
            objective="Implement payment rails, fraud rules/ML, consent ledger, and immutable logging in gated increments.",
            activities=[
                "Develop payment switch adapters, idempotency store, and UDIR/settlement handlers",
                "Implement deterministic fraud rules, velocity counters, mule graph analytics, and ML scorer",
                "Implement automated PMLA STR/FMR flagging and CERT-In 6-hour SIEM webhooks",
            ],
            responsible_roles=[StakeholderRole.ARCHITECT_DEVELOPER, StakeholderRole.INFOSEC_TEAM],
            deliverables=["Versioned Payment & Fraud Microservices", "CI/CD Security Scan Reports", "Automated Unit & Contract Test Suite"],
            security_activities=["Mandatory SAST, SCA dependency CVE checks, and secrets scanning on every PR", "Zero unmasked PAN/CVV/Aadhaar logging check"],
            testing_requirements=["100% unit/contract pass for idempotency, cooling limits (INR 5k/24h), and ML timeout fallback"],
            compliance_checkpoints=["Automated static check for India region deployment tags & NTP sync config"],
            human_approval_gates=["Peer + Security code review on authentication, cryptography, and fraud-decision modules"],
            entry_criteria=["Signed Threat Model & Architecture Blueprint"],
            exit_criteria=["Zero Critical/High SAST/SCA findings", "CI quality & coverage thresholds passed"],
            traceability_requirements=["Commit/PR IDs tagged with Requirement IDs and linked to automated test cases in RTM"],
        ),
        SDLCWorkflowPhase(
            order=4,
            phase_name="4. Verification, Transaction-Integrity & Regulatory UAT",
            objective="Validate functional accuracy, fraud efficacy, performance SLAs, and regulatory certification readiness.",
            activities=[
                "Execute NPCI UPI Sandbox/UAT and UDIR dispute end-to-end test cycles",
                "Run shadow-mode fraud model validation against historical fraud/mule replay datasets",
                "Execute chaos/failover testing (ML timeout fallback, active-active DB switchover)",
            ],
            responsible_roles=[StakeholderRole.RISK_MANAGEMENT, StakeholderRole.OPERATIONS, StakeholderRole.INFOSEC_TEAM, StakeholderRole.AUDITOR_REGULATOR],
            deliverables=["Transaction-Integrity Test Report", "DAST & VAPT Report", "NPCI UAT Sign-Off Evidence", "Updated RTM (100% coverage)"],
            security_activities=["Dynamic Application Security Testing (DAST)", "External VAPT / PCI-DSS ASV scan & API fuzzing"],
            testing_requirements=["Transaction-integrity & double-debit prevention tests", "5,000 TPS peak load test confirming <=150ms p99 fraud scoring", "180-day/5-year audit archive retrieval test"],
            compliance_checkpoints=["NPCI UAT certification verification", "PCI-DSS CoFT compliance & CERT-In 6-hour drill verification"],
            human_approval_gates=["Gate: Compliance & Security Pre-Release Sign-Off"],
            entry_criteria=["Feature-complete build passing SAST/SCA & staging integration tests"],
            exit_criteria=["100% Critical/High requirements verified", "Zero open VAPT Critical/High findings"],
            traceability_requirements=["Every test execution report mapped to Requirement ID, Acceptance Criteria, and Compliance Control"],
        ),
        SDLCWorkflowPhase(
            order=5,
            phase_name="5. Advisory Canary Release, Production Readiness & Continuous Governance",
            objective="Roll out safely with shadow/advisory validation, 24x7 monitoring, and ongoing regulatory drift governance.",
            activities=[
                "Launch in advisory/shadow mode comparing automated fraud decisions against analyst benchmarks",
                "Activate progressive canary traffic split (5% -> 25% -> 100%) with instant rollback triggers",
                "Monitor false-positive rate, FMR/STR pipeline health, and RBI/NPCI circular updates",
            ],
            responsible_roles=[StakeholderRole.OPERATIONS, StakeholderRole.PRODUCT_OWNER, StakeholderRole.COMPLIANCE_LEGAL, StakeholderRole.AUDITOR_REGULATOR],
            deliverables=["Production Readiness Review (PRR) Pack", "Runbooks & CERT-In 6h Playbook", "Immutable Audit Archive"],
            security_activities=["24x7 SIEM correlation, RASP telemetry monitoring, and periodic HSM key rotation"],
            testing_requirements=["Synthetic production canary probes & periodic DR failover drills (RPO<=1m, RTO<=15m)"],
            compliance_checkpoints=["Quarterly RBI/NPCI regulatory delta review & KB re-indexing", "Annual DPDP/ISO 27001 audit readiness"],
            human_approval_gates=["Gate: Production Readiness Sign-Off (Ops + InfoSec + Compliance)"],
            entry_criteria=["All V&V and VAPT exit criteria passed"],
            exit_criteria=["Production sign-off recorded in hash-chained audit log", "KPI & compliance telemetry green"],
            traceability_requirements=["Full production audit trail linking runtime alerts/decisions back to approved Requirement & KB versions"],
        ),
    ]


def build_sdlc_recommendation(
    project_id: str,
    requirements: List[RequirementItem],
    compliance_mappings: List[ComplianceMapping],
    risks: List[RiskItem],
    raw_text_corpus: str,
    llm: PluggableLLMClient,
    project_summary: str,
) -> SDLCRecommendation:
    factors = extract_sdlc_factors(requirements, compliance_mappings, risks, raw_text_corpus)
    rankings, justification = rank_sdlc_models(factors, llm, project_summary)
    recommended = rankings[0].model
    workflow = generate_sdlc_workflow(recommended)
    return SDLCRecommendation(
        project_id=project_id,
        recommended_model=recommended,
        factors=factors,
        rankings=rankings,
        workflow=workflow,
        llm_justification=justification,
        approval_status=ApprovalStatus.PENDING_HUMAN_APPROVAL,
    )
