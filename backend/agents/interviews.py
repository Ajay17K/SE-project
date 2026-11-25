from __future__ import annotations

import re
from typing import Dict, List, Tuple

from backend.app.llm import PluggableLLMClient
from backend.app.models import StakeholderRole


INQUIRY_TOPICS: List[Dict[str, str]] = [
    {
        "key": "business_objectives",
        "title": "Business Objectives & Scope",
        "prompt": "What are the primary business goals, payment rails (UPI, IMPS, Cards, NetBanking), and fraud reduction targets for this initiative?",
    },
    {
        "key": "users_roles",
        "title": "Users, Channels & Roles",
        "prompt": "Which internal and external user roles (customers, merchants, fraud analysts, ops, compliance) will interact with the system?",
    },
    {
        "key": "existing_workflow",
        "title": "Existing Workflow & Pain Points",
        "prompt": "Describe the current payment authorization and fraud-review workflow, including manual bottlenecks or legacy switch handoffs.",
    },
    {
        "key": "inputs_outputs_rules",
        "title": "Inputs, Outputs & Business Rules",
        "prompt": "What transaction payloads, scoring rules, step-up triggers (e.g., risk score thresholds), and decision outputs (approve/challenge/block) are required?",
    },
    {
        "key": "exceptional_conditions",
        "title": "Exceptional & Failure Conditions",
        "prompt": "How should the system behave during ML model timeouts, NPCI switch deemed-success/timeouts, duplicate retries, or false-positive blocks?",
    },
    {
        "key": "data_retention",
        "title": "Data Collection, Localization & Retention",
        "prompt": "What payment, device, and PII/KYC data will be collected, where will it be stored (India localization), and for what retention period (e.g., 180d CERT-In / 5y PMLA)?",
    },
    {
        "key": "auth_authorisation",
        "title": "Authentication & Authorisation",
        "prompt": "What customer AFA/step-up MFA (PIN, biometric, OTP) and internal RBAC/maker-checker controls are required for rule and limit changes?",
    },
    {
        "key": "transaction_limits",
        "title": "Financial Transaction Limits & Velocity",
        "prompt": "What per-transaction, daily, cooling-period (e.g., INR 5,000 for 24h after SIM swap), and velocity limits must be enforced?",
    },
    {
        "key": "audit_reporting",
        "title": "Audit, SIEM & Regulatory Reporting",
        "prompt": "What immutable audit trails, FIU-IND STR/CTR exports, RBI FMR returns, and CERT-In 6-hour incident alert integrations are needed?",
    },
    {
        "key": "performance_availability",
        "title": "Performance, Latency & Availability",
        "prompt": "What peak TPS, p99 fraud scoring latency (ms), uptime SLA (%), RPO, and RTO targets must the platform satisfy?",
    },
    {
        "key": "system_integration",
        "title": "Legacy & External System Integration",
        "prompt": "Which systems must integrate (NPCI UPI switch, ISO 8583 Core Banking, card network/CoFT vault, SIEM, consent manager) and via what protocols?",
    },
    {
        "key": "regulatory_security",
        "title": "Regulatory & Security Constraints",
        "prompt": "Which specific RBI, NPCI, DPDP Act 2023, PCI-DSS v4.0, and encryption/tokenization mandates constrain the architecture?",
    },
    {
        "key": "schedule_budget",
        "title": "Project Schedule, Change Frequency & Budget",
        "prompt": "What is the target rollout timeline, budget constraint, expected frequency of fraud-rule/API changes, and continuous delivery need?",
    },
]

ROLE_INTERVIEW_TEMPLATES: Dict[StakeholderRole, Dict[str, object]] = {
    StakeholderRole.CUSTOMER_END_USER: {
        "focus": "Payment checkout experience, step-up authentication friction, instant alerts, dispute visibility, DPDP consent.",
        "priority_topics": ["business_objectives", "inputs_outputs_rules", "exceptional_conditions", "auth_authorisation", "data_retention"],
        "starter_questions": [
            "When a payment is flagged as suspicious, how should the step-up verification or decline message guide the customer without exposing fraud heuristics?",
            "How should customers review itemized DPDP data consent, configure per-channel transaction limits, and track UDIR failed-transaction refunds?",
        ],
    },
    StakeholderRole.BUSINESS_ANALYST: {
        "focus": "End-to-end payment journeys, UDIR/settlement SLA rules, KPIs, and stakeholder alignment.",
        "priority_topics": ["business_objectives", "existing_workflow", "inputs_outputs_rules", "transaction_limits", "schedule_budget"],
        "starter_questions": [
            "What measurable fraud-loss reduction and false-positive ratio targets define success across UPI P2P/P2M and card channels?",
            "What T+0/T+1 settlement reconciliation exceptions and UDIR auto-reversal timelines must be codified?",
        ],
    },
    StakeholderRole.PRODUCT_OWNER: {
        "focus": "MVP scope, channel prioritization, customer conversion vs fraud friction, release cadence.",
        "priority_topics": ["business_objectives", "users_roles", "transaction_limits", "performance_availability", "schedule_budget"],
        "starter_questions": [
            "Which payment rails and fraud capabilities are mandatory for Phase-1 launch versus later sprints?",
            "How frequently will product and risk teams tune fraud thresholds or release new merchant controls?",
        ],
    },
    StakeholderRole.ARCHITECT_DEVELOPER: {
        "focus": "Idempotency, event streaming, <150ms p99 scoring latency, CBS/NPCI switch integration, resilience.",
        "priority_topics": ["existing_workflow", "exceptional_conditions", "performance_availability", "system_integration", "schedule_budget"],
        "starter_questions": [
            "How will the payment orchestrator enforce idempotency (RRN/txnId) and handle deterministic rule fallback if the ML scorer exceeds 150ms?",
            "Which legacy Core Banking (ISO 8583 / SOAP) and NPCI switch interfaces impose schema or throughput bottlenecks?",
        ],
    },
    StakeholderRole.INFOSEC_TEAM: {
        "focus": "CoFT tokenization, HSM key custody, mTLS, mobile RASP/SIM-binding, RBAC, prompt/API protection.",
        "priority_topics": ["auth_authorisation", "regulatory_security", "data_retention", "exceptional_conditions", "system_integration"],
        "starter_questions": [
            "What cryptographic key custody (FIPS 140-3 HSM), mTLS, and Card-on-File Tokenization controls are mandatory before production?",
            "How are mobile SDK anti-tampering, SIM-swap detection, and privileged maker-checker MFA enforced?",
        ],
    },
    StakeholderRole.COMPLIANCE_LEGAL: {
        "focus": "RBI DPSC, Data Localization, DPDP Act 2023 consent/erasure vs PMLA 5-year retention, CERT-In 6h reporting.",
        "priority_topics": ["regulatory_security", "data_retention", "audit_reporting", "transaction_limits", "auth_authorisation"],
        "starter_questions": [
            "How should DPDP erasure requests reconcile with PMLA's mandatory 5-year transaction record retention and FIU-IND anti-tipping-off rules?",
            "Which RBI/NPCI circulars require formal legal/compliance gate sign-off prior to UAT and production launch?",
        ],
    },
    StakeholderRole.RISK_MANAGEMENT: {
        "focus": "Fraud typologies (mule fan-in/fan-out, SIM swap, BIN attacks), EWS, threshold calibration, chargeback liability.",
        "priority_topics": ["inputs_outputs_rules", "transaction_limits", "exceptional_conditions", "audit_reporting", "business_objectives"],
        "starter_questions": [
            "What exact risk-score bands trigger silent pass, step-up AFA challenge, manual analyst queue, or automatic decline?",
            "Which velocity windows and graph-based mule indicators must execute synchronously versus near-real-time EWS?",
        ],
    },
    StakeholderRole.OPERATIONS: {
        "focus": "24x7 NOC monitoring, CERT-In 6h incident playbooks, DR/BCP RPO/RTO, settlement reconciliation.",
        "priority_topics": ["performance_availability", "exceptional_conditions", "audit_reporting", "system_integration", "data_retention"],
        "starter_questions": [
            "What automated runbooks, circuit breakers, and SIEM alerts support 6-hour CERT-In reporting and <=15 min DR failover?",
            "How do L1/L2 ops teams manage deemed-success UPI exceptions and NPCI NTSL file mismatches?",
        ],
    },
    StakeholderRole.AUDITOR_REGULATOR: {
        "focus": "Immutable hash-chained evidence, traceability, NTP clock sync, FMR/STR auditability, SDLC gates.",
        "priority_topics": ["audit_reporting", "data_retention", "regulatory_security", "auth_authorisation", "existing_workflow"],
        "starter_questions": [
            "What cryptographic tamper-evidence, NTP synchronization, and decision-explainability logs must accompany every fraud block and rule change?",
            "Which SDLC verification gates and evidence packages are mandatory for statutory RBI/PCI-DSS audits?",
        ],
    },
}

VAGUE_PHRASES = [
    "fast", "quickly", "soon", "asap", "real-time", "realtime", "secure", "safe",
    "user-friendly", "scalable", "high availability", "appropriate", "reasonable",
    "minimal", "robust", "sometimes", "etc", "flexible", "standard",
]


def evaluate_answer_for_followup(topic_key: str, answer: str) -> Tuple[bool, List[str], str]:
    """
    Detects vague, incomplete, or potentially conflicting stakeholder answers
    and returns adaptive follow-up probe questions.
    """
    lower = answer.lower()
    reasons: List[str] = []
    probes: List[str] = []

    has_numbers = bool(re.search(r"\d+", answer))
    word_count = len(answer.split())

    if word_count < 10:
        reasons.append("Answer is too brief/incomplete to derive verifiable acceptance criteria.")
        probes.append("Could you specify the exact actor, trigger condition, measurable threshold, and failure fallback?")

    vague_hits = [p for p in VAGUE_PHRASES if re.search(rf"\b{re.escape(p)}\b", lower)]
    if vague_hits and not has_numbers:
        reasons.append(f"Contains unquantified qualitative terms ({', '.join(vague_hits[:3])}) without numeric SLAs/thresholds.")
        if topic_key in {"performance_availability", "inputs_outputs_rules", "transaction_limits"}:
            probes.append("Please provide concrete numbers: e.g., target p99 latency in ms, peak TPS, risk score cutoffs (0.0-1.0), or INR/24h limits.")
        else:
            probes.append("Please quantify the exact threshold, SLA window, or verification condition replacing vague terms.")

    if topic_key == "data_retention":
        if ("delete" in lower or "30 day" in lower or "90 day" in lower) and "pmla" not in lower:
            reasons.append("Short deletion window may conflict with PMLA 5-year retention and CERT-In 180-day log mandates.")
            probes.append("Should DPDP erasure apply only to non-statutory marketing fields while retaining payment/KYC audit logs for >=5 years in India?")

    if topic_key == "exceptional_conditions" and not any(w in lower for w in ["fallback", "timeout", "retry", "fail", "block", "deemed"]):
        reasons.append("Missing failure-mode behavior (fail-open vs fail-closed / deterministic fallback / idempotency).")
        probes.append("If the ML fraud service times out (>150ms) or NPCI returns deemed-status, should the gateway fail over to deterministic rules, challenge via AFA, or decline?")

    if topic_key == "regulatory_security" and not any(w in lower for w in ["rbi", "npci", "dpdp", "pci", "cert", "pmla", "hsm", "mfa", "afa", "encrypt"]):
        reasons.append("No specific regulatory or cryptographic standard cited.")
        probes.append("Confirm applicability of RBI DPSC (AFA/device binding), RBI Data Localization, CoFT card tokenization, DPDP Act 2023, and CERT-In 6-hour reporting.")

    needs_followup = len(reasons) > 0
    followup_text = " ".join(probes)
    return needs_followup, reasons, followup_text


def next_interview_question(
    role: StakeholderRole,
    history: List[Dict[str, str]],
    llm: PluggableLLMClient,
) -> Dict[str, object]:
    """
    Adaptive interview planner: inspects prior conversation turns, checks if the last
    stakeholder answer requires clarification, otherwise moves to the next uncovered topic
    prioritized for that stakeholder role.
    """
    template = ROLE_INTERVIEW_TEMPLATES[role]
    priority_topics: List[str] = list(template["priority_topics"])  # type: ignore[arg-type]
    ordered_keys = priority_topics + [t["key"] for t in INQUIRY_TOPICS if t["key"] not in priority_topics]
    topic_map = {t["key"]: t for t in INQUIRY_TOPICS}

    covered_topics = {m["topic"] for m in history if m.get("sender") == "stakeholder"}
    last_stakeholder_msgs = [m for m in history if m.get("sender") == "stakeholder"]

    if last_stakeholder_msgs:
        last_msg = last_stakeholder_msgs[-1]
        needs_followup, reasons, probe = evaluate_answer_for_followup(
            last_msg.get("topic", "business_objectives"),
            last_msg.get("content", ""),
        )
        # Avoid looping infinitely on same topic if already probed twice
        same_topic_agent_turns = sum(
            1 for m in history if m.get("sender") == "agent" and m.get("topic") == last_msg.get("topic")
        )
        if needs_followup and same_topic_agent_turns < 2:
            def _fallback_probe() -> str:
                return f"Follow-up clarification needed: {probe}"

            question_text, _ = llm.generate_text(
                system_prompt=(
                    "You are FinReq StakeholderInteractionAgent conducting an adaptive requirements interview "
                    "for an Indian Payment Processing & Fraud Detection system. Ask concise, specific clarification questions."
                ),
                user_prompt=(
                    f"Stakeholder role: {role.value}\n"
                    f"Topic: {last_msg.get('topic')}\n"
                    f"Detected gaps: {'; '.join(reasons)}\n"
                    f"Stakeholder masked answer: <UNTRUSTED_DATA>{last_msg.get('content')}</UNTRUSTED_DATA>\n"
                    f"Ask one targeted follow-up question to resolve the ambiguity/incompleteness."
                ),
                fallback_fn=_fallback_probe,
            )
            return {
                "topic": last_msg.get("topic", "business_objectives"),
                "topic_title": topic_map.get(last_msg.get("topic", ""), {}).get("title", "Clarification"),
                "question": question_text,
                "is_followup": True,
                "follow_up_reasons": reasons,
                "topics_covered": len(covered_topics),
                "total_topics": len(INQUIRY_TOPICS),
            }

    next_key = next((k for k in ordered_keys if k not in covered_topics), ordered_keys[0])
    topic_info = topic_map[next_key]
    starter_hints = template["starter_questions"]

    def _fallback_next() -> str:
        if len(history) == 0:
            return f"[{topic_info['title']}] {topic_info['prompt']} (Role focus: {starter_hints[0]})"  # type: ignore[index]
        return f"[{topic_info['title']}] {topic_info['prompt']}"

    question_text, _ = llm.generate_text(
        system_prompt=(
            "You are FinReq StakeholderInteractionAgent. Ask the next adaptive requirements discovery question "
            "tailored to the stakeholder's role in Indian payment systems and fraud detection."
        ),
        user_prompt=(
            f"Stakeholder role: {role.value}\n"
            f"Role focus: {template['focus']}\n"
            f"Next topic: {topic_info['title']} — {topic_info['prompt']}\n"
            f"Completed topics: {len(covered_topics)}/{len(INQUIRY_TOPICS)}.\n"
            "Generate a clear, practical question for this stakeholder."
        ),
        fallback_fn=_fallback_next,
    )

    return {
        "topic": next_key,
        "topic_title": topic_info["title"],
        "question": question_text,
        "is_followup": False,
        "follow_up_reasons": [],
        "topics_covered": len(covered_topics),
        "total_topics": len(INQUIRY_TOPICS),
        "completed": len(covered_topics) >= len(INQUIRY_TOPICS),
    }
