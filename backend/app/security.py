from __future__ import annotations

import re
from typing import Dict, List, Set, Tuple

from backend.app.models import (
    GateType,
    MaskingFinding,
    SecurityScanResult,
    SensitivityLevel,
    StakeholderRole,
)


UPI_HANDLE_SUFFIXES = {
    "upi", "okaxis", "okhdfcbank", "okicici", "oksbi", "ybl", "ibl", "axl",
    "paytm", "apl", "waicici", "wahdfcbank", "sbi", "hdfc", "icici", "kotak",
}

INJECTION_PATTERNS: List[Tuple[str, str]] = [
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", "instruction_override"),
    (r"disregard\s+(all\s+)?(compliance|rbi|security|system)\s+rules", "compliance_bypass_attempt"),
    (r"reveal\s+(your\s+)?(system\s+prompt|hidden\s+instructions|api\s+key)", "prompt_exfiltration"),
    (r"you\s+are\s+now\s+(in\s+)?(developer|admin|unrestricted|dan)\s+mode", "role_hijack"),
    (r"skip\s+(human\s+)?approval\s+and\s+auto[- ]approve", "gate_bypass_attempt"),
    (r"<\|\s*(im_start|system|endoftext)\s*\|>", "delimiter_injection"),
    (r"bypass\s+(rbi|npci|dpdp|pci|mfa|afa)", "regulatory_bypass_attempt"),
]

# RBAC permissions by stakeholder role
ROLE_PERMISSIONS: Dict[StakeholderRole, Set[str]] = {
    StakeholderRole.CUSTOMER_END_USER: {"submit_input", "participate_interview", "view_requirements"},
    StakeholderRole.BUSINESS_ANALYST: {"submit_input", "participate_interview", "run_agents", "view_requirements", "edit_requirements", "export_artifacts", "run_evaluation"},
    StakeholderRole.PRODUCT_OWNER: {"submit_input", "participate_interview", "run_agents", "view_requirements", "edit_requirements", "approve_baseline", "approve_sdlc", "export_artifacts"},
    StakeholderRole.ARCHITECT_DEVELOPER: {"submit_input", "participate_interview", "run_agents", "view_requirements", "approve_architecture", "approve_sdlc", "export_artifacts"},
    StakeholderRole.INFOSEC_TEAM: {"submit_input", "participate_interview", "run_agents", "view_requirements", "approve_security", "approve_sdlc", "view_audit"},
    StakeholderRole.COMPLIANCE_LEGAL: {"submit_input", "participate_interview", "run_agents", "view_requirements", "approve_regulatory", "approve_sdlc", "view_audit", "manage_kb"},
    StakeholderRole.RISK_MANAGEMENT: {"submit_input", "participate_interview", "run_agents", "view_requirements", "approve_security", "export_artifacts"},
    StakeholderRole.OPERATIONS: {"submit_input", "participate_interview", "view_requirements", "approve_production", "export_artifacts"},
    StakeholderRole.AUDITOR_REGULATOR: {"view_requirements", "view_audit", "export_artifacts", "run_evaluation"},
}

GATE_APPROVER_MAP: Dict[GateType, List[StakeholderRole]] = {
    GateType.FINAL_REQUIREMENT_BASELINE: [StakeholderRole.PRODUCT_OWNER, StakeholderRole.BUSINESS_ANALYST],
    GateType.REGULATORY_INTERPRETATION: [StakeholderRole.COMPLIANCE_LEGAL],
    GateType.HIGH_RISK_SECURITY: [StakeholderRole.INFOSEC_TEAM, StakeholderRole.RISK_MANAGEMENT],
    GateType.CONFLICTING_STAKEHOLDER_DECISION: [StakeholderRole.PRODUCT_OWNER, StakeholderRole.BUSINESS_ANALYST, StakeholderRole.COMPLIANCE_LEGAL],
    GateType.ARCHITECTURE_CRITICAL_REQUIREMENT: [StakeholderRole.ARCHITECT_DEVELOPER, StakeholderRole.INFOSEC_TEAM],
    GateType.SDLC_SELECTION: [StakeholderRole.PRODUCT_OWNER, StakeholderRole.ARCHITECT_DEVELOPER, StakeholderRole.INFOSEC_TEAM, StakeholderRole.COMPLIANCE_LEGAL],
    GateType.APPROVED_REQUIREMENT_CHANGE: [StakeholderRole.PRODUCT_OWNER, StakeholderRole.COMPLIANCE_LEGAL],
    GateType.PRODUCTION_READINESS: [StakeholderRole.OPERATIONS, StakeholderRole.INFOSEC_TEAM, StakeholderRole.COMPLIANCE_LEGAL],
}

# Least-privilege matrix per AI agent (Item 17)
AGENT_PERMISSIONS: Dict[str, Set[str]] = {
    "CoordinatorAgent": {"orchestrate", "read_project_state"},
    "StakeholderInteractionAgent": {"read_masked_inputs", "ask_questions", "read_interview_templates"},
    "RequirementExtractionAgent": {"read_masked_inputs", "write_requirements", "read_allowlisted_kb"},
    "ClarificationAgent": {"read_requirements", "flag_quality_issues", "generate_clarifications"},
    "ClassificationAgent": {"read_requirements", "label_categories"},
    "ConflictDetectionAgent": {"read_requirements", "write_conflicts"},
    "ComplianceAgent": {"read_requirements", "read_allowlisted_kb", "write_compliance_mappings"},
    "SecurityPrivacyAgent": {"read_requirements", "read_allowlisted_kb", "write_security_controls"},
    "RiskAnalysisAgent": {"read_requirements", "read_compliance_mappings", "write_risks"},
    "SDLCSelectionAgent": {"read_requirements", "read_risks", "read_allowlisted_kb", "write_sdlc"},
    "DocumentationAgent": {"read_requirements", "read_compliance_mappings", "read_risks", "read_sdlc", "write_artifacts"},
    "ValidationAgent": {"read_all_outputs", "verify_citations", "score_confidence"},
    "HumanApprovalAgent": {"read_validation_results", "create_approval_gates"},
}


def _luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    rev = digits[::-1]
    for idx, ch in enumerate(rev):
        val = int(ch)
        if idx % 2 == 1:
            val *= 2
            if val > 9:
                val -= 9
        total += val
    return total % 10 == 0


def scan_and_mask_input(text: str) -> SecurityScanResult:
    """
    Detects sensitive Indian financial/PII/PCI entities and prompt-injection payloads
    prior to passing any content to an LLM or agent pipeline.
    """
    masked = text
    findings_counter: Dict[str, Tuple[str, str, int]] = {}

    def _replace(pattern: str, entity_type: str, flags: int = 0, validator=None) -> None:
        nonlocal masked
        seq = 0

        def _sub(match: re.Match[str]) -> str:
            nonlocal seq
            raw = match.group(0)
            if validator and not validator(raw):
                return raw
            seq += 1
            token = f"<MASKED_{entity_type}_{seq}>"
            preview = raw[:2] + "***" + raw[-2:] if len(raw) > 5 else "***"
            prev = findings_counter.get(entity_type)
            findings_counter[entity_type] = (token, preview, (prev[2] + 1) if prev else 1)
            return token

        masked = re.sub(pattern, _sub, masked, flags=flags)

    # 1. Secrets / API Keys / Bearer Tokens
    _replace(r"(?i)(?:sk-[a-z0-9]{16,}|AIza[0-9A-Za-z\-_]{20,}|Bearer\s+[A-Za-z0-9\-._~+/]+=*)", "SECRET")
    # 2. CVV / PIN literals
    _replace(r"(?i)\b(?:cvv|cvc|mpin|atm\s*pin)\s*(?:is|=|:)?\s*\d{3,6}\b", "CVV_PIN")
    # 3. Card PAN (13-19 digits, optionally hyphen/space separated, Luhn validated)
    _replace(
        r"\b(?:\d[ -]?){13,19}\b",
        "CARD_PAN",
        validator=lambda s: _luhn_valid(re.sub(r"[\s-]", "", s)),
    )
    # 4. Indian PAN card (ABCDE1234F)
    _replace(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", "INDIAN_PAN")
    # 5. Aadhaar (12 digits starting 2-9)
    _replace(r"\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b", "AADHAAR")
    # 6. Bank Account Numbers in explicit context
    _replace(r"(?i)\b(?:account|acct|a/c)\s*(?:no\.?|number|#|:)?\s*\d{9,18}\b", "BANK_ACCT")
    # 7. IFSC codes
    _replace(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", "IFSC")
    # 8. UPI VPAs vs Emails
    def _is_upi(val: str) -> bool:
        handle = val.split("@")[-1].lower()
        return handle in UPI_HANDLE_SUFFIXES

    _replace(r"\b[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,20}\b", "UPI_VPA", validator=_is_upi)
    _replace(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", "EMAIL")
    # 9. Indian mobile numbers
    _replace(r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)", "PHONE")

    findings = [
        MaskingFinding(entity_type=etype, token=tok, preview_masked=prev, count=cnt)
        for etype, (tok, prev, cnt) in findings_counter.items()
    ]

    # Prompt injection check
    signals: List[str] = []
    for pat, label in INJECTION_PATTERNS:
        if re.search(pat, text, flags=re.IGNORECASE):
            signals.append(label)

    # Neutralize injection directives inside masked text so untrusted input never acts as system instructions
    if signals:
        for pat, _ in INJECTION_PATTERNS:
            masked = re.sub(pat, "[REDACTED_UNTRUSTED_DIRECTIVE]", masked, flags=re.IGNORECASE)

    if any(f.entity_type in {"CARD_PAN", "CVV_PIN", "AADHAAR", "INDIAN_PAN", "BANK_ACCT", "SECRET"} for f in findings):
        sensitivity = SensitivityLevel.RESTRICTED_PII_PCI
    elif findings:
        sensitivity = SensitivityLevel.CONFIDENTIAL
    elif any(k in text.lower() for k in ["fraud", "rule", "threshold", "internal", "switch", "settlement"]):
        sensitivity = SensitivityLevel.INTERNAL
    else:
        sensitivity = SensitivityLevel.PUBLIC

    blocked = len(signals) >= 2 or "delimiter_injection" in signals or "prompt_exfiltration" in signals
    block_reason = (
        f"Blocked high-risk prompt-injection signals: {', '.join(signals)}" if blocked else None
    )

    return SecurityScanResult(
        sensitivity_level=sensitivity,
        masked_text=masked,
        findings=findings,
        injection_detected=bool(signals),
        injection_signals=signals,
        blocked=blocked,
        block_reason=block_reason,
    )


def filter_llm_output(text: str) -> str:
    """Output guard ensuring raw secrets or unmasked Aadhaar/PAN/Card strings do not leak."""
    res = scan_and_mask_input(text)
    return res.masked_text


def check_rbac(role: StakeholderRole, permission: str, mfa_verified: bool = True) -> Tuple[bool, str]:
    if not mfa_verified:
        return False, "MFA verification required for this operation."
    allowed = ROLE_PERMISSIONS.get(role, set())
    if permission not in allowed:
        return False, f"Role '{role.value}' lacks permission '{permission}'."
    return True, "OK"


def check_agent_permission(agent_name: str, capability: str) -> bool:
    return capability in AGENT_PERMISSIONS.get(agent_name, set())
