from __future__ import annotations

from typing import Any, Dict, List

from backend.app.models import (
    ComplianceMapping,
    ConflictRecord,
    ProjectSummary,
    RequirementItem,
    RiskItem,
    SDLCRecommendation,
    StakeholderInputRecord,
)


def generate_all_artifacts(
    project: ProjectSummary,
    inputs: List[StakeholderInputRecord],
    requirements: List[RequirementItem],
    conflicts: List[ConflictRecord],
    compliance_mappings: List[ComplianceMapping],
    risks: List[RiskItem],
    sdlc: SDLCRecommendation,
) -> Dict[str, Dict[str, Any]]:
    """Generates all 11 traceable requirement engineering & governance deliverables (Item 12)."""
    artifacts: Dict[str, Dict[str, Any]] = {}

    # 1. Software Requirements Specification (SRS)
    srs_lines = [
        f"# Software Requirements Specification (SRS): {project.name}",
        f"- **Domain:** {project.domain}",
        f"- **Jurisdiction:** {project.jurisdiction}",
        f"- **Recommended SDLC:** {sdlc.recommended_model.value} ({sdlc.rankings[0].score_pct}%)",
        "",
        "## 1. Functional & Non-Functional Requirements",
        "",
    ]
    for r in requirements:
        cats = ", ".join(c.value for c in r.categories)
        cits = ", ".join(c.kb_id for c in r.citations if c.verified) or "None"
        srs_lines.extend(
            [
                f"### {r.req_id}: {r.title}",
                f"- **Statement:** {r.statement}",
                f"- **Categories:** {cats}",
                f"- **Source Stakeholder:** `{r.source_stakeholder.value}` (Artifact `{r.source_artifact_id}`)",
                f"- **Source Quote:** \"{r.source_quote}\"",
                f"- **Business Justification:** {r.business_justification}",
                f"- **Priority:** {r.priority} | **Risk:** {r.risk_level} | **Confidence:** {r.confidence_score:.2f} | **Status:** `{r.approval_status.value}`",
                f"- **Applicable Regulations / KB:** {cits}",
                f"- **Acceptance Criteria:**",
                *[f"  - {ac}" for ac in r.acceptance_criteria],
                "",
            ]
        )
    artifacts["srs"] = {
        "title": "Software Requirements Specification (SRS)",
        "content_md": "\n".join(srs_lines),
        "structured": [r.model_dump() for r in requirements],
    }

    # 2. User Stories & Acceptance Criteria
    us_lines = [f"# User Stories & Gherkin Acceptance Criteria — {project.name}", ""]
    stories_json = []
    for idx, r in enumerate(requirements, start=1):
        role_label = r.source_stakeholder.value.replace("_", " ").title()
        story = {
            "story_id": f"US-{idx:03d}",
            "req_id": r.req_id,
            "as_a": role_label,
            "i_want": r.title,
            "so_that": r.business_justification,
            "acceptance_criteria": r.acceptance_criteria,
        }
        stories_json.append(story)
        us_lines.extend(
            [
                f"### {story['story_id']} (linked to `{r.req_id}`)",
                f"**As a** {role_label}, **I want** {r.statement.rstrip('.')}, **so that** {r.business_justification}",
                "**Acceptance Criteria:**",
                *[f"- {ac}" for ac in r.acceptance_criteria],
                "",
            ]
        )
    artifacts["user_stories"] = {
        "title": "User Stories & Acceptance Criteria",
        "content_md": "\n".join(us_lines),
        "structured": stories_json,
    }

    # 3. Use-Case Descriptions
    uc_lines = [f"# Use-Case Descriptions — {project.name}", ""]
    use_cases = [
        {
            "uc_id": "UC-PAY-001",
            "name": "Authorize Payment with Real-Time Fraud Scoring & Step-Up AFA",
            "primary_actor": "Customer / Payer PSP",
            "preconditions": ["Customer is SIM/device-bound", "DPDP consent recorded"],
            "main_flow": [
                "1. Payer submits payment instruction with unique idempotency key and RRN.",
                "2. Gateway masks PII/PAN in logs and evaluates deterministic velocity/cooling limits.",
                "3. Fraud ML + Graph engine computes risk score within <=150ms p99.",
                "4. Low risk (<0.65) proceeds; Medium-High (0.65-0.84) triggers dynamic Step-Up AFA; Critical (>=0.85) blocks & flags EWS.",
            ],
            "exception_flows": [
                "E1: ML scorer >150ms -> circuit breaker invokes deterministic rule fallback.",
                "E2: NPCI timeout / deemed status -> routed to UDIR reconciliation queue.",
            ],
            "postconditions": ["Immutable hash-chained audit record saved in India for >=5 years."],
        },
        {
            "uc_id": "UC-FRD-002",
            "name": "Mule Network Detection, Analyst Escalation & FIU-IND STR Filing",
            "primary_actor": "Fraud Analyst / Compliance Officer",
            "preconditions": ["EWS alerts aggregated from UPI/IMPS/Card switches"],
            "main_flow": [
                "1. Graph engine flags rapid fan-in/fan-out VPA cluster.",
                "2. Case opens in Fraud Ops Queue with masked telemetry and linked RBAC permissions.",
                "3. Compliance Officer reviews evidence and approves STR filing to FIU-IND within 7 days.",
            ],
            "exception_flows": ["E1: Anti-tipping-off guard hides STR status from customer-facing APIs."],
            "postconditions": ["STR & FMR audit dossier archived under PMLA rules."],
        },
    ]
    for uc in use_cases:
        uc_lines.extend(
            [
                f"## {uc['uc_id']}: {uc['name']}",
                f"- **Primary Actor:** {uc['primary_actor']}",
                f"- **Preconditions:** {', '.join(uc['preconditions'])}",
                "- **Main Flow:**",
                *[f"  - {s}" for s in uc["main_flow"]],
                "- **Exception Flows:**",
                *[f"  - {e}" for e in uc["exception_flows"]],
                f"- **Postconditions:** {', '.join(uc['postconditions'])}",
                "",
            ]
        )
    artifacts["use_cases"] = {
        "title": "Use-Case Descriptions",
        "content_md": "\n".join(uc_lines),
        "structured": use_cases,
    }

    # 4. Process Workflows
    wf_md = "\n".join(
        [
            f"# Payment & Fraud Process Workflows — {project.name}",
            "",
            "```mermaid",
            "flowchart LR",
            "    A[Payment Request + Idempotency Key] --> B[PII/PCI Masking & Limit Checks]",
            "    B --> C{Fraud Scoring <=150ms p99}",
            "    C -->|Score < 0.65| D[Standard AFA & NPCI/Card Switch]",
            "    C -->|0.65 - 0.84| E[Dynamic Step-Up MFA/AFA Challenge]",
            "    C -->|>= 0.85| F[Auto-Block + EWS + STR Queue]",
            "    C -->|Timeout| G[Deterministic Rule Fallback]",
            "    D --> H[T+0/T+1 Recon & UDIR]",
            "    E --> D",
            "```",
            "",
            "## Customized SDLC Workflow Summary",
            *[f"- **{p.phase_name}:** {p.objective}" for p in sdlc.workflow],
        ]
    )
    artifacts["process_workflows"] = {
        "title": "Process Workflows",
        "content_md": wf_md,
        "structured": {"phases": [p.model_dump() for p in sdlc.workflow]},
    }

    # 5. Data Requirements
    data_reqs = [r for r in requirements if any(k in r.statement.lower() for k in ["retain", "retention", "store", "delete", "dpdp", "consent", "180", "5 year", "india"])]
    data_lines = [
        f"# Data & Retention Requirements — {project.name}",
        "",
        "- **Data Residency:** 100% India localization for payment transactions, KYC, and fraud telemetry (`KB-RBI-LOCAL-01`).",
        "- **Rolling Security Logs:** 180 days hot/warm SIEM logs in India with NTP sync (`KB-CERTIN-01`).",
        "- **Statutory Financial Retention:** >=5 years transaction & KYC audit archive (`KB-PMLA-01`).",
        "- **Card Security:** CoFT tokens only; zero CVV persistence; masked PAN (`KB-PCIDSS-01`).",
        "",
        "## Mapped Data Requirements",
        *[f"- **{r.req_id}**: {r.statement}" for r in data_reqs],
    ]
    artifacts["data_requirements"] = {
        "title": "Data Requirements",
        "content_md": "\n".join(data_lines),
        "structured": [r.model_dump() for r in data_reqs],
    }

    # 6. Interface Requirements
    int_reqs = [r for r in requirements if any(k in r.statement.lower() for k in ["api", "switch", "npci", "cbs", "iso 8583", "webhook", "siem", "rrn"])]
    int_lines = [
        f"# External & Legacy Interface Requirements — {project.name}",
        "",
        "| Interface | Protocol / Standard | SLA / Security Control |",
        "|---|---|---|",
        "| NPCI UPI Switch | XML/JSON over mTLS + ReqPay/RespPay | 30s end-to-end SLA; idempotent RRN & UDIR webhooks |",
        "| Core Banking System (CBS) | ISO 8583 / REST Adapter | Connection pool isolation + circuit breaker |",
        "| Card Network / CoFT Vault | REST + FIPS 140-3 HSM | Tokenized PAN only; zero CVV storage |",
        "| SIEM / CERT-In Gateway | Syslog/OTLP + NTP sync | 6-hour cyber incident alert escalation |",
        "",
        "## Mapped Interface Requirements",
        *[f"- **{r.req_id}**: {r.statement}" for r in int_reqs],
    ]
    artifacts["interface_requirements"] = {
        "title": "Interface Requirements",
        "content_md": "\n".join(int_lines),
        "structured": [r.model_dump() for r in int_reqs],
    }

    # 7. Threat and Risk Register
    risk_lines = [
        f"# Threat & Risk Register — {project.name}",
        "",
        "| Risk ID | Category | Linked Req | Inherent (LxI) | Residual | Owner | Mitigation |",
        "|---|---|---|---|---|---|---|",
        *[
            f"| {rk.risk_id} | {rk.category} | {rk.req_id} | {rk.inherent_score} ({rk.likelihood}x{rk.impact}) | {rk.residual_score} | `{rk.owner_role.value}` | {'; '.join(rk.mitigation_controls)} |"
            for rk in risks
        ],
    ]
    artifacts["risk_register"] = {
        "title": "Threat & Risk Register",
        "content_md": "\n".join(risk_lines),
        "structured": [rk.model_dump() for rk in risks],
    }

    # 8. Compliance-Control Matrix
    comp_lines = [
        f"# Regulatory Compliance-Control Matrix — {project.name}",
        "",
        "> **Governance Note:** Automated compliance mappings are advisory only; high-impact regulatory determinations require Compliance/Legal Officer approval.",
        "",
        "| Mapping ID | Req ID | Jurisdiction | KB Citation | Required Control | Gap Status | Legal Review |",
        "|---|---|---|---|---|---|---|",
        *[
            f"| {m.mapping_id} | {m.req_id} | {m.jurisdiction} | `{m.kb_id}` | {m.required_control} | {m.compliance_gap} | {'Mandatory' if m.legal_review_required else 'Optional'} |"
            for m in compliance_mappings
        ],
    ]
    artifacts["compliance_matrix"] = {
        "title": "Compliance-Control Matrix",
        "content_md": "\n".join(comp_lines),
        "structured": [m.model_dump() for m in compliance_mappings],
    }

    # 9. Requirements Traceability Matrix (RTM)
    rtm_rows = []
    comp_by_req: Dict[str, List[str]] = {}
    for m in compliance_mappings:
        comp_by_req.setdefault(m.req_id, []).append(m.kb_id)
    risk_by_req: Dict[str, List[str]] = {}
    for rk in risks:
        for rid in [x.strip() for x in rk.req_id.split(",")]:
            risk_by_req.setdefault(rid, []).append(rk.risk_id)

    rtm_lines = [
        f"# Requirements Traceability Matrix (RTM) — {project.name}",
        "",
        "| Req ID | Stakeholder | Source Artifact | Categories | KB / Regulations | Linked Risks | Approval Status |",
        "|---|---|---|---|---|---|---|",
    ]
    for r in requirements:
        row = {
            "req_id": r.req_id,
            "stakeholder": r.source_stakeholder.value,
            "source_artifact": r.source_artifact_id,
            "source_quote": r.source_quote,
            "categories": [c.value for c in r.categories],
            "regulations": comp_by_req.get(r.req_id, r.applicable_regulations),
            "risks": risk_by_req.get(r.req_id, []),
            "acceptance_tests": len(r.acceptance_criteria),
            "approval_status": r.approval_status.value,
        }
        rtm_rows.append(row)
        rtm_lines.append(
            f"| {row['req_id']} | `{row['stakeholder']}` | `{row['source_artifact']}` | {', '.join(row['categories'][:3])} | {', '.join(row['regulations']) or '-'} | {', '.join(row['risks']) or '-'} | `{row['approval_status']}` |"
        )
    artifacts["rtm"] = {
        "title": "Requirements Traceability Matrix (RTM)",
        "content_md": "\n".join(rtm_lines),
        "structured": rtm_rows,
    }

    # 10. Assumptions & Dependency Register
    assumptions_lines = [
        f"# Assumptions & Dependency Register — {project.name}",
        "",
        "## Key Architectural & Regulatory Assumptions",
        "- NPCI UPI switch Sandbox/UAT access and bank sponsor BIN/PSP sponsorship are provisioned prior to Phase 4.",
        "- All payment/fraud data stores reside in RBI-compliant Indian cloud regions.",
        "- HSM appliances (FIPS 140-3) are available for Card-on-File Tokenization and mTLS key custody.",
        "",
        "## Input Source Traceability",
        *[f"- `{i.input_id}` ({i.source_type.value}, `{i.stakeholder_role.value}`, Sensitivity: `{i.sensitivity_level.value}`)" for i in inputs],
    ]
    artifacts["assumptions_dependencies"] = {
        "title": "Assumptions & Dependency Register",
        "content_md": "\n".join(assumptions_lines),
        "structured": {"inputs": [i.input_id for i in inputs]},
    }

    # 11. Open-Issues List
    open_issues: List[Dict[str, Any]] = []
    for r in requirements:
        for q in r.quality_issues:
            open_issues.append(
                {
                    "ref_id": r.req_id,
                    "type": q.issue_type.value,
                    "severity": q.severity,
                    "description": q.description,
                    "action": q.suggested_clarification,
                }
            )
    for c in conflicts:
        open_issues.append(
            {
                "ref_id": c.conflict_id,
                "type": c.conflict_type,
                "severity": c.severity,
                "description": c.description,
                "action": c.recommendation,
            }
        )
    oi_lines = [
        f"# Open-Issues & Clarification Register — {project.name}",
        "",
        "| Reference | Type | Severity | Issue | Recommended Resolution |",
        "|---|---|---|---|---|",
        *[
            f"| {oi['ref_id']} | {oi['type']} | {oi['severity']} | {oi['description']} | {oi['action']} |"
            for oi in open_issues
        ],
    ]
    artifacts["open_issues"] = {
        "title": "Open-Issues List",
        "content_md": "\n".join(oi_lines),
        "structured": open_issues,
    }

    return artifacts
