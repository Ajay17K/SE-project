from __future__ import annotations

from backend.agents.pipeline import MultiAgentOrchestrator
from backend.app.db import Database
from backend.app.models import (
    InputSourceType,
    StakeholderInputRecord,
    StakeholderRole,
)
from backend.app.security import scan_and_mask_input
from backend.knowledge_base.kb_data import INITIAL_KNOWLEDGE_BASE


def seed_demo_data(db: Database, orchestrator: MultiAgentOrchestrator) -> None:
    """Seeds KB and two realistic Indian Payment & Fraud demo projects if DB is fresh."""
    db.seed_knowledge_base(INITIAL_KNOWLEDGE_BASE)
    if db.list_projects():
        return

    # Project 1: UPI Real-Time Payment Processing & Fraud Detection Platform
    p1 = "proj-upi-fraud-india"
    db.upsert_project(
        project_id=p1,
        name="UPI Real-Time Payment & Mule Fraud Detection Engine",
        domain="Payment Processing & Fraud Detection",
        jurisdiction="India (RBI, NPCI/UPI, DPDP 2023, PMLA, CERT-In)",
        description=(
            "Enterprise real-time UPI payment orchestration and AI/rule-based fraud scoring platform "
            "handling 5,000 TPS peak, step-up AFA, mule graph detection, UDIR disputes, and Indian regulatory compliance."
        ),
        advisory_mode=True,
    )

    p1_inputs = [
        (
            "INP-UPI-01",
            StakeholderRole.RISK_MANAGEMENT,
            InputSourceType.STAKEHOLDER_CONVERSATION,
            "Fraud Scoring & Step-Up MFA Rules",
            (
                "The system shall score every UPI P2P and P2M payment within <=120ms at p99 across 5,000 TPS peak. "
                "Transactions with risk score between 0.65 and 0.84 shall trigger dynamic step-up AFA authentication, "
                "while scores >= 0.85 shall be automatically blocked and escalated to EWS and SCBMF review. "
                "Sample test customer rahul.verma@okicici (PAN ABCDE1234F, phone +91 9876543210) triggered mule fan-in alerts."
            ),
        ),
        (
            "INP-UPI-02",
            StakeholderRole.COMPLIANCE_LEGAL,
            InputSourceType.REGULATORY_CIRCULAR,
            "RBI, NPCI & PMLA Mandates",
            (
                "Enforce NPCI INR 1,00,000 daily UPI cap (INR 5,00,000 for verified hospital/tax MCCs) and INR 5,000 cooling limit "
                "for 24 hours after SIM swap or new device registration. "
                "All payment transaction data and KYC logs must be stored exclusively in India and retained for 5 years under PMLA, "
                "with FIU-IND STR filing within 7 days and CERT-In incident reporting within 6 hours."
            ),
        ),
        (
            "INP-UPI-03",
            StakeholderRole.PRODUCT_OWNER,
            InputSourceType.INTERVIEW_TRANSCRIPT,
            "Product Checkout & Privacy Feedback",
            (
                "Checkout alerts should be fast and user-friendly for rural and urban users. "
                "Delete all customer transaction logs after 30 days whenever a user clicks erase account."
            ),
        ),
        (
            "INP-UPI-04",
            StakeholderRole.ARCHITECT_DEVELOPER,
            InputSourceType.API_DB_SPEC,
            "NPCI Switch & CBS Integration",
            (
                "Payment initiation APIs shall enforce idempotency using globally unique RRN and txnId to prevent double debits. "
                "If the ML fraud model times out beyond 150ms, the orchestrator shall execute deterministic velocity fallback rules "
                "to stay inside NPCI's 30-second switch SLA, and maintain 99.95% uptime with RPO <= 1 min and RTO <= 15 min."
            ),
        ),
        (
            "INP-UPI-05",
            StakeholderRole.OPERATIONS,
            InputSourceType.INCIDENT_AUDIT_REPORT,
            "UDIR Dispute & Settlement Reconciliation",
            (
                "Deemed-success and failed UPI transactions shall automatically enter UDIR auto-reversal workflows and "
                "reconcile against NPCI T+0/T+1 NTSL files with NTP-synchronized 180-day hot SIEM logs."
            ),
        ),
    ]

    for iid, role, stype, title, content in p1_inputs:
        scan = scan_and_mask_input(content)
        db.save_input(
            StakeholderInputRecord(
                input_id=iid,
                project_id=p1,
                source_type=stype,
                stakeholder_role=role,
                title=title,
                masked_content=scan.masked_text,
                sensitivity_level=scan.sensitivity_level,
                masking_findings=scan.findings,
                injection_detected=scan.injection_detected,
            )
        )

    orchestrator.run_pipeline(p1, StakeholderRole.BUSINESS_ANALYST, "System Bootstrap")

    # Project 2: CoFT Card & UPI Payment Gateway
    p2 = "proj-card-pg-india"
    db.upsert_project(
        project_id=p2,
        name="CoFT Card & UPI Merchant Payment Gateway",
        domain="Payment Processing & Fraud Detection",
        jurisdiction="India (RBI CoFT, PCI-DSS v4.0, NPCI UDIR, DPDP 2023)",
        description=(
            "Merchant payment aggregator platform supporting RBI Card-on-File Tokenization, BIN-attack detection, "
            "3DS2/AFA authentication, and automated T+1 merchant settlement."
        ),
        advisory_mode=True,
    )
    p2_inputs = [
        (
            "INP-PG-01",
            StakeholderRole.INFOSEC_TEAM,
            InputSourceType.BANKING_POLICY,
            "CoFT & PCI-DSS v4.0 Controls",
            (
                "The gateway shall replace card PANs with RBI CoFT tokens managed inside FIPS 140-3 HSMs, "
                "never store CVV post-authorization, enforce TLS 1.3 mTLS across merchant APIs, and detect BIN enumeration attacks."
            ),
        ),
        (
            "INP-PG-02",
            StakeholderRole.COMPLIANCE_LEGAL,
            InputSourceType.BANKING_POLICY,
            "DPDP Consent & India Storage",
            (
                "Capture itemized DPDP Act 2023 consent notice before saving tokenized cards and retain settlement/audit trails "
                "exclusively in India for 5 years under PMLA."
            ),
        ),
    ]
    for iid, role, stype, title, content in p2_inputs:
        scan = scan_and_mask_input(content)
        db.save_input(
            StakeholderInputRecord(
                input_id=iid,
                project_id=p2,
                source_type=stype,
                stakeholder_role=role,
                title=title,
                masked_content=scan.masked_text,
                sensitivity_level=scan.sensitivity_level,
                masking_findings=scan.findings,
                injection_detected=scan.injection_detected,
            )
        )
    orchestrator.run_pipeline(p2, StakeholderRole.BUSINESS_ANALYST, "System Bootstrap")
