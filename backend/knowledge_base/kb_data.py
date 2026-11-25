from __future__ import annotations

from typing import List
from backend.app.models import KnowledgeItem


INITIAL_KNOWLEDGE_BASE: List[KnowledgeItem] = [
    KnowledgeItem(
        kb_id="KB-RBI-DPSC-01",
        title="RBI Master Direction on Digital Payment Security Controls — Authentication & Step-Up MFA",
        domain="Payment Processing & Fraud Detection",
        category="Regulatory & Security",
        source="RBI/2020-21/74 DoS.CO.CSITE.SEC.No.1852/31.01.015/2020-21",
        jurisdiction="India",
        effective_date="2021-02-18",
        version="2.1",
        applicability=["UPI", "IMPS", "Card", "Internet Banking", "Mobile Banking", "Payment Gateway"],
        approved=True,
        mandatory_controls=[
            "Additional Factor of Authentication (AFA) for digital payment authorization",
            "Dynamic step-up authentication when transaction exceeds risk or amount threshold",
            "SIM-binding and device-fingerprint verification on mobile payment channels",
            "Cooling period and reduced limits after credential reset, new device, or new beneficiary addition",
        ],
        content=(
            "Regulated entities operating digital payment channels in India must implement robust multi-factor "
            "authentication including Additional Factor of Authentication (AFA) with dynamic variables. Systems shall "
            "require step-up authentication for transactions exceeding organization-approved risk or monetary thresholds, "
            "enforce device/SIM binding for mobile payment apps, apply cooling periods with restricted limits upon SIM swap "
            "or new device registration, and block replay or brute-force authentication attempts with configurable lockouts."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-RBI-DPSC-02",
        title="RBI Master Direction on Digital Payment Security Controls — Real-Time Fraud Monitoring & App Hardening",
        domain="Payment Processing & Fraud Detection",
        category="Regulatory & Fraud",
        source="RBI/2020-21/74 Clauses 22-35 (Fraud Risk & Application Security)",
        jurisdiction="India",
        effective_date="2021-02-18",
        version="2.1",
        applicability=["Fraud Detection", "Payment Processing", "Mobile SDK", "API Gateway"],
        approved=True,
        mandatory_controls=[
            "Real-time transaction risk scoring and velocity checks across channels",
            "Instant SMS/app/email alerting on payment execution and suspicious attempts",
            "Mobile app anti-tampering, root/jailbreak detection, SSL pinning, and obfuscation",
            "Customer configurable per-transaction and daily channel limits",
        ],
        content=(
            "Payment systems must implement real-time transaction monitoring capable of evaluating velocity, geolocation "
            "anomalies, device reputation, behavioral biometrics, and beneficiary risk prior to settlement. Customers must "
            "be empowered to set channel-wise and per-transaction limits and toggle domestic/international/contactless modes. "
            "Mobile payment interfaces require runtime application self-protection (RASP), root/jailbreak checks, and "
            "mandatory TLS certificate pinning."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-RBI-LOCAL-01",
        title="RBI Directive on Storage of Payment System Data (Data Localization)",
        domain="Payment Processing & Fraud Detection",
        category="Regulatory & Data Residency",
        source="RBI/2017-18/153 DPSS.CO.OD No.2785/06.08.005/2017-2018",
        jurisdiction="India",
        effective_date="2018-04-06",
        version="1.2",
        applicability=["Payment Processing", "Data Storage", "Audit Logs", "Cross-Border Payments"],
        approved=True,
        mandatory_controls=[
            "Store entire end-to-end payment transaction data only in systems located in India",
            "Delete any temporary foreign-leg processing copy within 24 hours or 1 business day",
            "Restrict cross-border telemetry replication unless anonymized and compliant",
        ],
        content=(
            "All payment system providers and intermediaries in India must ensure that the entire data relating to "
            "payment systems operated by them—including full end-to-end transaction details, payment instructions, customer "
            "identifiers, and settlement records—is stored exclusively in systems physically located within India. For "
            "cross-border payment legs, data processed abroad must be brought back to India and purged overseas within 24 hours."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-RBI-FRM-01",
        title="RBI Master Directions on Fraud Risk Management — Early Warning Signals & Reporting",
        domain="Payment Processing & Fraud Detection",
        category="Regulatory & Fraud",
        source="RBI/DOS/2024-25/118 Master Directions on Fraud Risk Management",
        jurisdiction="India",
        effective_date="2024-07-15",
        version="3.0",
        applicability=["Fraud Detection", "Mule Account Detection", "Governance", "Audit"],
        approved=True,
        mandatory_controls=[
            "Automated Early Warning Signals (EWS) integrated with Core Banking and Payment Switches",
            "Special Committee of the Board for Monitoring and Follow-up of Frauds (SCBMF) escalation",
            "Structured Fraud Monitoring Return (FMR) generation and audit trail preservation",
            "Maker-checker governance for fraud rule threshold modifications",
        ],
        content=(
            "Institutions must operate automated Early Warning Signals (EWS) and data analytics frameworks integrated with "
            "core payment switches to detect mule accounts, circular fund flows, and anomalous merchant behavior. High-value "
            "or systemic fraud incidents require automated case workflows, root-cause tracking, maker-checker approval on "
            "rule updates, and timely regulatory Fraud Monitoring Return (FMR) filings."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-NPCI-UPI-01",
        title="NPCI UPI Procedural Guidelines — Transaction Caps, Cooling Limits & UPI Lite",
        domain="Payment Processing & Fraud Detection",
        category="Regulatory & Business Rules",
        source="NPCI/UPI/OC-182 & NPCI Circulars on UPI Limits",
        jurisdiction="India",
        effective_date="2024-01-01",
        version="4.3",
        applicability=["UPI", "P2P", "P2M", "Customer Onboarding"],
        approved=True,
        mandatory_controls=[
            "Enforce INR 1,00,000 standard 24-hour UPI transaction limit (INR 5,00,000 for verified hospitals/education/tax/IPO)",
            "Enforce INR 5,000 cumulative limit for first 24 hours after new device/SIM registration",
            "Enforce daily P2P velocity cap (max 20 transactions per 24 hours per VPA/account)",
            "Enforce UPI Lite cap of INR 500 per txn and INR 2,000 wallet balance",
        ],
        content=(
            "UPI processing engines must enforce NPCI-mandated transaction ceilings: standard P2P and general P2M cap of "
            "INR 1,00,000 per 24 hours, enhanced INR 5,00,000 limit exclusively for verified MCCs (hospitals, educational "
            "institutions, tax payments, IPO), max 20 P2P debit transactions per 24h, and a strict INR 5,000 cooling-off "
            "ceiling for the initial 24 hours post new UPI registration, SIM change, or device re-binding."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-NPCI-UPI-02",
        title="NPCI UPI Technical & Operational Guidelines — Latency, Idempotency, Recon & UDIR Disputes",
        domain="Payment Processing & Fraud Detection",
        category="Integration & Performance",
        source="NPCI/UPI/TECH-2024 & UDIR Procedural Guidelines",
        jurisdiction="India",
        effective_date="2024-04-01",
        version="3.5",
        applicability=["UPI", "Switch Integration", "Settlement", "Dispute Resolution"],
        approved=True,
        mandatory_controls=[
            "Idempotent ReqPay/RespPay processing with globally unique RRN and txnId",
            "End-to-end switch SLA within 30 seconds; internal fraud scoring budget <= 150ms p99",
            "Automated Unified Dispute and Issue Resolution (UDIR) for deemed/pending/failed txns",
            "Automated T+0/T+1 NPCI NTSL settlement reconciliation and NPCI UAT certification gate",
        ],
        content=(
            "Every UPI payment switch integration must guarantee idempotent request processing via unique transaction IDs "
            "and Retrieval Reference Numbers (RRNs) to prevent double debits. End-to-end transaction round-trip must meet "
            "NPCI 30-second timeout budgets, requiring internal fraud engines to return risk decisions within <=150ms at p99. "
            "Failed or deemed-success transactions must enter automated UDIR workflows and T+0/T+1 NTSL reconciliation. "
            "Production release requires mandatory NPCI sandbox/UAT certification."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-DPDP-01",
        title="Digital Personal Data Protection (DPDP) Act 2023 — Consent, Purpose Limitation & Principal Rights",
        domain="Payment Processing & Fraud Detection",
        category="Privacy & Regulatory",
        source="Digital Personal Data Protection Act, 2023 (Act No. 22 of 2023), Sections 4-14",
        jurisdiction="India",
        effective_date="2023-08-11",
        version="1.0",
        applicability=["Privacy", "Customer Data", "Fraud Telemetry", "Consent Management"],
        approved=True,
        mandatory_controls=[
            "Explicit itemized consent notice prior to collecting or processing personal data",
            "Strict purpose limitation and data minimization for payment and behavioral data",
            "Support consent withdrawal and erasure requests subject to statutory PMLA/RBI retention override",
            "Consent artifact logging with timestamp, notice version, and purpose ID",
        ],
        content=(
            "Under India's DPDP Act 2023, Data Fiduciaries processing customer payment profiles, device fingerprints, or "
            "KYC attributes must obtain free, specific, informed, unconditional, and unambiguous consent via an itemized "
            "notice available in English and Eighth Schedule languages. Data Principals may withdraw consent or request "
            "erasure; however, statutory overrides (such as PMLA 5-year retention and fraud-prevention legal obligations) "
            "must take precedence and be transparently explained in the compliance matrix."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-DPDP-02",
        title="DPDP Act 2023 — Security Safeguards, Breach Notification & Significant Data Fiduciary Audits",
        domain="Payment Processing & Fraud Detection",
        category="Privacy & Security",
        source="DPDP Act 2023 Sections 8(5), 8(6), 10",
        jurisdiction="India",
        effective_date="2023-08-11",
        version="1.0",
        applicability=["Privacy", "Security", "Incident Response", "Governance"],
        approved=True,
        mandatory_controls=[
            "Reasonable technical security safeguards (encryption, masking, access control)",
            "Mandatory breach notification workflow to Data Protection Board of India and affected users",
            "Data Protection Impact Assessment (DPIA) and annual independent audit for SDFs",
        ],
        content=(
            "Data Fiduciaries must protect personal data in their possession or control—including fraud-scoring feature "
            "stores and third-party processors—by taking reasonable security safeguards against personal data breaches. "
            "Upon breach detection, the platform must support rapid notification to the Data Protection Board of India and "
            "each affected Data Principal, and maintain DPIA records for high-volume payment/fraud analytics."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-PMLA-01",
        title="PMLA 2002 & FIU-IND Rules — Statutory Record Retention & STR/CTR Reporting",
        domain="Payment Processing & Fraud Detection",
        category="Compliance & Audit",
        source="Prevention of Money Laundering Act 2002 & PML (Maintenance of Records) Rules",
        jurisdiction="India",
        effective_date="2023-03-07",
        version="3.1",
        applicability=["AML", "Fraud Detection", "Audit Trail", "Data Retention"],
        approved=True,
        mandatory_controls=[
            "Retain immutable transaction and KYC/risk audit records for minimum 5 years",
            "Automated Suspicious Transaction Report (STR) flagging and FIU-IND filing within 7 days",
            "Strict anti-tipping-off access controls hiding STR investigation status from customers",
        ],
        content=(
            "Reporting entities must preserve complete transaction reconstruction trails, customer identity logs, and fraud "
            "investigation records for at least 5 years from the date of transaction or termination of business relationship. "
            "Transactions matching money-laundering or structured mule patterns must generate Suspicious Transaction Reports "
            "(STRs) for FIU-IND submission within 7 days of confirmation, with strict RBAC preventing tipping-off."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-CERTIN-01",
        title="CERT-In Cybersecurity Directions 2022 — 6-Hour Incident Reporting & 180-Day Log Retention",
        domain="Payment Processing & Fraud Detection",
        category="Security & Regulatory",
        source="MeitY / CERT-In Direction No. 20(3)/2022-CERT-In",
        jurisdiction="India",
        effective_date="2022-06-28",
        version="1.0",
        applicability=["Security", "SIEM", "Operations", "Incident Management"],
        approved=True,
        mandatory_controls=[
            "Report cyber/payment security incidents to CERT-In within 6 hours of detection",
            "Synchronize all payment and fraud server clocks to NTP/NPL India time source",
            "Retain ICT and security logs securely within Indian jurisdiction for rolling 180 days",
        ],
        content=(
            "All service providers, payment intermediaries, and financial institutions must synchronize system clocks via "
            "NTP linked to NPL/NIC servers, retain complete ICT and authentication logs within India for a rolling period "
            "of 180 days, and support automated alert escalation to enable mandatory incident reporting to CERT-In within "
            "6 hours of noticing unauthorized access, data leaks, or payment system disruption."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-PCIDSS-01",
        title="PCI-DSS v4.0 & RBI Card-on-File Tokenization (CoFT) Security Controls",
        domain="Payment Processing & Fraud Detection",
        category="Security & Privacy",
        source="PCI Security Standards Council v4.0 & RBI/2021-22/96 CoFT",
        jurisdiction="India & Global",
        effective_date="2024-03-31",
        version="4.0",
        applicability=["Card Payments", "Payment Gateway", "Tokenization", "Key Management"],
        approved=True,
        mandatory_controls=[
            "Replace stored card PANs with RBI-compliant Card-on-File Tokens (CoFT)",
            "Prohibit storage of CVV/CVC/PIN/full track data post-authorization",
            "Mask PAN in logs/UIs (show at most first 6 and last 4 digits) and encrypt with AES-256/HSM",
            "Enforce TLS 1.3 / mTLS for payment APIs and quarterly vulnerability/SAST/DAST gates",
        ],
        content=(
            "Entities handling card payments must comply with RBI Card-on-File Tokenization (CoFT) prohibiting merchants "
            "and payment aggregators from storing actual card credentials, and PCI-DSS v4.0 mandates: never store sensitive "
            "authentication data (CVV/PIN) post-authorization, mask PANs in UIs and logs, manage cryptographic keys inside "
            "FIPS 140-2/3 validated HSMs, enforce mTLS/TLS 1.3, and execute continuous SAST/DAST and pen-testing."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-ISO27001-01",
        title="ISO/IEC 27001:2022 & Payment Platform Availability/DR Controls",
        domain="Payment Processing & Fraud Detection",
        category="Security & Availability",
        source="ISO/IEC 27001:2022 Annex A & RBI BCP/DR Guidelines",
        jurisdiction="India & Global",
        effective_date="2022-10-25",
        version="2.0",
        applicability=["Architecture", "Security", "Operations", "DR/BCP"],
        approved=True,
        mandatory_controls=[
            "RBAC with least privilege and MFA for all administrative and production access",
            "Maker-checker segregation of duties for limit, settlement, and fraud-rule changes",
            "Active-active multi-AZ resilience with >=99.95% availability, RPO <= 1 min, RTO <= 15 min",
            "STRIDE threat modeling prior to coding and immutable hash-chained audit logging",
        ],
        content=(
            "Mission-critical payment and fraud platforms must enforce RBAC with least privilege, MFA for privileged access, "
            "maker-checker segregation of duties on threshold/rule changes, immutable tamper-evident audit logging, STRIDE "
            "threat modeling during design, and multi-region active-active Disaster Recovery targeting >=99.95% uptime, "
            "RPO <= 1 minute, and RTO <= 15 minutes."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-DOMAIN-PAY-01",
        title="Indian Payment Processing & Fraud Detection Domain Patterns",
        domain="Payment Processing & Fraud Detection",
        category="Domain Knowledge",
        source="FinReq Indian Payment Domain Reference",
        jurisdiction="India",
        effective_date="2025-01-01",
        version="2.0",
        applicability=["Payment Processing", "Fraud Detection", "Architecture", "Risk"],
        approved=True,
        mandatory_controls=[
            "Two-stage fraud decisioning: deterministic hard rules + real-time ML risk scoring",
            "Explicit fallback strategy (fail-safe rule fallback vs fail-closed) on ML timeout",
            "Mule network graph analytics tracking rapid fan-in/fan-out across VPAs and accounts",
        ],
        content=(
            "Indian payment architectures coordinate Payer/Payee PSPs, TPAPs, Remitter/Beneficiary Core Banking Systems (CBS), "
            "NPCI switches (UPI/IMPS), and card networks. Effective fraud pipelines combine deterministic velocity/sanction "
            "rules (<20ms) with real-time ML scoring (<120ms) and graph-based mule detection (detecting rapid pass-through "
            "fan-in/fan-out, newly activated dormant accounts, and SIM-swap collect scams). Systems must specify explicit "
            "circuit-breaker behavior (deterministic rule fallback) when ML scoring experiences latency spikes."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-RE-GUIDE-01",
        title="ISO/IEC/IEEE 29148 Requirement Engineering & Quality Verification Standard",
        domain="Payment Processing & Fraud Detection",
        category="RE Methodology",
        source="ISO/IEC/IEEE 29148:2018 & FinReq Quality Playbook",
        jurisdiction="India & Global",
        effective_date="2023-01-01",
        version="1.1",
        applicability=["Requirement Extraction", "Quality Analysis", "Traceability"],
        approved=True,
        mandatory_controls=[
            "Quantify non-functional SLAs (ms latency, TPS, availability %, retention years)",
            "Include actor, trigger, condition, system response, and failure/exception handling",
            "Maintain bidirectional traceability between stakeholder input, SRS, compliance control, and test case",
        ],
        content=(
            "Every financial requirement must be atomic, unambiguous, feasible, verifiable, and traceable. Vague terms such "
            "as 'fast', 'real-time' (without ms target), 'secure', 'user-friendly', 'scalable', or 'appropriate' fail "
            "quality verification and must trigger stakeholder clarification. Requirements must define measurable acceptance "
            "criteria (Given/When/Then) and explicit exception handling."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-SDLC-RULES-01",
        title="Financial Sector SDLC Selection Rules & Governance Matrix",
        domain="Payment Processing & Fraud Detection",
        category="SDLC Governance",
        source="FinReq SDLC Decision & Governance Policy",
        jurisdiction="India",
        effective_date="2025-01-01",
        version="2.2",
        applicability=["SDLC Selection", "Governance", "DevSecOps", "Compliance"],
        approved=True,
        mandatory_controls=[
            "High regulatory criticality + frequent fraud-rule/ML iteration -> Agile-DevSecOps Hybrid or Agile-V-Model Hybrid",
            "Embed threat modeling, SAST/DAST, transaction-integrity testing, and compliance sign-off gates",
            "Require PM, Architect, InfoSec, and Compliance Officer sign-off on SDLC adoption",
        ],
        content=(
            "SDLC selection in Indian payment & fraud engineering balances regulatory rigor against rapid adversarial "
            "evolution. Pure Waterfall suits only frozen legacy interfaces with rare changes. V-Model suits strict "
            "verification/certification systems with stable specs. Spiral suits high technical/algorithmic uncertainty. "
            "Pure Agile lacks mandatory regulatory validation gates. Therefore, payment gateways and fraud engines with "
            "evolving ML/rule requirements and strict RBI/NPCI/DPDP mandates favor Agile-DevSecOps Hybrid (continuous "
            "security/ML delivery with compliance release gates) or Agile-V-Model Hybrid (iterative builds paired with "
            "formal V-Model verification & NPCI/RBI sign-off)."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-TPL-SRS-01",
        title="Standard SRS, User Story & Use-Case Templates for Financial Systems",
        domain="Payment Processing & Fraud Detection",
        category="Templates",
        source="FinReq Standard Artifact Templates",
        jurisdiction="India",
        effective_date="2025-01-01",
        version="1.0",
        applicability=["Documentation", "SRS", "User Stories", "Traceability"],
        approved=True,
        mandatory_controls=[
            "Requirement ID naming convention: <TYPE>-<SUBDOMAIN>-<SEQ> (e.g., FR-PAY-001, SEC-FRD-002)",
            "User stories structured as As a <Role>, I want <Capability>, so that <Business/Compliance Value>",
            "Traceability Matrix linking Source -> Requirement -> Regulation/KB -> Risk -> Test/Acceptance Gate",
        ],
        content=(
            "Approved template standards mandate structured IDs (FR-PAY, FR-FRD, SEC-PAY, REG-RBI, PERF-FRD), Gherkin "
            "Given/When/Then acceptance criteria, full use-case pre/post-conditions and exception flows, a Risk & Threat "
            "Register scored by Likelihood x Impact, a Compliance Control Matrix, and a full Requirements Traceability Matrix."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-REF-PROJ-01",
        title="Approved Reference Case: UPI Real-Time Fraud Scoring & Mule Detection Platform v1.0",
        domain="Payment Processing & Fraud Detection",
        category="Approved Reference Project",
        source="FinReq Approved Case Archive — Case REF-UPI-FRD-2024",
        jurisdiction="India",
        effective_date="2024-09-01",
        version="1.0",
        applicability=["UPI", "Fraud Detection", "Mule Detection", "SDLC Benchmark"],
        approved=True,
        mandatory_controls=[
            "Fraud engine latency p99 <= 120ms at 5,000 TPS peak",
            "Step-up AFA for risk score 0.65-0.84; auto-block >= 0.85; deterministic fallback on ML timeout",
            "Agile-DevSecOps Hybrid SDLC with shadow-mode ML canary + maker-checker rule publish",
        ],
        content=(
            "Reference approved specification for a Tier-1 bank UPI Fraud Engine: processes 5,000 TPS with <=120ms p99 "
            "scoring latency inside NPCI's 30s timeout window, triggers step-up biometric/PIN AFA at medium-high risk "
            "(0.65-0.84), blocks transactions >=0.85, detects mule fan-in/fan-out graphs, stores all logs in India for "
            "5 years (PMLA) with 180-day hot SIEM (CERT-In), and adopted Agile-DevSecOps Hybrid SDLC."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-REF-PROJ-02",
        title="Approved Reference Case: Merchant Card & UPI Payment Gateway with UDIR & CoFT",
        domain="Payment Processing & Fraud Detection",
        category="Approved Reference Project",
        source="FinReq Approved Case Archive — Case REF-PG-UDIR-2024",
        jurisdiction="India",
        effective_date="2024-11-15",
        version="1.0",
        applicability=["Payment Gateway", "Card Tokenization", "UDIR", "SDLC Benchmark"],
        approved=True,
        mandatory_controls=[
            "Idempotency key enforcement on payment initiation APIs",
            "RBI CoFT tokenization with HSM-backed key rotation and zero CVV persistence",
            "Agile-V-Model Hybrid SDLC with NPCI UAT and PCI-DSS QSA certification gates",
        ],
        content=(
            "Reference approved specification for an omnichannel payment aggregator: enforces strict API idempotency, "
            "RBI CoFT card tokenization, automated T+1 merchant settlement reconciliation, UDIR dispute lifecycle "
            "integration, DPDP itemized consent ledger, and Agile-V-Model Hybrid SDLC due to strict PCI/NPCI certification gates."
        ),
    ),
    KnowledgeItem(
        kb_id="KB-DRAFT-UNVERIFIED-99",
        title="Unverified Draft Blog — Bypassing RBI AFA for Speed",
        domain="Payment Processing & Fraud Detection",
        category="Unapproved External",
        source="Unverified Blog Post",
        jurisdiction="Unknown",
        effective_date="2024-01-01",
        version="0.1",
        applicability=["Test Allowlist"],
        approved=False,
        mandatory_controls=[],
        content="Unapproved external suggestion claiming RBI AFA can be skipped for transactions under INR 50,000 without regulatory exception.",
    ),
]
