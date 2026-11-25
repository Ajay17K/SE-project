from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

from backend.app.config import DB_PATH
from backend.app.models import (
    ApprovalGateItem,
    ApprovalStatus,
    AuditEvent,
    ComplianceMapping,
    ConflictRecord,
    InterviewMessage,
    KnowledgeItem,
    ProjectSummary,
    RequirementItem,
    RiskItem,
    SDLCRecommendation,
    StakeholderInputRecord,
    utc_now,
)


class Database:
    def __init__(self, db_path: Path = DB_PATH):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    project_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    jurisdiction TEXT NOT NULL,
                    description TEXT NOT NULL,
                    advisory_mode INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS knowledge_base (
                    kb_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    category TEXT NOT NULL,
                    source TEXT NOT NULL,
                    jurisdiction TEXT NOT NULL,
                    effective_date TEXT NOT NULL,
                    version TEXT NOT NULL,
                    applicability_json TEXT NOT NULL,
                    approved INTEGER NOT NULL,
                    mandatory_controls_json TEXT NOT NULL,
                    content TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS stakeholder_inputs (
                    input_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    stakeholder_role TEXT NOT NULL,
                    title TEXT NOT NULL,
                    masked_content TEXT NOT NULL,
                    sensitivity_level TEXT NOT NULL,
                    masking_findings_json TEXT NOT NULL,
                    injection_detected INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS interview_messages (
                    message_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    sender TEXT NOT NULL,
                    stakeholder_role TEXT NOT NULL,
                    topic TEXT NOT NULL,
                    content TEXT NOT NULL,
                    follow_up_reasons_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS requirements (
                    req_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (project_id, req_id)
                );

                CREATE TABLE IF NOT EXISTS conflicts (
                    conflict_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (project_id, conflict_id)
                );

                CREATE TABLE IF NOT EXISTS compliance_mappings (
                    mapping_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (project_id, mapping_id)
                );

                CREATE TABLE IF NOT EXISTS risk_items (
                    risk_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (project_id, risk_id)
                );

                CREATE TABLE IF NOT EXISTS sdlc_recommendations (
                    project_id TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS approval_gates (
                    gate_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    PRIMARY KEY (project_id, gate_id)
                );

                CREATE TABLE IF NOT EXISTS artifacts (
                    project_id TEXT NOT NULL,
                    artifact_key TEXT NOT NULL,
                    title TEXT NOT NULL,
                    content_md TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (project_id, artifact_key)
                );

                CREATE TABLE IF NOT EXISTS agent_traces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    project_id TEXT NOT NULL,
                    run_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE,
                    project_id TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    actor_name TEXT NOT NULL,
                    action TEXT NOT NULL,
                    agent_name TEXT NOT NULL,
                    target_id TEXT NOT NULL,
                    input_summary TEXT NOT NULL,
                    retrieved_kb_ids_json TEXT NOT NULL,
                    confidence_score REAL,
                    details_json TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL
                );
                """
            )

    # --- Knowledge Base ---
    def seed_knowledge_base(self, items: List[KnowledgeItem]) -> None:
        with self._connect() as conn:
            for item in items:
                conn.execute(
                    """
                    INSERT INTO knowledge_base (
                        kb_id, title, domain, category, source, jurisdiction,
                        effective_date, version, applicability_json, approved,
                        mandatory_controls_json, content
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(kb_id) DO UPDATE SET
                        title=excluded.title,
                        domain=excluded.domain,
                        category=excluded.category,
                        source=excluded.source,
                        jurisdiction=excluded.jurisdiction,
                        effective_date=excluded.effective_date,
                        version=excluded.version,
                        applicability_json=excluded.applicability_json,
                        approved=excluded.approved,
                        mandatory_controls_json=excluded.mandatory_controls_json,
                        content=excluded.content
                    """,
                    (
                        item.kb_id,
                        item.title,
                        item.domain,
                        item.category,
                        item.source,
                        item.jurisdiction,
                        item.effective_date,
                        item.version,
                        json.dumps(item.applicability),
                        1 if item.approved else 0,
                        json.dumps(item.mandatory_controls),
                        item.content,
                    ),
                )

    def list_knowledge_base(self, approved_only: bool = True) -> List[KnowledgeItem]:
        query = "SELECT * FROM knowledge_base"
        if approved_only:
            query += " WHERE approved = 1"
        query += " ORDER BY kb_id"
        with self._connect() as conn:
            rows = conn.execute(query).fetchall()
        return [
            KnowledgeItem(
                kb_id=r["kb_id"],
                title=r["title"],
                domain=r["domain"],
                category=r["category"],
                source=r["source"],
                jurisdiction=r["jurisdiction"],
                effective_date=r["effective_date"],
                version=r["version"],
                applicability=json.loads(r["applicability_json"]),
                approved=bool(r["approved"]),
                mandatory_controls=json.loads(r["mandatory_controls_json"]),
                content=r["content"],
            )
            for r in rows
        ]

    # --- Projects ---
    def upsert_project(
        self,
        project_id: str,
        name: str,
        domain: str,
        jurisdiction: str,
        description: str,
        advisory_mode: bool = True,
    ) -> ProjectSummary:
        now = utc_now()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT created_at FROM projects WHERE project_id = ?", (project_id,)
            ).fetchone()
            created_at = existing["created_at"] if existing else now
            conn.execute(
                """
                INSERT INTO projects (project_id, name, domain, jurisdiction, description, advisory_mode, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(project_id) DO UPDATE SET
                    name=excluded.name,
                    domain=excluded.domain,
                    jurisdiction=excluded.jurisdiction,
                    description=excluded.description,
                    advisory_mode=excluded.advisory_mode,
                    updated_at=excluded.updated_at
                """,
                (project_id, name, domain, jurisdiction, description, 1 if advisory_mode else 0, created_at, now),
            )
        return self.get_project(project_id)  # type: ignore[return-value]

    def list_projects(self) -> List[ProjectSummary]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM projects ORDER BY updated_at DESC").fetchall()
        return [self._row_to_project_summary(r) for r in rows]

    def get_project(self, project_id: str) -> Optional[ProjectSummary]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM projects WHERE project_id = ?", (project_id,)).fetchone()
        return self._row_to_project_summary(row) if row else None

    def _row_to_project_summary(self, row: sqlite3.Row) -> ProjectSummary:
        pid = row["project_id"]
        with self._connect() as conn:
            req_count = conn.execute(
                "SELECT COUNT(*) AS c FROM requirements WHERE project_id = ?", (pid,)
            ).fetchone()["c"]
            gates = conn.execute(
                "SELECT payload_json FROM approval_gates WHERE project_id = ?", (pid,)
            ).fetchall()
            pending = sum(
                1
                for g in gates
                if json.loads(g["payload_json"]).get("status") == ApprovalStatus.PENDING_HUMAN_APPROVAL.value
            )
            sdlc_row = conn.execute(
                "SELECT payload_json FROM sdlc_recommendations WHERE project_id = ?", (pid,)
            ).fetchone()
            rec_sdlc = json.loads(sdlc_row["payload_json"]).get("recommended_model") if sdlc_row else None
        return ProjectSummary(
            project_id=pid,
            name=row["name"],
            domain=row["domain"],
            jurisdiction=row["jurisdiction"],
            description=row["description"],
            advisory_mode=bool(row["advisory_mode"]),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            requirement_count=req_count,
            pending_approvals=pending,
            recommended_sdlc=rec_sdlc,
        )

    # --- Stakeholder Inputs & Interviews ---
    def save_input(self, record: StakeholderInputRecord) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO stakeholder_inputs (
                    input_id, project_id, source_type, stakeholder_role, title,
                    masked_content, sensitivity_level, masking_findings_json,
                    injection_detected, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.input_id,
                    record.project_id,
                    record.source_type.value,
                    record.stakeholder_role.value,
                    record.title,
                    record.masked_content,
                    record.sensitivity_level.value,
                    json.dumps([f.model_dump() for f in record.masking_findings]),
                    1 if record.injection_detected else 0,
                    record.created_at,
                ),
            )

    def list_inputs(self, project_id: str) -> List[StakeholderInputRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM stakeholder_inputs WHERE project_id = ? ORDER BY created_at ASC",
                (project_id,),
            ).fetchall()
        return [
            StakeholderInputRecord(
                input_id=r["input_id"],
                project_id=r["project_id"],
                source_type=r["source_type"],
                stakeholder_role=r["stakeholder_role"],
                title=r["title"],
                masked_content=r["masked_content"],
                sensitivity_level=r["sensitivity_level"],
                masking_findings=json.loads(r["masking_findings_json"]),
                injection_detected=bool(r["injection_detected"]),
                created_at=r["created_at"],
            )
            for r in rows
        ]

    def save_interview_message(self, project_id: str, msg: InterviewMessage) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO interview_messages (
                    message_id, project_id, session_id, sender, stakeholder_role,
                    topic, content, follow_up_reasons_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    msg.message_id,
                    project_id,
                    msg.session_id,
                    msg.sender,
                    msg.stakeholder_role.value,
                    msg.topic,
                    msg.content,
                    json.dumps(msg.follow_up_reasons),
                    msg.created_at,
                ),
            )

    def list_interview_messages(self, project_id: str, session_id: Optional[str] = None) -> List[InterviewMessage]:
        with self._connect() as conn:
            if session_id:
                rows = conn.execute(
                    "SELECT * FROM interview_messages WHERE project_id = ? AND session_id = ? ORDER BY created_at ASC",
                    (project_id, session_id),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM interview_messages WHERE project_id = ? ORDER BY created_at ASC",
                    (project_id,),
                ).fetchall()
        return [
            InterviewMessage(
                message_id=r["message_id"],
                session_id=r["session_id"],
                sender=r["sender"],
                stakeholder_role=r["stakeholder_role"],
                topic=r["topic"],
                content=r["content"],
                follow_up_reasons=json.loads(r["follow_up_reasons_json"]),
                created_at=r["created_at"],
            )
            for r in rows
        ]

    # --- Structured Analysis Outputs ---
    def replace_requirements(self, project_id: str, items: List[RequirementItem]) -> None:
        now = utc_now()
        with self._connect() as conn:
            conn.execute("DELETE FROM requirements WHERE project_id = ?", (project_id,))
            for item in items:
                conn.execute(
                    "INSERT INTO requirements (req_id, project_id, payload_json, updated_at) VALUES (?, ?, ?, ?)",
                    (item.req_id, project_id, item.model_dump_json(), now),
                )
            conn.execute("UPDATE projects SET updated_at = ? WHERE project_id = ?", (now, project_id))

    def upsert_requirement(self, project_id: str, item: RequirementItem) -> None:
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO requirements (req_id, project_id, payload_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(project_id, req_id) DO UPDATE SET
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (item.req_id, project_id, item.model_dump_json(), now),
            )

    def list_requirements(self, project_id: str) -> List[RequirementItem]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM requirements WHERE project_id = ? ORDER BY req_id ASC",
                (project_id,),
            ).fetchall()
        return [RequirementItem.model_validate_json(r["payload_json"]) for r in rows]

    def replace_conflicts(self, project_id: str, items: List[ConflictRecord]) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM conflicts WHERE project_id = ?", (project_id,))
            for item in items:
                conn.execute(
                    "INSERT INTO conflicts (conflict_id, project_id, payload_json) VALUES (?, ?, ?)",
                    (item.conflict_id, project_id, item.model_dump_json()),
                )

    def list_conflicts(self, project_id: str) -> List[ConflictRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM conflicts WHERE project_id = ? ORDER BY conflict_id ASC",
                (project_id,),
            ).fetchall()
        return [ConflictRecord.model_validate_json(r["payload_json"]) for r in rows]

    def replace_compliance_mappings(self, project_id: str, items: List[ComplianceMapping]) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM compliance_mappings WHERE project_id = ?", (project_id,))
            for item in items:
                conn.execute(
                    "INSERT INTO compliance_mappings (mapping_id, project_id, payload_json) VALUES (?, ?, ?)",
                    (item.mapping_id, project_id, item.model_dump_json()),
                )

    def list_compliance_mappings(self, project_id: str) -> List[ComplianceMapping]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM compliance_mappings WHERE project_id = ? ORDER BY mapping_id ASC",
                (project_id,),
            ).fetchall()
        return [ComplianceMapping.model_validate_json(r["payload_json"]) for r in rows]

    def replace_risks(self, project_id: str, items: List[RiskItem]) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM risk_items WHERE project_id = ?", (project_id,))
            for item in items:
                conn.execute(
                    "INSERT INTO risk_items (risk_id, project_id, payload_json) VALUES (?, ?, ?)",
                    (item.risk_id, project_id, item.model_dump_json()),
                )

    def list_risks(self, project_id: str) -> List[RiskItem]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM risk_items WHERE project_id = ? ORDER BY risk_id ASC",
                (project_id,),
            ).fetchall()
        return [RiskItem.model_validate_json(r["payload_json"]) for r in rows]

    def save_sdlc(self, rec: SDLCRecommendation) -> None:
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO sdlc_recommendations (project_id, payload_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(project_id) DO UPDATE SET
                    payload_json=excluded.payload_json,
                    updated_at=excluded.updated_at
                """,
                (rec.project_id, rec.model_dump_json(), now),
            )

    def get_sdlc(self, project_id: str) -> Optional[SDLCRecommendation]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM sdlc_recommendations WHERE project_id = ?",
                (project_id,),
            ).fetchone()
        return SDLCRecommendation.model_validate_json(row["payload_json"]) if row else None

    def replace_approval_gates(self, project_id: str, gates: List[ApprovalGateItem]) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM approval_gates WHERE project_id = ?", (project_id,))
            for g in gates:
                conn.execute(
                    "INSERT INTO approval_gates (gate_id, project_id, payload_json) VALUES (?, ?, ?)",
                    (g.gate_id, project_id, g.model_dump_json()),
                )

    def upsert_approval_gate(self, gate: ApprovalGateItem) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO approval_gates (gate_id, project_id, payload_json)
                VALUES (?, ?, ?)
                ON CONFLICT(project_id, gate_id) DO UPDATE SET
                    payload_json=excluded.payload_json
                """,
                (gate.gate_id, gate.project_id, gate.model_dump_json()),
            )

    def list_approval_gates(self, project_id: str) -> List[ApprovalGateItem]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM approval_gates WHERE project_id = ? ORDER BY gate_id ASC",
                (project_id,),
            ).fetchall()
        return [ApprovalGateItem.model_validate_json(r["payload_json"]) for r in rows]

    def save_artifacts(self, project_id: str, artifacts: Dict[str, Dict[str, Any]]) -> None:
        now = utc_now()
        with self._connect() as conn:
            conn.execute("DELETE FROM artifacts WHERE project_id = ?", (project_id,))
            for key, data in artifacts.items():
                conn.execute(
                    """
                    INSERT INTO artifacts (project_id, artifact_key, title, content_md, payload_json, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        project_id,
                        key,
                        data["title"],
                        data["content_md"],
                        json.dumps(data.get("structured", {})),
                        now,
                    ),
                )

    def list_artifacts(self, project_id: str) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT artifact_key, title, content_md, payload_json, updated_at FROM artifacts WHERE project_id = ? ORDER BY artifact_key",
                (project_id,),
            ).fetchall()
        return [
            {
                "artifact_key": r["artifact_key"],
                "title": r["title"],
                "content_md": r["content_md"],
                "structured": json.loads(r["payload_json"]),
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]

    def save_agent_traces(self, project_id: str, run_id: str, traces: List[Dict[str, Any]]) -> None:
        now = utc_now()
        with self._connect() as conn:
            for t in traces:
                conn.execute(
                    "INSERT INTO agent_traces (project_id, run_id, payload_json, created_at) VALUES (?, ?, ?, ?)",
                    (project_id, run_id, json.dumps(t), now),
                )

    def list_agent_traces(self, project_id: str) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT run_id, payload_json, created_at FROM agent_traces WHERE project_id = ? ORDER BY id DESC LIMIT 100",
                (project_id,),
            ).fetchall()
        out = []
        for r in rows:
            payload = json.loads(r["payload_json"])
            payload["run_id"] = r["run_id"]
            payload["created_at"] = r["created_at"]
            out.append(payload)
        return list(reversed(out))

    # --- Immutable Hash-Chained Audit Ledger ---
    def append_audit_event(
        self,
        event_id: str,
        project_id: str,
        actor_role: str,
        actor_name: str,
        action: str,
        agent_name: str,
        target_id: str,
        input_summary: str,
        retrieved_kb_ids: List[str] | None = None,
        confidence_score: Optional[float] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditEvent:
        retrieved = retrieved_kb_ids or []
        detail_dict = details or {}
        ts = utc_now()
        with self._connect() as conn:
            last = conn.execute("SELECT event_hash FROM audit_events ORDER BY seq DESC LIMIT 1").fetchone()
            prev_hash = last["event_hash"] if last else "GENESIS"
            hash_payload = json.dumps(
                {
                    "event_id": event_id,
                    "project_id": project_id,
                    "timestamp": ts,
                    "actor_role": actor_role,
                    "actor_name": actor_name,
                    "action": action,
                    "agent_name": agent_name,
                    "target_id": target_id,
                    "input_summary": input_summary,
                    "retrieved_kb_ids": retrieved,
                    "confidence_score": confidence_score,
                    "details": detail_dict,
                    "prev_hash": prev_hash,
                },
                sort_keys=True,
            )
            event_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()
            conn.execute(
                """
                INSERT INTO audit_events (
                    event_id, project_id, timestamp, actor_role, actor_name,
                    action, agent_name, target_id, input_summary,
                    retrieved_kb_ids_json, confidence_score, details_json,
                    prev_hash, event_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    project_id,
                    ts,
                    actor_role,
                    actor_name,
                    action,
                    agent_name,
                    target_id,
                    input_summary,
                    json.dumps(retrieved),
                    confidence_score,
                    json.dumps(detail_dict),
                    prev_hash,
                    event_hash,
                ),
            )
        return AuditEvent(
            event_id=event_id,
            project_id=project_id,
            timestamp=ts,
            actor_role=actor_role,
            actor_name=actor_name,
            action=action,
            agent_name=agent_name,
            target_id=target_id,
            input_summary=input_summary,
            retrieved_kb_ids=retrieved,
            confidence_score=confidence_score,
            details=detail_dict,
            prev_hash=prev_hash,
            event_hash=event_hash,
        )

    def list_audit_events(self, project_id: Optional[str] = None, limit: int = 200) -> List[AuditEvent]:
        with self._connect() as conn:
            if project_id:
                rows = conn.execute(
                    "SELECT * FROM audit_events WHERE project_id = ? ORDER BY seq DESC LIMIT ?",
                    (project_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM audit_events ORDER BY seq DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [
            AuditEvent(
                event_id=r["event_id"],
                project_id=r["project_id"],
                timestamp=r["timestamp"],
                actor_role=r["actor_role"],
                actor_name=r["actor_name"],
                action=r["action"],
                agent_name=r["agent_name"],
                target_id=r["target_id"],
                input_summary=r["input_summary"],
                retrieved_kb_ids=json.loads(r["retrieved_kb_ids_json"]),
                confidence_score=r["confidence_score"],
                details=json.loads(r["details_json"]),
                prev_hash=r["prev_hash"],
                event_hash=r["event_hash"],
            )
            for r in rows
        ]

    def verify_audit_chain(self) -> Dict[str, Any]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM audit_events ORDER BY seq ASC").fetchall()
        prev_hash = "GENESIS"
        for idx, r in enumerate(rows):
            if r["prev_hash"] != prev_hash:
                return {"valid": False, "checked": idx + 1, "broken_at": r["event_id"]}
            payload = json.dumps(
                {
                    "event_id": r["event_id"],
                    "project_id": r["project_id"],
                    "timestamp": r["timestamp"],
                    "actor_role": r["actor_role"],
                    "actor_name": r["actor_name"],
                    "action": r["action"],
                    "agent_name": r["agent_name"],
                    "target_id": r["target_id"],
                    "input_summary": r["input_summary"],
                    "retrieved_kb_ids": json.loads(r["retrieved_kb_ids_json"]),
                    "confidence_score": r["confidence_score"],
                    "details": json.loads(r["details_json"]),
                    "prev_hash": r["prev_hash"],
                },
                sort_keys=True,
            )
            expected = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if r["event_hash"] != expected:
                return {"valid": False, "checked": idx + 1, "broken_at": r["event_id"]}
            prev_hash = r["event_hash"]
        return {"valid": True, "checked": len(rows), "broken_at": None}
