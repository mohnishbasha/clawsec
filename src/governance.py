import uuid
import logging
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, String, DateTime, Text, Boolean, JSON
from sqlalchemy.orm import DeclarativeBase, Session
import os

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./clawsec_audit.db")

_connect_args = {"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
engine = create_engine(DATABASE_URL, echo=False, connect_args=_connect_args)


class Base(DeclarativeBase):
    pass


class AuditEvent(Base):
    """Immutable audit record written for every security-relevant event."""

    __tablename__ = "audit_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    event_type = Column(String(64), nullable=False)
    user_id = Column(String(256))
    role = Column(String(64))
    action = Column(String(128))
    resource = Column(String(256))
    outcome = Column(String(32))        # allowed | denied | error
    policy_violations = Column(JSON, default=list)
    metadata_ = Column("metadata", JSON, default=dict)
    ip_address = Column(String(64))
    request_id = Column(String(64))


# Create tables on module import (idempotent)
Base.metadata.create_all(engine)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def log_event(
    event_type: str,
    user_id: str = None,
    role: str = None,
    action: str = None,
    resource: str = None,
    outcome: str = "allowed",
    policy_violations: list = None,
    metadata: dict = None,
    ip_address: str = None,
    request_id: str = None,
) -> AuditEvent:
    """
    Persist a single audit event and return the saved ORM object.

    All parameters are optional except *event_type* so callers can record only
    the fields that are relevant to their context.
    """
    event = AuditEvent(
        event_type=event_type,
        user_id=user_id,
        role=role,
        action=action,
        resource=resource,
        outcome=outcome,
        policy_violations=policy_violations or [],
        metadata_=metadata or {},
        ip_address=ip_address,
        request_id=request_id or str(uuid.uuid4()),
    )
    with Session(engine) as session:
        session.add(event)
        session.commit()
        session.refresh(event)

    logger.info(
        "AUDIT | type=%-30s user=%-20s role=%-15s outcome=%s",
        event_type,
        user_id or "-",
        role or "-",
        outcome,
    )
    return event


def get_audit_events(
    limit: int = 100,
    event_type: str = None,
    user_id: str = None,
) -> list:
    """
    Retrieve audit events in reverse-chronological order.

    Args:
        limit: Maximum number of records to return (hard cap: 1000).
        event_type: Optional filter — only return events of this type.
        user_id: Optional filter — only return events for this user.

    Returns:
        List of plain dicts (JSON-serialisable).
    """
    with Session(engine) as session:
        q = session.query(AuditEvent).order_by(AuditEvent.timestamp.desc())
        if event_type:
            q = q.filter(AuditEvent.event_type == event_type)
        if user_id:
            q = q.filter(AuditEvent.user_id == user_id)
        events = q.limit(min(limit, 1000)).all()
        return [
            {
                "id": e.id,
                "timestamp": e.timestamp.isoformat(),
                "event_type": e.event_type,
                "user_id": e.user_id,
                "role": e.role,
                "action": e.action,
                "resource": e.resource,
                "outcome": e.outcome,
                "policy_violations": e.policy_violations,
                "metadata": e.metadata_,
                "ip_address": e.ip_address,
                "request_id": e.request_id,
            }
            for e in events
        ]
