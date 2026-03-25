import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Use in-memory DB for tests — must be set before importing governance
os.environ["DATABASE_URL"] = "sqlite:///:memory:"

from src.governance import log_event, get_audit_events, AuditEvent, Base, engine
from sqlalchemy.orm import Session

# Ensure fresh schema for in-memory DB
Base.metadata.create_all(engine)


class TestAuditLogging:
    def test_log_event_creates_record(self):
        event = log_event(
            event_type="test_event",
            user_id="user1",
            role="agent",
            action="test:action",
            outcome="allowed",
        )
        assert event.id is not None
        assert event.event_type == "test_event"
        assert event.user_id == "user1"
        assert event.role == "agent"
        assert event.outcome == "allowed"

    def test_log_event_auto_generates_id(self):
        event = log_event("auto_id_test")
        assert isinstance(event.id, str)
        assert len(event.id) == 36  # UUID4 length

    def test_log_event_auto_generates_request_id(self):
        event = log_event("request_id_test")
        assert event.request_id is not None

    def test_log_policy_violation(self):
        event = log_event(
            event_type="policy_violation",
            user_id="attacker",
            role="agent",
            action="query:submit",
            outcome="denied",
            policy_violations=["Prompt injection detected"],
        )
        assert event.outcome == "denied"
        assert len(event.policy_violations) == 1
        assert "Prompt injection" in event.policy_violations[0]

    def test_log_event_with_metadata(self):
        event = log_event(
            "meta_event",
            metadata={"prompt_length": 42, "response_length": 100},
        )
        assert event.metadata_["prompt_length"] == 42
        assert event.metadata_["response_length"] == 100

    def test_log_event_with_ip_address(self):
        event = log_event("ip_test", ip_address="192.168.1.1")
        assert event.ip_address == "192.168.1.1"

    def test_audit_event_has_timestamp(self):
        event = log_event("timestamped_event", user_id="user3")
        assert event.timestamp is not None

    def test_explicit_request_id_preserved(self):
        rid = "my-custom-request-id-123"
        event = log_event("rid_test", request_id=rid)
        assert event.request_id == rid


class TestGetAuditEvents:
    def test_get_audit_events_returns_records(self):
        log_event("retrieval_test", user_id="retrieval_user", role="developer", outcome="allowed")
        events = get_audit_events(limit=50)
        assert len(events) >= 1

    def test_get_audit_events_returns_dicts(self):
        log_event("dict_test")
        events = get_audit_events(limit=10)
        assert all(isinstance(e, dict) for e in events)

    def test_get_audit_events_dict_keys(self):
        log_event("key_test", user_id="keyuser")
        events = get_audit_events(limit=5, user_id="keyuser")
        assert len(events) >= 1
        expected_keys = {
            "id", "timestamp", "event_type", "user_id", "role",
            "action", "resource", "outcome", "policy_violations",
            "metadata", "ip_address", "request_id",
        }
        assert expected_keys.issubset(set(events[0].keys()))

    def test_filter_by_event_type(self):
        log_event("rbac_denial", user_id="hacker", role="unknown", outcome="denied")
        events = get_audit_events(limit=50, event_type="rbac_denial")
        for e in events:
            assert e["event_type"] == "rbac_denial"

    def test_filter_by_user_id(self):
        log_event("test_event", user_id="specific_user_xyz", outcome="allowed")
        events = get_audit_events(limit=50, user_id="specific_user_xyz")
        assert len(events) >= 1
        for e in events:
            assert e["user_id"] == "specific_user_xyz"

    def test_limit_respected(self):
        for i in range(5):
            log_event("limit_test_event", user_id=f"limit_user_{i}")
        events = get_audit_events(limit=2)
        assert len(events) <= 2

    def test_hard_cap_at_1000(self):
        # Even if limit=9999 is passed, we cap at 1000
        events = get_audit_events(limit=9999)
        assert len(events) <= 1000

    def test_timestamp_is_string(self):
        log_event("ts_str_test")
        events = get_audit_events(limit=5)
        for e in events:
            assert isinstance(e["timestamp"], str)

    def test_policy_violations_is_list(self):
        log_event("pv_list_test", policy_violations=["v1", "v2"])
        events = get_audit_events(limit=5, event_type="pv_list_test")
        assert len(events) >= 1
        assert isinstance(events[0]["policy_violations"], list)
