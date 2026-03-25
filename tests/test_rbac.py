import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.rbac import create_token, verify_token, check_permission, ROLE_PERMISSIONS
from fastapi import HTTPException

SECRET_KEY = "test-secret-key-for-testing-only-32bytes!"


class TestCreateToken:
    def test_create_agent_token(self):
        token = create_token("user1", "agent", SECRET_KEY)
        assert isinstance(token, str)
        assert len(token) > 20

    def test_create_developer_token(self):
        token = create_token("dev1", "developer", SECRET_KEY)
        assert isinstance(token, str)

    def test_create_auditor_token(self):
        token = create_token("auditor1", "auditor", SECRET_KEY)
        assert isinstance(token, str)

    def test_create_administrator_token(self):
        token = create_token("admin1", "administrator", SECRET_KEY)
        assert isinstance(token, str)

    def test_invalid_role_raises(self):
        with pytest.raises(ValueError, match="Unknown role"):
            create_token("user1", "superuser", SECRET_KEY)

    def test_token_is_string(self):
        token = create_token("user1", "agent", SECRET_KEY)
        assert isinstance(token, str)
        # JWT has three dot-separated segments
        assert token.count(".") == 2


class TestVerifyToken:
    def test_valid_token_verified(self):
        token = create_token("user1", "agent", SECRET_KEY)
        payload = verify_token(token, SECRET_KEY)
        assert payload["sub"] == "user1"
        assert payload["role"] == "agent"

    def test_invalid_token_raises(self):
        with pytest.raises(HTTPException) as exc:
            verify_token("invalid.token.here", SECRET_KEY)
        assert exc.value.status_code == 401

    def test_wrong_secret_raises(self):
        token = create_token("user1", "agent", SECRET_KEY)
        with pytest.raises(HTTPException) as exc:
            verify_token(token, "wrong-secret")
        assert exc.value.status_code == 401

    def test_token_contains_permissions(self):
        token = create_token("user1", "agent", SECRET_KEY)
        payload = verify_token(token, SECRET_KEY)
        assert "query:submit" in payload["permissions"]
        assert "output:read" in payload["permissions"]

    def test_empty_token_raises(self):
        with pytest.raises(HTTPException) as exc:
            verify_token("", SECRET_KEY)
        assert exc.value.status_code == 401

    def test_tampered_token_raises(self):
        token = create_token("user1", "agent", SECRET_KEY)
        tampered = token[:-5] + "XXXXX"
        with pytest.raises(HTTPException) as exc:
            verify_token(tampered, SECRET_KEY)
        assert exc.value.status_code == 401


class TestCheckPermission:
    def test_agent_has_query_permission(self):
        token = create_token("user1", "agent", SECRET_KEY)
        payload = verify_token(token, SECRET_KEY)
        assert check_permission(payload, "query:submit") is True

    def test_agent_has_output_read(self):
        token = create_token("user1", "agent", SECRET_KEY)
        payload = verify_token(token, SECRET_KEY)
        assert check_permission(payload, "output:read") is True

    def test_agent_lacks_audit_permission(self):
        token = create_token("user1", "agent", SECRET_KEY)
        payload = verify_token(token, SECRET_KEY)
        assert check_permission(payload, "audit:read") is False

    def test_agent_lacks_rbac_manage(self):
        token = create_token("user1", "agent", SECRET_KEY)
        payload = verify_token(token, SECRET_KEY)
        assert check_permission(payload, "rbac:manage") is False

    def test_auditor_has_audit_permission(self):
        token = create_token("auditor1", "auditor", SECRET_KEY)
        payload = verify_token(token, SECRET_KEY)
        assert check_permission(payload, "audit:read") is True

    def test_auditor_lacks_query_submit(self):
        token = create_token("auditor1", "auditor", SECRET_KEY)
        payload = verify_token(token, SECRET_KEY)
        assert check_permission(payload, "query:submit") is False

    def test_auditor_has_metrics_read(self):
        token = create_token("auditor1", "auditor", SECRET_KEY)
        payload = verify_token(token, SECRET_KEY)
        assert check_permission(payload, "metrics:read") is True

    def test_administrator_has_all_permissions(self):
        token = create_token("admin1", "administrator", SECRET_KEY)
        payload = verify_token(token, SECRET_KEY)
        for perm in [
            "query:submit", "audit:read", "audit:delete",
            "rbac:manage", "system:admin", "policy:manage", "metrics:read",
        ]:
            assert check_permission(payload, perm) is True, f"admin missing: {perm}"

    def test_developer_permissions(self):
        token = create_token("dev1", "developer", SECRET_KEY)
        payload = verify_token(token, SECRET_KEY)
        assert check_permission(payload, "query:submit") is True
        assert check_permission(payload, "policy:read") is True
        assert check_permission(payload, "model:configure") is True
        assert check_permission(payload, "audit:read") is False
        assert check_permission(payload, "rbac:manage") is False

    def test_empty_permissions_dict(self):
        assert check_permission({}, "query:submit") is False

    def test_nonexistent_permission(self):
        token = create_token("admin1", "administrator", SECRET_KEY)
        payload = verify_token(token, SECRET_KEY)
        assert check_permission(payload, "nonexistent:permission") is False


class TestRolePermissionMatrix:
    def test_all_roles_defined(self):
        for role in ["agent", "developer", "auditor", "administrator"]:
            assert role in ROLE_PERMISSIONS

    def test_least_privilege_agent(self):
        agent_perms = set(ROLE_PERMISSIONS["agent"])
        assert agent_perms == {"query:submit", "output:read"}

    def test_auditor_cannot_submit_queries(self):
        assert "query:submit" not in ROLE_PERMISSIONS["auditor"]

    def test_auditor_cannot_manage_policy(self):
        assert "policy:manage" not in ROLE_PERMISSIONS["auditor"]

    def test_developer_cannot_manage_rbac(self):
        assert "rbac:manage" not in ROLE_PERMISSIONS["developer"]

    def test_developer_cannot_delete_audit(self):
        assert "audit:delete" not in ROLE_PERMISSIONS["developer"]

    def test_administrator_is_superset_of_developer(self):
        dev_perms = set(ROLE_PERMISSIONS["developer"])
        admin_perms = set(ROLE_PERMISSIONS["administrator"])
        assert dev_perms.issubset(admin_perms)

    def test_no_empty_permission_lists(self):
        for role, perms in ROLE_PERMISSIONS.items():
            assert len(perms) > 0, f"Role {role} has no permissions"
