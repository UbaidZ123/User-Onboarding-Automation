#!/usr/bin/env python3
"""
Enterprise User Onboarding Automation (RBAC + Audit Logging)

What this simulates:
- Onboarding: validate request, assign role-based access, enforce MFA, write audit log
- Offboarding: revoke access and log actions (often more security-critical than onboarding)

No external dependencies. CLI-first because internal IT automation tools are commonly CLI-based.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# Logging (Audit Trail)
def _utc_time_tuple(*args):
    return datetime.utcnow().timetuple()


def setup_audit_logger(log_path: str = "audit.log") -> logging.Logger:
    logger = logging.getLogger("audit")
    logger.setLevel(logging.INFO)

    if not logger.handlers:
        formatter = logging.Formatter("%(asctime)sZ | %(levelname)s | %(message)s")
        formatter.converter = _utc_time_tuple

        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


# Data Models
@dataclass(frozen=True)
class UserRequest:
    username: str
    department: str
    role: str
    password: str


@dataclass(frozen=True)
class RoleConfig:
    permissions: List[str]
    requires_mfa: bool


# Utilities
def load_json_file(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(f"Missing file: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_roles(path: str) -> Dict[str, RoleConfig]:
    raw = load_json_file(path)
    roles: Dict[str, RoleConfig] = {}

    for role_name, cfg in raw.items():
        permissions = cfg.get("permissions", [])
        requires_mfa = bool(cfg.get("requires_mfa", True))

        if not isinstance(permissions, list) or not all(isinstance(x, str) for x in permissions):
            raise ValueError(f"Invalid permissions list for role '{role_name}'")

        roles[role_name] = RoleConfig(
            permissions=permissions,
            requires_mfa=requires_mfa
        )

    return roles


def validate_username(username: str) -> Optional[str]:
    if not re.fullmatch(r"[a-z0-9._]{3,20}", username):
        return "Username must be 3–20 chars and contain only lowercase letters, digits, '.' or '_'"
    return None


def validate_department(dept: str) -> Optional[str]:
    if len(dept.strip()) < 2:
        return "Department must be at least 2 characters"
    return None


def validate_password_strength(password: str) -> Optional[str]:
    rules = [
        (len(password) >= 10, "Password must be at least 10 characters"),
        (re.search(r"[A-Z]", password) is not None, "Password must include an uppercase letter"),
        (re.search(r"[a-z]", password) is not None, "Password must include a lowercase letter"),
        (re.search(r"[0-9]", password) is not None, "Password must include a digit"),
        (re.search(r"[^A-Za-z0-9]", password) is not None, "Password must include a symbol"),
    ]
    failures = [msg for ok, msg in rules if not ok]
    return "; ".join(failures) if failures else None


def parse_user_request_from_dict(data: Dict[str, Any]) -> Tuple[Optional[UserRequest], List[str]]:
    errors: List[str] = []

    username = str(data.get("username", "")).strip()
    department = str(data.get("department", "")).strip()
    role = str(data.get("role", "")).strip()
    password = str(data.get("password", "")).strip()

    if not username:
        errors.append("Missing required field: username")
    if not department:
        errors.append("Missing required field: department")
    if not role:
        errors.append("Missing required field: role")
    if not password:
        errors.append("Missing required field: password")

    if username:
        msg = validate_username(username)
        if msg:
            errors.append(msg)
    if department:
        msg = validate_department(department)
        if msg:
            errors.append(msg)
    if password:
        msg = validate_password_strength(password)
        if msg:
            errors.append(msg)

    if errors:
        return None, errors

    return UserRequest(username=username, department=department, role=role, password=password), []


def print_summary(title: str, lines: List[Tuple[str, str]]) -> None:
    width = max(len(k) for k, _ in lines) if lines else 10
    print(title)
    for k, v in lines:
        print(f"{k:<{width}} : {v}")


# Core Actions
def onboard_user(user: UserRequest, roles: Dict[str, RoleConfig], audit: logging.Logger) -> Dict[str, Any]:
    if user.role not in roles:
        audit.error(f"Rejected onboarding | username={user.username} reason=unknown_role role={user.role}")
        raise ValueError(f"Unknown role '{user.role}'. Valid roles: {', '.join(sorted(roles.keys()))}")

    role_cfg = roles[user.role]

    # Simulated workflow steps (no real systems touched)
    audit.info(f"CreateAccount | username={user.username} department={user.department}")
    audit.info(f"AssignRole | username={user.username} role={user.role}")

    # RBAC permissions (least privilege as defined in roles.json)
    permissions = role_cfg.permissions
    audit.info(f"GrantAccess | username={user.username} permissions={permissions}")

    # MFA policy
    mfa_enabled = bool(role_cfg.requires_mfa)
    audit.info(f"EnforceMFA | username={user.username} enabled={str(mfa_enabled).lower()}")

    # Never log passwords; only log that policy passed.
    audit.info(f"PasswordPolicy | username={user.username} passed=true")

    return {
        "action": "onboard",
        "username": user.username,
        "department": user.department,
        "role": user.role,
        "permissions": permissions,
        "mfa_enabled": mfa_enabled,
    }


def offboard_user(username: str, audit: logging.Logger) -> Dict[str, Any]:
    """
    Offboarding is often more security-critical than onboarding.
    We simulate:
    - disabling account
    - revoking access
    - recording an audit trail
    """
    msg = validate_username(username)
    if msg:
        audit.error(f"Rejected offboarding | username={username} reason=invalid_username")
        raise ValueError(msg)

    # Simulated workflow steps
    audit.info(f"DisableAccount | username={username}")
    audit.info(f"RevokeAccess | username={username} revoked=all")
    audit.info(f"InvalidateSessions | username={username} done=true")

    return {
        "action": "offboard",
        "username": username,
        "revoked": "all",
        "account_disabled": True,
        "sessions_invalidated": True,
    }

# CLI
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Enterprise onboarding/offboarding simulation with RBAC + audit logging."
    )
    p.add_argument("--roles-file", default="roles.json", help="Path to roles JSON (default: roles.json)")
    p.add_argument("--user-file", help="Path to onboarding request JSON (e.g., users.json)")

    # Onboarding via CLI args (if no --user-file)
    p.add_argument("--username", help="Username (lowercase letters/digits/._, 3-20 chars)")
    p.add_argument("--department", help="Department name (e.g., Finance)")
    p.add_argument("--role", help="Role name (must exist in roles.json)")
    p.add_argument("--password", help="Password (min 10 chars, upper/lower/digit/symbol)")

    # Offboarding
    p.add_argument("--offboard", metavar="USERNAME", help="Offboard a user (revoke access + disable account)")

    return p


def main() -> int:
    args = build_arg_parser().parse_args()
    audit = setup_audit_logger("audit.log")

    # Offboarding path
    if args.offboard:
        try:
            summary = offboard_user(args.offboard.strip(), audit)
        except Exception as e:
            print(f"[ERROR] Offboarding failed: {e}", file=sys.stderr)
            return 1

        print("Offboarding Completed Successfully")
        print_summary(
            "Summary",
            [
                ("User", summary["username"]),
                ("Account Disabled", str(summary["account_disabled"])),
                ("Access Revoked", summary["revoked"]),
                ("Sessions Invalidated", str(summary["sessions_invalidated"])),
            ],
        )
        print("\nAudit log written to: audit.log")
        return 0

    # Onboarding path (needs roles + user request)
    try:
        roles = load_roles(args.roles_file)
    except Exception as e:
        print(f"[ERROR] Failed to load roles: {e}", file=sys.stderr)
        return 2

    user_data: Dict[str, Any] = {}
    if args.user_file:
        try:
            user_data = load_json_file(args.user_file)
        except Exception as e:
            print(f"[ERROR] Failed to load user file: {e}", file=sys.stderr)
            return 2
    else:
        user_data = {
            "username": args.username or "",
            "department": args.department or "",
            "role": args.role or "",
            "password": args.password or "",
        }

    user_req, errors = parse_user_request_from_dict(user_data)
    if errors:
        audit.error(f"Rejected onboarding | reason=validation_errors errors={errors}")
        print("[VALIDATION FAILED]")
        for err in errors:
            print(f"- {err}")
        print("\nTip: Try --user-file users.json or pass all required CLI args.")
        return 1

    try:
        summary = onboard_user(user_req, roles, audit)
    except Exception as e:
        print(f"[ERROR] Onboarding failed: {e}", file=sys.stderr)
        return 1

    print("Onboarding Completed Successfully")
    print_summary(
        "Summary",
        [
            ("User", summary["username"]),
            ("Department", summary["department"]),
            ("Role", summary["role"]),
            ("MFA", "Enabled" if summary["mfa_enabled"] else "Disabled"),
            ("Access", ", ".join(summary["permissions"])),
        ],
    )
    print("\nAudit log written to: audit.log")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
