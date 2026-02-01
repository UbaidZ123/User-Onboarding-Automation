#!/usr/bin/env python3
"""
User Onboarding & Access Automation (RBAC + Audit Logging)

This script simulates an enterprise onboarding workflow:
- Loads roles/permissions from roles.json
- Accepts a user request via --user-file or CLI flags
- Validates input and password strength
- Assigns role-based permissions (least privilege)
- Logs all actions for auditability

No external dependencies are needed.
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
def setup_audit_logger(log_path: str = "audit.log") -> logging.Logger:
    logger = logging.getLogger("audit")
    logger.setLevel(logging.INFO)

    # This will avoid duplicate handlers if re-imported/run in some environments
    if not logger.handlers:
        formatter = logging.Formatter("%(asctime)sZ | %(levelname)s | %(message)s")
        formatter.converter = time_gmt  # ensure UTC timestamps in log

        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


def time_gmt(*args):
    # UTC time formatting for consistent audit logs
    return datetime.utcnow().timetuple()


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


def validate_username(username: str) -> Optional[str]:
    # Simple enterprise-style username rule: lowercase letters, digits, dot, underscore; 3-20 chars
    if not re.fullmatch(r"[a-z0-9._]{3,20}", username):
        return "Username must be 3–20 chars and contain only lowercase letters, digits, '.' or '_'"
    return None


def validate_department(dept: str) -> Optional[str]:
    if len(dept.strip()) < 2:
        return "Department must be at least 2 characters"
    return None


def validate_password_strength(password: str) -> Optional[str]:
    # Basic but clear password policy (adjustable)
    rules = [
        (len(password) >= 10, "Password must be at least 10 characters"),
        (re.search(r"[A-Z]", password) is not None, "Password must include an uppercase letter"),
        (re.search(r"[a-z]", password) is not None, "Password must include a lowercase letter"),
        (re.search(r"[0-9]", password) is not None, "Password must include a digit"),
        (re.search(r"[^A-Za-z0-9]", password) is not None, "Password must include a symbol")
    ]
    failures = [msg for ok, msg in rules if not ok]
    if failures:
        return "; ".join(failures)
    return None


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


def load_roles(path: str) -> Dict[str, RoleConfig]:
    raw = load_json_file(path)
    roles: Dict[str, RoleConfig] = {}
    for role_name, cfg in raw.items():
        permissions = cfg.get("permissions", [])
        requires_mfa = bool(cfg.get("requires_mfa", True))

        if not isinstance(permissions, list) or not all(isinstance(x, str) for x in permissions):
            raise ValueError(f"Invalid permissions list for role '{role_name}'")

        roles[role_name] = RoleConfig(permissions=permissions, requires_mfa=requires_mfa)
    return roles


# Onboarding Simulation
def onboard_user(user: UserRequest, roles: Dict[str, RoleConfig], audit: logging.Logger) -> Dict[str, Any]:
    if user.role not in roles:
        audit.error(f"Rejected onboarding for '{user.username}': unknown role '{user.role}'")
        raise ValueError(f"Unknown role '{user.role}'. Valid roles: {', '.join(sorted(roles.keys()))}")

    role_cfg = roles[user.role]

    # Account creation
    audit.info(f"CreateAccount | username={user.username} department={user.department}")
    audit.info(f"AssignRole | username={user.username} role={user.role}")

    # Least privilege via RBAC config
    permissions = role_cfg.permissions
    audit.info(f"GrantAccess | username={user.username} permissions={permissions}")

    # Enforce MFA if required by policy
    if role_cfg.requires_mfa:
        audit.info(f"EnforceMFA | username={user.username} enabled=true")
        mfa_enabled = True
    else:
        audit.info(f"EnforceMFA | username={user.username} enabled=false")
        mfa_enabled = False

    # No logging passwords, only log that password policy passed.
    audit.info(f"PasswordPolicy | username={user.username} passed=true")

    # Return a summary object (for printing / potential future extension)
    return {
        "username": user.username,
        "department": user.department,
        "role": user.role,
        "permissions": permissions,
        "mfa_enabled": mfa_enabled
    }

# CLI
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Simulate user onboarding with RBAC + audit logging (recruiter-friendly mini project)."
    )
    p.add_argument("--roles-file", default="roles.json", help="Path to roles config JSON (default: roles.json)")
    p.add_argument("--user-file", help="Path to a user request JSON (e.g., users.json)")

    p.add_argument("--username", help="Username (lowercase letters/digits/._, 3-20 chars)")
    p.add_argument("--department", help="Department name (e.g., Finance)")
    p.add_argument("--role", help="Role name (must exist in roles.json)")
    p.add_argument("--password", help="Password (min 10 chars, upper/lower/digit/symbol)")

    return p


def main() -> int:
    args = build_arg_parser().parse_args()
    audit = setup_audit_logger("audit.log")

    try:
        roles = load_roles(args.roles_file)
    except Exception as e:
        print(f"[ERROR] Failed to load roles: {e}", file=sys.stderr)
        return 2

    # Input can come from a JSON file or CLI args
    user_data: Dict[str, Any] = {}
    if args.user_file:
        try:
            user_data = load_json_file(args.user_file)
        except Exception as e:
            print(f"[ERROR] Failed to load user file: {e}", file=sys.stderr)
            return 2
    else:
        # Gather from CLI flags
        user_data = {
            "username": args.username or "",
            "department": args.department or "",
            "role": args.role or "",
            "password": args.password or ""
        }

    user_req, errors = parse_user_request_from_dict(user_data)
    if errors:
        audit.error(f"Rejected onboarding: validation errors={errors}")
        print("[VALIDATION FAILED]")
        for err in errors:
            print(f"- {err}")
        print("\nTip: Try running with --user-file users.json or pass all CLI args.")
        return 1

    # Perform onboarding simulation
    try:
        summary = onboard_user(user_req, roles, audit)
    except Exception as e:
        print(f"[ERROR] Onboarding failed: {e}", file=sys.stderr)
        return 1

    # Print a clean summary
    print("Onboarding Completed Successfully")
    print(f"User:       {summary['username']}")
    print(f"Department: {summary['department']}")
    print(f"Role:       {summary['role']}")
    print(f"MFA:        {'Enabled' if summary['mfa_enabled'] else 'Disabled'}")
    print("Access:")
    for perm in summary["permissions"]:
        print(f"  - {perm}")

    print("\nAudit log written to: audit.log")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
