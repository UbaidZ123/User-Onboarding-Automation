# User Onboarding & Access Automation (RBAC + Audit Logging)

## Problem
Manual user onboarding is error-prone and can lead to excessive access, missed security steps, and inconsistent account setup.

## Solution
A small Python CLI tool that simulates enterprise onboarding:
- validates a new user request
- assigns role-based access (RBAC)
- logs every action for auditability

## Tech Stack
- Python 3
- JSON (configuration + input)
- Python logging (audit trail)

## Key Features
- Role-Based Access Control (RBAC) via `roles.json`
- Input validation (missing fields, invalid role, weak password)
- Audit logging to `audit.log`
- Clear CLI output suitable for demoing in interviews

## How to run

### Option A: Onboard the sample user from `users.json`
```bash
python onboard_user.py --user-file users.json
