"""
scripts/init_admin.py — First-run admin setup
=============================================

Creates an initial administrator account for the API. Replaces the previous
hard-coded ``DEFAULT_USERS`` table that shipped with well-known credentials.

Usage::

    python -m scripts.init_admin                  # interactive prompt
    python -m scripts.init_admin --user alice --password 'Strong!Pa$$w0rd'

The credentials are stored in ``data/config.json`` under ``api.users.<name>``
with bcrypt-hashed passwords.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from datetime import datetime, timezone
from pathlib import Path

# Allow running as a plain script (``python scripts/init_admin.py``) too.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def _validate_password(pwd: str) -> str:
    if len(pwd) < 12:
        raise SystemExit("Password must be at least 12 characters long.")
    classes = sum(
        bool(any(c in s for c in pwd))
        for s in (
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "0123456789",
            "!@#$%^&*()-_=+[]{};:,.?/<>",
        )
    )
    if classes < 3:
        raise SystemExit(
            "Password must contain at least 3 of: lowercase, uppercase, digit, symbol."
        )
    return pwd


def _prompt_password() -> str:
    while True:
        pwd = getpass.getpass("New admin password: ")
        confirm = getpass.getpass("Confirm password: ")
        if pwd != confirm:
            print("Passwords do not match, please try again.\n")
            continue
        return _validate_password(pwd)


def main() -> int:
    parser = argparse.ArgumentParser(description="Initialize an admin user for the API")
    parser.add_argument("--user", default="admin", help="Username (default: admin)")
    parser.add_argument("--password", help="Password (omit to be prompted securely)")
    parser.add_argument(
        "--role", choices=("admin", "reader"), default="admin", help="Role"
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Overwrite the user if it already exists",
    )
    args = parser.parse_args()

    from api.auth import get_password_hash
    from core.config_manager import config

    users = config.get("api.users", {}) or {}
    if args.user in users and not args.force:
        print(
            f"User {args.user!r} already exists. Re-run with --force to overwrite "
            "or pick another --user.",
            file=sys.stderr,
        )
        return 2

    password = args.password or _prompt_password()
    if args.password:
        # Still enforce strength when supplied via argv
        _validate_password(args.password)

    hashed = get_password_hash(password)
    users[args.user] = {
        "username": args.user,
        "hashed_password": hashed,
        "role": args.role,
        "disabled": False,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    if not config.set("api.users", users, persist=True):
        print("Failed to persist users to data/config.json", file=sys.stderr)
        return 1

    print(f"User {args.user!r} ({args.role}) saved to data/config.json.")
    print(
        "Next steps:\n"
        "  1. Set RANSOMWARE_JWT_SECRET env var (recommended for prod):\n"
        "     PowerShell -> $env:RANSOMWARE_JWT_SECRET = 'long-random-string'\n"
        "     cmd        -> set RANSOMWARE_JWT_SECRET=long-random-string\n"
        "  2. Start the API:\n"
        "     python -m api.main --host 127.0.0.1 --port 8000"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
