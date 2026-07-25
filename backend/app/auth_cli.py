"""
auth_cli.py - operator CLI for authenticated-testing approval and session
credentials (build-order item #3, part 2).

Plain-language: this is the ONLY intended way to move a project out of
the default-deny state or register a session credential. Deliberately a
standalone CLI you run by hand on the box, not a FastAPI endpoint - a
credential-management HTTP endpoint is new attack surface on a tool that
already sits on the public internet (OCI), for a feature whose entire
point is protecting live bug-bounty account credentials. A CLI you SSH
in and run has no such exposure. API endpoints can be added later if
this genuinely becomes a bottleneck, but that's a deliberate future
decision, not a default.

Usage (run from backend/, same as the other app.* scripts in this repo):
    python3 -m app.auth_cli list-projects
    python3 -m app.auth_cli status --project-id 5
    python3 -m app.auth_cli approve --project-id 5 --by yash \\
        --note "program's VDP section 4.2 permits automated multi-account testing"
    python3 -m app.auth_cli deny --project-id 5 --by yash --note "no mention in policy, asked, no response yet"
    python3 -m app.auth_cli add-session --project-id 5 --name user_a --type cookie \\
        --notes "free-tier account"
        (prompts for the credential value via getpass - never as a CLI arg, so it
         never ends up in shell history or `ps`/process-list output)
    python3 -m app.auth_cli list-sessions --project-id 5
    python3 -m app.auth_cli delete-session --project-id 5 --name user_a

Every subcommand opens one connection, does one thing, closes it - this
is an occasional manual operation, not a hot path, so there's no pool
here.
"""

import argparse
import asyncio
import getpass
import os

import asyncpg

from . import auth_policy, auth_sessions


async def _connect() -> asyncpg.Connection:
    return await asyncpg.connect(os.environ["DATABASE_URL"])


async def cmd_list_projects(_args) -> None:
    conn = await _connect()
    try:
        rows = await conn.fetch(
            """
            SELECT p.id, p.name, p.platform, p.status,
                   COALESCE(a.status, 'unset') AS auth_status
            FROM projects p
            LEFT JOIN project_auth_policy a ON a.project_id = p.id
            ORDER BY p.id
            """
        )
        if not rows:
            print("No projects found.")
            return
        for r in rows:
            print(f"  [{r['id']}] {r['name']} ({r['platform']}, {r['status']}) - auth_policy: {r['auth_status']}")
    finally:
        await conn.close()


async def cmd_status(args) -> None:
    conn = await _connect()
    try:
        policy = await auth_policy.get_policy(conn, args.project_id)
        print(f"project_id={args.project_id}")
        print(f"  auth_policy status: {policy['status']}")
        if policy["set_by"]:
            print(f"  set by {policy['set_by']} at {policy['set_at']}")
        if policy["policy_note"]:
            print(f"  note: {policy['policy_note']}")
        sessions = await auth_sessions.list_sessions(conn, args.project_id)
        if sessions:
            print("  sessions:")
            for s in sessions:
                last_used = s["last_used_at"] or "never"
                print(f"    - {s['session_name']} ({s['session_type']}) - last used: {last_used}")
        else:
            print("  sessions: none registered")
    finally:
        await conn.close()


async def cmd_approve(args) -> None:
    conn = await _connect()
    try:
        await auth_policy.set_policy(conn, args.project_id, "approved", args.note, args.by)
        print(f"project_id={args.project_id} set to APPROVED by {args.by}.")
    finally:
        await conn.close()


async def cmd_deny(args) -> None:
    conn = await _connect()
    try:
        await auth_policy.set_policy(conn, args.project_id, "denied", args.note, args.by)
        print(f"project_id={args.project_id} set to DENIED by {args.by}.")
    finally:
        await conn.close()


async def cmd_add_session(args) -> None:
    if not os.environ.get("SWAS_SESSION_KEY"):
        raise SystemExit("SWAS_SESSION_KEY is not set in this shell - set it before adding a session.")
    if args.type == "header" and not args.header_name:
        raise SystemExit("--header-name is required when --type header")

    value = getpass.getpass(f"Paste the {args.type} value for session '{args.name}' (input hidden): ")
    if not value.strip():
        raise SystemExit("Empty value entered, aborting.")

    conn = await _connect()
    try:
        await auth_sessions.store_session(
            conn, args.project_id, args.name, value,
            session_type=args.type, header_name=args.header_name, notes=args.notes,
        )
        print(f"Session '{args.name}' stored for project_id={args.project_id}.")
    except auth_policy.AuthPolicyError as exc:
        raise SystemExit(
            f"Blocked: {exc}\nRun 'auth_cli approve --project-id {args.project_id} ...' first."
        )
    finally:
        await conn.close()


async def cmd_list_sessions(args) -> None:
    conn = await _connect()
    try:
        sessions = await auth_sessions.list_sessions(conn, args.project_id)
        if not sessions:
            print("No sessions registered for this project.")
            return
        for s in sessions:
            print(f"  {s['session_name']} ({s['session_type']}) - notes: {s['notes'] or '(none)'}")
    finally:
        await conn.close()


async def cmd_delete_session(args) -> None:
    conn = await _connect()
    try:
        await auth_sessions.delete_session(conn, args.project_id, args.name)
        print(f"Session '{args.name}' deleted for project_id={args.project_id} (if it existed).")
    finally:
        await conn.close()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auth_cli")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list-projects").set_defaults(func=cmd_list_projects)

    p = sub.add_parser("status")
    p.add_argument("--project-id", type=int, required=True)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("approve")
    p.add_argument("--project-id", type=int, required=True)
    p.add_argument("--by", required=True, help="who is approving this - accountability trail")
    p.add_argument("--note", required=True, help="what in the program's policy makes this OK")
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("deny")
    p.add_argument("--project-id", type=int, required=True)
    p.add_argument("--by", required=True)
    p.add_argument("--note", required=True)
    p.set_defaults(func=cmd_deny)

    p = sub.add_parser("add-session")
    p.add_argument("--project-id", type=int, required=True)
    p.add_argument("--name", required=True, help="operator label, e.g. user_a")
    p.add_argument("--type", choices=["cookie", "bearer_token", "header"], default="cookie")
    p.add_argument("--header-name", default=None, help="required if --type header, e.g. X-Api-Key")
    p.add_argument("--notes", default=None)
    p.set_defaults(func=cmd_add_session)

    p = sub.add_parser("list-sessions")
    p.add_argument("--project-id", type=int, required=True)
    p.set_defaults(func=cmd_list_sessions)

    p = sub.add_parser("delete-session")
    p.add_argument("--project-id", type=int, required=True)
    p.add_argument("--name", required=True)
    p.set_defaults(func=cmd_delete_session)

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    asyncio.run(args.func(args))


if __name__ == "__main__":
    main()
