"""Command-line interface for ACCESSREVIEW.

Subcommands:
    run       Build a review campaign from an entitlements snapshot.
    revoke    Emit the revocation work-list (grants recommended for removal).
    summary   Print campaign summary statistics only.

Global:
    --version
    --format {table,json}
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    build_campaign,
    load_entitlements,
    load_roster,
    _parse_date,
)


def _read_file(path: str) -> str:
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _build(args) -> object:
    ents = load_entitlements(_read_file(args.entitlements), args.entitlements)
    roster = None
    if args.roster:
        roster = load_roster(_read_file(args.roster), args.roster)
    as_of = None
    if args.as_of:
        as_of = _parse_date(args.as_of)
        if as_of is None:
            print(
                f"error: --as-of value {args.as_of!r} is not a recognisable date "
                "(expected YYYY-MM-DD)",
                file=sys.stderr,
            )
            raise SystemExit(2)
    if args.stale_days <= 0:
        print(
            f"error: --stale-days must be a positive integer, got {args.stale_days}",
            file=sys.stderr,
        )
        raise SystemExit(2)
    return build_campaign(
        ents,
        roster,
        name=args.name,
        as_of=as_of,
        stale_days=args.stale_days,
    )


def _print_table(rows: List[List[str]], headers: List[str]) -> None:
    widths = [len(h) for h in headers]
    for r in rows:
        for idx, cell in enumerate(r):
            widths[idx] = max(widths[idx], len(str(cell)))
    line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(line)
    print("  ".join("-" * widths[i] for i in range(len(headers))))
    for r in rows:
        print("  ".join(str(c).ljust(widths[i]) for i, c in enumerate(r)))


def _emit_campaign(campaign, fmt: str, only_revoke: bool = False) -> None:
    items = campaign.items
    if only_revoke:
        items = [i for i in items if i.recommendation == "revoke"]
    if fmt == "json":
        payload = campaign.to_dict()
        if only_revoke:
            payload["items"] = [i.to_dict() for i in items]
        print(json.dumps(payload, indent=2))
        return
    s = campaign.summary
    print(f"{campaign.name}  (as of {campaign.as_of})")
    print(f"grants={s['total_grants']} users={s['distinct_users']} "
          f"systems={s['distinct_systems']} flagged={s['flagged_grants']} "
          f"clean={s['clean_pct']}%")
    print()
    rows = []
    for i in items:
        codes = ",".join(sorted({f.code for f in i.findings})) or "-"
        rows.append([
            i.recommendation.upper(),
            i.risk_score,
            i.user_id,
            i.system,
            i.role,
            "P" if i.privileged else "-",
            codes,
        ])
    _print_table(rows, ["ACTION", "RISK", "USER", "SYSTEM", "ROLE", "PRV", "FINDINGS"])


def _emit_summary(campaign, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps({"name": campaign.name, "as_of": campaign.as_of,
                          "summary": campaign.summary}, indent=2))
        return
    s = campaign.summary
    print(f"{campaign.name}  (as of {campaign.as_of})")
    rows = [[k, v] for k, v in s.items() if not isinstance(v, dict)]
    _print_table([[k, json.dumps(v) if isinstance(v, (list, dict)) else v]
                  for k, v in rows], ["METRIC", "VALUE"])
    for label in ("by_recommendation", "by_finding"):
        print()
        print(label + ":")
        for k, v in s[label].items():
            print(f"  {k}: {v}")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Periodic user-access-review (UAR) campaign runner.",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json"], default="table")
    sub = p.add_subparsers(dest="command", required=True)

    def add_common(sp):
        sp.add_argument("entitlements", help="Entitlements snapshot (JSON or CSV)")
        sp.add_argument("--roster", help="HR roster file (JSON or CSV)")
        sp.add_argument("--name", default="UAR Campaign")
        sp.add_argument("--as-of", dest="as_of", help="Review date (YYYY-MM-DD)")
        sp.add_argument("--stale-days", type=int, default=90)

    add_common(sub.add_parser("run", help="Build a full review campaign"))
    add_common(sub.add_parser("revoke", help="Revocation work-list only"))
    add_common(sub.add_parser("summary", help="Summary statistics only"))
    return p


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        campaign = _build(args)
    except SystemExit as exc:
        code = exc.code
        return int(code) if isinstance(code, int) else 2
    except FileNotFoundError as exc:
        filename = getattr(exc, "filename", None) or str(exc)
        print(f"error: file not found: {filename}", file=sys.stderr)
        return 2
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # unexpected I/O or encoding error
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.command == "run":
        _emit_campaign(campaign, args.format)
        # Non-zero exit when any grant must be revoked (CI/audit gate).
        return 1 if campaign.summary["by_recommendation"]["revoke"] else 0
    if args.command == "revoke":
        _emit_campaign(campaign, args.format, only_revoke=True)
        return 1 if campaign.summary["by_recommendation"]["revoke"] else 0
    if args.command == "summary":
        _emit_summary(campaign, args.format)
        return 0
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
