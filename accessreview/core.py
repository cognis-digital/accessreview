"""Core engine for ACCESSREVIEW.

Real logic, standard library only. No stubs.

Input model
-----------
Entitlements snapshot (JSON or CSV) — one row per (user, system, role) grant:
    user_id, user_name, system, role, privileged(bool), last_used(ISO date),
    granted_on(ISO date)

Roster (optional, JSON or CSV) — one row per identity:
    user_id, user_name, department, manager, status(active|terminated|leave),
    title

The engine joins grants to the roster, applies a configurable rule set, and
emits a campaign with per-grant review items + findings + summary stats.
"""
from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field, asdict
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Tuple

# ----- Default policy knobs ------------------------------------------------

STALE_DAYS_DEFAULT = 90          # access unused for >= N days is "stale"
STALE_DAYS_PRIVILEGED = 30       # tighter window for privileged grants

# Separation-of-duties: holding BOTH roles in a pair is a toxic combination.
# Stored as frozensets of role names (case-insensitive comparison).
DEFAULT_SOD_PAIRS: List[Tuple[str, str]] = [
    ("ap_clerk", "ap_approver"),          # create + approve payments
    ("developer", "prod_deployer"),        # write code + push to prod
    ("requestor", "approver"),             # raise + approve requests
    ("vendor_create", "payment_release"),  # add vendor + release payment
    ("user_admin", "auditor"),             # grant access + audit access
]


# ----- Helpers -------------------------------------------------------------

def _parse_date(value: Any) -> Optional[date]:
    if value in (None, "", "null"):
        return None
    if isinstance(value, date) and not isinstance(value, datetime):
        return value
    if isinstance(value, datetime):
        return value.date()
    s = str(value).strip()
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%m/%d/%Y", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    # ISO with timezone / fractional
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in ("1", "true", "yes", "y", "t")


def _days_between(a: Optional[date], b: date) -> Optional[int]:
    if a is None:
        return None
    return (b - a).days


# ----- Data model ----------------------------------------------------------

@dataclass
class Entitlement:
    user_id: str
    system: str
    role: str
    user_name: str = ""
    privileged: bool = False
    last_used: Optional[date] = None
    granted_on: Optional[date] = None

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Entitlement":
        uid = str(d.get("user_id") or d.get("user") or d.get("id") or "").strip()
        if not uid:
            raise ValueError("entitlement row missing user_id")
        system = str(d.get("system") or d.get("app") or d.get("application") or "").strip()
        role = str(d.get("role") or d.get("entitlement") or d.get("permission") or "").strip()
        if not system or not role:
            raise ValueError(f"entitlement for {uid} missing system/role")
        return cls(
            user_id=uid,
            system=system,
            role=role,
            user_name=str(d.get("user_name") or d.get("name") or "").strip(),
            privileged=_as_bool(d.get("privileged") or d.get("admin")),
            last_used=_parse_date(d.get("last_used") or d.get("last_login")),
            granted_on=_parse_date(d.get("granted_on") or d.get("created")),
        )


@dataclass
class Person:
    user_id: str
    user_name: str = ""
    department: str = ""
    manager: str = ""
    title: str = ""
    status: str = "active"  # active | terminated | leave

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Person":
        uid = str(d.get("user_id") or d.get("user") or d.get("id") or "").strip()
        if not uid:
            raise ValueError("roster row missing user_id")
        return cls(
            user_id=uid,
            user_name=str(d.get("user_name") or d.get("name") or "").strip(),
            department=str(d.get("department") or d.get("dept") or "").strip(),
            manager=str(d.get("manager") or "").strip(),
            title=str(d.get("title") or "").strip(),
            status=str(d.get("status") or "active").strip().lower() or "active",
        )


@dataclass
class Finding:
    code: str        # ORPHAN | TERMINATED | STALE | SOD | PRIVILEGED | NO_MANAGER
    severity: str    # critical | high | medium | low
    message: str


@dataclass
class ReviewItem:
    user_id: str
    user_name: str
    system: str
    role: str
    privileged: bool
    department: str
    manager: str
    recommendation: str  # revoke | review | certify
    risk_score: int
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


@dataclass
class Campaign:
    name: str
    as_of: str
    items: List[ReviewItem]
    summary: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "as_of": self.as_of,
            "summary": self.summary,
            "items": [i.to_dict() for i in self.items],
        }


# ----- Loaders -------------------------------------------------------------

def _read_records(text: str, path_hint: str = "") -> List[Dict[str, Any]]:
    """Parse JSON (array or {"items":[...]}) or CSV into list of dicts."""
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("[") or path_hint.endswith(".json"):
        data = json.loads(text)
        if isinstance(data, dict):
            for key in ("items", "entitlements", "grants", "roster", "records", "data"):
                if key in data and isinstance(data[key], list):
                    return data[key]
            raise ValueError("JSON object has no recognized list field")
        if isinstance(data, list):
            return data
        raise ValueError("unsupported JSON shape")
    # CSV
    reader = csv.DictReader(io.StringIO(text))
    return [dict(row) for row in reader]


def load_entitlements(text: str, path_hint: str = "") -> List[Entitlement]:
    return [Entitlement.from_dict(r) for r in _read_records(text, path_hint)]


def load_roster(text: str, path_hint: str = "") -> Dict[str, Person]:
    people = [Person.from_dict(r) for r in _read_records(text, path_hint)]
    return {p.user_id: p for p in people}


# ----- Engine --------------------------------------------------------------

def _normalize_pairs(pairs: List[Tuple[str, str]]) -> List[frozenset]:
    return [frozenset((a.strip().lower(), b.strip().lower())) for a, b in pairs]


def build_campaign(
    entitlements: List[Entitlement],
    roster: Optional[Dict[str, Person]] = None,
    *,
    name: str = "UAR Campaign",
    as_of: Optional[date] = None,
    stale_days: int = STALE_DAYS_DEFAULT,
    stale_days_privileged: int = STALE_DAYS_PRIVILEGED,
    sod_pairs: Optional[List[Tuple[str, str]]] = None,
) -> Campaign:
    """Produce a review campaign from an entitlements snapshot.

    Each grant becomes a ReviewItem with findings, a risk score, and a
    recommendation (revoke / review / certify).
    """
    roster = roster or {}
    as_of = as_of or date.today()
    sod = _normalize_pairs(sod_pairs if sod_pairs is not None else DEFAULT_SOD_PAIRS)

    # roles held per user (lowercased) for SoD evaluation
    roles_by_user: Dict[str, set] = {}
    for e in entitlements:
        roles_by_user.setdefault(e.user_id, set()).add(e.role.strip().lower())

    items: List[ReviewItem] = []
    for e in entitlements:
        person = roster.get(e.user_id)
        findings: List[Finding] = []
        score = 0

        # 1. Orphaned account: grant exists, no roster identity
        if roster and person is None:
            findings.append(Finding("ORPHAN", "high",
                "No HR/identity record found for this account."))
            score += 40

        # 2. Terminated / leave user still holding access
        if person is not None:
            if person.status == "terminated":
                findings.append(Finding("TERMINATED", "critical",
                    "User is marked terminated in HR but still has active access."))
                score += 60
            elif person.status == "leave":
                findings.append(Finding("LEAVE", "medium",
                    "User is on leave; consider suspending access."))
                score += 15
            if not person.manager:
                findings.append(Finding("NO_MANAGER", "low",
                    "No manager assigned; reviewer/approver is ambiguous."))
                score += 5

        # 3. Privileged grant always warrants explicit attention
        if e.privileged:
            findings.append(Finding("PRIVILEGED", "high",
                "Privileged/administrative entitlement requires elevated scrutiny."))
            score += 25

        # 4. Stale access (unused). Tighter window for privileged.
        threshold = stale_days_privileged if e.privileged else stale_days
        idle = _days_between(e.last_used, as_of)
        if idle is None:
            findings.append(Finding("STALE", "medium",
                "No last-used timestamp recorded; usage cannot be confirmed."))
            score += 20
        elif idle >= threshold:
            sev = "high" if e.privileged else "medium"
            findings.append(Finding("STALE", sev,
                f"Access unused for {idle} days (threshold {threshold})."))
            score += 30 if e.privileged else 20

        # 5. Separation of duties / toxic role pairs
        held = roles_by_user.get(e.user_id, set())
        this_role = e.role.strip().lower()
        for pair in sod:
            if this_role in pair and pair.issubset(held):
                other = next(iter(pair - {this_role}), this_role)
                findings.append(Finding("SOD", "high",
                    f"Separation-of-duties conflict: also holds '{other}'."))
                score += 35
                break

        # Recommendation from severity of findings
        codes = {f.code for f in findings}
        sevs = {f.severity for f in findings}
        if codes & {"TERMINATED", "ORPHAN"} or "critical" in sevs:
            rec = "revoke"
        elif findings:
            rec = "review"
        else:
            rec = "certify"

        items.append(ReviewItem(
            user_id=e.user_id,
            user_name=e.user_name or (person.user_name if person else ""),
            system=e.system,
            role=e.role,
            privileged=e.privileged,
            department=person.department if person else "",
            manager=person.manager if person else "",
            recommendation=rec,
            risk_score=min(score, 100),
            findings=findings,
        ))

    # Sort: highest risk first, then revoke before review before certify
    rec_order = {"revoke": 0, "review": 1, "certify": 2}
    items.sort(key=lambda i: (rec_order.get(i.recommendation, 3), -i.risk_score))

    summary = _summarize(items, as_of)
    return Campaign(name=name, as_of=as_of.isoformat(), items=items, summary=summary)


def _summarize(items: List[ReviewItem], as_of: date) -> Dict[str, Any]:
    by_rec: Dict[str, int] = {"revoke": 0, "review": 0, "certify": 0}
    by_finding: Dict[str, int] = {}
    users = set()
    systems = set()
    privileged = 0
    for i in items:
        by_rec[i.recommendation] = by_rec.get(i.recommendation, 0) + 1
        users.add(i.user_id)
        systems.add(i.system)
        if i.privileged:
            privileged += 1
        for f in i.findings:
            by_finding[f.code] = by_finding.get(f.code, 0) + 1
    flagged = by_rec["revoke"] + by_rec["review"]
    total = len(items)
    return {
        "total_grants": total,
        "distinct_users": len(users),
        "distinct_systems": len(systems),
        "privileged_grants": privileged,
        "by_recommendation": by_rec,
        "by_finding": dict(sorted(by_finding.items())),
        "flagged_grants": flagged,
        "clean_pct": round(100.0 * (total - flagged) / total, 1) if total else 0.0,
    }
