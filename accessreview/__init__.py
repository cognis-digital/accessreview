"""ACCESSREVIEW — periodic user-access-review (UAR) campaign runner.

A zero-dependency engine for SOC 2 / ISO 27001 style periodic access reviews.
Given an entitlements snapshot (who has access to what) plus optional HR roster
and prior-decision context, it builds a review campaign, flags risk findings
(orphaned accounts, terminated users with live access, stale access, separation
of duties / toxic-pair conflicts, privileged grants, over-provisioning), and
produces an auditable revocation work-list.
"""
from .core import (
    Entitlement,
    Person,
    ReviewItem,
    Finding,
    Campaign,
    build_campaign,
    load_entitlements,
    load_roster,
)

TOOL_NAME = "accessreview"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Entitlement",
    "Person",
    "ReviewItem",
    "Finding",
    "Campaign",
    "build_campaign",
    "load_entitlements",
    "load_roster",
    "TOOL_NAME",
    "TOOL_VERSION",
]
