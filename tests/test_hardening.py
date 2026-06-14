"""Hardening tests: edge-cases, bad input, and error paths.

These tests cover paths added by the production-hardening pass:
  - empty input collections
  - malformed / invalid JSON
  - missing required fields in entitlement / roster rows
  - invalid CLI arguments (bad --as-of, zero --stale-days)
  - missing input file -> exit 2
  - stale_days validation in build_campaign
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from accessreview.core import (
    load_entitlements,
    load_roster,
    build_campaign,
    _read_records,
    TOOL_NAME,
    TOOL_VERSION,
)
from accessreview.cli import main


# ---------------------------------------------------------------------------
# core._read_records / loaders
# ---------------------------------------------------------------------------

class TestReadRecordsEdgeCases(unittest.TestCase):
    def test_empty_string_returns_empty_list(self):
        self.assertEqual(_read_records(""), [])

    def test_whitespace_only_returns_empty_list(self):
        self.assertEqual(_read_records("   \n  "), [])

    def test_empty_json_array_returns_empty_list(self):
        self.assertEqual(_read_records("[]"), [])

    def test_malformed_json_raises_value_error(self):
        with self.assertRaises(ValueError) as cm:
            _read_records("{bad json", "data.json")
        self.assertIn("invalid JSON", str(cm.exception))

    def test_json_object_no_list_field_raises(self):
        with self.assertRaises(ValueError) as cm:
            _read_records('{"foo": "bar"}', "data.json")
        self.assertIn("recognized list field", str(cm.exception))

    def test_json_scalar_raises_value_error(self):
        with self.assertRaises(ValueError) as cm:
            _read_records('42', "data.json")
        self.assertIn("unsupported JSON shape", str(cm.exception))

    def test_csv_header_only_returns_empty_list(self):
        self.assertEqual(_read_records("user_id,system,role\n"), [])


class TestLoadEntitlementsEdgeCases(unittest.TestCase):
    def test_empty_list_returns_empty(self):
        result = load_entitlements("[]")
        self.assertEqual(result, [])

    def test_missing_user_id_raises_with_row_context(self):
        data = json.dumps([{"system": "AWS", "role": "admin"}])
        with self.assertRaises(ValueError) as cm:
            load_entitlements(data)
        self.assertIn("row 0", str(cm.exception))

    def test_missing_system_raises_with_row_context(self):
        data = json.dumps([{"user_id": "u1", "role": "admin"}])
        with self.assertRaises(ValueError) as cm:
            load_entitlements(data)
        self.assertIn("row 0", str(cm.exception))

    def test_malformed_json_raises_clear_message(self):
        with self.assertRaises(ValueError) as cm:
            load_entitlements("{not valid}")
        self.assertIn("invalid JSON", str(cm.exception))


class TestLoadRosterEdgeCases(unittest.TestCase):
    def test_empty_input_returns_empty_dict(self):
        result = load_roster("[]")
        self.assertEqual(result, {})

    def test_missing_user_id_raises_with_row_context(self):
        data = json.dumps([{"user_name": "Alice", "department": "Eng"}])
        with self.assertRaises(ValueError) as cm:
            load_roster(data)
        self.assertIn("row 0", str(cm.exception))


# ---------------------------------------------------------------------------
# build_campaign edge cases
# ---------------------------------------------------------------------------

class TestBuildCampaignEdgeCases(unittest.TestCase):
    def test_empty_entitlements_produces_empty_campaign(self):
        campaign = build_campaign([])
        self.assertEqual(campaign.items, [])
        s = campaign.summary
        self.assertEqual(s["total_grants"], 0)
        self.assertEqual(s["flagged_grants"], 0)
        self.assertEqual(s["clean_pct"], 0.0)

    def test_invalid_stale_days_zero_raises(self):
        with self.assertRaises(ValueError) as cm:
            build_campaign([], stale_days=0)
        self.assertIn("stale_days", str(cm.exception))

    def test_invalid_stale_days_negative_raises(self):
        with self.assertRaises(ValueError) as cm:
            build_campaign([], stale_days=-5)
        self.assertIn("stale_days", str(cm.exception))

    def test_invalid_stale_days_privileged_zero_raises(self):
        with self.assertRaises(ValueError) as cm:
            build_campaign([], stale_days_privileged=0)
        self.assertIn("stale_days_privileged", str(cm.exception))

    def test_risk_score_bounded_on_worst_case(self):
        """A grant with every bad flag should still not exceed 100."""
        from accessreview.core import Entitlement, Person
        from datetime import date

        ent = Entitlement(
            user_id="u_bad",
            system="AWS",
            role="user_admin",
            privileged=True,
            last_used=None,
            granted_on=None,
        )
        ent2 = Entitlement(
            user_id="u_bad",
            system="SIEM",
            role="auditor",
            privileged=False,
            last_used=None,
            granted_on=None,
        )
        roster = {
            "u_bad": Person(
                user_id="u_bad",
                status="terminated",
                manager="",
            )
        }
        campaign = build_campaign([ent, ent2], roster, as_of=date(2026, 6, 30))
        for item in campaign.items:
            self.assertLessEqual(item.risk_score, 100)


# ---------------------------------------------------------------------------
# CLI argument validation
# ---------------------------------------------------------------------------

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic")
ENTS = os.path.join(DEMO, "entitlements.json")
ROSTER = os.path.join(DEMO, "roster.csv")


class TestCLIHardening(unittest.TestCase):
    def test_missing_entitlements_file_returns_exit_2(self):
        rc = main(["run", "nonexistent_file.json"])
        self.assertEqual(rc, 2)

    def test_bad_as_of_date_returns_exit_2(self):
        rc = main(["run", ENTS, "--as-of", "not-a-date"])
        self.assertEqual(rc, 2)

    def test_stale_days_zero_returns_exit_2(self):
        rc = main(["run", ENTS, "--stale-days", "0"])
        self.assertEqual(rc, 2)

    def test_stale_days_negative_returns_exit_2(self):
        rc = main(["run", ENTS, "--stale-days", "-10"])
        self.assertEqual(rc, 2)

    def test_malformed_json_entitlements_returns_exit_2(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("{this is not valid json")
            tmp_name = fh.name
        try:
            rc = main(["run", tmp_name])
            self.assertEqual(rc, 2)
        finally:
            os.unlink(tmp_name)

    def test_missing_roster_file_returns_exit_2(self):
        rc = main(["revoke", ENTS, "--roster", "does_not_exist.csv"])
        self.assertEqual(rc, 2)


# ---------------------------------------------------------------------------
# Package identity now exported from core
# ---------------------------------------------------------------------------

class TestPackageIdentity(unittest.TestCase):
    def test_tool_name_and_version_exported_from_core(self):
        self.assertEqual(TOOL_NAME, "accessreview")
        self.assertIsInstance(TOOL_VERSION, str)
        self.assertTrue(TOOL_VERSION)


if __name__ == "__main__":
    unittest.main()
