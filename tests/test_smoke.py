"""Smoke tests for ACCESSREVIEW. Standard library only, no network."""
import json
import os
import sys
import unittest
from datetime import date

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from accessreview import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    build_campaign,
    load_entitlements,
    load_roster,
)
from accessreview.cli import main  # noqa: E402

DEMO = os.path.join(os.path.dirname(__file__), "..", "demos", "01-basic")
ENTS = os.path.join(DEMO, "entitlements.json")
ROSTER = os.path.join(DEMO, "roster.csv")
AS_OF = "2026-06-30"


def _load():
    with open(ENTS, encoding="utf-8") as fh:
        ents = load_entitlements(fh.read(), ENTS)
    with open(ROSTER, encoding="utf-8") as fh:
        roster = load_roster(fh.read(), ROSTER)
    return ents, roster


class TestMeta(unittest.TestCase):
    def test_version(self):
        self.assertEqual(TOOL_NAME, "accessreview")
        self.assertTrue(TOOL_VERSION)


class TestEngine(unittest.TestCase):
    def setUp(self):
        ents, roster = _load()
        self.campaign = build_campaign(
            ents, roster, as_of=date(2026, 6, 30), stale_days=90)
        self.by_user = {}
        for it in self.campaign.items:
            self.by_user.setdefault(it.user_id, []).append(it)

    def _findings(self, user_id):
        codes = set()
        for it in self.by_user.get(user_id, []):
            codes.update(f.code for f in it.findings)
        return codes

    def test_terminated_user_revoked(self):
        for it in self.by_user["u_carol"]:
            self.assertEqual(it.recommendation, "revoke")
        self.assertIn("TERMINATED", self._findings("u_carol"))

    def test_orphan_detected(self):
        self.assertIn("ORPHAN", self._findings("u_ghost"))
        for it in self.by_user["u_ghost"]:
            self.assertEqual(it.recommendation, "revoke")

    def test_sod_conflict(self):
        self.assertIn("SOD", self._findings("u_alice"))

    def test_stale_privileged(self):
        # Dave's AWS admin unused since 2025-12-10 (> 30d privileged window)
        self.assertIn("STALE", self._findings("u_dave"))
        self.assertIn("PRIVILEGED", self._findings("u_dave"))

    def test_clean_user_certified(self):
        for it in self.by_user["u_bob"]:
            self.assertEqual(it.recommendation, "certify")
            self.assertEqual(it.findings, [])

    def test_summary_counts(self):
        s = self.campaign.summary
        self.assertEqual(s["total_grants"], 11)
        self.assertEqual(s["distinct_users"], 6)
        self.assertGreater(s["by_recommendation"]["revoke"], 0)
        self.assertGreaterEqual(s["flagged_grants"], 1)

    def test_risk_scores_bounded(self):
        for it in self.campaign.items:
            self.assertGreaterEqual(it.risk_score, 0)
            self.assertLessEqual(it.risk_score, 100)


class TestCSVEntitlements(unittest.TestCase):
    def test_csv_parse(self):
        csv_text = (
            "user_id,system,role,privileged,last_used\n"
            "u1,AWS,admin,true,2020-01-01\n"
        )
        ents = load_entitlements(csv_text)
        self.assertEqual(len(ents), 1)
        self.assertTrue(ents[0].privileged)


class TestCLI(unittest.TestCase):
    def test_run_nonzero_on_revoke(self):
        rc = main(["--format", "json", "run", ENTS, "--roster", ROSTER,
                   "--as-of", AS_OF])
        self.assertEqual(rc, 1)  # terminated + orphan present

    def test_summary_zero_exit(self):
        rc = main(["summary", ENTS, "--roster", ROSTER, "--as-of", AS_OF])
        self.assertEqual(rc, 0)

    def test_json_output_valid(self):
        from io import StringIO
        buf, old = StringIO(), sys.stdout
        sys.stdout = buf
        try:
            main(["--format", "json", "revoke", ENTS, "--roster", ROSTER,
                  "--as-of", AS_OF])
        finally:
            sys.stdout = old
        payload = json.loads(buf.getvalue())
        self.assertIn("items", payload)
        self.assertTrue(all(i["recommendation"] == "revoke"
                            for i in payload["items"]))

    def test_missing_file_exit_2(self):
        rc = main(["run", "does_not_exist.json"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
