"""Safety and API tests for the local AuthTrace control center."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

import control_center


class TargetSafetyTests(unittest.TestCase):
    def test_only_loopback_http_is_allowed(self):
        self.assertEqual(control_center.safe_local_target("http://127.0.0.1:8000/"),
                         "http://127.0.0.1:8000")
        self.assertEqual(control_center.safe_local_target("http://localhost:8000"),
                         "http://localhost:8000")

    def test_external_target_is_rejected(self):
        with self.assertRaises(HTTPException) as caught:
            control_center.safe_local_target("https://example.com")
        self.assertEqual(caught.exception.status_code, 400)

    def test_credentials_query_fragment_and_path_are_rejected(self):
        targets = [
            "http://user:pass@127.0.0.1:8000",
            "http://127.0.0.1:8000/?token=secret",
            "http://127.0.0.1:8000/#fragment",
            "http://127.0.0.1:8000/api",
        ]
        for target in targets:
            with self.subTest(target=target), self.assertRaises(HTTPException):
                control_center.safe_local_target(target)


class PolicyApiTests(unittest.TestCase):
    def test_policy_diff_uses_existing_pipeline(self):
        result = control_center.policy_diff()
        self.assertIn("changes", result)
        self.assertIn("old_sha256", result)
        self.assertIn("new_sha256", result)
        self.assertTrue(all("risk_score" in item for item in result["changes"]))

    def test_checked_in_policy_v2_is_default_when_no_local_proposal_exists(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(control_center, "PROPOSAL_PATH", Path(directory) / "policy.proposed.json"):
                result = control_center.get_policies()
        self.assertEqual(result["proposal_source"], "policy.v2.json")
        self.assertEqual(result["proposal"]["policy_version"], "2.0")

    def test_regression_plan_is_explicitly_planned_not_executed(self):
        result = control_center.regression_plan()
        self.assertTrue(result["planned_only"])
        self.assertIn("selected_tests", result)
        self.assertIn("unmapped_rules", result)

    def test_policy_validation_endpoint_rejects_missing_expected_outcome(self):
        policy = control_center.read_json(control_center.ROOT / "policy.json")
        policy["rules"][0].pop("expected")
        with self.assertRaises(HTTPException) as caught:
            control_center.validate_submitted_policy(control_center.PolicySubmission(policy=policy))
        self.assertEqual(caught.exception.status_code, 422)
        self.assertIn("expected", caught.exception.detail)

    def test_policy_submission_saves_proposal_without_overwriting_baseline(self):
        policy = control_center.read_json(control_center.ROOT / "policy.json")
        baseline_bytes = (control_center.ROOT / "policy.json").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            proposal_path = Path(directory) / "policy.proposed.json"
            with patch.object(control_center, "PROPOSAL_PATH", proposal_path):
                result = control_center.submit_policy(control_center.PolicySubmission(policy=policy))
                self.assertTrue(result["saved"])
                self.assertEqual(json.loads(proposal_path.read_text(encoding="utf-8")), policy)
        self.assertEqual((control_center.ROOT / "policy.json").read_bytes(), baseline_bytes)

    def test_run_history_keeps_report_associated_with_its_run(self):
        module = control_center.pipeline_module()
        nodeid = "test_authorization.py::test_cross_user_access_matches_declared_mode"
        evidence = {"expected": "allow", "observed": "deny", "http_status": 404,
                    "policy_match": False, "security_invariant_violated": False,
                    "classification": "POLICY_MISMATCH"}
        checks = [{"test_nodeids": [nodeid], "rule_ids": ["INV-READ-OTHER"],
                   "verdict": "POLICY_MISMATCH", "duration_seconds": 0.01,
                   "evidence": evidence, "error_class": "OBSERVED_BEHAVIOR_DIFFERS_FROM_POLICY"}]
        with tempfile.TemporaryDirectory() as directory:
            report_dir = Path(directory)
            db_path = report_dir / "history.db"
            with patch.object(control_center, "REPORT_DIR", report_dir), \
                 patch.object(control_center, "DB_PATH", db_path), \
                 patch.object(module, "run_selected", return_value=(checks, 1, "POLICY_MISMATCH")):
                control_center.init_db()
                run = control_center.start_run(control_center.RunRequest(confirm_local_target=True))
                detail = control_center.get_run(run["id"])
                self.assertEqual(detail["report"]["run_id"], run["id"])
                self.assertEqual(detail["report"]["checks"][0]["evidence"], evidence)
                self.assertEqual(detail["report"]["checks"][0]["rule_ids"], ["INV-READ-OTHER"])
                self.assertTrue(detail["report"]["baseline_sha256"])
                self.assertTrue(detail["report"]["proposal_sha256"])

    def test_invalid_json_reports_a_readable_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.json"
            path.write_text("{broken", encoding="utf-8")
            with patch.object(control_center, "ROOT", Path(directory)):
                with self.assertRaises(HTTPException) as caught:
                    control_center.read_json(path)
            self.assertEqual(caught.exception.status_code, 422)
            self.assertIn("line", caught.exception.detail)


if __name__ == "__main__":
    unittest.main()
