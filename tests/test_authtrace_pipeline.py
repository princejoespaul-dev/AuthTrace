import html
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from authtrace_pipeline import (
    build_plan,
    diff_policies,
    render_dashboard,
    risk_score,
    run_selected,
    safe_target,
    validate_mapping,
    validate_mapping_rule_ids,
    validate_nodeid_paths,
    validate_policy,
)


class PolicyPipelineTests(unittest.TestCase):
    def setUp(self):
        self.old = {"policy_version": "1", "rules": [
            {"id": "A", "expected": "deny", "condition": "owner == actor"},
            {"id": "B", "expected": "allow"},
        ]}
        self.new = {"policy_version": "2", "rules": [
            {"id": "A", "expected": "allow", "condition": "owner == actor"},
            {"id": "C", "expected": "deny"},
        ]}

    def test_diff_detects_modified_added_and_removed_rules(self):
        changes = diff_policies(self.old, self.new)
        self.assertEqual([(c["rule_id"], c["change"]) for c in changes], [
            ("A", "modified"), ("B", "removed"), ("C", "added")
        ])
        self.assertIn("expected", changes[0]["changed_fields"])

    def test_allowing_previously_denied_action_is_high_risk(self):
        change = diff_policies(self.old, self.new)[0]
        self.assertGreaterEqual(risk_score(change), 7)

    def test_allow_to_deny_is_detected(self):
        change = diff_policies(
            {"rules": [{"id": "A", "expected": "allow"}]},
            {"rules": [{"id": "A", "expected": "deny"}]},
        )[0]
        self.assertEqual(change["change"], "modified")
        self.assertGreater(risk_score(change), 1)

    def test_identical_policies_have_no_changes(self):
        self.assertEqual(diff_policies(self.old, self.old), [])

    def test_plan_prioritizes_risk_and_deduplicates_tests(self):
        changes = diff_policies(self.old, self.new)
        mapping = {"mappings": [
            {"policy_rule_ids": ["A"], "test_nodeids": ["tests/test_a.py::test_a", "tests/test_a.py::test_shared"]},
            {"policy_rule_ids": ["B"], "test_nodeids": ["tests/test_b.py::test_b", "tests/test_a.py::test_shared"]},
        ]}
        plan = build_plan(changes, mapping)
        self.assertEqual(plan["selected_tests"], [
            "tests/test_a.py::test_a", "tests/test_a.py::test_shared", "tests/test_b.py::test_b"
        ])
        self.assertEqual(plan["unmapped_rules"], ["C"])
        self.assertGreaterEqual(plan["items"][0]["risk_score"], plan["items"][-1]["risk_score"])

    def test_duplicate_rule_ids_are_rejected(self):
        with self.assertRaises(SystemExit):
            diff_policies({"rules": [{"id": "A"}, {"id": "A"}]}, {"rules": []})

    def test_invalid_policy_shapes_are_rejected(self):
        for policy in (None, [], {}, {"rules": [None]}, {"rules": [{"id": "A", "expected": "maybe"}]}):
            with self.subTest(policy=policy), self.assertRaises(SystemExit):
                diff_policies(policy, {"rules": []})

    def test_invalid_mapping_shapes_are_rejected(self):
        invalid = [
            None, {}, {"mappings": {}},
            {"mappings": [None]},
            {"mappings": [{"policy_rule_ids": [], "test_nodeids": ["tests/test_x.py::test_x"]}]},
            {"mappings": [{"policy_rule_ids": ["A"], "test_nodeids": []}]},
            {"mappings": [{"policy_rule_ids": ["A"], "test_nodeids": ["not-a-node-id"]}]},
        ]
        for mapping in invalid:
            with self.subTest(mapping=mapping), self.assertRaises(SystemExit):
                validate_mapping(mapping)

    def test_duplicate_mappings_are_rejected(self):
        entry = {"policy_rule_ids": ["A"], "test_nodeids": ["tests/test_x.py::test_x"]}
        with self.assertRaises(SystemExit):
            validate_mapping({"mappings": [entry, entry]})

    def test_nonexistent_test_files_are_reported(self):
        mapping = {"mappings": [
            {"policy_rule_ids": ["A"], "test_nodeids": ["tests/does_not_exist.py::test_x"]}
        ]}
        self.assertEqual(validate_nodeid_paths(mapping), ["tests/does_not_exist.py::test_x"])

    def test_mapping_paths_cannot_escape_repository(self):
        mapping = {"mappings": [
            {"policy_rule_ids": ["A"], "test_nodeids": ["../outside.py::test_x"]}
        ]}
        self.assertEqual(validate_nodeid_paths(mapping), ["../outside.py::test_x"])

    def test_target_safety_blocks_non_loopback_without_opt_in(self):
        with patch.dict("os.environ", {}, clear=True), self.assertRaises(SystemExit):
            safe_target("https://example.com")

    def test_target_safety_rejects_embedded_credentials(self):
        with self.assertRaises(SystemExit):
            safe_target("http://user:pass@127.0.0.1:8000")

    def test_target_safety_allows_loopback(self):
        self.assertEqual(safe_target("http://127.0.0.1:8000/"), "http://127.0.0.1:8000")

    def test_selected_runner_classifies_timeout_separately(self):
        plan = {"selected_tests": ["test_authorization.py::test_cross_user_access_matches_declared_mode"],
                "items": []}
        with patch("authtrace_pipeline.subprocess.run",
                   side_effect=subprocess.TimeoutExpired(cmd=["pytest"], timeout=1)):
            results, return_code, overall = run_selected(plan, "http://127.0.0.1:8000", timeout_seconds=1)
        self.assertEqual(results[0]["verdict"], "TIMEOUT")
        self.assertEqual(results[0]["error_class"], "TEST_TIMEOUT")
        self.assertEqual(overall, "TIMEOUT")
        self.assertNotEqual(return_code, 0)

    def test_selected_runner_classifies_collection_errors(self):
        plan = {"selected_tests": ["test_authorization.py::missing_test"], "items": []}
        failed = subprocess.CompletedProcess(
            args=["pytest"], returncode=2, stdout="ERROR: not found: test_authorization.py::missing_test"
        )
        with patch("authtrace_pipeline.subprocess.run", return_value=failed):
            results, return_code, overall = run_selected(plan, "http://127.0.0.1:8000")
        self.assertEqual(results[0]["verdict"], "ERROR")
        self.assertEqual(results[0]["error_class"], "COLLECTION_OR_RUNNER_ERROR")
        self.assertEqual(overall, "ERROR")
        self.assertNotEqual(return_code, 0)

    def test_selected_runner_parses_sanitized_policy_mismatch_evidence(self):
        nodeid = "test_authorization.py::test_cross_user_access_matches_declared_mode"
        plan = {"selected_tests": [nodeid], "items": [
            {"rule_id": "INV-READ-OTHER", "test_nodeids": [nodeid]}
        ]}
        evidence = {"expected": "allow", "observed": "deny", "classification": "POLICY_MISMATCH",
                    "security_invariant_violated": False}
        output = "AUTHTRACE_EVIDENCE=" + json.dumps(evidence) + "\n1 failed"
        failed = subprocess.CompletedProcess(args=["pytest"], returncode=1, stdout=output)
        with patch("authtrace_pipeline.subprocess.run", return_value=failed):
            results, return_code, overall = run_selected(
                plan, "http://127.0.0.1:8000", {"INV-READ-OTHER": "allow"}
            )
        self.assertEqual(results[0]["verdict"], "POLICY_MISMATCH")
        self.assertEqual(results[0]["rule_ids"], ["INV-READ-OTHER"])
        self.assertEqual(results[0]["evidence"], evidence)
        self.assertEqual(overall, "POLICY_MISMATCH")
        self.assertNotEqual(return_code, 0)

    def _run_mocked_evidence(self, evidence, returncode=0, output_suffix=""):
        nodeid = "test_authorization.py::test_cross_user_access_matches_declared_mode"
        plan = {"selected_tests": [nodeid], "items": [
            {"rule_id": "INV-READ-OTHER", "test_nodeids": [nodeid]}
        ]}
        output = ("" if evidence is None else "AUTHTRACE_EVIDENCE=" + (
            evidence if isinstance(evidence, str) else json.dumps(evidence)
        ) + "\n") + output_suffix
        proc = subprocess.CompletedProcess(args=["pytest"], returncode=returncode, stdout=output)
        with patch("authtrace_pipeline.subprocess.run", return_value=proc):
            return run_selected(plan, "http://127.0.0.1:8000", {"INV-READ-OTHER": "allow"})

    def test_zero_exit_policy_mismatch_never_passes(self):
        evidence = {"classification": "POLICY_MISMATCH", "expected": "allow", "observed": "deny",
                    "policy_match": False, "security_invariant_violated": False, "http_status": 403}
        results, rc, overall = self._run_mocked_evidence(evidence)
        self.assertEqual(results[0]["verdict"], "POLICY_MISMATCH")
        self.assertEqual(overall, "POLICY_MISMATCH")
        self.assertNotEqual(rc, 0)

    def test_zero_exit_security_regression_never_passes(self):
        evidence = {"classification": "SECURITY_REGRESSION", "security_invariant_violated": True}
        results, rc, overall = self._run_mocked_evidence(evidence)
        self.assertEqual(results[0]["verdict"], "SECURITY_REGRESSION")
        self.assertEqual(overall, "SECURITY_REGRESSION")
        self.assertNotEqual(rc, 0)

    def test_zero_exit_without_evidence_is_inconclusive(self):
        results, rc, overall = self._run_mocked_evidence(None)
        self.assertEqual(results[0]["verdict"], "INCONCLUSIVE")
        self.assertEqual(overall, "INCONCLUSIVE")
        self.assertNotEqual(rc, 0)

    def test_complete_consistent_policy_match_passes(self):
        evidence = {"classification": "POLICY_MATCH", "expected": "allow", "observed": "allow",
                    "policy_match": True, "security_invariant_violated": False, "http_status": 200}
        results, rc, overall = self._run_mocked_evidence(evidence)
        self.assertEqual(results[0]["verdict"], "PASS")
        self.assertEqual(overall, "PASS")
        self.assertEqual(rc, 0)

    def test_violated_security_invariant_is_security_regression(self):
        evidence = {"classification": "POLICY_MATCH", "expected": "allow", "observed": "allow",
                    "policy_match": True, "security_invariant_violated": True, "http_status": 200}
        results, rc, overall = self._run_mocked_evidence(evidence)
        self.assertEqual(results[0]["verdict"], "SECURITY_REGRESSION")
        self.assertNotEqual(rc, 0)

    def test_malformed_or_incomplete_evidence_is_non_passing(self):
        for evidence in ("{not-json", {"classification": "POLICY_MATCH", "expected": "allow"}):
            with self.subTest(evidence=evidence):
                results, rc, overall = self._run_mocked_evidence(evidence)
                self.assertNotEqual(results[0]["verdict"], "PASS")
                self.assertNotEqual(rc, 0)

    def test_contradictory_evidence_is_inconclusive(self):
        evidence = {"classification": "POLICY_MATCH", "expected": "allow", "observed": "deny",
                    "policy_match": True, "security_invariant_violated": False, "http_status": 403}
        results, rc, overall = self._run_mocked_evidence(evidence)
        self.assertEqual(results[0]["verdict"], "INCONCLUSIVE")
        self.assertNotEqual(rc, 0)

    def test_zero_exit_unknown_classification_is_inconclusive(self):
        evidence = {"classification": "UNRECOGNIZED", "expected": "allow", "observed": "allow",
                    "policy_match": True, "security_invariant_violated": False, "http_status": 200}
        results, rc, overall = self._run_mocked_evidence(evidence)
        self.assertEqual(results[0]["verdict"], "INCONCLUSIVE")
        self.assertNotEqual(rc, 0)

    def test_evidence_expected_outcome_conflict_is_inconclusive(self):
        evidence = {"classification": "POLICY_MATCH", "expected": "deny", "observed": "deny",
                    "policy_match": True, "security_invariant_violated": False, "http_status": 403}
        results, rc, overall = self._run_mocked_evidence(evidence)
        self.assertEqual(results[0]["verdict"], "INCONCLUSIVE")
        self.assertNotEqual(rc, 0)

    def test_connection_error_is_error_even_if_process_exit_is_zero(self):
        nodeid = "test_authorization.py::test_cross_user_access_matches_declared_mode"
        plan = {"selected_tests": [nodeid], "items": []}
        proc = subprocess.CompletedProcess(args=["pytest"], returncode=0,
                                           stdout="httpx.ConnectError: connection refused")
        with patch("authtrace_pipeline.subprocess.run", return_value=proc):
            results, rc, overall = run_selected(plan, "http://127.0.0.1:8000")
        self.assertEqual(results[0]["verdict"], "ERROR")
        self.assertEqual(results[0]["error_class"], "API_CONNECTION_ERROR")
        self.assertEqual(overall, "ERROR")
        self.assertNotEqual(rc, 0)

    def test_aggregate_status_and_exit_code_are_conservative(self):
        from authtrace_pipeline import _aggregate_return_code, _aggregate_status

        cases = [
            (["INCONCLUSIVE"], "INCONCLUSIVE", 1),
            (["PASS", "ERROR"], "ERROR", 2),
            (["PASS", "TIMEOUT"], "TIMEOUT", 124),
            (["PASS", "POLICY_MISMATCH"], "POLICY_MISMATCH", 1),
            (["PASS", "SECURITY_REGRESSION"], "SECURITY_REGRESSION", 1),
            (["PASS", "MYSTERY"], "INCONCLUSIVE", 1),
            (["PASS"], "PASS", 0),
            ([], "ERROR", 2),
        ]
        for statuses, expected_status, expected_rc in cases:
            with self.subTest(statuses=statuses):
                self.assertEqual(_aggregate_status(statuses), expected_status)
                self.assertEqual(_aggregate_return_code(statuses, [0] * len(statuses)), expected_rc)

    def test_aggregate_prioritizes_security_finding_over_other_failures(self):
        from authtrace_pipeline import _aggregate_status
        self.assertEqual(
            _aggregate_status(["INCONCLUSIVE", "ERROR", "TIMEOUT", "POLICY_MISMATCH",
                               "SECURITY_REGRESSION"]),
            "SECURITY_REGRESSION",
        )

    def test_empty_execution_selection_is_error_not_pass(self):
        results, return_code, overall = run_selected({"selected_tests": []}, "http://127.0.0.1:8000")
        self.assertEqual(results, [])
        self.assertNotEqual(return_code, 0)
        self.assertEqual(overall, "ERROR")

    def test_dashboard_escapes_untrusted_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "dashboard.html"
            render_dashboard({
                "generated_at": '<script>alert("x")</script>',
                "overall": "PLANNED",
                "plan": {"items": [{
                    "rule_id": '<img src=x onerror=alert(1)>',
                    "risk": "high",
                    "test_nodeids": ["tests/test_x.py::test_x"],
                }]},
            }, target)
            text = target.read_text(encoding="utf-8")
            self.assertNotIn('<script>alert("x")</script>', text)
            self.assertNotIn('<img src=x onerror=alert(1)>', text)
            self.assertIn(html.escape('<img src=x onerror=alert(1)>'), text)

    def test_strict_policy_validation_requires_all_authorization_fields(self):
        valid = {
            "policy_version": "1", "description": "test",
            "rules": [{"id": "A", "actor": "user", "action": "read_invoice",
                       "resource": "invoice", "condition": "invoice.owner_id == actor.user_id",
                       "expected": "allow"}],
            "scope": {"base_url": "http://127.0.0.1:8000",
                      "allowed_hosts": ["127.0.0.1", "localhost"], "default_methods": ["GET"]},
        }
        self.assertEqual(validate_policy(valid), valid)
        for invalid in (
            {},
            {**valid, "rules": [{**valid["rules"][0], "expected": "maybe"}]},
            {**valid, "rules": [{k: v for k, v in valid["rules"][0].items() if k != "expected"}]},
            {**valid, "rules": [{**valid["rules"][0], "actor": ["user"]}]},
            {**valid, "rules": [{**valid["rules"][0], "condition": "arbitrary code"}]},
            {**valid, "rules": [valid["rules"][0], valid["rules"][0]]},
            {**valid, "unsupported": True},
        ):
            with self.subTest(policy=invalid), self.assertRaises(SystemExit):
                validate_policy(invalid)

    def test_mapping_rejects_unsupported_fields_and_duplicate_node_ids(self):
        for mapping in (
            {"mappings": [{"policy_rule_ids": ["A"], "test_nodeids": ["tests/test_a.py::test_a"],
                           "unexpected": "value"}]},
            {"mappings": [{"policy_rule_ids": ["A", "A"], "test_nodeids": ["tests/test_a.py::test_a"]}]},
            {"mappings": [{"policy_rule_ids": ["A"], "test_nodeids": [
                "tests/test_a.py::test_a", "tests/test_a.py::test_a"]}]},
        ):
            with self.subTest(mapping=mapping), self.assertRaises(SystemExit):
                validate_mapping(mapping)

    def test_mapping_rejects_unknown_policy_rule_ids(self):
        mapping = {"mappings": [
            {"policy_rule_ids": ["UNKNOWN"], "test_nodeids": ["tests/test_x.py::test_x"]}
        ]}
        with self.assertRaisesRegex(SystemExit, "unknown policy rule"):
            validate_mapping_rule_ids(mapping, {"A", "B"})

    def test_mapping_accepts_rules_present_in_either_policy_version(self):
        mapping = {"mappings": [
            {"policy_rule_ids": ["A", "REMOVED"], "test_nodeids": ["tests/test_x.py::test_x"]}
        ]}
        validate_mapping_rule_ids(mapping, {"A", "REMOVED", "ADDED"})

    def test_plan_is_reproducible_for_identical_inputs(self):
        changes = diff_policies(self.old, self.new)
        mapping = {"mappings": [
            {"policy_rule_ids": ["A"], "test_nodeids": ["tests/test_a.py::test_a"]},
            {"policy_rule_ids": ["B"], "test_nodeids": ["tests/test_b.py::test_b"]},
        ]}
        self.assertEqual(build_plan(changes, mapping), build_plan(changes, mapping))

    def test_policy_rejects_invalid_rule_field_types(self):
        invalid_policies = [
            {"rules": [{"id": "A", "actor": ["user"]}]},
            {"rules": [{"id": "A", "condition": ""}]},
            {"rules": [{"id": "A", "expected": True}]},
        ]
        for policy in invalid_policies:
            with self.subTest(policy=policy), self.assertRaises(SystemExit):
                diff_policies(policy, {"rules": []})

    def test_target_url_rejects_query_and_fragment(self):
        for target in (
            "http://127.0.0.1:8000/?token=secret",
            "http://127.0.0.1:8000/#private",
        ):
            with self.subTest(target=target), self.assertRaises(SystemExit):
                safe_target(target)


if __name__ == "__main__":
    unittest.main()
