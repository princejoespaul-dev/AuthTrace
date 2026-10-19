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
