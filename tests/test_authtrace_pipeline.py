import unittest

from authtrace_pipeline import build_plan, diff_policies, risk_score


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

    def test_plan_prioritizes_risk_and_deduplicates_tests(self):
        changes = diff_policies(self.old, self.new)
        mapping = {"mappings": [
            {"policy_rule_ids": ["A"], "test_nodeids": ["test_a", "test_shared"]},
            {"policy_rule_ids": ["B"], "test_nodeids": ["test_b", "test_shared"]},
        ]}
        plan = build_plan(changes, mapping)
        self.assertEqual(plan["selected_tests"], ["test_a", "test_shared", "test_b"])
        self.assertEqual(plan["unmapped_rules"], ["C"])
        self.assertGreaterEqual(plan["items"][0]["risk_score"], plan["items"][-1]["risk_score"])

    def test_duplicate_rule_ids_are_rejected(self):
        with self.assertRaises(SystemExit):
            diff_policies({"rules": [{"id": "A"}, {"id": "A"}]}, {"rules": []})


if __name__ == "__main__":
    unittest.main()
