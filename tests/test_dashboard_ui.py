"""Smoke tests for user-facing dashboard workflows and accessibility hooks."""
from pathlib import Path
import unittest

DASHBOARD = Path(__file__).resolve().parents[1] / "web" / "index.html"


class DashboardUiSmokeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = DASHBOARD.read_text(encoding="utf-8")

    def test_primary_navigation_is_task_oriented(self):
        for label in ("Overview", "Policies", "Run tests", "Test history", "Reports", "Advanced tools"):
            with self.subTest(label=label):
                self.assertIn(label, self.html)

    def test_advanced_pages_remain_available(self):
        for page in ("findings", "planner", "evidence", "targets", "suites", "settings"):
            with self.subTest(page=page):
                self.assertIn(f'data-page="{page}"', self.html)

    def test_results_explain_security_outcomes_in_plain_language(self):
        for label in ("Policy mismatch", "Security regression", "observed API behavior did not match",
                      "does not prove the whole API is secure", "Technical evidence"):
            with self.subTest(label=label):
                self.assertIn(label, self.html)

    def test_dashboard_preserves_local_demo_warning_and_test_workflow(self):
        for step in ("Review policy changes", "Review the test selection", "Confirm execution"):
            with self.subTest(step=step):
                self.assertIn(step, self.html)
        self.assertIn("local synthetic API", self.html)
        self.assertIn("Run selected regression tests", self.html)
        self.assertIn("Unmapped rules are shown as coverage gaps", self.html)

    def test_navigation_has_accessible_label_and_current_page_state(self):
        self.assertIn('aria-label="Main navigation"', self.html)
        self.assertIn('aria-current', self.html)


if __name__ == "__main__":
    unittest.main()
