import tempfile
import unittest
from pathlib import Path

from oss_security_audit.models import Severity
from oss_security_audit.scanner import scan_repository


class ScannerTests(unittest.TestCase):
    def test_secret_values_are_redacted_and_sensitive_files_are_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            aws_key = "AKIA" + "1234567890ABCDEF"
            setting_name = "API" + "_" + "KEY"
            setting_value = "sensitive" + "-value"
            (root / ".env").write_text("AWS_ACCESS_KEY_ID=" + aws_key + "\n", encoding="utf-8")
            (root / "config.txt").write_text(
                setting_name + '="' + setting_value + '"\n', encoding="utf-8"
            )

            summary = scan_repository(root)
            self.assertTrue(any(item.rule_id == "SECRET002" for item in summary.findings))
            secret_findings = [item for item in summary.findings if item.rule_id == "SECRET001"]
            self.assertEqual(2, len(secret_findings))
            for item in secret_findings:
                self.assertNotIn(aws_key, item.message)
                self.assertNotIn(setting_value, item.message)
                self.assertEqual(Severity.HIGH, item.severity)

    def test_placeholders_do_not_create_secret_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env.example").write_text('API_KEY="${API_KEY}"\n', encoding="utf-8")
            summary = scan_repository(root)
            self.assertFalse(any(item.rule_id == "SECRET001" for item in summary.findings))
            self.assertFalse(any(item.rule_id == "SECRET002" for item in summary.findings))

    def test_workflow_permissions_and_docker_user_checks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            workflow = root / ".github" / "workflows"
            workflow.mkdir(parents=True)
            (workflow / "check.yml").write_text(
                "name: check\non: push\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
                encoding="utf-8",
            )
            (root / "Dockerfile").write_text("FROM python:3.12-slim\nCMD [\"python\"]\n", encoding="utf-8")
            summary = scan_repository(root)
            rule_ids = {item.rule_id for item in summary.findings}
            self.assertIn("GHA001", rule_ids)
            self.assertIn("DOCKER001", rule_ids)

    def test_gitignore_baseline_is_clean(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".gitignore").write_text(".env\n*.pem\n*.key\n", encoding="utf-8")
            summary = scan_repository(root)
            self.assertEqual(0, len(summary.findings))


if __name__ == "__main__":
    unittest.main()
