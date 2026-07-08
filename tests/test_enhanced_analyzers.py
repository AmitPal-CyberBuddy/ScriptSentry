import os
import tempfile
import unittest

from core.scanner import scan_file
from core.reporter import generate_report


class EnhancedAnalyzersTest(unittest.TestCase):
    def test_scan_file_collects_structured_security_analysis(self):
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as handle:
            handle.write("""
            const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def";
            fetch('/api/v1/profile', {headers:{Authorization:'Bearer abc123'}});
            localStorage.setItem('token', token);
            eval(userInput);
            const apiKey = "AIzaSyTest123";
            """
            )
            path = handle.name

        try:
            results = scan_file(path)
            self.assertIn("auth_summary", results)
            self.assertIn("api_inventory", results)
            self.assertIn("storage_analysis", results)
            self.assertIn("technology_stack", results)
            self.assertIn("dom_risks", results)
            self.assertIn("data_flow_summary", results)
            self.assertIn("obfuscation_analysis", results)
        finally:
            os.unlink(path)

    def test_report_includes_enhanced_sections(self):
        sample = {
            "sample.js": {
                "secrets": ["apiKey=abc"],
                "api_inventory": [{"endpoint": "/api/v1/profile", "method": "GET"}],
                "auth_summary": [{"type": "jwt", "evidence": "jwt"}],
                "storage_analysis": [{"storage": "localStorage", "classification": "sensitive"}],
                "technology_stack": [{"name": "React", "version": "18"}],
                "dom_risks": ["eval"],
                "data_flow_summary": ["input -> storage -> api"],
                "obfuscation_analysis": {"decoded_values": ["secret"]},
            }
        }
        report = generate_report(sample)
        self.assertIn("Technology Stack", report)
        self.assertIn("Authentication Analysis", report)
        self.assertIn("Storage Analysis", report)
        self.assertIn("API Inventory", report)


if __name__ == "__main__":
    unittest.main()
