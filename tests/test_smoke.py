"""Smoke tests for TFSCAN. No network. Standard library only."""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from tfscan import TOOL_NAME, TOOL_VERSION, scan_text  # noqa: E402
from tfscan.cli import main, _render_html  # noqa: E402
from tfscan.core import parse_hcl, parse_plan_json  # noqa: E402

INSECURE_TF = '''
resource "aws_s3_bucket" "data" {
  bucket = "b"
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted   = false
}
'''

SECURE_TF = '''
resource "aws_db_instance" "db" {
  publicly_accessible = false
  storage_encrypted   = true
}
'''

PLAN_JSON = json.dumps({
    "planned_values": {
        "root_module": {
            "resources": [
                {
                    "type": "aws_ebs_volume",
                    "name": "v",
                    "values": {"encrypted": False, "size": 10},
                }
            ]
        }
    }
})


class TestParsing(unittest.TestCase):
    def test_parse_hcl_resources(self):
        rs = parse_hcl(INSECURE_TF)
        types = sorted(r.rtype for r in rs)
        self.assertEqual(
            types,
            ["aws_db_instance", "aws_s3_bucket", "aws_security_group"],
        )

    def test_nested_ingress_block(self):
        rs = parse_hcl(INSECURE_TF)
        sg = next(r for r in rs if r.rtype == "aws_security_group")
        self.assertIn("ingress", sg.attrs)
        self.assertIsInstance(sg.attrs["ingress"], list)
        self.assertEqual(sg.attrs["ingress"][0]["from_port"], 22)
        self.assertIn("0.0.0.0/0", sg.attrs["ingress"][0]["cidr_blocks"])

    def test_parse_plan_json(self):
        rs = parse_plan_json(PLAN_JSON)
        self.assertEqual(len(rs), 1)
        self.assertEqual(rs[0].rtype, "aws_ebs_volume")
        self.assertFalse(rs[0].attrs["encrypted"])


class TestChecks(unittest.TestCase):
    def test_insecure_findings(self):
        res = scan_text(INSECURE_TF, "main.tf")
        ids = {f.check_id for f in res.findings}
        # public S3 ACL, SSH open, RDS public, RDS unencrypted
        for expected in ("TFS001", "TFS012", "TFS020", "TFS021"):
            self.assertIn(expected, ids, f"missing {expected}")
        self.assertTrue(any(f.severity == "CRITICAL" for f in res.findings))

    def test_secure_has_no_rds_findings(self):
        res = scan_text(SECURE_TF, "main.tf")
        ids = {f.check_id for f in res.findings}
        self.assertNotIn("TFS020", ids)
        self.assertNotIn("TFS021", ids)

    def test_plan_json_ebs(self):
        res = scan_text(PLAN_JSON, "plan.json")
        ids = {f.check_id for f in res.findings}
        self.assertIn("TFS030", ids)

    def test_findings_sorted_by_severity(self):
        res = scan_text(INSECURE_TF, "main.tf")
        ranks = [_sev_rank(f.severity) for f in res.findings]
        self.assertEqual(ranks, sorted(ranks, reverse=True))


def _sev_rank(s):
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}[s]


class TestOutputs(unittest.TestCase):
    def test_json_serializable(self):
        res = scan_text(INSECURE_TF, "main.tf")
        blob = json.dumps(res.to_dict())
        data = json.loads(blob)
        self.assertIn("findings", data)
        self.assertEqual(data["total_findings"], len(res.findings))

    def test_html_self_contained(self):
        res = scan_text(INSECURE_TF, "main.tf")
        out = _render_html(res)
        self.assertIn("<!doctype html>", out)
        self.assertIn("<style>", out)
        self.assertIn(TOOL_NAME, out)
        self.assertNotIn("http://", out)  # no external assets

    def test_meta(self):
        self.assertEqual(TOOL_NAME, "tfscan")
        self.assertTrue(TOOL_VERSION)


class TestCli(unittest.TestCase):
    def setUp(self):
        self.tmp = os.path.join(os.path.dirname(__file__), "_tmp_main.tf")
        with open(self.tmp, "w", encoding="utf-8") as fh:
            fh.write(INSECURE_TF)

    def tearDown(self):
        for p in (self.tmp, self.tmp + ".secure"):
            if os.path.exists(p):
                os.remove(p)

    def test_exit_nonzero_on_findings(self):
        rc = main(["scan", self.tmp, "--format", "json"])
        self.assertEqual(rc, 1)

    def test_exit_zero_when_clean(self):
        secure = self.tmp + ".secure"
        # use .secure suffix won't be scanned by walk; pass file directly
        with open(secure, "w", encoding="utf-8") as fh:
            fh.write(SECURE_TF)
        rc = main(["scan", secure, "--format", "json"])
        # SECURE_TF only has a db instance that is private+encrypted -> clean
        self.assertEqual(rc, 0)

    def test_version_exits(self):
        with self.assertRaises(SystemExit) as ctx:
            main(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_min_severity_filter(self):
        rc = main(["scan", self.tmp, "--format", "json",
                   "--min-severity", "CRITICAL"])
        self.assertEqual(rc, 1)


class TestHardening(unittest.TestCase):
    """Tests for hardened error-handling and edge-case paths."""

    # ------------------------------------------------------------------
    # CLI: missing / non-existent path -> exit 2, clear stderr message
    # ------------------------------------------------------------------

    def test_cli_missing_path_exits_2(self):
        """Scanning a non-existent path must return exit code 2."""
        rc = main(["scan", "/no/such/path/tfscan_test_xyz"])
        self.assertEqual(rc, 2)

    def test_cli_no_subcommand_exits_2(self):
        """Invoking without a subcommand must return exit code 2."""
        rc = main([])
        self.assertEqual(rc, 2)

    # ------------------------------------------------------------------
    # scan_path: path validation
    # ------------------------------------------------------------------

    def test_scan_path_nonexistent_returns_error(self):
        from tfscan.core import scan_path
        res = scan_path("/no/such/path/tfscan_test_xyz")
        self.assertTrue(res.errors, "expected an error entry for missing path")
        self.assertEqual(res.files_scanned, 0)

    def test_scan_path_empty_string_returns_error(self):
        from tfscan.core import scan_path
        res = scan_path("")
        self.assertTrue(res.errors, "expected an error entry for empty path")

    def test_scan_path_empty_dir_returns_zero_files(self):
        """An existing directory with no .tf/.json files is valid; zero findings."""
        import tempfile
        from tfscan.core import scan_path
        with tempfile.TemporaryDirectory() as tmpdir:
            res = scan_path(tmpdir)
        self.assertEqual(res.files_scanned, 0)
        self.assertEqual(res.findings, [])
        self.assertEqual(res.errors, [])

    # ------------------------------------------------------------------
    # parse_plan_json: malformed / wrong-type JSON
    # ------------------------------------------------------------------

    def test_parse_plan_json_array_raises(self):
        """A JSON array at the top level should raise ValueError."""
        from tfscan.core import parse_plan_json
        with self.assertRaises((ValueError, Exception)):
            parse_plan_json("[1, 2, 3]", "bad.json")

    def test_parse_plan_json_empty_raises(self):
        """An empty string should raise (not silently return [])."""
        from tfscan.core import parse_plan_json
        with self.assertRaises(Exception):
            parse_plan_json("", "empty.json")

    # ------------------------------------------------------------------
    # scan_text: resilience to bad inputs
    # ------------------------------------------------------------------

    def test_scan_text_malformed_json_returns_error(self):
        """Malformed JSON content is captured as an error, not a traceback."""
        res = scan_text('{"unclosed": ', "broken.json")
        self.assertEqual(res.files_scanned, 1)
        self.assertTrue(res.errors, "expected a parse error entry")
        self.assertEqual(res.findings, [])

    def test_scan_text_empty_hcl_returns_no_findings(self):
        """Empty HCL content is valid; zero resources, zero findings."""
        res = scan_text("", "empty.tf")
        self.assertEqual(res.files_scanned, 1)
        self.assertEqual(res.resources_scanned, 0)
        self.assertEqual(res.findings, [])

    def test_scan_text_none_text_does_not_raise(self):
        """None passed as text should not raise; treated as empty."""
        res = scan_text(None, "none.tf")  # type: ignore[arg-type]
        self.assertEqual(res.files_scanned, 1)
        self.assertEqual(res.findings, [])


if __name__ == "__main__":
    unittest.main()
