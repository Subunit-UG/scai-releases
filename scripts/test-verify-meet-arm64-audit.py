#!/usr/bin/env python3
"""Synthetic build evidence; no private source or recordings in public output."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).with_name("verify-meet-arm64-audit.py")
spec = importlib.util.spec_from_file_location("audit_gate", SCRIPT)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ReleaseAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.directory = self.root / "whisper-rs-sys-synthetic/out/build/scai-meet-isa/Release"
        self.directory.mkdir(parents=True)
        self.scanner = self.root / "scanner.py"
        self.scanner.write_text("synthetic scanner identity\n")
        self.start = int(time.time()) - 1
        self.report = {"status": "pass", "policy": "ARMv8-A + FP/NEON; no ISA exceptions",
                       "scanner_sha256": gate.digest(self.scanner), "violation_count": 0,
                       "self_test": [{"case": case, "expected_rejection": case != "armv8-neon",
                                      "rejected": case != "armv8-neon"} for case in sorted(gate.SELF_TESTS)],
                       "targets": []}
        for name in sorted(gate.TARGETS):
            obj = self.directory / (name + ".obj")
            obj.write_bytes(b"synthetic object " + name.encode())
            manifest = self.directory / (name + ".objects.txt")
            manifest.write_text(str(obj) + "\n")
            self.report["targets"].append({"manifest": str(manifest), "objects": [{
                "path": str(obj), "sha256": gate.digest(obj), "instruction_count": 1, "violations": []}]})
        self.audit = self.directory / "audit.json"
        self.write()

    def write(self):
        self.audit.write_text(json.dumps(self.report))

    def verify(self):
        return gate.verify(self.root, self.scanner, self.start)

    def test_pass_and_public_cli_contains_only_status_and_hashes(self):
        self.assertEqual(self.verify()["status"], "pass")
        run = subprocess.run([sys.executable, str(SCRIPT), "--build-root", str(self.root),
                              "--scanner", str(self.scanner), "--build-start", str(self.start)],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 0)
        self.assertEqual(run.stderr, "")
        result = json.loads(run.stdout)
        self.assertEqual(set(result), {"status", "scanner_sha256", "audit_sha256", "verifier_sha256", "targets_sha256"})
        self.assertNotIn(str(self.root), run.stdout)
        self.assertNotIn("synthetic", run.stdout)

    def test_missing_disabled_hook_and_stale_audit_fail(self):
        self.assertRaises(ValueError, gate.verify, self.root / "missing", self.scanner, self.start)
        os.utime(self.audit, (1, 1))
        self.assertRaises(ValueError, self.verify)

    def test_each_library_is_required_and_duplicates_rejected(self):
        original = copy.deepcopy(self.report)
        for name in gate.TARGETS:
            self.report = copy.deepcopy(original)
            self.report["targets"] = [t for t in self.report["targets"] if Path(t["manifest"]).name != name + ".objects.txt"]
            self.write()
            self.assertRaises(ValueError, self.verify)
        self.report = original
        self.report["targets"][1] = self.report["targets"][0]
        self.write()
        self.assertRaises(ValueError, self.verify)

    def test_failure_status_hash_changes_and_self_test_tampering_fail(self):
        original = copy.deepcopy(self.report)
        for key, value in [("status", "self-test-only"), ("status", "fail"),
                           ("scanner_sha256", "0" * 64), ("violation_count", 1), ("self_test", [])]:
            self.report = copy.deepcopy(original)
            self.report[key] = value
            self.write()
            self.assertRaises(ValueError, self.verify)
        self.report = original
        self.report["self_test"][1]["rejected"] = False
        self.write()
        self.assertRaises(ValueError, self.verify)

    def test_object_change_missing_object_and_manifest_mismatch_fail(self):
        obj = Path(self.report["targets"][0]["objects"][0]["path"])
        obj.write_bytes(b"changed after scan")
        self.assertRaises(ValueError, self.verify)
        self.report["targets"][0]["objects"][0]["path"] = str(self.root / "missing.obj")
        self.write()
        self.assertRaises(ValueError, self.verify)

    def test_multiple_audits_fail(self):
        other = self.root / "whisper-rs-sys-other/out/build/scai-meet-isa/Release"
        other.mkdir(parents=True)
        (other / "audit.json").write_text(self.audit.read_text())
        self.assertRaises(ValueError, self.verify)

    def test_corrupt_report_never_prints_private_data(self):
        self.audit.write_text("PRIVATE-SYNTHETIC-PATH: corrupt json")
        run = subprocess.run([sys.executable, str(SCRIPT), "--build-root", str(self.root),
                              "--scanner", str(self.scanner), "--build-start", str(self.start)],
                             capture_output=True, text=True)
        self.assertEqual(run.returncode, 1)
        self.assertEqual(set(json.loads(run.stdout)), {"status", "verifier_sha256"})
        self.assertNotIn("PRIVATE", run.stdout + run.stderr)

    def test_workflow_gate_is_independent_and_precedes_upload(self):
        workflow = SCRIPT.parents[1] / ".github/workflows/build-all.yml"
        source = workflow.read_text()
        at = source.index('if [ "$TARGET" = "aarch64-pc-windows-msvc" ]; then', source.index('MEET_BUILD_START='))
        end = source.index('\n          fi', at)
        block = source[at:end]
        self.assertIn('verify-meet-arm64-audit.py', block)
        self.assertNotIn('ENABLE_MEET', block)
        self.assertNotIn('run-confidential', block)
        self.assertLess(at, source.index('upload-draft-assets.sh', at))
        self.assertIn('--build-start "$MEET_BUILD_START"', block)


if __name__ == "__main__":
    unittest.main(verbosity=2)
