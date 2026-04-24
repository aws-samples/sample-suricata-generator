"""
PCAP Tester for the Suricata Rule Generator AI Agent Layer.

Runs a Suricata rule against a PCAP file and parses the resulting alerts.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Optional

import boto3

from src.agent.models import PcapTestResult

logger = logging.getLogger(__name__)


class PcapTester:
    """Tests Suricata rules against PCAP files."""

    def __init__(
        self,
        s3_client=None,
        bucket: Optional[str] = None,
    ):
        self.s3 = s3_client
        self.bucket = bucket

    def test_rule(self, rule_str: str, pcap_path: str) -> PcapTestResult:
        """Run a rule against a local PCAP file using suricata CLI.

        Args:
            rule_str: The Suricata rule string to test.
            pcap_path: Path to a local PCAP file.

        Returns:
            PcapTestResult with alert details.
        """
        if not os.path.isfile(pcap_path):
            return PcapTestResult(error=f"PCAP file not found: {pcap_path}")

        # Find suricata binary — check common paths since Homebrew may not be in PATH
        suricata_bin = shutil.which("suricata")
        if not suricata_bin:
            for path in ["/opt/homebrew/bin/suricata", "/usr/local/bin/suricata", "/usr/bin/suricata"]:
                if os.path.isfile(path):
                    suricata_bin = path
                    break
        if not suricata_bin:
            return PcapTestResult(error="Suricata binary not found. Install with: brew install suricata")

        tmpdir = tempfile.mkdtemp(prefix="suricata_test_")
        try:
            rules_file = os.path.join(tmpdir, "test.rules")
            with open(rules_file, "w") as f:
                f.write(rule_str + "\n")

            result = subprocess.run(
                [suricata_bin, "-r", pcap_path, "-S", rules_file, "-l", tmpdir, "-k", "none"],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode != 0 and "error" in result.stderr.lower():
                return PcapTestResult(error=f"Suricata error: {result.stderr[:500]}")

            return self._parse_eve_log(tmpdir)

        except subprocess.TimeoutExpired:
            return PcapTestResult(error="Suricata execution timed out (60s)")
        except Exception as e:
            return PcapTestResult(error=f"PCAP test failed: {e}")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_rule_from_s3(self, rule_str: str, s3_key: str) -> PcapTestResult:
        """Download a PCAP from S3 and test the rule against it."""
        if not self.s3 or not self.bucket:
            return PcapTestResult(error="S3 client/bucket not configured")

        tmpdir = tempfile.mkdtemp(prefix="pcap_dl_")
        local_pcap = os.path.join(tmpdir, "test.pcap")
        try:
            self.s3.download_file(self.bucket, s3_key, local_pcap)
            return self.test_rule(rule_str, local_pcap)
        except Exception as e:
            return PcapTestResult(error=f"S3 download failed: {e}")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    @staticmethod
    def _parse_eve_log(log_dir: str) -> PcapTestResult:
        """Parse eve.json for alert events."""
        eve_path = os.path.join(log_dir, "eve.json")
        if not os.path.isfile(eve_path):
            return PcapTestResult(triggered=False, alert_count=0)

        alerts = []
        with open(eve_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        alerts.append(event)
                except json.JSONDecodeError:
                    continue

        return PcapTestResult(
            triggered=len(alerts) > 0,
            alert_count=len(alerts),
            alerts=alerts,
        )
