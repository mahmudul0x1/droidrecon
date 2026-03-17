"""
DroidRecon - SARIF Exporter
Author: mahmudul0x1

Exports findings in SARIF 2.1.0 format for integration with:
- GitHub Advanced Security (Code Scanning)
- VS Code SARIF Viewer
- Azure DevOps
- GitLab SAST
"""

import json
import os
from datetime import datetime, timezone
from typing import List, Dict
from core.models import Finding, ManifestFinding, ScanResult

TOOL_VERSION = "1.0.0"
TOOL_NAME = "DroidRecon"
TOOL_URL = "https://github.com/mahmudul0x1/droidrecon"

SEVERITY_TO_SARIF = {
    "CRITICAL": "error",
    "HIGH":     "error",
    "MEDIUM":   "warning",
    "LOW":      "note",
    "INFO":     "none",
}

CWE_URLS = {
    "CWE-78":  "https://cwe.mitre.org/data/definitions/78.html",
    "CWE-89":  "https://cwe.mitre.org/data/definitions/89.html",
    "CWE-200": "https://cwe.mitre.org/data/definitions/200.html",
    "CWE-276": "https://cwe.mitre.org/data/definitions/276.html",
    "CWE-295": "https://cwe.mitre.org/data/definitions/295.html",
    "CWE-312": "https://cwe.mitre.org/data/definitions/312.html",
    "CWE-319": "https://cwe.mitre.org/data/definitions/319.html",
    "CWE-321": "https://cwe.mitre.org/data/definitions/321.html",
    "CWE-327": "https://cwe.mitre.org/data/definitions/327.html",
    "CWE-328": "https://cwe.mitre.org/data/definitions/328.html",
    "CWE-329": "https://cwe.mitre.org/data/definitions/329.html",
    "CWE-338": "https://cwe.mitre.org/data/definitions/338.html",
    "CWE-470": "https://cwe.mitre.org/data/definitions/470.html",
    "CWE-532": "https://cwe.mitre.org/data/definitions/532.html",
    "CWE-749": "https://cwe.mitre.org/data/definitions/749.html",
    "CWE-925": "https://cwe.mitre.org/data/definitions/925.html",
    "CWE-927": "https://cwe.mitre.org/data/definitions/927.html",
}


class SARIFExporter:
    """Exports DroidRecon scan results to SARIF 2.1.0 format."""

    def export(self, result: ScanResult, output_path: str):
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [self._build_run(result)]
        }

        with open(output_path, "w") as f:
            json.dump(sarif, f, indent=2, default=str)

        return output_path

    def _build_run(self, result: ScanResult) -> Dict:
        all_findings = result.all_findings + result.smali_findings + result.native_findings
        rules = self._build_rules(all_findings)

        return {
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": TOOL_URL,
                    "organization": "mahmudul0x1",
                    "shortDescription": {"text": "Advanced Android APK Security Scanner"},
                    "rules": rules,
                }
            },
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": result.scan_timestamp,
                "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                "toolExecutionNotifications": [],
            }],
            "results": self._build_results(all_findings, result),
            "properties": {
                "apk": result.apk_path,
                "package": result.package_name,
                "version": result.app_version,
                "minSdk": result.min_sdk,
                "targetSdk": result.target_sdk,
            }
        }

    def _build_rules(self, findings: List[Finding]) -> List[Dict]:
        seen_rules = {}
        for f in findings:
            rule_id = self._pattern_to_rule_id(f.pattern_name)
            if rule_id not in seen_rules:
                cwe = f.validation_detail.get("cwe") if f.validation_detail else None
                desc = f.validation_detail.get("description", f.pattern_name) if f.validation_detail else f.pattern_name

                rule = {
                    "id": rule_id,
                    "name": f.pattern_name.replace(" ", ""),
                    "shortDescription": {"text": f.pattern_name},
                    "fullDescription": {"text": desc},
                    "defaultConfiguration": {
                        "level": SEVERITY_TO_SARIF.get(f.severity, "warning")
                    },
                    "properties": {
                        "tags": f.tags + ([cwe] if cwe else []),
                        "severity": f.severity,
                    }
                }

                if cwe and cwe in CWE_URLS:
                    rule["helpUri"] = CWE_URLS[cwe]
                    rule["help"] = {
                        "text": f"{desc}\nSee: {CWE_URLS[cwe]}",
                        "markdown": f"{desc}\n\n[{cwe}]({CWE_URLS[cwe]})"
                    }

                seen_rules[rule_id] = rule

        return list(seen_rules.values())

    def _build_results(self, findings: List[Finding], result: ScanResult) -> List[Dict]:
        sarif_results = []
        for f in findings:
            rule_id = self._pattern_to_rule_id(f.pattern_name)
            level = SEVERITY_TO_SARIF.get(f.severity, "warning")
            message = f"{f.pattern_name}: `{f.match[:200]}`"
            if f.validated is True:
                message += " ⚠ CONFIRMED VALID"
            if f.validation_detail and f.validation_detail.get("description"):
                message += f". {f.validation_detail['description']}"

            sarif_result = {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.source_file,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": f.line_number or 1,
                        }
                    }
                }],
                "properties": {
                    "severity": f.severity,
                    "sourceType": f.source_type,
                    "tags": f.tags,
                    "validated": f.validated,
                    "timestamp": f.timestamp,
                }
            }

            if f.validated is True:
                sarif_result["suppressions"] = []  # Unsuppressed — confirmed valid
                sarif_result["rank"] = 100.0

            sarif_results.append(sarif_result)

        return sarif_results

    def _pattern_to_rule_id(self, pattern_name: str) -> str:
        """Convert pattern name to a valid SARIF rule ID."""
        return "DR" + re.sub(r'[^a-zA-Z0-9]', '', pattern_name)[:40]


import re  # noqa: E402 (needed for _pattern_to_rule_id)
