"""
DroidRecon - Unified Data Models
Author: mahmudul0x1
https://github.com/mahmudul0x1/droidrecon
"""
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from datetime import datetime


@dataclass
class Finding:
    pattern_name: str
    match: str
    severity: str
    source_file: str
    source_type: str
    line_number: Optional[int] = None
    validated: Optional[bool] = None
    validation_detail: Optional[dict] = None
    tags: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self):
        return {
            "severity": self.severity,
            "pattern": self.pattern_name,
            "match": self.match,
            "source": self.source_file,
            "source_type": self.source_type,
            "line": self.line_number,
            "validated": self.validated,
            "validation": self.validation_detail,
            "tags": self.tags,
            "timestamp": self.timestamp,
        }


@dataclass
class ManifestFinding:
    component_type: str
    name: str
    exported: bool = False
    dangerous: bool = False
    details: dict = field(default_factory=dict)
    severity: str = "INFO"

    def to_dict(self):
        return {
            "component_type": self.component_type,
            "name": self.name,
            "exported": self.exported,
            "dangerous": self.dangerous,
            "details": self.details,
            "severity": self.severity,
        }


@dataclass
class ProbeResult:
    url: str
    status_code: Optional[int] = None
    server: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    redirect_chain: List[str] = field(default_factory=list)
    flags: List[str] = field(default_factory=list)
    error: Optional[str] = None
    response_preview: Optional[str] = None

    @property
    def is_alive(self):
        return self.status_code is not None and self.error is None

    def to_dict(self):
        return {
            "url": self.url,
            "status_code": self.status_code,
            "server": self.server,
            "content_type": self.content_type,
            "content_length": self.content_length,
            "redirect_chain": self.redirect_chain,
            "flags": self.flags,
            "error": self.error,
            "alive": self.is_alive,
        }


@dataclass
class ScanResult:
    apk_path: str
    package_name: str = "unknown"
    app_name: str = "unknown"
    app_version: str = "unknown"
    min_sdk: str = "unknown"
    target_sdk: str = "unknown"
    scan_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    findings: List[Finding] = field(default_factory=list)
    manifest_findings: List[ManifestFinding] = field(default_factory=list)
    probe_results: List[ProbeResult] = field(default_factory=list)
    smali_findings: List[Finding] = field(default_factory=list)
    native_findings: List[Finding] = field(default_factory=list)

    cert_info: Dict = field(default_factory=dict)
    sdk_info: Dict = field(default_factory=dict)
    obfuscation_info: Dict = field(default_factory=dict)
    domain_info: Dict = field(default_factory=dict)

    @property
    def all_findings(self):
        return self.findings + self.smali_findings + self.native_findings

    @property
    def critical_count(self):
        return sum(1 for f in self.all_findings if f.severity == "CRITICAL")

    @property
    def high_count(self):
        return sum(1 for f in self.all_findings if f.severity == "HIGH")

    def to_dict(self):
        summary = {
            "total_findings": len(self.all_findings),
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": sum(1 for f in self.all_findings if f.severity == "MEDIUM"),
            "low": sum(1 for f in self.all_findings if f.severity == "LOW"),
            "info": sum(1 for f in self.all_findings if f.severity == "INFO"),
            "manifest_issues": len(self.manifest_findings),
            "endpoints_probed": len(self.probe_results),
            "live_endpoints": sum(1 for p in self.probe_results if p.is_alive),
            "sdks_detected": self.sdk_info.get("total_sdks_detected", 0),
            "high_risk_sdks": self.sdk_info.get("high_risk_count", 0),
            "obfuscation_level": self.obfuscation_info.get("obfuscation_level", "N/A"),
            "obfuscation_score": self.obfuscation_info.get("obfuscation_score", 0),
            "cert_issues": len(self.cert_info.get("issues", [])),
            "unique_domains": self.domain_info.get("total", 0),
        }
        return {
            "tool": "DroidRecon",
            "author": "mahmudul0x1",
            "github": "https://github.com/mahmudul0x1/droidrecon",
            "apk": self.apk_path,
            "package": self.package_name,
            "app_name": self.app_name,
            "version": self.app_version,
            "min_sdk": self.min_sdk,
            "target_sdk": self.target_sdk,
            "timestamp": self.scan_timestamp,
            "summary": summary,
            "findings": [f.to_dict() for f in self.findings],
            "smali_findings": [f.to_dict() for f in self.smali_findings],
            "native_findings": [f.to_dict() for f in self.native_findings],
            "manifest": [m.to_dict() for m in self.manifest_findings],
            "probe_results": [p.to_dict() for p in self.probe_results],
            "certificate": self.cert_info,
            "sdks": self.sdk_info,
            "obfuscation": self.obfuscation_info,
            "domains": self.domain_info,
        }
