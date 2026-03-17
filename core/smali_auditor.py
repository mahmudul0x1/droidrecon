"""
APKLeaks Pro - Smali Bytecode Vulnerability Auditor
Detects dangerous API usage patterns in decompiled Smali code.
"""
import os
import re
from pathlib import Path
from typing import List, Dict
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from core.models import Finding
from core.severity import SeverityScorer

console = Console()

# Smali vulnerability patterns mapped to severity and description
SMALI_VULN_PATTERNS: Dict[str, Dict] = {
    "Insecure Random (java.util.Random)": {
        "pattern": r"Ljava/util/Random;->next(Int|Long|Bytes|Double|Float|Gaussian|Boolean)",
        "severity": "MEDIUM",
        "description": "java.util.Random is not cryptographically secure. Use SecureRandom instead.",
        "cwe": "CWE-338",
    },
    "AES ECB Mode": {
        "pattern": r'Cipher\.getInstance\("AES(?:/")?"\)|Cipher/getInstance.*"AES"',
        "severity": "HIGH",
        "description": "AES without mode defaults to ECB — deterministic and vulnerable to pattern analysis.",
        "cwe": "CWE-327",
    },
    "ECB Mode Explicit": {
        "pattern": r'"AES/ECB/',
        "severity": "HIGH",
        "description": "Explicit ECB mode — does not provide semantic security.",
        "cwe": "CWE-327",
    },
    "MD5 Hash": {
        "pattern": r'MessageDigest\.getInstance.*"MD5"|"MD5".*MessageDigest',
        "severity": "MEDIUM",
        "description": "MD5 is cryptographically broken. Use SHA-256 or SHA-3.",
        "cwe": "CWE-328",
    },
    "SHA-1 Hash": {
        "pattern": r'MessageDigest\.getInstance.*"SHA-1"|MessageDigest\.getInstance.*"SHA1"',
        "severity": "LOW",
        "description": "SHA-1 is deprecated for security use. Use SHA-256 or SHA-3.",
        "cwe": "CWE-328",
    },
    "WebView JavaScript Enabled": {
        "pattern": r"Landroid/webkit/WebSettings;->setJavaScriptEnabled\(Z\)V",
        "severity": "MEDIUM",
        "description": "JavaScript enabled in WebView — potential XSS or RCE if loading untrusted content.",
        "cwe": "CWE-749",
    },
    "WebView File Access Enabled": {
        "pattern": r"Landroid/webkit/WebSettings;->setAllowFileAccess\(Z\)V",
        "severity": "HIGH",
        "description": "File system access enabled in WebView — may allow file:// URL attacks.",
        "cwe": "CWE-200",
    },
    "WebView Universal File Access": {
        "pattern": r"setAllowUniversalAccessFromFileURLs\(Z\)V",
        "severity": "CRITICAL",
        "description": "Universal file access from file:// URLs — can read arbitrary files on device.",
        "cwe": "CWE-200",
    },
    "WebView addJavascriptInterface": {
        "pattern": r"Landroid/webkit/WebView;->addJavascriptInterface",
        "severity": "HIGH",
        "description": "JavaScript interface bridge exposed — may allow Java reflection attacks on Android < 4.2.",
        "cwe": "CWE-749",
    },
    "Raw SQL Query": {
        "pattern": r"->rawQuery\(Ljava/lang/String|->execSQL\(Ljava/lang/String",
        "severity": "HIGH",
        "description": "Raw SQL query with string argument — potential SQL injection.",
        "cwe": "CWE-89",
    },
    "World-Readable File": {
        "pattern": r"MODE_WORLD_READABLE|openFileOutput.*0x1\b",
        "severity": "HIGH",
        "description": "File created with world-readable permissions — other apps can read it.",
        "cwe": "CWE-276",
    },
    "World-Writable File": {
        "pattern": r"MODE_WORLD_WRITEABLE|openFileOutput.*0x2\b",
        "severity": "HIGH",
        "description": "File created with world-writable permissions — other apps can modify it.",
        "cwe": "CWE-276",
    },
    "Dynamic Code Loading": {
        "pattern": r"Ldalvik/system/DexClassLoader;|Ldalvik/system/PathClassLoader;->.*\.dex",
        "severity": "MEDIUM",
        "description": "Dynamic DEX loading detected — may indicate dynamic code execution or plugin system.",
        "cwe": "CWE-470",
    },
    "Runtime Command Execution": {
        "pattern": r"Ljava/lang/Runtime;->exec\(|ProcessBuilder",
        "severity": "HIGH",
        "description": "Runtime.exec() detected — command injection if user input is involved.",
        "cwe": "CWE-78",
    },
    "Reflection Invocation": {
        "pattern": r"Ljava/lang/reflect/Method;->invoke\(",
        "severity": "LOW",
        "description": "Reflection usage detected — may bypass access controls or indicate obfuscation.",
        "cwe": "CWE-470",
    },
    "Log Sensitive Data": {
        "pattern": r"Landroid/util/Log;->[dvewi]\(Ljava/lang/String",
        "severity": "LOW",
        "description": "Logging detected — verify no sensitive data (tokens, PII) is logged in production.",
        "cwe": "CWE-532",
    },
    "Clipboard Sensitive Write": {
        "pattern": r"Landroid/content/ClipboardManager;->setPrimaryClip",
        "severity": "LOW",
        "description": "Data written to clipboard — other apps can read clipboard contents.",
        "cwe": "CWE-200",
    },
    "Sticky Broadcast": {
        "pattern": r"->sendStickyBroadcast\(|->sendStickyOrderedBroadcast\(",
        "severity": "MEDIUM",
        "description": "Sticky broadcasts are deprecated and can be read by any app.",
        "cwe": "CWE-927",
    },
    "Custom Trust Manager (SSL Bypass)": {
        "pattern": r"X509TrustManager|checkServerTrusted|checkClientTrusted",
        "severity": "HIGH",
        "description": "Custom TrustManager — may accept all certificates, disabling SSL verification.",
        "cwe": "CWE-295",
    },
    "AllowAllHostnameVerifier": {
        "pattern": r"AllowAllHostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER",
        "severity": "CRITICAL",
        "description": "All hostnames accepted — SSL certificate validation bypassed.",
        "cwe": "CWE-295",
    },
    "Hardcoded Encryption Key": {
        "pattern": r'SecretKeySpec\(.*"[A-Za-z0-9+/=]{8,}"',
        "severity": "CRITICAL",
        "description": "Hardcoded encryption key in SecretKeySpec — trivially extractable.",
        "cwe": "CWE-321",
    },
    "Predictable IV": {
        "pattern": r'IvParameterSpec\(new byte\[|IvParameterSpec\(\{0',
        "severity": "HIGH",
        "description": "Predictable or zero IV used in symmetric encryption.",
        "cwe": "CWE-329",
    },
    "SharedPreferences Sensitive Data": {
        "pattern": r"->getString\(.*(?:password|token|secret|key|credential)",
        "severity": "MEDIUM",
        "description": "Possible sensitive data read from SharedPreferences — stored in plaintext by default.",
        "cwe": "CWE-312",
    },
    "Insecure HTTP Connection": {
        "pattern": r'"http://(?!localhost|127\.0\.0\.1|10\.|192\.168)',
        "severity": "MEDIUM",
        "description": "Plaintext HTTP URL detected — traffic is not encrypted.",
        "cwe": "CWE-319",
    },
    "Pending Intent Mutable": {
        "pattern": r"PendingIntent\.FLAG_MUTABLE|FLAG_MUTABLE",
        "severity": "MEDIUM",
        "description": "Mutable PendingIntent — may be intercepted and modified by other apps.",
        "cwe": "CWE-925",
    },
}


class SmaliAuditor:
    def __init__(self, scorer: SeverityScorer):
        self.scorer = scorer
        self._compiled = {
            name: (re.compile(info["pattern"], re.IGNORECASE), info)
            for name, info in SMALI_VULN_PATTERNS.items()
        }

    def scan(self, decompiled_dir: str) -> List[Finding]:
        """Walk decompiled directory, scan Smali files for vuln patterns."""
        findings: List[Finding] = []
        seen = set()

        smali_files = list(Path(decompiled_dir).rglob("*.smali"))

        if not smali_files:
            # Try Java files if no Smali (jadx may output Java)
            smali_files = list(Path(decompiled_dir).rglob("*.java"))

        if not smali_files:
            console.print("[yellow]No Smali/Java files found for audit.[/yellow]")
            return findings

        console.print(f"[cyan]🛡️  Auditing {len(smali_files)} Smali/Java files for {len(self._compiled)} vulnerability patterns...[/cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            task = progress.add_task("Smali audit...", total=len(smali_files))

            for smali_file in smali_files:
                try:
                    file_findings = self._audit_file(str(smali_file), decompiled_dir, seen)
                    findings.extend(file_findings)
                except Exception:
                    pass
                progress.advance(task)

        return findings

    def _audit_file(self, filepath: str, base_dir: str, seen: set) -> List[Finding]:
        findings = []
        rel_path = os.path.relpath(filepath, base_dir)

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.splitlines()
        except Exception:
            return findings

        for vuln_name, (pattern, info) in self._compiled.items():
            try:
                for lineno, line in enumerate(lines, 1):
                    if pattern.search(line):
                        dedup_key = (vuln_name, rel_path)
                        if dedup_key in seen:
                            break  # Report once per file per vulnerability
                        seen.add(dedup_key)

                        findings.append(Finding(
                            pattern_name=vuln_name,
                            match=line.strip()[:200],
                            severity=info["severity"],
                            source_file=rel_path,
                            source_type="smali",
                            line_number=lineno,
                            tags=["vulnerability", info.get("cwe", "").lower()],
                            validation_detail={
                                "description": info["description"],
                                "cwe": info.get("cwe"),
                            }
                        ))
                        break
            except re.error:
                continue

        return findings
