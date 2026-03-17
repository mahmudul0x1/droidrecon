"""
DroidRecon - Core Regex Scanner
Scans decompiled APK sources for secrets, endpoints, and URIs.
"""
import os
import re
import math
import json
import zipfile
import tempfile
import subprocess
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Set
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from core.models import Finding
from core.severity import SeverityScorer

console = Console()

SCANNABLE_EXTENSIONS = {
    '.java', '.kt', '.smali', '.xml', '.json',
    '.js', '.html', '.txt', '.gradle', '.properties',
    '.yml', '.yaml'
}

SKIP_DIRS = {
    'R.java', 'BuildConfig.java', 'META-INF',
    'com/google', 'com/facebook', 'com/twitter', 'com/microsoft',
    'com/amazon', 'com/stripe', 'com/paypal', 'com/braintree',
    'com/appsflyer', 'com/adjust', 'com/onesignal', 'com/unity3d',
    'com/squareup', 'com/okhttp3', 'com/retrofit2', 'com/bumptech',
    'io/sentry', 'io/branch', 'androidx', 'kotlin', 'kotlinx',
    'org/apache', 'org/json', 'org/slf4j', 'javax', 'java',
    'rx/android', 'io/reactivex',
}

FALSE_POSITIVE_VALUES = {
    'your_api_key_here', 'insert_your_key_here', 'api_key_here',
    'your_secret_here', 'your_token_here', 'enter_your_key',
    'replace_with_your', 'your_client_secret', 'xxxxxxxxxxxx',
    'aaaaaaaaaaaa', '0000000000000000', '1234567890abcdef',
    'test_key', 'example_key', 'sample_key', 'dummy_key',
    'placeholder', 'changeme', 'password123', 'secret123',
    'mysecret', 'mysecretkey', 'mypassword', 'example',
    'test', 'demo', 'sample', 'fake', 'mock',
    'paypal_client_id', 'paypal_client_secret',
    'AZDxjDScFpQtjW1zDqT7T8Z4CCd9seffameamvqumgmg',
}

HIGH_ENTROPY_REQUIRED = {
    'PayPal Client Secret', 'Generic API Key', 'Generic Secret',
    'Generic Credential', 'Mailchimp API Key', 'Twilio Auth Token',
    'Twitter OAuth', 'LinkedIn Client Secret',
}

CONTEXT_REQUIRED = {
    'Generic API Key', 'Generic Secret', 'Generic Credential',
    'Authorization Bearer', 'Basic Auth Credentials',
}

APK_CONTEXT_KEYWORDS = {
    'key', 'secret', 'token', 'api', 'auth', 'credential',
    'password', 'passwd', 'client_id', 'client_secret',
    'access_key', 'private', 'bearer', 'webhook',
}

# Timezone region prefixes — LinkFinder false positives
TIMEZONE_PREFIXES = {
    'africa', 'america', 'antarctica', 'arctic', 'asia',
    'atlantic', 'australia', 'brazil', 'canada', 'chile',
    'europe', 'indian', 'mexico', 'pacific', 'us', 'etcetera',
}

# Compiled timezone pattern — e.g. America/Edmonton, Asia/Dhaka
_TIMEZONE_RE = re.compile(r'^[A-Z][a-zA-Z_]+/[A-Z][a-zA-Z_/]+$')


class APKScanner:
    def __init__(self, apk_path: str, patterns_path: str, severity_scorer: SeverityScorer,
                 jadx_args: str = "", output_dir: Optional[str] = None):
        self.apk_path = apk_path
        self.patterns_path = patterns_path
        self.scorer = severity_scorer
        self.jadx_args = jadx_args
        self.output_dir = output_dir
        self._decompiled_dir = None
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> Dict[str, str]:
        config_file = self.patterns_path or os.path.join(
            os.path.dirname(os.path.dirname(__file__)), "config", "regexes.json"
        )
        with open(config_file) as f:
            return json.load(f)

    def decompile(self) -> Optional[str]:
        jadx_path = shutil.which("jadx")
        if jadx_path:
            return self._decompile_jadx(jadx_path)
        else:
            console.print("[yellow]⚠ jadx not found — using basic extraction.[/yellow]")
            return self._extract_basic()

    def _decompile_jadx(self, jadx_path: str) -> Optional[str]:
        out_dir = self.output_dir or tempfile.mkdtemp(prefix="droidrecon_tmp_")
        self._decompiled_dir = out_dir
        cmd = [jadx_path, "-d", out_dir]
        if self.jadx_args:
            cmd.extend(self.jadx_args.split())
        cmd.append(self.apk_path)
        console.print(f"[cyan]🔧 Decompiling with jadx → {out_dir}[/cyan]")
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            if result.returncode not in (0, 1):
                console.print(f"[red]jadx error: {result.stderr[:500]}[/red]")
                return None
            return out_dir
        except subprocess.TimeoutExpired:
            console.print("[red]jadx timed out after 5 minutes.[/red]")
            return None
        except Exception as e:
            console.print(f"[red]jadx failed: {e}[/red]")
            return None

    def _extract_basic(self) -> Optional[str]:
        out_dir = self.output_dir or tempfile.mkdtemp(prefix="droidrecon_tmp_")
        self._decompiled_dir = out_dir
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                z.extractall(out_dir)
            console.print(f"[cyan]📦 Extracted APK → {out_dir}[/cyan]")
            return out_dir
        except Exception as e:
            console.print(f"[red]Extraction failed: {e}[/red]")
            return None

    def scan(self, decompiled_dir: str, min_severity: str = "INFO") -> List[Finding]:
        findings: List[Finding] = []
        seen: Set[tuple] = set()

        files_to_scan = []
        for root, dirs, files in os.walk(decompiled_dir):
            dirs[:] = [
                d for d in dirs
                if not self._is_vendor_dir(os.path.join(root, d), decompiled_dir)
            ]
            for fname in files:
                ext = Path(fname).suffix.lower()
                if ext in SCANNABLE_EXTENSIONS:
                    fpath = os.path.join(root, fname)
                    if not self._is_vendor_file(fpath, decompiled_dir):
                        files_to_scan.append(fpath)

        console.print(
            f"[cyan]🔍 Scanning {len(files_to_scan)} APK source files "
            f"for {len(self.patterns)} patterns...[/cyan]"
        )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.completed}/{task.total}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=len(files_to_scan))
            for filepath in files_to_scan:
                try:
                    file_findings = self._scan_file(filepath, decompiled_dir, seen)
                    findings.extend(file_findings)
                except Exception:
                    pass
                progress.advance(task)

        if min_severity != "INFO":
            findings = self.scorer.filter_by_severity(findings, min_severity)

        return findings

    def _is_vendor_dir(self, dirpath: str, base_dir: str) -> bool:
        rel = os.path.relpath(dirpath, base_dir).replace(os.sep, '/')
        for skip in SKIP_DIRS:
            if skip in rel:
                return True
        return False

    def _is_vendor_file(self, filepath: str, base_dir: str) -> bool:
        rel = os.path.relpath(filepath, base_dir).replace(os.sep, '/')
        for skip in SKIP_DIRS:
            if skip in rel:
                return True
        return False

    def _scan_file(self, filepath: str, base_dir: str, seen: Set[tuple]) -> List[Finding]:
        findings = []
        rel_path = os.path.relpath(filepath, base_dir)

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception:
            return findings

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith('//') or stripped.startswith('*'):
                continue

            ctx_start = max(0, lineno - 4)
            ctx_end = min(len(lines), lineno + 3)
            context = ' '.join(lines[ctx_start:ctx_end]).lower()

            for pattern_name, pattern_regex in self.patterns.items():
                try:
                    matches = re.findall(pattern_regex, stripped, re.IGNORECASE)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = next((m for m in match if m), '')
                        match = str(match).strip()

                        # ── Basic length filter ──
                        if len(match) < 4 or len(match) > 500:
                            continue

                        # ── Known false positive values ──
                        if self._is_known_false_positive(match):
                            continue

                        # ── Timezone filter (LinkFinder / Endpoints noise) ──
                        if pattern_name in ('LinkFinder', 'Endpoints'):
                            if self._is_timezone(match):
                                continue

                        # ── Entropy filter for noisy patterns ──
                        if pattern_name in HIGH_ENTROPY_REQUIRED:
                            if self._shannon_entropy(match) < 3.5:
                                continue

                        # ── Context relevance check ──
                        if pattern_name in CONTEXT_REQUIRED:
                            if not self._has_relevant_context(context):
                                continue

                        # ── Deduplication ──
                        dedup_key = (pattern_name, match)
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)

                        severity = self.scorer.score(pattern_name)
                        source_type = self._classify_source(filepath)

                        findings.append(Finding(
                            pattern_name=pattern_name,
                            match=match,
                            severity=severity,
                            source_file=rel_path,
                            source_type=source_type,
                            line_number=lineno,
                            tags=self._auto_tag(pattern_name, match),
                        ))
                except re.error:
                    continue

        return findings

    def _is_known_false_positive(self, match: str) -> bool:
        lower = match.lower().strip('\'"')
        if lower in FALSE_POSITIVE_VALUES:
            return True
        if len(set(lower)) <= 2:
            return True
        if lower in ('abcdefghijklmnopqrstuvwxyz', '0123456789'):
            return True
        if len(lower) < 6:
            return True
        return False

    def _is_timezone(self, match: str) -> bool:
        """
        Returns True if match looks like a timezone string.
        e.g. America/Edmonton, Asia/Dhaka, Europe/London
        These are caught by LinkFinder but have zero security value.
        """
        clean = match.strip('\'"/ ')
        if not _TIMEZONE_RE.match(clean):
            return False
        prefix = clean.split('/')[0].lower()
        return prefix in TIMEZONE_PREFIXES

    def _shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        freq: Dict[str, int] = {}
        for c in data:
            freq[c] = freq.get(c, 0) + 1
        entropy = 0.0
        length = len(data)
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _has_relevant_context(self, context: str) -> bool:
        return any(kw in context for kw in APK_CONTEXT_KEYWORDS)

    def _classify_source(self, filepath: str) -> str:
        ext = Path(filepath).suffix.lower()
        if ext == '.smali':         return 'smali'
        if ext in ('.java', '.kt'): return 'java'
        if ext == '.xml':           return 'resource'
        if ext in ('.json', '.js'): return 'asset'
        if ext == '.gradle':        return 'build'
        return 'other'

    def _auto_tag(self, pattern_name: str, match: str) -> List[str]:
        tags = []
        name_lower = pattern_name.lower()
        match_lower = match.lower()
        if any(k in name_lower for k in ['key', 'secret', 'token', 'password', 'credential']):
            tags.append('secret')
        if any(k in name_lower for k in ['url', 'endpoint', 'uri', 'link']):
            tags.append('endpoint')
        if 'aws' in name_lower:                                     tags.append('aws')
        if 'firebase' in name_lower or 'firebase' in match_lower:  tags.append('firebase')
        if 'google' in name_lower:                                  tags.append('google')
        if 'http' in match_lower:                                   tags.append('http')
        if any(x in match_lower for x in ['localhost', '127.0.0.1', '192.168']):
            tags.append('internal')
        return tags

    def cleanup(self):
        if self._decompiled_dir and not self.output_dir:
            shutil.rmtree(self._decompiled_dir, ignore_errors=True)
