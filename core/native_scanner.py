"""
APKLeaks Pro - Native Library (.so) Scanner
Extracts and scans strings from native libraries inside APKs.
"""
import re
import zipfile
from typing import List, Dict
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from core.models import Finding
from core.severity import SeverityScorer

console = Console()

# Min/max string length to consider
MIN_STRING_LEN = 8
MAX_STRING_LEN = 512

# Additional patterns specifically useful for native libs
NATIVE_PATTERNS = {
    "URL (Native)":             rb'https?://[^\x00\s"\'<>]{8,}',
    "IP Address (Native)":      rb'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b',
    "AWS Key (Native)":         rb'AKIA[0-9A-Z]{16}',
    "Generic Secret (Native)":  rb'(?:secret|password|passwd|token|key|api)[_\-]?[=:][^\x00\s]{6,}',
    "Email (Native)":           rb'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    "Firebase URL (Native)":    rb'[a-z0-9\-]+\.firebaseio\.com',
}


class NativeScanner:
    def __init__(self, apk_path: str, patterns: Dict[str, str], scorer: SeverityScorer):
        self.apk_path = apk_path
        self.patterns = self._compile_patterns(patterns)
        self.scorer = scorer
        self._compiled_native = {k: re.compile(v) for k, v in NATIVE_PATTERNS.items()}

    def _compile_patterns(self, patterns: Dict[str, str]) -> Dict[str, re.Pattern]:
        compiled = {}
        for name, pattern in patterns.items():
            try:
                # Convert text patterns to bytes patterns
                compiled[name] = re.compile(pattern.encode('utf-8', errors='ignore'), re.IGNORECASE)
            except re.error:
                pass
        return compiled

    def scan(self) -> List[Finding]:
        """Open APK as ZIP, find all .so files, extract and scan strings."""
        findings: List[Finding] = []
        seen = set()

        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                so_files = [f for f in apk.namelist() if f.endswith('.so')]
        except Exception as e:
            console.print(f"[red]Failed to open APK for native scanning: {e}[/red]")
            return findings

        if not so_files:
            console.print("[yellow]No native .so libraries found.[/yellow]")
            return findings

        console.print(f"[cyan]🔬 Scanning {len(so_files)} native libraries (.so)...[/cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Native scan...", total=len(so_files))

            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                for so_path in so_files:
                    try:
                        data = apk.read(so_path)
                        lib_findings = self._scan_binary(data, so_path, seen)
                        findings.extend(lib_findings)
                    except Exception as e:
                        console.print(f"[yellow]Skipping {so_path}: {e}[/yellow]")
                    progress.advance(task)

        return findings

    def _scan_binary(self, data: bytes, source_path: str, seen: set) -> List[Finding]:
        findings = []

        # Extract all printable ASCII strings
        printable_strings = self._extract_strings(data)

        for string_bytes in printable_strings:
            # Run all regex patterns against each extracted string
            all_patterns = {**self.patterns, **self._compiled_native}
            for name, pattern in all_patterns.items():
                try:
                    matches = pattern.findall(string_bytes)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        try:
                            match_str = match.decode('utf-8', errors='ignore').strip()
                        except AttributeError:
                            match_str = str(match).strip()

                        if len(match_str) < MIN_STRING_LEN:
                            continue

                        dedup_key = (name, match_str)
                        if dedup_key in seen:
                            continue
                        seen.add(dedup_key)

                        severity = self.scorer.score(name)
                        arch = self._get_arch(source_path)

                        findings.append(Finding(
                            pattern_name=name,
                            match=match_str,
                            severity=severity,
                            source_file=source_path,
                            source_type="native",
                            tags=["native", arch] + self._native_tags(name, match_str),
                        ))
                except Exception:
                    continue

        return findings

    def _extract_strings(self, data: bytes, min_len: int = MIN_STRING_LEN) -> List[bytes]:
        """Extract printable ASCII strings from binary data (like Unix `strings`)."""
        pattern = re.compile(rb'[ -~]{' + str(min_len).encode() + rb',}')
        return pattern.findall(data)

    def _get_arch(self, path: str) -> str:
        """Determine CPU architecture from library path."""
        path_lower = path.lower()
        if 'arm64-v8a' in path_lower:
            return 'arm64'
        elif 'armeabi-v7a' in path_lower:
            return 'arm32'
        elif 'x86_64' in path_lower:
            return 'x86_64'
        elif 'x86' in path_lower:
            return 'x86'
        return 'unknown_arch'

    def _native_tags(self, pattern_name: str, match: str) -> List[str]:
        tags = []
        name_lower = pattern_name.lower()
        match_lower = match.lower()
        if 'http' in match_lower:
            tags.append('endpoint')
        if any(k in name_lower for k in ['secret', 'key', 'token', 'password']):
            tags.append('secret')
        if 'aws' in name_lower or 'akia' in match:
            tags.append('aws')
        if '192.168' in match or '10.' in match or '172.' in match:
            tags.append('internal_ip')
        return tags
