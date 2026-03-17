"""
APKLeaks Pro - Async Endpoint Prober
Validates discovered URLs, fingerprints backends, and flags interesting responses.
"""
import asyncio
import re
from typing import List, Dict, Optional
from urllib.parse import urlparse
from rich.console import Console

from core.models import ProbeResult, Finding

console = Console()

# Headers that suggest interesting technology
TECH_HEADERS = {
    "x-powered-by": "Technology",
    "x-aspnet-version": "ASP.NET",
    "x-aspnetmvc-version": "ASP.NET MVC",
    "x-generator": "Generator",
    "cf-ray": "Cloudflare",
    "x-amzn-requestid": "AWS",
    "x-amz-cf-id": "AWS CloudFront",
    "x-cache": "Cache Layer",
    "via": "Proxy/CDN",
}

# Response body patterns that indicate interesting content
INTERESTING_BODY_PATTERNS = {
    "api_docs":         r'swagger|openapi|api-docs|redoc|graphiql|graphql-playground',
    "credentials_exposed": r'"access_key"|"api_key"|"token"|"secret"|"password"\s*:',
    "server_error":     r'stack trace|exception|error.*at.*line|syntax error|at.*\(.*\.java',
    "directory_listing": r'Index of /|<title>Directory listing|Parent Directory',
    "debug_info":       r'debug=true|DEBUG MODE|phpinfo\(\)|Server information',
    "admin_panel":      r'admin panel|administration|dashboard.*login|wp-admin',
    "database_error":   r'SQL syntax|mysql_fetch|ORA-\d{5}|pg_query|SQLiteException',
    "aws_metadata":     r'ami-id|instance-id|iam/security-credentials',
    "firebase_data":    r'"rules".*"\.read".*true|"rules".*"\.write".*true',
    "env_exposed":      r'APP_KEY=|DB_PASSWORD=|SECRET_KEY=|API_KEY=',
    "source_code":      r'<\?php|#!/usr/bin|from django|import flask|require\s+[\'"]express',
}


class EndpointProber:
    def __init__(self, timeout: int = 10, concurrency: int = 20,
                 custom_headers: Optional[Dict] = None, verify_ssl: bool = False):
        self.timeout = timeout
        self.concurrency = concurrency
        self.verify_ssl = verify_ssl
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36",
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
            **(custom_headers or {}),
        }
        self._compiled_body_patterns = {
            k: re.compile(v, re.IGNORECASE | re.DOTALL)
            for k, v in INTERESTING_BODY_PATTERNS.items()
        }

    def probe_all(self, findings: List[Finding]) -> List[ProbeResult]:
        """Extract unique URLs from findings and probe all of them."""
        urls = self._extract_urls(findings)
        if not urls:
            console.print("[yellow]No probeable URLs found in findings.[/yellow]")
            return []

        console.print(f"[cyan]🌐 Probing {len(urls)} unique endpoints (concurrency={self.concurrency})...[/cyan]")
        return asyncio.run(self._probe_all_async(urls))

    def _extract_urls(self, findings: List[Finding]) -> List[str]:
        """Extract unique, valid HTTP/HTTPS URLs from all findings."""
        urls = set()
        url_pattern = re.compile(
            r'https?://[^\s\'"<>\[\]{}|\\^`\x00-\x1f\x7f-\xff]{4,}',
            re.IGNORECASE
        )
        for finding in findings:
            matches = url_pattern.findall(finding.match)
            for url in matches:
                url = url.rstrip('.,;:\'\")')
                try:
                    parsed = urlparse(url)
                    if parsed.scheme in ('http', 'https') and parsed.netloc:
                        # Skip obviously internal/localhost unless flagged
                        urls.add(url)
                except Exception:
                    continue
        return list(urls)

    async def _probe_all_async(self, urls: List[str]) -> List[ProbeResult]:
        try:
            import httpx
        except ImportError:
            console.print("[red]httpx not installed. Run: pip install httpx[/red]")
            return []

        semaphore = asyncio.Semaphore(self.concurrency)
        results = []

        async with httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout),
            follow_redirects=True,
            verify=self.verify_ssl,
            headers=self.headers,
        ) as client:
            tasks = [self._probe_single(client, semaphore, url) for url in urls]
            completed = await asyncio.gather(*tasks, return_exceptions=True)

            for result in completed:
                if isinstance(result, ProbeResult):
                    results.append(result)
                elif isinstance(result, Exception):
                    pass  # Silently skip failed probes

        # Sort: alive first, then by status code
        results.sort(key=lambda r: (not r.is_alive, r.status_code or 999))
        return results

    async def _probe_single(self, client, semaphore, url: str) -> ProbeResult:
        async with semaphore:
            result = ProbeResult(url=url)
            try:
                response = await client.get(url)
                result.status_code = response.status_code
                result.server = response.headers.get("server", "")
                result.content_type = response.headers.get("content-type", "")
                result.content_length = len(response.content)
                result.redirect_chain = [str(r.url) for r in response.history]

                body_preview = response.text[:5000]
                result.response_preview = response.text[:300]

                # Fingerprint technologies from headers
                tech_stack = self._fingerprint_headers(dict(response.headers))
                if tech_stack:
                    result.flags.extend(tech_stack)

                # Flag interesting body patterns
                body_flags = self._analyze_body(body_preview, response.status_code)
                result.flags.extend(body_flags)

                # Flag authentication-related status codes
                if response.status_code == 401:
                    result.flags.append("requires_auth_basic")
                elif response.status_code == 403:
                    result.flags.append("access_forbidden")
                elif response.status_code == 302:
                    result.flags.append("redirect")
                elif response.status_code == 200 and not body_flags:
                    result.flags.append("alive")

            except Exception as e:
                result.error = str(e)[:200]

            return result

    def _fingerprint_headers(self, headers: Dict) -> List[str]:
        flags = []
        for header, label in TECH_HEADERS.items():
            value = headers.get(header, "")
            if value:
                flags.append(f"tech:{label}:{value[:50]}")

        # WAF Detection
        waf_headers = ["x-sucuri-id", "x-firewall", "x-waf", "x-akamai"]
        for h in waf_headers:
            if h in headers:
                flags.append("waf_detected")
                break

        return flags

    def _analyze_body(self, body: str, status_code: int) -> List[str]:
        flags = []
        for flag_name, pattern in self._compiled_body_patterns.items():
            if pattern.search(body):
                flags.append(flag_name)
        return flags

    def generate_interesting_summary(self, results: List[ProbeResult]) -> Dict:
        """Summarize probe results highlighting actionable findings."""
        alive = [r for r in results if r.is_alive]
        interesting = [r for r in alive if r.flags]
        high_value_flags = {"api_docs", "credentials_exposed", "directory_listing",
                            "database_error", "debug_info", "aws_metadata",
                            "firebase_data", "env_exposed", "source_code"}

        critical_findings = [
            r for r in alive
            if any(f in high_value_flags for f in r.flags)
        ]

        return {
            "total_probed": len(results),
            "alive": len(alive),
            "errors": len(results) - len(alive),
            "interesting": len(interesting),
            "critical_findings": len(critical_findings),
            "status_distribution": self._count_statuses(alive),
            "top_flags": self._top_flags(alive),
        }

    def _count_statuses(self, results: List[ProbeResult]) -> Dict:
        counts = {}
        for r in results:
            key = str(r.status_code)
            counts[key] = counts.get(key, 0) + 1
        return dict(sorted(counts.items()))

    def _top_flags(self, results: List[ProbeResult]) -> List[str]:
        flag_counts = {}
        for r in results:
            for flag in r.flags:
                flag_counts[flag] = flag_counts.get(flag, 0) + 1
        return sorted(flag_counts, key=lambda k: flag_counts[k], reverse=True)[:10]
