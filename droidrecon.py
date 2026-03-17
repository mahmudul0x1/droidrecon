#!/usr/bin/env python3
"""
██████╗ ██████╗  ██████╗ ██╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║  ██║██████╔╝██║   ██║██║██║  ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║  ██║██╔══██╗██║   ██║██║██║  ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██████╔╝██║  ██║╚██████╔╝██║██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝

DroidRecon — Advanced Android APK Security Scanner
Author  : mahmudul0x1
GitHub  : https://github.com/mahmudul0x1/droidrecon
License : MIT

Usage:
    python droidrecon.py -f target.apk [options]
    python droidrecon.py -f target.apk --all -o report.html --html
"""

import os
import sys
import json
import argparse
import asyncio
import shutil
from datetime import datetime
from pathlib import Path
from rich.console import Console
from rich.rule import Rule

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.models import ScanResult
from core.severity import SeverityScorer, SEVERITY_ORDER
from core.scanner import APKScanner
from core.manifest_parser import ManifestParser
from core.native_scanner import NativeScanner
from core.smali_auditor import SmaliAuditor
from core.prober import EndpointProber
from core.secret_validator import SecretValidator
from core.reporter import Reporter
from core.cert_analyzer import CertAnalyzer
from core.sdk_fingerprinter import SDKFingerprinter
from core.obfuscation_detector import ObfuscationDetector
from core.domain_extractor import DomainExtractor
from core.sarif_exporter import SARIFExporter

console = Console()
TOOL_VERSION = "1.0.0"


# ─── CLI Arguments ────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="droidrecon",
        description="DroidRecon — Advanced Android APK Security Scanner by mahmudul0x1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Examples:
  # Basic scan (auto-saves JSON)
  python droidrecon.py -f app.apk

  # Full pentest mode — all features
  python droidrecon.py -f app.apk --all

  # CRITICAL/HIGH only, HTML report
  python droidrecon.py -f app.apk --all --severity HIGH -o report.html --html

  # Selective modules
  python droidrecon.py -f app.apk --manifest --smali-audit --cert --sdk-fingerprint

  # Active validation + probing
  python droidrecon.py -f app.apk --probe --validate --concurrency 30

  # CI/CD mode — SARIF output, non-zero exit on HIGH+
  python droidrecon.py -f app.apk --all --sarif -o results.sarif

  # Batch scan all APKs in a directory
  python droidrecon.py --batch /path/to/apk/folder/ --all -o /output/dir/
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        """
    )

    # ── Input ──────────────────────────────────────────────────────────────
    input_group = parser.add_argument_group("Input")
    input_mutex = input_group.add_mutually_exclusive_group(required=True)
    input_mutex.add_argument("-f", "--file", help="Single APK file to scan")
    input_mutex.add_argument("--batch", metavar="DIR", help="Batch scan all APKs in directory")

    parser.add_argument("-p", "--pattern",
                        default=os.path.join(os.path.dirname(__file__), "config", "regexes.json"),
                        help="Custom patterns JSON (default: config/regexes.json)")
    parser.add_argument("-a", "--args", default="",
                        help='jadx arguments (e.g., "--deobf --threads-count 8")')
    parser.add_argument("-d", "--output-dir",
                        help="Directory to store decompiled APK source (default: auto temp)")

    # ── Feature Flags ───────────────────────────────────────────────────────
    feat = parser.add_argument_group("Feature Flags")
    feat.add_argument("--manifest",         action="store_true", help="Parse AndroidManifest.xml — exported components, deep links, permissions")
    feat.add_argument("--scan-native",      action="store_true", help="Scan native .so libraries for secrets/endpoints")
    feat.add_argument("--smali-audit",      action="store_true", help="Audit bytecode for 25+ vulnerability patterns (weak crypto, SSL bypass, SQLi...)")
    feat.add_argument("--probe",            action="store_true", help="Actively probe discovered HTTP/HTTPS endpoints")
    feat.add_argument("--validate",         action="store_true", help="Validate secrets against live APIs (Firebase, GitHub, Slack, Stripe...)")
    feat.add_argument("--cert",             action="store_true", help="Analyze APK signing certificate (debug cert, weak algo, Janus vuln)")
    feat.add_argument("--sdk-fingerprint",  action="store_true", help="Detect 60+ third-party SDKs with risk classification")
    feat.add_argument("--obfuscation",      action="store_true", help="Detect ProGuard/R8/DexGuard obfuscation + packing")
    feat.add_argument("--domain-intel",     action="store_true", help="Extract, classify and deduplicate all domains from findings")
    feat.add_argument("--all",              action="store_true", help="Enable ALL features (recommended for full pentest)")

    # ── Filtering ───────────────────────────────────────────────────────────
    filt = parser.add_argument_group("Filtering")
    filt.add_argument("--severity", choices=SEVERITY_ORDER, default="INFO",
                      help="Minimum severity to display (default: INFO = all)")
    filt.add_argument("--tags", nargs="+", metavar="TAG",
                      help="Filter findings by tags (e.g. --tags aws firebase)")

    # ── Output ──────────────────────────────────────────────────────────────
    out = parser.add_argument_group("Output")
    out.add_argument("-o", "--output",  help="Output file path (auto-named if omitted)")
    out.add_argument("--json",  action="store_true", help="Save JSON report")
    out.add_argument("--html",  action="store_true", help="Save HTML pentest report")
    out.add_argument("--sarif", action="store_true", help="Save SARIF report (GitHub Code Scanning / CI/CD)")
    out.add_argument("--quiet", action="store_true", help="Suppress progress output")

    # ── Probe Options ───────────────────────────────────────────────────────
    probe = parser.add_argument_group("Probe Options")
    probe.add_argument("--timeout",     type=int, default=10,  help="HTTP timeout seconds (default: 10)")
    probe.add_argument("--concurrency", type=int, default=20,  help="Concurrent probe requests (default: 20)")
    probe.add_argument("--verify-ssl",  action="store_true",   help="Verify SSL certificates (default: off)")
    probe.add_argument("--header",      action="append", dest="headers", metavar="Key:Value",
                       help="Custom HTTP header — repeatable: --header 'Authorization: Bearer tok'")

    return parser.parse_args()


# ─── Helper Functions ─────────────────────────────────────────────────────────

def build_headers(header_args):
    headers = {}
    if not header_args:
        return headers
    for h in header_args:
        if ":" in h:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()
    return headers


def auto_name(base: str, ext: str) -> str:
    stem = Path(base).stem
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{stem}_droidrecon_{ts}.{ext}"


def apply_tag_filter(findings, tags):
    if not tags:
        return findings
    return [f for f in findings if any(t in f.tags for t in tags)]


# ─── Single APK Scan ─────────────────────────────────────────────────────────

def scan_apk(apk_path: str, args, scorer: SeverityScorer, reporter: Reporter) -> ScanResult:
    result = ScanResult(apk_path=os.path.abspath(apk_path))

    console.print(Rule(f"[bold cyan]Scanning: {Path(apk_path).name}[/bold cyan]"))
    console.print(f"[bold]📱 Target:[/bold] {apk_path}")

    active_features = []
    if args.manifest:        active_features.append("manifest")
    if args.scan_native:     active_features.append("native")
    if args.smali_audit:     active_features.append("smali-audit")
    if args.cert:            active_features.append("cert")
    if args.sdk_fingerprint: active_features.append("sdk")
    if args.obfuscation:     active_features.append("obfuscation")
    if args.domain_intel:    active_features.append("domain-intel")
    if args.probe:           active_features.append("probe")
    if args.validate:        active_features.append("validate")
    console.print(f"[bold]🎯 Modules:[/bold] core-scan {' '.join(active_features)}")
    console.print(f"[bold]🔍 Min severity:[/bold] {args.severity}\n")

    # ── Phase 1: Decompile ────────────────────────────────────────────────
    scanner = APKScanner(
        apk_path=apk_path,
        patterns_path=args.pattern,
        severity_scorer=scorer,
        jadx_args=args.args,
        output_dir=args.output_dir,
    )
    decompiled_dir = scanner.decompile()
    if not decompiled_dir:
        console.print("[bold red]Decompilation failed — aborting this APK.[/bold red]")
        return result

    # ── Phase 2: Certificate Analysis ─────────────────────────────────────
    if args.cert:
        console.print(Rule("[cyan]🔏 Certificate Analysis[/cyan]"))
        cert_analyzer = CertAnalyzer(apk_path)
        result.cert_info = cert_analyzer.analyze()
        issues = len(result.cert_info.get("issues", []))
        debug = result.cert_info.get("is_debug_signed", False)
        console.print(f"[green]✓ Cert: {issues} issues{'  [bold red]DEBUG SIGNED![/bold red]' if debug else ''}[/green]")

    # ── Phase 3: Obfuscation Detection ────────────────────────────────────
    if args.obfuscation:
        console.print(Rule("[cyan]🔒 Obfuscation Detection[/cyan]"))
        obf_detector = ObfuscationDetector(apk_path)
        result.obfuscation_info = obf_detector.analyze(decompiled_dir)
        level = result.obfuscation_info.get("obfuscation_level", "None")
        score = result.obfuscation_info.get("obfuscation_score", 0)
        packers = result.obfuscation_info.get("packers_detected", [])
        console.print(f"[green]✓ Obfuscation: {level} ({score}/100){' — Packer: '+', '.join(packers) if packers else ''}[/green]")

    # ── Phase 4: Manifest Analysis ────────────────────────────────────────
    if args.manifest:
        console.print(Rule("[cyan]🗺️  Manifest Analysis[/cyan]"))
        mp = ManifestParser(apk_path)
        result.manifest_findings = mp.get_findings()
        manifest_data = mp.parse()
        if manifest_data:
            result.package_name = manifest_data.get("package_name", "unknown")
            result.app_version  = manifest_data.get("version_name", "unknown")
            result.min_sdk      = str(manifest_data.get("min_sdk", "unknown"))
            result.target_sdk   = str(manifest_data.get("target_sdk", "unknown"))
        console.print(f"[green]✓ Manifest: {len(result.manifest_findings)} issues[/green]")

    # ── Phase 5: Core Regex Scan ──────────────────────────────────────────
    console.print(Rule("[cyan]🔑 Core Secret & Endpoint Scan[/cyan]"))
    findings = scanner.scan(decompiled_dir, min_severity=args.severity)
    if args.tags:
        findings = apply_tag_filter(findings, args.tags)
    result.findings = findings
    console.print(f"[green]✓ Core scan: {len(findings)} findings[/green]")

    # ── Phase 6: Smali Vulnerability Audit ───────────────────────────────
    if args.smali_audit:
        console.print(Rule("[cyan]🛡️  Vulnerability Audit[/cyan]"))
        auditor = SmaliAuditor(scorer)
        smali_findings = auditor.scan(decompiled_dir)
        result.smali_findings = [
            f for f in smali_findings
            if SEVERITY_ORDER.index(f.severity) <= SEVERITY_ORDER.index(args.severity)
        ]
        console.print(f"[green]✓ Audit: {len(result.smali_findings)} issues[/green]")

    # ── Phase 7: Native Library Scan ─────────────────────────────────────
    if args.scan_native:
        console.print(Rule("[cyan]🔬 Native Library Scan[/cyan]"))
        native_scanner = NativeScanner(apk_path=apk_path, patterns=scanner.patterns, scorer=scorer)
        native_findings = native_scanner.scan()
        result.native_findings = [
            f for f in native_findings
            if SEVERITY_ORDER.index(f.severity) <= SEVERITY_ORDER.index(args.severity)
        ]
        console.print(f"[green]✓ Native: {len(result.native_findings)} findings[/green]")

    # ── Phase 8: SDK Fingerprinting ───────────────────────────────────────
    if args.sdk_fingerprint:
        console.print(Rule("[cyan]📦 SDK Fingerprinting[/cyan]"))
        sdk_fp = SDKFingerprinter()
        result.sdk_info = sdk_fp.scan(decompiled_dir)
        console.print(
            f"[green]✓ SDKs: {result.sdk_info.get('total_sdks_detected',0)} detected "
            f"({result.sdk_info.get('high_risk_count',0)} high-risk)[/green]"
        )

    # ── Phase 9: Domain Intelligence ─────────────────────────────────────
    if args.domain_intel:
        console.print(Rule("[cyan]🌍 Domain Intelligence[/cyan]"))
        de = DomainExtractor()
        result.domain_info = de.extract(result.all_findings)
        console.print(f"[green]✓ Domains: {result.domain_info.get('total',0)} unique domains extracted[/green]")

    # ── Phase 10: Active Endpoint Probing ─────────────────────────────────
    if args.probe:
        console.print(Rule("[cyan]🌐 Active Endpoint Probing[/cyan]"))
        prober = EndpointProber(
            timeout=args.timeout,
            concurrency=args.concurrency,
            custom_headers=build_headers(args.headers),
            verify_ssl=args.verify_ssl,
        )
        result.probe_results = prober.probe_all(result.all_findings)
        summary = prober.generate_interesting_summary(result.probe_results)
        console.print(
            f"[green]✓ Probe: {summary['total_probed']} probed → "
            f"{summary['alive']} alive, {summary['interesting']} interesting[/green]"
        )

    # ── Phase 11: Live Secret Validation ──────────────────────────────────
    if args.validate:
        console.print(Rule("[cyan]🔐 Live Secret Validation[/cyan]"))
        validator = SecretValidator(timeout=args.timeout)
        asyncio.run(validator.validate_all(result.all_findings))
        confirmed = sum(1 for f in result.all_findings if f.validated is True)
        console.print(f"[green]✓ Validation: {confirmed} secrets confirmed LIVE[/green]")
        if confirmed > 0:
            console.print(f"[bold red]  ⚠ {confirmed} live credential(s) found! Escalate immediately.[/bold red]")

    scanner.cleanup()
    return result


# ─── Display Results ──────────────────────────────────────────────────────────

def display_results(result: ScanResult, args, reporter: Reporter):
    console.print()
    reporter.print_summary(result)

    if result.cert_info:
        reporter.print_cert_info(result.cert_info)

    if result.obfuscation_info:
        reporter.print_obfuscation_info(result.obfuscation_info)

    console.print(Rule("[bold]🔑 Core Findings[/bold]"))
    reporter.print_findings(result.findings)

    if result.smali_findings:
        console.print(Rule("[bold]🛡️  Vulnerability Audit[/bold]"))
        reporter.print_smali_findings(result.smali_findings)

    if result.native_findings:
        console.print(Rule("[bold]🔬 Native Findings[/bold]"))
        reporter.print_findings(result.native_findings, title="Native Findings")

    if result.manifest_findings:
        console.print(Rule("[bold]🗺️  Manifest[/bold]"))
        reporter.print_manifest_findings(result.manifest_findings)

    if result.sdk_info:
        console.print(Rule("[bold]📦 SDK Fingerprint[/bold]"))
        reporter.print_sdk_findings(result.sdk_info)

    if result.domain_info:
        console.print(Rule("[bold]🌍 Domain Intelligence[/bold]"))
        reporter.print_domain_info(result.domain_info)

    if result.probe_results:
        console.print(Rule("[bold]🌐 Endpoint Probe[/bold]"))
        reporter.print_probe_results(result.probe_results)


# ─── Save Outputs ────────────────────────────────────────────────────────────

def save_outputs(result: ScanResult, args, reporter: Reporter):
    base = args.file or "batch"

    if args.json or (not args.html and not args.sarif):
        path = args.output if (args.output and not args.html and not args.sarif) else auto_name(base, "json")
        if not path.endswith(".json"):
            path += ".json"
        reporter.save_json(result, path)

    if args.html:
        path = args.output if args.output else auto_name(base, "html")
        if not path.endswith(".html"):
            path += ".html"
        reporter.save_html(result, path)

    if args.sarif:
        path = args.output if args.output else auto_name(base, "sarif")
        if not path.endswith(".sarif"):
            path += ".sarif"
        exporter = SARIFExporter()
        exporter.export(result, path)
        console.print(f"[green]✅ SARIF → {path}[/green]")


# ─── Batch Mode ──────────────────────────────────────────────────────────────

def run_batch(args, scorer: SeverityScorer, reporter: Reporter):
    batch_dir = args.batch
    apk_files = list(Path(batch_dir).glob("**/*.apk"))

    if not apk_files:
        console.print(f"[red]No APK files found in: {batch_dir}[/red]")
        sys.exit(1)

    console.print(f"[bold cyan]📂 Batch mode: {len(apk_files)} APK(s) found in {batch_dir}[/bold cyan]\n")

    all_results = []
    max_exit_code = 0

    for i, apk_path in enumerate(apk_files, 1):
        console.print(f"\n[bold]({i}/{len(apk_files)})[/bold]")

        # Override file arg temporarily
        args.file = str(apk_path)

        try:
            result = scan_apk(str(apk_path), args, scorer, reporter)
            all_results.append(result)
            display_results(result, args, reporter)

            # Save individual outputs
            if args.output:
                out_dir = Path(args.output)
                out_dir.mkdir(parents=True, exist_ok=True)
                stem = apk_path.stem
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                if args.html:
                    reporter.save_html(result, str(out_dir / f"{stem}_{ts}.html"))
                if args.json:
                    reporter.save_json(result, str(out_dir / f"{stem}_{ts}.json"))
                if args.sarif:
                    SARIFExporter().export(result, str(out_dir / f"{stem}_{ts}.sarif"))
            else:
                save_outputs(result, args, reporter)

            if result.critical_count > 0:
                max_exit_code = max(max_exit_code, 2)
            elif result.high_count > 0:
                max_exit_code = max(max_exit_code, 1)

        except Exception as e:
            console.print(f"[red]Error scanning {apk_path.name}: {e}[/red]")

    # Batch summary
    console.print(Rule("[bold cyan]📊 Batch Summary[/bold cyan]"))
    console.print(f"[bold]Total APKs scanned:[/bold] {len(all_results)}")
    total_crit = sum(r.critical_count for r in all_results)
    total_high = sum(r.high_count for r in all_results)
    console.print(f"[bold red]Total CRITICAL:[/bold red] {total_crit}  [red]Total HIGH:[/red] {total_high}")

    return max_exit_code


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    # Expand --all
    if args.all:
        args.manifest        = True
        args.scan_native     = True
        args.smali_audit     = True
        args.probe           = True
        args.validate        = True
        args.cert            = True
        args.sdk_fingerprint = True
        args.obfuscation     = True
        args.domain_intel    = True

    scorer   = SeverityScorer()
    reporter = Reporter(scorer)

    if not args.quiet:
        reporter.print_banner()

    # ── Batch Mode ────────────────────────────────────────────────────────
    if args.batch:
        exit_code = run_batch(args, scorer, reporter)
        sys.exit(exit_code)

    # ── Single APK Mode ───────────────────────────────────────────────────
    if not os.path.exists(args.file):
        console.print(f"[bold red]Error: APK not found: {args.file}[/bold red]")
        sys.exit(1)

    result = scan_apk(args.file, args, scorer, reporter)
    display_results(result, args, reporter)
    save_outputs(result, args, reporter)

    # Exit codes for CI/CD
    summary = result.to_dict()["summary"]
    if summary["critical"] > 0:
        sys.exit(2)
    elif summary["high"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
