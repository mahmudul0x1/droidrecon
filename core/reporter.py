"""
DroidRecon - Reporter
Author: mahmudul0x1
https://github.com/mahmudul0x1/droidrecon
"""
import json
from datetime import datetime
from typing import List, Dict
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from core.models import ScanResult, Finding, ManifestFinding, ProbeResult
from core.severity import SeverityScorer, SEVERITY_ORDER

console = Console()
TOOL_VERSION = "1.0.0"

class Reporter:
    def __init__(self, scorer: SeverityScorer):
        self.scorer = scorer

    def print_banner(self):
        console.print("""[bold red]
██████╗ ██████╗  ██████╗ ██╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║  ██║██████╔╝██║   ██║██║██║  ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║  ██║██╔══██╗██║   ██║██║██║  ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██████╔╝██║  ██║╚██████╔╝██║██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝[/bold red]""")
        console.print(f"[dim]  Advanced Android APK Security Scanner | Author: [bold]mahmudul0x1[/bold] | v{TOOL_VERSION} | github.com/mahmudul0x1/droidrecon[/dim]\n")

    def print_summary(self, result: ScanResult):
        s = result.to_dict()["summary"]
        obf = s.get("obfuscation_level","N/A")
        obf_color = "red" if "Heavy" in obf or "Packed" in obf else "yellow" if obf not in ("None","N/A") else "green"
        console.print(Panel(
            f"[bold]Package:[/bold] {result.package_name}  [bold]App:[/bold] {result.app_name}  [bold]v[/bold]{result.app_version}  [bold]SDK:[/bold] {result.min_sdk}–{result.target_sdk}",
            title="📱 App Info", border_style="blue"))
        console.print(Panel(
            f"[bold red]💀 CRITICAL:{s['critical']}[/bold red]  [red]🔴 HIGH:{s['high']}[/red]  [yellow]🟡 MEDIUM:{s['medium']}[/yellow]  [cyan]🔵 LOW:{s['low']}[/cyan]  INFO:{s['info']}\n"
            f"[bold]Manifest:[/bold]{s['manifest_issues']}  [bold]Probed:[/bold]{s['endpoints_probed']}  [bold]Live:[/bold]{s['live_endpoints']}  "
            f"[bold]SDKs:[/bold]{s['sdks_detected']}  [bold]Risk SDKs:[/bold][red]{s['high_risk_sdks']}[/red]  [bold]Domains:[/bold]{s['unique_domains']}\n"
            f"[bold]Cert Issues:[/bold]{s['cert_issues']}  [bold]Obfuscation:[/bold][{obf_color}]{obf}({s['obfuscation_score']}%)[/{obf_color}]",
            title="📊 DroidRecon Summary",
            border_style="red" if s['critical']>0 else "yellow" if s['high']>0 else "green"))

    def print_findings(self, findings: List[Finding], title="Findings"):
        if not findings:
            console.print(f"[dim]  No {title.lower()}.[/dim]"); return
        grouped = {sev: [] for sev in SEVERITY_ORDER}
        for f in findings:
            grouped.get(f.severity, grouped["INFO"]).append(f)
        for sev in SEVERITY_ORDER:
            sf = grouped[sev]
            if not sf: continue
            color = self.scorer.get_color(sev)
            t = Table(title=f"{self.scorer.get_emoji(sev)} {sev} ({len(sf)})", box=box.ROUNDED,
                      border_style=color, show_lines=True, title_style=f"bold {color}")
            t.add_column("Pattern", width=28); t.add_column("Match", width=48, overflow="fold")
            t.add_column("Source", style="dim", width=32, overflow="fold"); t.add_column("Type", width=9)
            t.add_column("✓", width=10)
            for f in sf:
                val = "[bold green]✅ LIVE[/bold green]" if f.validated is True else "[dim]❌[/dim]" if f.validated is False else ""
                t.add_row(f.pattern_name, Text(f.match, overflow="fold"),
                          Text(f.source_file+(f":{f.line_number}" if f.line_number else ""), overflow="fold"),
                          f.source_type, val)
            console.print(t)

    def print_manifest_findings(self, findings: List[ManifestFinding]):
        if not findings: return
        t = Table(title="🗺️  Manifest Attack Surface", box=box.ROUNDED, border_style="magenta", show_lines=True)
        t.add_column("Type",width=22); t.add_column("Name",width=48,overflow="fold")
        t.add_column("Severity",width=10); t.add_column("Details",width=42,overflow="fold")
        for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.severity)):
            color=self.scorer.get_color(f.severity)
            d=f.details.get("risk") or f.details.get("description") or f.details.get("authorities") or ""
            t.add_row(f.component_type.replace("_"," ").title(), f.name, f"[{color}]{f.severity}[/{color}]", Text(d[:90],overflow="fold"))
        console.print(t)

    def print_probe_results(self, results: List[ProbeResult]):
        alive=[r for r in results if r.is_alive]
        if not alive: return
        t = Table(title=f"🌐 Live Endpoints ({len(alive)}/{len(results)} alive)", box=box.ROUNDED, border_style="blue", show_lines=True)
        t.add_column("URL",width=48,overflow="fold"); t.add_column("Status",width=8)
        t.add_column("Server",width=18); t.add_column("Flags",width=38,overflow="fold")
        for r in alive:
            sc = f"[green]{r.status_code}[/green]" if r.status_code and 200<=r.status_code<300 else f"[yellow]{r.status_code}[/yellow]" if r.status_code and 300<=r.status_code<400 else f"[red]{r.status_code}[/red]"
            flags=", ".join(r.flags[:4]) if r.flags else "—"
            if any(f in r.flags for f in ["credentials_exposed","api_docs","database_error","env_exposed"]):
                flags=f"[bold red]{flags}[/bold red]"
            t.add_row(Text(r.url,overflow="fold"),sc,r.server or "—",Text(flags,overflow="fold"))
        console.print(t)

    def print_smali_findings(self, findings: List[Finding]):
        if not findings: return
        t = Table(title=f"🛡️  Vulnerability Audit ({len(findings)} issues)", box=box.ROUNDED, border_style="yellow", show_lines=True)
        t.add_column("Vulnerability",width=34); t.add_column("Severity",width=10)
        t.add_column("CWE",width=10); t.add_column("File",width=36,overflow="fold"); t.add_column("Description",width=42,overflow="fold")
        for f in sorted(findings, key=lambda x: SEVERITY_ORDER.index(x.severity)):
            color=self.scorer.get_color(f.severity)
            cwe=f.validation_detail.get("cwe","—") if f.validation_detail else "—"
            desc=(f.validation_detail.get("description","—")[:55] if f.validation_detail else "—")
            t.add_row(f.pattern_name, f"[{color}]{f.severity}[/{color}]", cwe,
                      Text(f.source_file+(f":{f.line_number}" if f.line_number else ""),overflow="fold"),
                      Text(desc,overflow="fold"))
        console.print(t)

    def print_sdk_findings(self, sdk_info: Dict):
        sdks=sdk_info.get("sdks",[])
        if not sdks: return
        t = Table(title=f"📦 Third-Party SDKs ({len(sdks)} detected)", box=box.ROUNDED, border_style="cyan", show_lines=True)
        t.add_column("SDK",width=28); t.add_column("Category",width=14)
        t.add_column("Risk",width=10); t.add_column("Notes",width=50,overflow="fold")
        for sdk in sdks:
            risk=sdk.get("risk","INFO"); color=self.scorer.get_color(risk)
            t.add_row(sdk.get("name","?"), sdk.get("category","?").title(), f"[{color}]{risk}[/{color}]", Text(sdk.get("notes",""),overflow="fold"))
        console.print(t)

    def print_cert_info(self, cert_info: Dict):
        if not cert_info: return
        sig=", ".join(cert_info.get("signature_versions",[])) or "unknown"
        lines=[
            f"[bold]Signature Versions:[/bold] {sig}",
            f"[bold]V1-Only (Janus):[/bold] {'[red]YES[/red]' if cert_info.get('v1_only') else '[green]No[/green]'}",
            f"[bold]Debug Signed:[/bold] {'[bold red]YES — CRITICAL[/bold red]' if cert_info.get('is_debug_signed') else '[green]No[/green]'}",
        ]
        for c in cert_info.get("certificates",[]):
            lines.append(f"[bold]SHA-256:[/bold] {c.get('sha256_fingerprint','N/A')}")
            if c.get("signature_algorithm"):
                w=" [red](WEAK)[/red]" if c.get("weak_signature") else ""
                lines.append(f"[bold]Sig Algo:[/bold] {c['signature_algorithm']}{w}")
        for issue in cert_info.get("issues",[]):
            color=self.scorer.get_color(issue.get("severity","INFO"))
            lines.append(f"  [{color}][{issue['severity']}][/{color}] {issue['issue']}")
        console.print(Panel("\n".join(lines), title="🔏 Certificate Analysis", border_style="magenta"))

    def print_obfuscation_info(self, obf: Dict):
        if not obf: return
        score=obf.get("obfuscation_score",0); level=obf.get("obfuscation_level","Unknown")
        color="red" if score>70 else "yellow" if score>30 else "green"
        lines=[
            f"[bold]Level:[/bold] [{color}]{level}[/{color}]  [bold]Score:[/bold] [{color}]{score}/100[/{color}]",
            f"[bold]Short Class Ratio:[/bold] {obf.get('short_class_ratio',0):.1%}  [bold]Classes:[/bold] {obf.get('total_classes',0)}",
            f"[bold]MultiDEX:[/bold] {'Yes ('+str(obf.get('dex_count',0))+' files)' if obf.get('multidex') else 'No'}  [bold]String Encryption:[/bold] {'[yellow]Yes[/yellow]' if obf.get('string_encryption') else 'No'}",
        ]
        if obf.get("packers_detected"):
            lines.append(f"[bold]Packers:[/bold] [red]{', '.join(obf['packers_detected'])}[/red]")
        console.print(Panel("\n".join(lines), title="🔒 Obfuscation Analysis", border_style="blue"))

    def print_domain_info(self, domain_info: Dict):
        if not domain_info or domain_info.get("total",0)==0: return
        t = Table(title=f"🌍 Domain Intelligence ({domain_info.get('total',0)} domains)", box=box.ROUNDED, border_style="cyan", show_lines=True)
        t.add_column("Domain",width=42,overflow="fold"); t.add_column("Category",width=14)
        t.add_column("Internal?",width=10); t.add_column("Env-Specific?",width=14)
        for d in domain_info.get("all_domains",[])[:40]:
            cat=d.get("category","unknown"); cat_color="red" if cat=="tracking" else "yellow" if cat=="cloud" else "cyan"
            t.add_row(Text(d.get("domain",""),overflow="fold"), f"[{cat_color}]{cat}[/{cat_color}]",
                      "[red]YES[/red]" if d.get("is_internal") else "—",
                      "[yellow]YES[/yellow]" if d.get("is_environment_specific") else "—")
        console.print(t)

    def save_json(self, result: ScanResult, output_path: str):
        with open(output_path,"w") as f:
            json.dump(result.to_dict(), f, indent=2, default=str)
        console.print(f"[green]✅ JSON → {output_path}[/green]")

    def save_html(self, result: ScanResult, output_path: str):
        """Generate full self-contained HTML pentest report."""
        data = result.to_dict()
        s = data["summary"]

        def badge(sev):
            c={"CRITICAL":"#dc2626","HIGH":"#ea580c","MEDIUM":"#ca8a04","LOW":"#2563eb","INFO":"#6b7280"}.get(sev,"#6b7280")
            return f'<span class="badge" style="background:{c}">{sev}</span>'

        def frows(fl, vcol=False):
            if not fl: return '<tr><td colspan="6" class="empty">No findings.</td></tr>'
            out=""
            for f in fl:
                val=""
                if vcol:
                    val='<span style="color:#16a34a;font-weight:700">✅ LIVE</span>' if f.get("validated") is True else ('<span style="color:#6b7280">❌</span>' if f.get("validated") is False else "")
                src=f.get("source","—")+(f':{f["line"]}' if f.get("line") else "")
                out+=f'<tr><td>{badge(f.get("severity","INFO"))}</td><td><code>{f.get("pattern","")}</code></td><td class="mono br">{str(f.get("match",""))[:250]}</td><td class="dim sm">{src}</td><td>{f.get("source_type","")}</td>{"<td>"+val+"</td>" if vcol else ""}</tr>'
            return out

        def sdkrows(sdks):
            if not sdks: return '<tr><td colspan="4" class="empty">None detected.</td></tr>'
            rc={"HIGH":"#dc2626","MEDIUM":"#ca8a04","LOW":"#2563eb","INFO":"#6b7280","CRITICAL":"#7c3aed"}
            return "".join(f'<tr><td>{s.get("name","")}</td><td>{s.get("category","").title()}</td><td><span class="badge" style="background:{rc.get(s.get("risk","INFO"),"#6b7280")}">{s.get("risk","INFO")}</span></td><td class="dim">{s.get("notes","")}</td></tr>' for s in sdks)

        def mrows(ml):
            if not ml: return '<tr><td colspan="4" class="empty">No issues.</td></tr>'
            return "".join(f'<tr><td>{badge(m.get("severity","INFO"))}</td><td>{m.get("component_type","").replace("_"," ").title()}</td><td><code>{m.get("name","")}</code></td><td class="dim">{(m.get("details",{}).get("risk") or m.get("details",{}).get("description") or "")[:120]}</td></tr>' for m in ml)

        def prows(probes):
            alive=[p for p in probes if p.get("alive")]
            if not alive: return '<tr><td colspan="4" class="empty">No live endpoints.</td></tr>'
            return "".join(f'<tr><td class="br"><a href="{p["url"]}" target="_blank">{p["url"]}</a></td><td style="color:{"#16a34a" if str(p.get("status_code","")).startswith("2") else "#ca8a04" if str(p.get("status_code","")).startswith("3") else "#dc2626"};font-weight:700">{p.get("status_code","—")}</td><td>{p.get("server") or "—"}</td><td class="dim">{", ".join(p.get("flags",[])[:4]) or "—"}</td></tr>' for p in alive)

        def drows(ds):
            return "".join(f'<tr><td class="mono">{d.get("domain","")}</td><td>{d.get("category","")}</td><td>{"<span style=color:#dc2626>YES</span>" if d.get("is_internal") else "—"}</td><td>{"<span style=color:#ca8a04>YES</span>" if d.get("is_environment_specific") else "—"}</td></tr>' for d in ds[:60])

        obf=data.get("obfuscation",{}); cert=data.get("certificate",{})
        sdks=data.get("sdks",{}).get("sdks",[])
        dom=data.get("domains",{})

        html=f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DroidRecon — {result.package_name}</title>
<style>
:root{{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#e2e8f0;--dim:#94a3b8;--accent:#38bdf8}}
*{{box-sizing:border-box;margin:0;padding:0}}body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;line-height:1.6;font-size:14px}}
header{{background:linear-gradient(135deg,#1e293b,#0f172a);padding:2rem 2.5rem;border-bottom:1px solid var(--border)}}
header h1{{font-size:1.7rem;color:var(--accent)}}header .sub{{color:var(--dim);margin-top:.3rem;font-size:.85rem}}
nav{{background:#1e293b;border-bottom:1px solid var(--border);padding:.4rem 2.5rem;display:flex;gap:1rem;overflow-x:auto;position:sticky;top:0;z-index:100}}
nav a{{color:var(--dim);text-decoration:none;font-size:.8rem;white-space:nowrap;padding:.25rem .5rem;border-radius:5px}}nav a:hover{{color:var(--text);background:rgba(255,255,255,.07)}}
.container{{max-width:1400px;margin:0 auto;padding:1.5rem 2rem}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:.8rem;margin:1.2rem 0}}
.stat{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1rem;text-align:center}}
.stat .n{{font-size:2rem;font-weight:800;line-height:1}}.stat .l{{color:var(--dim);font-size:.74rem;margin-top:.25rem;text-transform:uppercase;letter-spacing:.05em}}
.cr{{color:#dc2626;border-color:#dc2626}}.hi{{color:#ea580c;border-color:#ea580c}}.me{{color:#ca8a04;border-color:#ca8a04}}.lo{{color:#2563eb;border-color:#2563eb}}.ok{{color:#16a34a;border-color:#16a34a}}
section{{margin:2rem 0}}section h2{{font-size:1.1rem;color:var(--accent);padding-bottom:.4rem;border-bottom:1px solid var(--border);margin-bottom:.8rem}}
table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:8px;overflow:hidden;font-size:.8rem}}
thead th{{background:#0f172a;padding:.6rem .9rem;text-align:left;color:var(--dim);text-transform:uppercase;font-size:.7rem;letter-spacing:.06em;white-space:nowrap}}
tbody td{{padding:.5rem .9rem;border-bottom:1px solid var(--border);vertical-align:top}}tbody tr:last-child td{{border-bottom:none}}tbody tr:hover td{{background:rgba(56,189,248,.04)}}
.badge{{padding:.18rem .5rem;border-radius:9999px;font-size:.67rem;font-weight:700;color:#fff;white-space:nowrap}}
code{{font-family:'Courier New',monospace;font-size:.78rem}}.mono{{font-family:'Courier New',monospace;font-size:.77rem}}.br{{word-break:break-all}}.dim{{color:var(--dim)}}.sm{{font-size:.77rem}}
.empty{{text-align:center;color:var(--dim);font-style:italic;padding:1.2rem}}a{{color:var(--accent);text-decoration:none}}a:hover{{text-decoration:underline}}
.ig{{display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1.2rem}}.ic{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1rem}}.ic h3{{color:var(--accent);font-size:.85rem;margin-bottom:.6rem}}
.ir{{display:flex;justify-content:space-between;padding:.2rem 0;border-bottom:1px solid rgba(51,65,85,.5);font-size:.8rem}}.ir:last-child{{border-bottom:none}}.ir .k{{color:var(--dim)}}
footer{{text-align:center;color:var(--dim);padding:1.5rem;font-size:.78rem;border-top:1px solid var(--border);margin-top:2rem}}
</style></head><body>
<header><h1>🔍 DroidRecon — Security Report</h1>
<div class="sub">📱 <strong>{result.package_name}</strong> | {result.app_name} v{result.app_version} | SDK {result.min_sdk}–{result.target_sdk} | 🕐 {result.scan_timestamp[:19].replace("T"," ")} UTC | by <strong>mahmudul0x1</strong></div></header>
<nav>
  <a href="#sum">📊 Summary</a><a href="#sec">🔑 Secrets</a><a href="#vuln">🛡️ Vulns</a><a href="#nat">🔬 Native</a>
  <a href="#man">🗺️ Manifest</a><a href="#ep">🌐 Endpoints</a><a href="#sdk">📦 SDKs</a><a href="#dom">🌍 Domains</a>
  <a href="#cert">🔏 Cert</a><a href="#obf">🔒 Obfusc.</a>
</nav>
<div class="container">
<section id="sum"><h2>📊 Scan Summary</h2>
<div class="grid">
  <div class="stat cr"><div class="n">{s['critical']}</div><div class="l">Critical</div></div>
  <div class="stat hi"><div class="n">{s['high']}</div><div class="l">High</div></div>
  <div class="stat me"><div class="n">{s['medium']}</div><div class="l">Medium</div></div>
  <div class="stat lo"><div class="n">{s['low']}</div><div class="l">Low</div></div>
  <div class="stat"><div class="n">{s['info']}</div><div class="l">Info</div></div>
  <div class="stat"><div class="n">{s['sdks_detected']}</div><div class="l">SDKs</div></div>
  <div class="stat {'hi' if s['high_risk_sdks']>0 else 'ok'}"><div class="n">{s['high_risk_sdks']}</div><div class="l">Risk SDKs</div></div>
  <div class="stat"><div class="n">{s['live_endpoints']}</div><div class="l">Live URLs</div></div>
  <div class="stat"><div class="n">{s['unique_domains']}</div><div class="l">Domains</div></div>
  <div class="stat {'hi' if s['cert_issues']>0 else 'ok'}"><div class="n">{s['cert_issues']}</div><div class="l">Cert Issues</div></div>
  <div class="stat"><div class="n">{s['obfuscation_score']}</div><div class="l">Obfusc.%</div></div>
</div></section>
<section id="sec"><h2>🔑 Secret & Endpoint Findings ({len(data['findings'])})</h2>
<table><thead><tr><th>Severity</th><th>Pattern</th><th>Match</th><th>Source</th><th>Type</th><th>Valid?</th></tr></thead><tbody>{frows(data['findings'],vcol=True)}</tbody></table></section>
<section id="vuln"><h2>🛡️ Vulnerability Audit ({len(data['smali_findings'])} issues)</h2>
<table><thead><tr><th>Severity</th><th>Vulnerability</th><th>Code</th><th>File</th><th>Type</th></tr></thead><tbody>{frows(data['smali_findings'])}</tbody></table></section>
<section id="nat"><h2>🔬 Native (.so) Findings ({len(data['native_findings'])})</h2>
<table><thead><tr><th>Severity</th><th>Pattern</th><th>Match</th><th>Library</th><th>Type</th></tr></thead><tbody>{frows(data['native_findings'])}</tbody></table></section>
<section id="man"><h2>🗺️ Manifest Attack Surface ({len(data['manifest'])} issues)</h2>
<table><thead><tr><th>Severity</th><th>Type</th><th>Name</th><th>Details</th></tr></thead><tbody>{mrows(data['manifest'])}</tbody></table></section>
<section id="ep"><h2>🌐 Active Endpoint Probe</h2>
<table><thead><tr><th>URL</th><th>Status</th><th>Server</th><th>Flags</th></tr></thead><tbody>{prows(data['probe_results'])}</tbody></table></section>
<section id="sdk"><h2>📦 Third-Party SDK Fingerprint ({len(sdks)} detected)</h2>
<table><thead><tr><th>SDK</th><th>Category</th><th>Risk</th><th>Notes</th></tr></thead><tbody>{sdkrows(sdks)}</tbody></table></section>
<section id="dom"><h2>🌍 Domain Intelligence ({dom.get('total',0)} domains)</h2>
<table><thead><tr><th>Domain</th><th>Category</th><th>Internal?</th><th>Env-Specific?</th></tr></thead><tbody>{drows(dom.get('all_domains',[]))}</tbody></table></section>
<section id="cert"><h2>🔏 Certificate Analysis</h2>
<div class="ig">
  <div class="ic"><h3>Signing Info</h3>
    <div class="ir"><span class="k">Signature Versions</span><span>{", ".join(cert.get("signature_versions",[])) or "unknown"}</span></div>
    <div class="ir"><span class="k">V1-Only (Janus)</span><span style="color:{'#dc2626' if cert.get('v1_only') else '#16a34a'}">{"YES ⚠" if cert.get("v1_only") else "No"}</span></div>
    <div class="ir"><span class="k">Debug Signed</span><span style="color:{'#dc2626' if cert.get('is_debug_signed') else '#16a34a'}">{"YES — CRITICAL" if cert.get("is_debug_signed") else "No"}</span></div>
    {"".join(f'<div class="ir"><span class="k">SHA-256</span><span class="dim sm">{c.get("sha256_fingerprint","N/A")[:40]}...</span></div>' for c in cert.get("certificates",[]))}
  </div>
  <div class="ic"><h3>Certificate Issues</h3>
    {"".join(f'<div class="ir"><span class="k">{badge(i.get("severity","INFO"))}</span><span>{i.get("issue","")}</span></div>' for i in cert.get("issues",[])) or '<div class="empty">No issues found.</div>'}
  </div>
</div></section>
<section id="obf"><h2>🔒 Obfuscation & Packing</h2>
<div class="ig">
  <div class="ic"><h3>Analysis</h3>
    <div class="ir"><span class="k">Level</span><span style="color:{'#dc2626' if obf.get('obfuscation_score',0)>70 else '#ca8a04' if obf.get('obfuscation_score',0)>30 else '#16a34a'}">{obf.get("obfuscation_level","N/A")} ({obf.get("obfuscation_score",0)}/100)</span></div>
    <div class="ir"><span class="k">Short Class Ratio</span><span>{obf.get("short_class_ratio",0):.1%}</span></div>
    <div class="ir"><span class="k">Total Classes</span><span>{obf.get("total_classes",0)}</span></div>
    <div class="ir"><span class="k">MultiDEX</span><span>{"Yes ("+str(obf.get("dex_count",1))+" DEX)" if obf.get("multidex") else "No"}</span></div>
    <div class="ir"><span class="k">String Encryption</span><span style="color:{'#ca8a04' if obf.get('string_encryption') else '#16a34a'}">{"Detected ⚠" if obf.get("string_encryption") else "Not detected"}</span></div>
  </div>
  <div class="ic"><h3>Packers / Shielding</h3>
    {"".join(f'<div class="ir"><span class="k">Detected</span><span style="color:#dc2626;font-weight:700">{p}</span></div>' for p in obf.get("packers_detected",[])) or '<div class="empty">No known packers detected.</div>'}
  </div>
</div></section>
</div>
<footer>Generated by <strong>DroidRecon v{TOOL_VERSION}</strong> by <strong>mahmudul0x1</strong> — <a href="https://github.com/mahmudul0x1/droidrecon">github.com/mahmudul0x1/droidrecon</a> — For authorized security testing only.</footer>
</body></html>"""

        with open(output_path,"w") as f:
            f.write(html)
        console.print(f"[green]✅ HTML → {output_path}[/green]")
