# DroidRecon

<div align="center">

<pre>
██████╗ ██████╗  ██████╗ ██╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔══██╗██╔═══██╗██║██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██║  ██║██████╔╝██║   ██║██║██║  ██║██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║  ██║██╔══██╗██║   ██║██║██║  ██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██████╔╝██║  ██║╚██████╔╝██║██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
</pre>

**Android Mobile Security Assessment Framework — static analysis, live credential validation, attack surface mapping, and CI/CD integration in one tool**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/Author-mahmudul0x1-red?style=flat-square)](https://github.com/mahmudul0x1)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgray?style=flat-square)](https://github.com/mahmudul0x1/droidrecon)

</div>

---

## 🔥 What is DroidRecon?

**DroidRecon** is a comprehensive static + active security analysis tool for Android APK files, built for professional penetration testers and bug bounty hunters. It goes far beyond simple regex scanning — combining decompiled source analysis, native binary scanning, manifest attack surface extraction, live credential validation, and certificate forensics into one unified tool.

Key design principle: **precision over noise**. DroidRecon uses Shannon entropy filtering, vendor library exclusion, and context-aware matching to surface only APK-developer secrets — not third-party SDK boilerplate or placeholder values.

---

## ✨ Feature Matrix

| Module | Flag | What It Does |
|--------|------|--------------|
| 🔑 **Core Scanner** | *(always on)* | 45+ curated regex patterns — AWS, Firebase, GitHub, Slack, Stripe, JWT, endpoints |
| 🗺️ **Manifest Parser** | `--manifest` | Exported components, deep links, dangerous permissions, misconfigs |
| 🔬 **Native Scanner** | `--scan-native` | Extracts strings from `.so` libraries — catches what Java decompilation misses |
| 🛡️ **Smali Auditor** | `--smali-audit` | 25+ vuln patterns: SSL bypass, ECB mode, SQLi, WebView, command injection |
| 🌐 **Endpoint Prober** | `--probe` | Async HTTP prober — fingerprints tech stack, flags interesting responses |
| 🔐 **Secret Validator** | `--validate` | Tests credentials live: Firebase, GitHub, Slack, Stripe, Google, Telegram, JWT |
| 🔏 **Cert Analyzer** | `--cert` | Debug cert detection, weak algo, Janus attack, key size, expiry |
| 📦 **SDK Fingerprinter** | `--sdk-fingerprint` | Detects 60+ third-party SDKs with privacy/security risk classification |
| 🔒 **Obfuscation Detector** | `--obfuscation` | ProGuard/R8/DexGuard/packer detection with confidence score |
| 🌍 **Domain Extractor** | `--domain-intel` | Extracts all domains, classifies as API/internal/CDN/tracking/cloud |
| 📂 **Batch Scanner** | `--batch DIR` | Scan entire directories of APKs with aggregated reporting |
| 📊 **HTML Report** | `--html` | Self-contained dark-themed pentest report |
| 📋 **SARIF Export** | `--sarif` | GitHub Advanced Security / CI/CD integration |

---

## 🧠 False Positive Reduction

DroidRecon is built to minimise noise so findings are actionable:

- **Vendor library exclusion** — skips `com/google`, `com/paypal`, `com/stripe`, `androidx`, `kotlin`, and 20+ other third-party SDK packages automatically
- **Shannon entropy filtering** — strings with entropy below 3.5 bits are discarded (catches placeholder and test values)
- **Known fake value blocklist** — common dummy values like `your_api_key_here`, `xxxxxxxxxxxx`, `changeme` are ignored
- **Context-aware matching** — generic patterns only fire when surrounding code contains security-relevant keywords
- **Tight regex patterns** — vendor-specific patterns (PayPal, Slack, etc.) require meaningful context, not just character length

---

## 📦 Installation

```bash
# Clone the repository
git clone https://github.com/mahmudul0x1/droidrecon
cd droidrecon

# Install dependencies
pip install -r requirements.txt

# Optional — highly recommended for binary manifest parsing
pip install androguard
```

### Dependencies

| Tool | Required | Purpose |
|------|----------|---------|
| `rich` | ✅ Required | Terminal UI |
| `httpx` | ✅ For `--probe`/`--validate` | Async HTTP client |
| `jadx` | 🔶 Recommended | Full Java/Kotlin decompilation |
| `androguard` | 🔷 Optional | Binary AndroidManifest.xml + cert parsing |

**Install jadx:** https://github.com/skylot/jadx/releases — extract and add to PATH.

---

## 🚀 Usage

### Quick Start

```bash
# Basic scan — auto-saves JSON
python droidrecon.py -f target.apk

# Full pentest mode — ALL modules
python droidrecon.py -f target.apk --all

# Full scan with HTML report
python droidrecon.py -f target.apk --all -o report.html --html
```

### Targeted Scanning

```bash
# Manifest + cert + smali, HIGH severity and above only
python droidrecon.py -f app.apk --manifest --cert --smali-audit --severity HIGH

# Active recon — probe endpoints + validate secrets
python droidrecon.py -f app.apk --probe --validate --concurrency 30

# SDK + domain intelligence
python droidrecon.py -f app.apk --sdk-fingerprint --domain-intel

# Deobfuscated scan with threaded jadx
python droidrecon.py -f app.apk --all -a "--deobf --threads-count 8"
```

### CI/CD Integration

```bash
# SARIF output for GitHub Code Scanning
python droidrecon.py -f app.apk --all --sarif -o results.sarif

# Non-zero exit code on HIGH+ findings (blocks CI pipeline)
python droidrecon.py -f app.apk --all --severity HIGH
echo "Exit code: $?"  # 0=clean, 1=HIGH, 2=CRITICAL
```

### Batch Scanning

```bash
# Scan all APKs in a folder, save reports to /output/
python droidrecon.py --batch /path/to/apks/ --all -o /output/reports/
```

### Custom Headers (authenticated endpoint probing)

```bash
python droidrecon.py -f app.apk --probe \
  --header "Authorization: Bearer YOUR_TOKEN" \
  --header "X-API-Key: YOUR_KEY"
```

---

## 📋 CLI Reference

```
usage: droidrecon [-h] (-f FILE | --batch DIR) [-p PATTERN] [-a ARGS]
                  [--manifest] [--scan-native] [--smali-audit] [--probe]
                  [--validate] [--cert] [--sdk-fingerprint] [--obfuscation]
                  [--domain-intel] [--all]
                  [--severity {CRITICAL,HIGH,MEDIUM,LOW,INFO}]
                  [--tags TAG [TAG ...]] [-o OUTPUT] [--json] [--html]
                  [--sarif] [--quiet] [--timeout N] [--concurrency N]
                  [--verify-ssl] [--header Key:Value]
```

---

## 🛡️ Smali Vulnerability Patterns (25+)

| Vulnerability | Severity | CWE |
|---------------|----------|-----|
| AllowAllHostnameVerifier | 💀 CRITICAL | CWE-295 |
| Hardcoded SecretKeySpec | 💀 CRITICAL | CWE-321 |
| WebView Universal File Access | 💀 CRITICAL | CWE-200 |
| WebView addJavascriptInterface | 🔴 HIGH | CWE-749 |
| AES ECB Mode | 🔴 HIGH | CWE-327 |
| Custom TrustManager (SSL bypass) | 🔴 HIGH | CWE-295 |
| Runtime.exec() Command Execution | 🔴 HIGH | CWE-78 |
| Raw SQL Query | 🔴 HIGH | CWE-89 |
| World-Readable/Writable Files | 🔴 HIGH | CWE-276 |
| Predictable IV | 🔴 HIGH | CWE-329 |
| V1-Only Signature (Janus) | 🔴 HIGH | CVE-2017-13156 |
| WebView JS Enabled | 🟡 MEDIUM | CWE-749 |
| MD5 Hash | 🟡 MEDIUM | CWE-328 |
| Insecure java.util.Random | 🟡 MEDIUM | CWE-338 |
| Dynamic DEX Loading | 🟡 MEDIUM | CWE-470 |
| Sticky Broadcast | 🟡 MEDIUM | CWE-927 |
| SharedPreferences Sensitive Data | 🟡 MEDIUM | CWE-312 |
| Insecure HTTP URL | 🟡 MEDIUM | CWE-319 |
| SHA-1 Hash | 🔵 LOW | CWE-328 |
| Log Sensitive Data | 🔵 LOW | CWE-532 |
| ... and more | | |

---

## 🔐 Live Secret Validators

| Secret Type | Validation Method |
|-------------|------------------|
| Firebase Realtime DB | Unauthenticated `.json?shallow=true` read |
| GitHub Token | `/user` endpoint — returns username + scopes |
| Slack Token | `auth.test` — returns team + user |
| Slack Webhook | POST test |
| Google API Key | Maps Geocoding (safe, read-only) |
| Stripe Secret Key | `/v1/balance` read — confirms livemode |
| SendGrid API Key | `/v3/user/profile` |
| Mailgun API Key | `/v3/domains` list |
| Telegram Bot Token | `getMe` method |
| JWT Token | Decode + check `alg:none` + expiry |
| Twilio SID | Format validation + hint |
| AWS Access Key | Format validation + STS hint |

---

## 📦 SDK Risk Classification

DroidRecon detects 60+ SDKs across these risk levels:

- 🔴 **HIGH**: Facebook SDK, Tencent/Alibaba SDKs, Umeng Analytics
- 🟡 **MEDIUM**: AppsFlyer, Adjust, Branch.io, OneSignal, Google AdMob, AppLovin, Unity Ads
- 🔵 **LOW**: Firebase Crashlytics, OkHttp, Retrofit, Glide, Stripe, PayPal

---

## 📁 Project Structure

```
droidrecon/
├── droidrecon.py               # Main CLI entry point
├── requirements.txt
├── README.md
├── .gitignore
├── config/
│   └── regexes.json            # 45+ curated regex patterns (entropy-filtered)
└── core/
    ├── models.py               # Finding, ScanResult, ProbeResult dataclasses
    ├── severity.py             # Scoring engine — pattern → severity mappings
    ├── scanner.py              # Core regex scanner — vendor skip + entropy filter
    ├── manifest_parser.py      # AndroidManifest.xml attack surface extractor
    ├── native_scanner.py       # .so binary string extraction
    ├── smali_auditor.py        # 25+ Smali/Java vulnerability patterns
    ├── prober.py               # Async endpoint prober + fingerprinting
    ├── secret_validator.py     # Live credential validators
    ├── cert_analyzer.py        # APK signing certificate analysis
    ├── sdk_fingerprinter.py    # Third-party SDK detection (60+ SDKs)
    ├── obfuscation_detector.py # ProGuard/DexGuard/packer detection
    ├── domain_extractor.py     # Domain extraction + classification
    ├── sarif_exporter.py       # SARIF 2.1.0 export
    └── reporter.py             # Terminal + JSON + HTML reporting
```

---

## ⚠️ Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no CRITICAL or HIGH findings |
| `1` | HIGH severity findings present |
| `2` | CRITICAL severity findings present |

---

## ⚖️ Legal Disclaimer

**DroidRecon is for authorized security testing only.**

Do not use this tool on applications you do not own or have explicit written permission to test. The `--probe` and `--validate` flags make real network requests and must only be used within authorized scope. The author is not responsible for any misuse.

---

## 👤 Author

**Md Mahmudul Hasan** — Security Engineer & Red Teamer

- GitHub: [@mahmudul0x1](https://github.com/mahmudul0x1)
- LinkedIn: [mahmudul-hasan](https://www.linkedin.com/in/mahmudul-hasan-816a471a4)
- Medium: [@mahmudul24x7](https://medium.com/@mahmudul24x7)
- Email: mahmudul24x7@gmail.com

---

## 🙏 Credits

- [dwisiswant0/apkleaks](https://github.com/dwisiswant0/apkleaks) — original inspiration
- [skylot/jadx](https://github.com/skylot/jadx) — Java decompiler
- [androguard](https://github.com/androguard/androguard) — APK analysis library
- Pattern sources: truffleHogRegexes, LinkFinder, gf patterns, NotKeyHacks

---

Built with ❤️ by [mahmudul0x1](https://github.com/mahmudul0x1) — Star ⭐ if you find it useful!
