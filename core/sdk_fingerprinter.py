"""
DroidRecon - Third-Party SDK Fingerprinter
Author: mahmudul0x1

Detects embedded third-party SDKs by package name patterns.
Flags SDKs with known privacy/security concerns.
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Set
from rich.console import Console

console = Console()

# SDK registry: package_prefix -> {name, category, risk, notes}
SDK_REGISTRY = {
    # Analytics & Tracking
    "com.google.firebase.analytics":     {"name": "Firebase Analytics",    "category": "analytics",   "risk": "LOW",    "notes": "Google analytics SDK"},
    "com.google.android.gms":            {"name": "Google Play Services",  "category": "platform",    "risk": "LOW",    "notes": "Core Google services"},
    "com.amplitude.android":             {"name": "Amplitude",             "category": "analytics",   "risk": "LOW",    "notes": "Product analytics"},
    "com.mixpanel.android":              {"name": "Mixpanel",              "category": "analytics",   "risk": "LOW",    "notes": "Product analytics"},
    "com.segment.analytics":             {"name": "Segment",               "category": "analytics",   "risk": "LOW",    "notes": "Customer data platform"},
    "com.appsflyer":                     {"name": "AppsFlyer",             "category": "attribution", "risk": "MEDIUM", "notes": "Mobile attribution — tracks installs and deep links"},
    "com.adjust.sdk":                    {"name": "Adjust",                "category": "attribution", "risk": "MEDIUM", "notes": "Mobile measurement & fraud prevention"},
    "com.branch.referral":               {"name": "Branch.io",             "category": "attribution", "risk": "MEDIUM", "notes": "Deep linking & attribution"},
    "io.branch.referral":                {"name": "Branch.io",             "category": "attribution", "risk": "MEDIUM", "notes": "Deep linking & attribution"},
    "com.singular.sdk":                  {"name": "Singular",              "category": "attribution", "risk": "MEDIUM", "notes": "Marketing analytics"},
    "com.kochava":                       {"name": "Kochava",               "category": "attribution", "risk": "MEDIUM", "notes": "Mobile attribution"},

    # Advertising
    "com.google.android.gms.ads":        {"name": "Google AdMob",          "category": "advertising", "risk": "MEDIUM", "notes": "Collects device ID, location for ad targeting"},
    "com.facebook.ads":                  {"name": "Facebook Audience Network","category": "advertising","risk": "HIGH",   "notes": "Extensive data collection — IDFA, device info, behavioral data"},
    "com.unity3d.ads":                   {"name": "Unity Ads",             "category": "advertising", "risk": "MEDIUM", "notes": "Game ad SDK"},
    "com.ironsource.mediationsdk":       {"name": "ironSource",            "category": "advertising", "risk": "MEDIUM", "notes": "Ad mediation"},
    "com.applovin":                      {"name": "AppLovin",              "category": "advertising", "risk": "MEDIUM", "notes": "Ad network — collects extensive device data"},
    "com.mopub":                         {"name": "MoPub (deprecated)",    "category": "advertising", "risk": "HIGH",   "notes": "Shutdown by Twitter — may indicate outdated dependencies"},
    "com.chartboost":                    {"name": "Chartboost",            "category": "advertising", "risk": "MEDIUM", "notes": "Game-focused ad network"},
    "com.vungle":                        {"name": "Vungle",                "category": "advertising", "risk": "MEDIUM", "notes": "Video ad network"},

    # Crash Reporting
    "com.google.firebase.crashlytics":   {"name": "Firebase Crashlytics",  "category": "crash",       "risk": "LOW",    "notes": "Crash reporting"},
    "com.crashlytics.sdk.android":       {"name": "Crashlytics (legacy)",  "category": "crash",       "risk": "LOW",    "notes": "Legacy Fabric Crashlytics"},
    "com.bugsnag.android":              {"name": "Bugsnag",               "category": "crash",       "risk": "LOW",    "notes": "Error monitoring"},
    "io.sentry.android":                 {"name": "Sentry",                "category": "crash",       "risk": "LOW",    "notes": "Error monitoring — may capture PII in breadcrumbs"},
    "com.instabug.library":              {"name": "Instabug",              "category": "crash",       "risk": "MEDIUM", "notes": "Bug reporting — can capture screen recordings"},
    "io.rollbar":                        {"name": "Rollbar",               "category": "crash",       "risk": "LOW",    "notes": "Error tracking"},

    # Social / Login
    "com.facebook.login":               {"name": "Facebook Login SDK",    "category": "social",      "risk": "HIGH",   "notes": "Shares login events with Facebook — GDPR implications"},
    "com.facebook":                     {"name": "Facebook SDK",          "category": "social",      "risk": "HIGH",   "notes": "Data shared with Facebook including installs and events"},
    "com.twitter.sdk.android":          {"name": "Twitter SDK",           "category": "social",      "risk": "MEDIUM", "notes": "Twitter authentication SDK"},
    "com.google.android.gms.auth":      {"name": "Google Sign-In",        "category": "social",      "risk": "LOW",    "notes": "Google OAuth flow"},
    "net.openid.appauth":               {"name": "AppAuth (OAuth)",        "category": "social",      "risk": "LOW",    "notes": "Open-source OAuth 2.0 / OIDC"},

    # Payment
    "com.stripe.android":               {"name": "Stripe",                "category": "payment",     "risk": "LOW",    "notes": "Payment processing — PCI compliant"},
    "com.braintreepayments":            {"name": "Braintree",             "category": "payment",     "risk": "LOW",    "notes": "PayPal payment SDK"},
    "com.paypal.android.sdk":           {"name": "PayPal SDK",            "category": "payment",     "risk": "LOW",    "notes": "PayPal payment integration"},
    "com.squareup.sdk.pos":             {"name": "Square POS SDK",        "category": "payment",     "risk": "LOW",    "notes": "Square payment processing"},
    "io.razorpay":                      {"name": "Razorpay",              "category": "payment",     "risk": "LOW",    "notes": "Indian payment gateway"},

    # Security Concern SDKs
    "com.appdome":                      {"name": "Appdome",               "category": "security",    "risk": "INFO",   "notes": "App protection/shielding platform"},
    "com.guardsquare.dexguard":         {"name": "DexGuard",              "category": "security",    "risk": "INFO",   "notes": "Commercial obfuscator/protector"},
    "com.licel.jscrambler":             {"name": "Jscrambler",            "category": "security",    "risk": "INFO",   "notes": "JS code protection"},
    "com.tencent.bugly":                {"name": "Tencent Bugly",         "category": "crash",       "risk": "HIGH",   "notes": "Chinese crash SDK — data sent to Tencent servers"},
    "com.tencent":                      {"name": "Tencent SDK",           "category": "thirdparty",  "risk": "HIGH",   "notes": "Chinese tech company SDK — review data handling"},
    "com.umeng":                        {"name": "Umeng Analytics",       "category": "analytics",   "risk": "HIGH",   "notes": "Chinese analytics — data sent to Alibaba-owned servers"},
    "com.taobao":                       {"name": "Taobao/Alibaba SDK",    "category": "thirdparty",  "risk": "HIGH",   "notes": "Alibaba ecosystem SDK"},

    # Push Notifications
    "com.google.firebase.messaging":    {"name": "Firebase Cloud Messaging","category": "push",      "risk": "LOW",    "notes": "Google push notifications"},
    "io.pusher.client.android":         {"name": "Pusher",                "category": "push",        "risk": "LOW",    "notes": "Real-time push service"},
    "com.onesignal":                    {"name": "OneSignal",             "category": "push",        "risk": "MEDIUM", "notes": "Push notification SDK — collects device identifiers"},
    "com.urbanairship.android":         {"name": "Airship",               "category": "push",        "risk": "MEDIUM", "notes": "Mobile engagement platform"},
    "com.clevertap.android":            {"name": "CleverTap",             "category": "push",        "risk": "MEDIUM", "notes": "Customer engagement platform"},

    # Networking
    "com.squareup.okhttp3":             {"name": "OkHttp3",               "category": "networking",  "risk": "LOW",    "notes": "HTTP client"},
    "retrofit2":                        {"name": "Retrofit",              "category": "networking",  "risk": "LOW",    "notes": "REST client"},
    "com.android.volley":               {"name": "Volley",                "category": "networking",  "risk": "LOW",    "notes": "Google HTTP library"},
    "io.ktor":                          {"name": "Ktor Client",           "category": "networking",  "risk": "LOW",    "notes": "Kotlin async HTTP client"},

    # Database
    "io.realm.android":                 {"name": "Realm DB",              "category": "database",    "risk": "LOW",    "notes": "Mobile database"},
    "com.couchbase.lite.android":       {"name": "Couchbase Lite",        "category": "database",    "risk": "LOW",    "notes": "Embedded NoSQL database"},
    "net.sqlcipher":                    {"name": "SQLCipher",             "category": "database",    "risk": "INFO",   "notes": "Encrypted SQLite — good security practice"},

    # UI & Image Loading
    "com.squareup.picasso":             {"name": "Picasso",               "category": "ui",          "risk": "LOW",    "notes": "Image loading"},
    "com.bumptech.glide":               {"name": "Glide",                 "category": "ui",          "risk": "LOW",    "notes": "Image loading"},
    "com.facebook.fresco":              {"name": "Fresco (Facebook)",     "category": "ui",          "risk": "MEDIUM", "notes": "Facebook image library — connects to FB infrastructure"},

    # Game Engines
    "com.unity3d.player":               {"name": "Unity Engine",          "category": "gameengine",  "risk": "LOW",    "notes": "Unity game engine runtime"},
    "org.cocos2dx":                     {"name": "Cocos2d-x",             "category": "gameengine",  "risk": "LOW",    "notes": "Open-source game engine"},

    # Location
    "com.here.android.mpa":             {"name": "HERE Maps SDK",         "category": "maps",        "risk": "MEDIUM", "notes": "Location SDK — collects GPS data"},
    "com.mapbox.mapboxsdk":             {"name": "Mapbox",                "category": "maps",        "risk": "MEDIUM", "notes": "Maps SDK — may collect location telemetry"},
}

HIGH_RISK_CATEGORIES = {"advertising", "thirdparty"}
HIGH_RISK_SDKS = [k for k, v in SDK_REGISTRY.items() if v["risk"] in ("HIGH", "CRITICAL")]


class SDKFingerprinter:
    """Detects third-party SDKs present in decompiled APK source."""

    def __init__(self):
        self._compiled = [
            (prefix, info) for prefix, info in SDK_REGISTRY.items()
        ]

    def scan(self, decompiled_dir: str) -> Dict:
        """
        Walk decompiled source and match package patterns to known SDKs.
        Returns dict with detected SDKs, risk summary, and raw package list.
        """
        detected: Dict[str, Dict] = {}
        all_packages: Set[str] = set()

        console.print(f"[cyan]📦 Fingerprinting third-party SDKs...[/cyan]")

        # Collect all unique package prefixes from directory names (fast path)
        for root, dirs, files in os.walk(decompiled_dir):
            rel = os.path.relpath(root, decompiled_dir)
            if rel == ".":
                continue
            pkg = rel.replace(os.sep, ".")
            all_packages.add(pkg)

        # Also scan Java/Kotlin imports
        for root, _, files in os.walk(decompiled_dir):
            for fname in files:
                if fname.endswith((".java", ".kt", ".smali")):
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", errors="ignore") as f:
                            for line in f:
                                line = line.strip()
                                if line.startswith("import ") or line.startswith(".class"):
                                    pkg = line.split()[1].strip(";")
                                    all_packages.add(pkg)
                    except Exception:
                        pass

        # Match packages against SDK registry
        for pkg in all_packages:
            for prefix, info in self._compiled:
                if pkg.startswith(prefix) and prefix not in detected:
                    detected[prefix] = {**info, "matched_package": pkg}
                    break

        return self._build_report(detected, all_packages)

    def _build_report(self, detected: Dict, all_packages: Set[str]) -> Dict:
        sdks = list(detected.values())
        high_risk = [s for s in sdks if s["risk"] in ("HIGH", "CRITICAL")]
        categories = {}
        for s in sdks:
            cat = s["category"]
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "total_sdks_detected": len(sdks),
            "high_risk_count": len(high_risk),
            "categories": categories,
            "sdks": sorted(sdks, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(x["risk"], 5)),
            "high_risk_sdks": high_risk,
            "total_packages_scanned": len(all_packages),
        }
