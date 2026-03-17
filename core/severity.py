"""
DroidRecon - Severity Scoring Engine
Author: mahmudul0x1
https://github.com/mahmudul0x1/droidrecon
"""
import json, os

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEVERITY_COLORS = {"CRITICAL":"bold red","HIGH":"red","MEDIUM":"yellow","LOW":"cyan","INFO":"white"}
SEVERITY_EMOJI  = {"CRITICAL":"💀","HIGH":"🔴","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}

DEFAULT_SEVERITY_MAP = {
    "CRITICAL": ["AWS Access Key","AWS Secret Key","Google API Key","Private Key","RSA Private Key",
                 "SSH Private Key","Stripe Secret Key","Slack Token","Slack Webhook","GitHub Token",
                 "GitHub OAuth","Heroku API Key","Twilio Auth Token","Discord Bot Token",
                 "Telegram Bot API Token","PayPal Client Secret","AllowAllHostnameVerifier",
                 "Hardcoded Encryption Key","WebView Universal File Access"],
    "HIGH":     ["Firebase URL","Firebase API Key","Basic Auth Credentials","Bearer Token",
                 "Generic Secret","Generic API Key","Authorization Bearer","Mailgun API Key",
                 "SendGrid API Key","Mailchimp API Key","Stripe Publishable Key","Square Access Token",
                 "Artifactory API Token","Password in URL","AES ECB Mode","ECB Mode Explicit",
                 "WebView File Access Enabled","WebView addJavascriptInterface","Raw SQL Query",
                 "World-Readable File","World-Writable File","Runtime Command Execution",
                 "Custom Trust Manager (SSL Bypass)","Predictable IV","V1-Only Signature (Janus)"],
    "MEDIUM":   ["Google OAuth","Google OAuth Access Token","Twilio Account SID","AWS ARN",
                 "S3 Bucket URL","Azure Storage Account Key","JWT Token","Generic Credential",
                 "Facebook Access Token","Twitter OAuth","LinkedIn Client Secret","MD5 Hash",
                 "Dynamic Code Loading","SharedPreferences Sensitive Data","Insecure HTTP Connection",
                 "Pending Intent Mutable","Sticky Broadcast","Insecure Random (java.util.Random)"],
    "LOW":      ["IP Address","Internal IP Address","Email Address","URL","LinkFinder","Endpoints",
                 "Google Maps API","PGP private key block","SHA-1 Hash","Reflection Invocation",
                 "Log Sensitive Data","Clipboard Sensitive Write"],
    "INFO":     ["Comments","Dependency","Package Name"],
}

class SeverityScorer:
    def __init__(self, config_path=None):
        self.severity_map = dict(DEFAULT_SEVERITY_MAP)
        if config_path and os.path.exists(config_path):
            with open(config_path) as f:
                custom = json.load(f)
            for sev, patterns in custom.items():
                self.severity_map.setdefault(sev, []).extend(patterns)
        self._lookup = {}
        for sev, patterns in self.severity_map.items():
            for p in patterns:
                self._lookup[p.lower()] = sev

    def score(self, pattern_name: str) -> str:
        return self._lookup.get(pattern_name.lower(), "INFO")

    def filter_by_severity(self, findings, min_severity: str):
        min_idx = SEVERITY_ORDER.index(min_severity) if min_severity in SEVERITY_ORDER else 4
        return [f for f in findings if SEVERITY_ORDER.index(f.severity) <= min_idx]

    @staticmethod
    def get_color(severity: str) -> str:
        return SEVERITY_COLORS.get(severity, "white")

    @staticmethod
    def get_emoji(severity: str) -> str:
        return SEVERITY_EMOJI.get(severity, "⚪")
