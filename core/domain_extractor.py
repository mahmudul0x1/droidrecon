"""
DroidRecon - Domain Extractor & Classifier
Author: mahmudul0x1

Extracts all unique domains from findings, classifies them
(internal, CDN, cloud, API, tracking), and prepares them for probing.
"""

import re
from urllib.parse import urlparse
from typing import List, Dict, Set
from collections import defaultdict

from core.models import Finding

# Well-known CDN/cloud/platform domains
CDN_DOMAINS = {
    "cloudfront.net", "cloudflare.com", "fastly.net", "akamai.net",
    "akamaiedge.net", "edgesuite.net", "stackpathcdn.com",
}

CLOUD_DOMAINS = {
    "amazonaws.com", "azure.com", "azurewebsites.net", "googleapis.com",
    "googleapis.com", "cloudfunctions.net", "firebaseio.com",
    "firebase.google.com", "firebaseapp.com", "storage.googleapis.com",
    "run.app", "appspot.com", "heroku.com", "herokuapp.com",
    "vercel.app", "netlify.app", "pages.dev",
}

TRACKING_DOMAINS = {
    "google-analytics.com", "googletagmanager.com", "analytics.google.com",
    "facebook.com", "fb.com", "fbcdn.net", "appsflyer.com",
    "adjust.com", "branch.io", "kochava.com", "singular.net",
    "amplitude.com", "mixpanel.com", "segment.io", "segment.com",
    "intercom.io", "intercom.com", "moengage.com", "clevertap.com",
    "onesignal.com", "pusher.com", "firebase.googleapis.com",
}

PAYMENT_DOMAINS = {
    "stripe.com", "api.stripe.com", "paypal.com", "braintreegateway.com",
    "square.com", "razorpay.com", "paytm.com", "checkout.com",
}

INTERNAL_PATTERNS = [
    re.compile(r'^(localhost|127\.0\.0\.1|0\.0\.0\.0)$'),
    re.compile(r'^10\.\d+\.\d+\.\d+$'),
    re.compile(r'^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$'),
    re.compile(r'^192\.168\.\d+\.\d+$'),
    re.compile(r'\.internal$'),
    re.compile(r'\.local$'),
    re.compile(r'\.corp$'),
    re.compile(r'\.lan$'),
    re.compile(r'api\.(dev|staging|test|internal|local)\.'),
    re.compile(r'\.(dev|staging|stage|test|qa|uat)\.[a-z]+$'),
]

URL_RE = re.compile(
    r'https?://([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*'
    r'(\.[a-zA-Z]{2,})+)(:\d+)?',
    re.IGNORECASE
)


class DomainExtractor:
    """Extracts, deduplicates, and classifies all domains from scan findings."""

    def extract(self, findings: List[Finding]) -> Dict:
        all_domains: Set[str] = set()
        domain_to_urls: Dict[str, List[str]] = defaultdict(list)
        domain_to_sources: Dict[str, List[str]] = defaultdict(list)

        for finding in findings:
            urls = URL_RE.findall(finding.match)
            for url_match in urls:
                domain = url_match[0].lower()
                all_domains.add(domain)
                # Also try to get full URL
                m = re.search(r'https?://[^\s\'"<>]+', finding.match, re.IGNORECASE)
                if m:
                    domain_to_urls[domain].append(m.group(0))
                domain_to_sources[domain].append(finding.source_file)

            # Also extract bare domains (non-URL)
            bare = re.findall(
                r'\b([a-zA-Z0-9][a-zA-Z0-9\-]{0,61}'
                r'(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]{0,61})+'
                r'\.[a-zA-Z]{2,})\b',
                finding.match
            )
            for b in bare:
                b_lower = b.lower()
                all_domains.add(b_lower)
                domain_to_sources[b_lower].append(finding.source_file)

        classified = self._classify_domains(all_domains, domain_to_urls, domain_to_sources)
        return classified

    def _classify_domains(self, domains: Set[str], domain_urls: Dict, domain_sources: Dict) -> Dict:
        result = {
            "total": len(domains),
            "api_endpoints": [],
            "internal": [],
            "cloud": [],
            "cdn": [],
            "tracking": [],
            "payment": [],
            "unknown": [],
            "all_domains": [],
        }

        for domain in sorted(domains):
            urls = list(set(domain_to_urls for domain_to_urls in domain_urls.get(domain, [])))
            sources = list(set(domain_sources.get(domain, [])))
            entry = {
                "domain": domain,
                "sample_urls": urls[:3],
                "sources": sources[:3],
                "category": self._categorize(domain),
                "is_internal": self._is_internal(domain),
                "is_environment_specific": self._is_env_specific(domain),
            }
            result["all_domains"].append(entry)

            # Bucket
            category = entry["category"]
            if entry["is_internal"]:
                result["internal"].append(entry)
            elif category == "cloud":
                result["cloud"].append(entry)
            elif category == "cdn":
                result["cdn"].append(entry)
            elif category == "tracking":
                result["tracking"].append(entry)
            elif category == "payment":
                result["payment"].append(entry)
            elif self._looks_like_api(domain):
                result["api_endpoints"].append(entry)
            else:
                result["unknown"].append(entry)

        return result

    def _categorize(self, domain: str) -> str:
        for cdn in CDN_DOMAINS:
            if domain.endswith(cdn):
                return "cdn"
        for cloud in CLOUD_DOMAINS:
            if domain.endswith(cloud):
                return "cloud"
        for tracker in TRACKING_DOMAINS:
            if domain.endswith(tracker):
                return "tracking"
        for payment in PAYMENT_DOMAINS:
            if domain.endswith(payment):
                return "payment"
        return "unknown"

    def _is_internal(self, domain: str) -> bool:
        return any(p.search(domain) for p in INTERNAL_PATTERNS)

    def _is_env_specific(self, domain: str) -> bool:
        return bool(re.search(r'\b(dev|staging|stage|test|qa|uat|sandbox|preprod)\b', domain, re.IGNORECASE))

    def _looks_like_api(self, domain: str) -> bool:
        return bool(re.search(r'(api|service|services|backend|server|gateway|proxy|endpoint)', domain, re.IGNORECASE))
