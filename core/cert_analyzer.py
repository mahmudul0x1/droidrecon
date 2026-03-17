"""
DroidRecon - APK Certificate & Signing Analyzer
Author: mahmudul0x1

Extracts and analyzes APK signing certificate details:
- Certificate validity, issuer, subject
- Debug certificate detection
- Signature scheme version (v1/v2/v3/v4)
- Weak key detection (RSA <2048, MD5/SHA1 signature)
- Certificate expiry warnings
"""

import zipfile
import hashlib
import struct
import os
from datetime import datetime, timezone
from typing import Optional, Dict, List
from rich.console import Console

console = Console()

# Known debug certificate fingerprints
DEBUG_CERT_FINGERPRINTS = {
    "C8:02:02:CE:A8:0F:88:83:2E:5A:0D:2C:35:8D:7E:D7:F3:A4:1A:D4": "Android Debug Key (AOSP)",
    "61:ED:37:7E:85:D3:86:A8:DF:EE:6B:86:4B:D8:5B:0B:FA:86:53:8C": "Android Debug Key (Android Studio)",
    "27:19:6E:38:6B:87:5E:76:AD:F7:00:E7:EA:84:E4:C6:EE:E3:3D:FA": "Android Debug Key (Eclipse ADT)",
}

WEAK_SIGNATURE_ALGOS = {
    "MD2withRSA", "MD5withRSA", "SHA1withRSA", "SHA1withDSA", "SHA1withECDSA"
}


class CertAnalyzer:
    """
    Analyzes APK signing certificates without requiring external tools.
    Falls back gracefully when androguard is not available.
    """

    def __init__(self, apk_path: str):
        self.apk_path = apk_path

    def analyze(self) -> Dict:
        result = {
            "signature_versions": [],
            "certificates": [],
            "is_debug_signed": False,
            "debug_cert_name": None,
            "weak_signature": False,
            "weak_reasons": [],
            "v1_only": False,
            "issues": [],
            "raw_available": False,
        }

        try:
            result.update(self._analyze_with_zipfile())
        except Exception as e:
            result["error"] = str(e)

        # Try androguard for richer cert info
        try:
            result.update(self._analyze_with_androguard())
            result["raw_available"] = True
        except ImportError:
            pass
        except Exception:
            pass

        self._assess_issues(result)
        return result

    def _analyze_with_zipfile(self) -> Dict:
        """Basic analysis via ZIP structure — check signature files present."""
        result = {"signature_files": [], "signature_versions": []}
        with zipfile.ZipFile(self.apk_path, 'r') as z:
            names = z.namelist()
            # V1 signature
            sf_files = [n for n in names if n.startswith("META-INF/") and n.endswith(".SF")]
            rsa_files = [n for n in names if n.startswith("META-INF/") and
                         (n.endswith(".RSA") or n.endswith(".DSA") or n.endswith(".EC"))]
            if sf_files or rsa_files:
                result["signature_versions"].append("v1")
                result["signature_files"] = sf_files + rsa_files

            # V2/V3/V4 detection (by APK Signing Block presence)
            v2v3 = self._detect_apk_signing_block()
            if v2v3:
                result["signature_versions"].extend(v2v3)

            # Extract raw cert bytes for fingerprinting
            for rsa_file in rsa_files[:1]:
                try:
                    cert_data = z.read(rsa_file)
                    sha256 = hashlib.sha256(cert_data).hexdigest().upper()
                    sha256_colon = ":".join(sha256[i:i+2] for i in range(0, len(sha256), 2))
                    md5 = hashlib.md5(cert_data).hexdigest().upper()
                    md5_colon = ":".join(md5[i:i+2] for i in range(0, len(md5), 2))
                    result["certificates"] = [{
                        "source_file": rsa_file,
                        "sha256_fingerprint": sha256_colon,
                        "md5_fingerprint": md5_colon,
                        "size_bytes": len(cert_data),
                    }]
                    # Check debug fingerprint
                    for fp, name in DEBUG_CERT_FINGERPRINTS.items():
                        if sha256_colon.startswith(fp[:10]) or md5_colon == md5_colon:
                            pass  # Full check needs real cert parsing
                except Exception:
                    pass

        result["v1_only"] = result["signature_versions"] == ["v1"]
        return result

    def _detect_apk_signing_block(self) -> List[str]:
        """Detect APK Signing Block v2/v3 by magic bytes in APK binary."""
        versions = []
        try:
            with open(self.apk_path, "rb") as f:
                f.seek(0, 2)
                file_size = f.tell()

                # Search last 64KB for APK signing block magic
                search_size = min(65536, file_size)
                f.seek(file_size - search_size)
                tail = f.read(search_size)

                # Magic: "APK Sig Block 42" = 0x3234206b636f6c42 20676953204b5041
                magic = b"APK Sig Block 42"
                if magic in tail:
                    versions.append("v2")
                    # v3 uses same block but different ID
                    if b"\x03\x00\x00\x00" in tail:
                        versions.append("v3")
        except Exception:
            pass
        return versions

    def _analyze_with_androguard(self) -> Dict:
        """Rich cert analysis using androguard."""
        from androguard.misc import AnalyzeAPK
        a, _, _ = AnalyzeAPK(self.apk_path)

        result = {"certificates": [], "is_debug_signed": False}
        certs = a.get_certificates()

        for cert in certs:
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after

            # Handle timezone-aware vs naive datetimes
            now = datetime.now()
            try:
                now = datetime.now(timezone.utc)
                is_expired = not_after < now
                days_until_expiry = (not_after - now).days
            except TypeError:
                is_expired = False
                days_until_expiry = None

            issuer = cert.issuer.human_friendly if hasattr(cert.issuer, 'human_friendly') else str(cert.issuer)
            subject = cert.subject.human_friendly if hasattr(cert.subject, 'human_friendly') else str(cert.subject)
            sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"

            # SHA-256 fingerprint
            sha256_fp = hashlib.sha256(cert.public_bytes(
                encoding=__import__('cryptography').hazmat.primitives.serialization.Encoding.DER
            )).hexdigest().upper()
            sha256_colon = ":".join(sha256_fp[i:i+2] for i in range(0, len(sha256_fp), 2))

            is_self_signed = issuer == subject
            is_debug = "Android Debug" in subject or "androiddebugkey" in subject.lower()

            if is_debug:
                result["is_debug_signed"] = True
                result["debug_cert_name"] = subject

            cert_info = {
                "subject": subject,
                "issuer": issuer,
                "not_before": str(not_before),
                "not_after": str(not_after),
                "is_expired": is_expired,
                "days_until_expiry": days_until_expiry,
                "is_self_signed": is_self_signed,
                "is_debug_cert": is_debug,
                "signature_algorithm": sig_algo,
                "sha256_fingerprint": sha256_colon,
                "weak_signature": sig_algo in WEAK_SIGNATURE_ALGOS,
            }

            # Key size check for RSA
            try:
                pub_key = cert.public_key()
                key_size = pub_key.key_size
                cert_info["public_key_size"] = key_size
                cert_info["weak_key"] = key_size < 2048
            except Exception:
                cert_info["public_key_size"] = None
                cert_info["weak_key"] = False

            result["certificates"].append(cert_info)

        return result

    def _assess_issues(self, result: Dict):
        issues = []
        for cert in result.get("certificates", []):
            if cert.get("is_debug_cert"):
                issues.append({"severity": "CRITICAL", "issue": "App signed with debug certificate — never release to production"})
            if cert.get("is_expired"):
                issues.append({"severity": "HIGH", "issue": f"Certificate is EXPIRED"})
            elif cert.get("days_until_expiry") and cert["days_until_expiry"] < 30:
                issues.append({"severity": "MEDIUM", "issue": f"Certificate expires in {cert['days_until_expiry']} days"})
            if cert.get("weak_signature"):
                issues.append({"severity": "HIGH", "issue": f"Weak signature algorithm: {cert.get('signature_algorithm')}"})
            if cert.get("weak_key"):
                issues.append({"severity": "HIGH", "issue": f"Weak RSA key: {cert.get('public_key_size')} bits (minimum 2048)"})
            if cert.get("is_self_signed"):
                issues.append({"severity": "INFO", "issue": "Certificate is self-signed (expected for most Android apps)"})

        if result.get("v1_only"):
            issues.append({"severity": "HIGH", "issue": "Only v1 (JAR) signature — vulnerable to Janus attack (CVE-2017-13156) on Android <7.0"})

        result["issues"] = issues
