"""
APKLeaks Pro - AndroidManifest.xml Attack Surface Parser
Extracts exported components, deep links, permissions, and security misconfigs.
"""
import zipfile
import os
from typing import List, Dict, Optional
from xml.etree import ElementTree as ET
from rich.console import Console

from core.models import ManifestFinding

console = Console()

ANDROID_NS = "http://schemas.android.com/apk/res/android"

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS":          "HIGH",
    "android.permission.WRITE_CONTACTS":         "HIGH",
    "android.permission.RECORD_AUDIO":           "HIGH",
    "android.permission.ACCESS_FINE_LOCATION":   "HIGH",
    "android.permission.ACCESS_COARSE_LOCATION": "MEDIUM",
    "android.permission.READ_CALL_LOG":          "HIGH",
    "android.permission.WRITE_CALL_LOG":         "HIGH",
    "android.permission.CAMERA":                 "MEDIUM",
    "android.permission.READ_SMS":               "HIGH",
    "android.permission.SEND_SMS":               "HIGH",
    "android.permission.RECEIVE_SMS":            "HIGH",
    "android.permission.READ_EXTERNAL_STORAGE":  "MEDIUM",
    "android.permission.WRITE_EXTERNAL_STORAGE": "MEDIUM",
    "android.permission.PROCESS_OUTGOING_CALLS": "HIGH",
    "android.permission.READ_PHONE_STATE":       "MEDIUM",
    "android.permission.GET_ACCOUNTS":           "MEDIUM",
    "android.permission.USE_BIOMETRIC":          "LOW",
    "android.permission.BLUETOOTH":              "LOW",
    "android.permission.NFC":                    "LOW",
    "android.permission.INTERNET":               "INFO",
    "android.permission.ACCESS_NETWORK_STATE":   "INFO",
}

COMPONENT_TAGS = {
    "activity": "Activity",
    "service": "Service",
    "receiver": "Broadcast Receiver",
    "provider": "Content Provider",
}


class ManifestParser:
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self._manifest_xml = None

    def parse(self) -> Dict:
        """Main entry — returns structured manifest analysis."""
        self._manifest_xml = self._extract_manifest()
        if not self._manifest_xml:
            console.print("[yellow]⚠ Could not parse AndroidManifest.xml[/yellow]")
            return {}

        try:
            root = ET.fromstring(self._manifest_xml)
        except ET.ParseError as e:
            console.print(f"[yellow]⚠ Manifest XML parse error: {e}[/yellow]")
            return {}

        results = {
            "package_name": root.get("package", "unknown"),
            "version_name": root.get(f"{{{ANDROID_NS}}}versionName", "unknown"),
            "version_code": root.get(f"{{{ANDROID_NS}}}versionCode", "unknown"),
            "min_sdk": "unknown",
            "target_sdk": "unknown",
            "allow_backup": False,
            "debuggable": False,
            "network_security_config": False,
            "exported_components": [],
            "deep_links": [],
            "dangerous_permissions": [],
            "all_permissions": [],
            "content_providers": [],
            "intent_filters": [],
        }

        # SDK versions
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            results["min_sdk"] = uses_sdk.get(f"{{{ANDROID_NS}}}minSdkVersion", "unknown")
            results["target_sdk"] = uses_sdk.get(f"{{{ANDROID_NS}}}targetSdkVersion", "unknown")

        # Application-level flags
        app = root.find("application")
        if app is not None:
            results["allow_backup"] = self._bool_attr(app, "allowBackup", default=True)
            results["debuggable"] = self._bool_attr(app, "debuggable", default=False)
            results["network_security_config"] = app.get(f"{{{ANDROID_NS}}}networkSecurityConfig") is not None

        # Permissions
        for perm in root.findall("uses-permission"):
            name = perm.get(f"{{{ANDROID_NS}}}name", "")
            results["all_permissions"].append(name)
            if name in DANGEROUS_PERMISSIONS:
                results["dangerous_permissions"].append({
                    "permission": name,
                    "severity": DANGEROUS_PERMISSIONS[name],
                })

        # Components
        if app is not None:
            for tag, label in COMPONENT_TAGS.items():
                for comp in app.findall(tag):
                    name = comp.get(f"{{{ANDROID_NS}}}name", "unknown")
                    exported_raw = comp.get(f"{{{ANDROID_NS}}}exported")

                    has_intent_filter = comp.find("intent-filter") is not None

                    # Android default: activities with intent filters are exported by default
                    if exported_raw is None:
                        exported = has_intent_filter and tag == "activity"
                    else:
                        exported = exported_raw.lower() == "true"

                    if exported:
                        comp_info = {
                            "type": label,
                            "name": name,
                            "has_intent_filter": has_intent_filter,
                            "permission_required": comp.get(f"{{{ANDROID_NS}}}permission"),
                        }

                        if tag == "provider":
                            comp_info["authorities"] = comp.get(f"{{{ANDROID_NS}}}authorities", "")
                            comp_info["read_permission"] = comp.get(f"{{{ANDROID_NS}}}readPermission")
                            comp_info["write_permission"] = comp.get(f"{{{ANDROID_NS}}}writePermission")
                            results["content_providers"].append(comp_info)

                        results["exported_components"].append(comp_info)

                    # Deep link extraction from intent filters
                    for intent_filter in comp.findall("intent-filter"):
                        for data in intent_filter.findall("data"):
                            scheme = data.get(f"{{{ANDROID_NS}}}scheme")
                            host = data.get(f"{{{ANDROID_NS}}}host", "")
                            path = data.get(f"{{{ANDROID_NS}}}path", "")
                            path_prefix = data.get(f"{{{ANDROID_NS}}}pathPrefix", "")

                            if scheme:
                                uri = f"{scheme}://{host}{path or path_prefix}"
                                if uri not in results["deep_links"]:
                                    results["deep_links"].append(uri)

        return results

    def get_findings(self) -> List[ManifestFinding]:
        """Convert parsed manifest to ManifestFinding objects for unified reporting."""
        data = self.parse()
        findings = []

        if not data:
            return findings

        # Exported components
        for comp in data.get("exported_components", []):
            sev = "HIGH" if not comp.get("permission_required") else "MEDIUM"
            findings.append(ManifestFinding(
                component_type=comp["type"].lower().replace(" ", "_"),
                name=comp["name"],
                exported=True,
                dangerous=sev == "HIGH",
                severity=sev,
                details={
                    "has_intent_filter": comp.get("has_intent_filter", False),
                    "permission_required": comp.get("permission_required"),
                    "authorities": comp.get("authorities"),
                }
            ))

        # Dangerous permissions
        for perm in data.get("dangerous_permissions", []):
            findings.append(ManifestFinding(
                component_type="permission",
                name=perm["permission"],
                exported=False,
                dangerous=True,
                severity=perm["severity"],
                details={"category": "dangerous_permission"}
            ))

        # Deep links
        for dl in data.get("deep_links", []):
            findings.append(ManifestFinding(
                component_type="deeplink",
                name=dl,
                exported=True,
                dangerous=False,
                severity="LOW",
                details={"category": "deep_link_scheme"}
            ))

        # Security misconfigs
        if data.get("allow_backup"):
            findings.append(ManifestFinding(
                component_type="misconfiguration",
                name="allowBackup=true",
                exported=False,
                dangerous=True,
                severity="MEDIUM",
                details={"risk": "App data can be extracted via ADB backup without root"}
            ))

        if data.get("debuggable"):
            findings.append(ManifestFinding(
                component_type="misconfiguration",
                name="debuggable=true",
                exported=False,
                dangerous=True,
                severity="HIGH",
                details={"risk": "App is debuggable — attacker can attach debugger, extract memory"}
            ))

        if not data.get("network_security_config"):
            try:
                min_sdk = int(data.get("min_sdk", "0"))
                if min_sdk < 28:
                    findings.append(ManifestFinding(
                        component_type="misconfiguration",
                        name="No Network Security Config",
                        exported=False,
                        dangerous=False,
                        severity="MEDIUM",
                        details={"risk": "App may allow cleartext HTTP traffic on older SDK versions"}
                    ))
            except ValueError:
                pass

        return findings

    def _extract_manifest(self) -> Optional[str]:
        """Try to read manifest — from decompiled dir or raw ZIP."""
        # Try text manifest from jadx output first
        jadx_manifest = os.path.join(
            os.path.dirname(self.apk_path), "resources", "AndroidManifest.xml"
        )
        if os.path.exists(jadx_manifest):
            with open(jadx_manifest, 'r', errors='ignore') as f:
                return f.read()

        # Try reading raw from ZIP (will be binary-encoded for most APKs)
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                if 'AndroidManifest.xml' in z.namelist():
                    raw = z.read('AndroidManifest.xml')
                    # Try plain text parse first
                    try:
                        decoded = raw.decode('utf-8')
                        ET.fromstring(decoded)
                        return decoded
                    except (UnicodeDecodeError, ET.ParseError):
                        # Binary XML — try androguard
                        return self._decode_binary_xml(raw)
        except Exception as e:
            console.print(f"[yellow]Warning: {e}[/yellow]")

        return None

    def _decode_binary_xml(self, data: bytes) -> Optional[str]:
        """Decode Android binary XML using androguard if available."""
        try:
            from androguard.core.axml import AXMLPrinter
            printer = AXMLPrinter(data)
            return printer.get_xml().decode('utf-8', errors='ignore')
        except ImportError:
            try:
                # Try axmldec as fallback
                import subprocess, tempfile
                with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as tmp:
                    tmp.write(data)
                    tmp_path = tmp.name
                result = subprocess.run(['axmldec', tmp_path], capture_output=True, text=True)
                if result.returncode == 0:
                    return result.stdout
            except Exception:
                pass
            console.print("[yellow]⚠ Binary manifest detected. Install androguard for full parsing: pip install androguard[/yellow]")
            return None
        except Exception:
            return None

    def _bool_attr(self, element, attr_name: str, default: bool = False) -> bool:
        val = element.get(f"{{{ANDROID_NS}}}{attr_name}")
        if val is None:
            return default
        return val.lower() == "true"
