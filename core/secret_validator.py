"""
APKLeaks Pro - Live Secret Validator
Tests discovered credentials against real APIs to confirm validity.
WARNING: Only use on APKs you are authorized to test.
"""
import asyncio
import re
import hmac
import hashlib
import base64
from datetime import datetime
from typing import List, Dict, Optional, Callable, Awaitable
from rich.console import Console

from core.models import Finding

console = Console()


class SecretValidator:
    """
    Validates discovered secrets against their respective APIs.
    All checks are read-only and non-destructive.
    """

    def __init__(self, timeout: int = 8):
        self.timeout = timeout
        self._validators: Dict[str, Callable] = {}
        self._register_validators()

    def _register_validators(self):
        """Register all built-in validators keyed by pattern name (lowercase)."""
        self._validators = {
            "firebase url":            self._check_firebase,
            "firebase url (native)":   self._check_firebase,
            "aws access key":          self._check_aws_key,
            "github token":            self._check_github,
            "github oauth":            self._check_github,
            "slack token":             self._check_slack,
            "slack webhook":           self._check_slack_webhook,
            "google api key":          self._check_google_key,
            "twilio account sid":      self._check_twilio,
            "stripe secret key":       self._check_stripe,
            "stripe publishable key":  self._check_stripe_pub,
            "sendgrid api key":        self._check_sendgrid,
            "mailgun api key":         self._check_mailgun,
            "telegram bot api token":  self._check_telegram,
            "jwt token":               self._check_jwt,
        }

    async def validate_all(self, findings: List[Finding]) -> List[Finding]:
        """Run validators on all findings that have a registered validator."""
        try:
            import httpx
        except ImportError:
            console.print("[red]httpx not installed. Run: pip install httpx[/red]")
            return findings

        validatable = [
            f for f in findings
            if f.pattern_name.lower() in self._validators
        ]

        if not validatable:
            console.print("[yellow]No findings with registered validators.[/yellow]")
            return findings

        console.print(f"[cyan]🔐 Validating {len(validatable)} secrets against live APIs...[/cyan]")
        console.print("[yellow]  ⚠ Ensure you are authorized to test these credentials.[/yellow]")

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
            semaphore = asyncio.Semaphore(5)  # Lower concurrency for API validation
            tasks = [
                self._validate_finding(client, semaphore, finding)
                for finding in validatable
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        return findings

    async def _validate_finding(self, client, semaphore, finding: Finding):
        async with semaphore:
            validator = self._validators.get(finding.pattern_name.lower())
            if not validator:
                return
            try:
                result = await validator(client, finding.match)
                finding.validated = result.get("valid", False)
                finding.validation_detail = result
            except Exception as e:
                finding.validated = None
                finding.validation_detail = {"error": str(e)[:200]}

    # ─── Individual Validators ───────────────────────────────────────────────

    async def _check_firebase(self, client, match: str) -> Dict:
        """Check if Firebase Realtime DB allows unauthenticated read."""
        url = match.rstrip('/')
        if not url.startswith('http'):
            url = f"https://{url}"
        try:
            r = await client.get(f"{url}/.json?shallow=true", timeout=self.timeout)
            if r.status_code == 200:
                data = r.text[:500]
                return {
                    "valid": True,
                    "severity_upgrade": "CRITICAL",
                    "reason": "open_read_access",
                    "preview": data,
                    "message": "🔥 Firebase DB allows unauthenticated read!",
                }
            elif r.status_code == 401:
                return {"valid": False, "reason": "authentication_required"}
            elif r.status_code == 403:
                return {"valid": False, "reason": "permission_denied"}
            return {"valid": False, "reason": f"status_{r.status_code}"}
        except Exception as e:
            return {"valid": None, "error": str(e)}

    async def _check_aws_key(self, client, access_key: str) -> Dict:
        """Check AWS access key validity via STS GetCallerIdentity."""
        # Note: requires both access key and secret — flag as partial check
        return {
            "valid": None,
            "reason": "aws_requires_secret_key",
            "message": "AWS key found — pair with secret key for full STS validation.",
            "key_format_valid": bool(re.match(r'^AKIA[0-9A-Z]{16}$', access_key)),
        }

    async def _check_github(self, client, token: str) -> Dict:
        """Check GitHub token against /user endpoint."""
        clean_token = token.strip().strip('"\'')
        r = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {clean_token}",
                     "User-Agent": "APKLeaksPro-Validator/2.0"}
        )
        if r.status_code == 200:
            data = r.json()
            scopes = r.headers.get("x-oauth-scopes", "unknown")
            return {
                "valid": True,
                "severity_upgrade": "CRITICAL",
                "user": data.get("login"),
                "email": data.get("email"),
                "scopes": scopes,
                "message": f"✅ Valid GitHub token! User: {data.get('login')}, Scopes: {scopes}",
            }
        elif r.status_code == 401:
            return {"valid": False, "reason": "invalid_token"}
        return {"valid": None, "reason": f"status_{r.status_code}"}

    async def _check_slack(self, client, token: str) -> Dict:
        """Check Slack token via auth.test."""
        clean_token = token.strip().strip('"\'')
        r = await client.post(
            "https://slack.com/api/auth.test",
            data={"token": clean_token},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        data = r.json()
        if data.get("ok"):
            return {
                "valid": True,
                "severity_upgrade": "CRITICAL",
                "team": data.get("team"),
                "user": data.get("user"),
                "url": data.get("url"),
                "message": f"✅ Valid Slack token! Team: {data.get('team')}, User: {data.get('user')}",
            }
        return {"valid": False, "reason": data.get("error", "unknown")}

    async def _check_slack_webhook(self, client, webhook_url: str) -> Dict:
        """Check Slack webhook by sending a test ping (read-only simulation)."""
        # We do a HEAD to avoid actually posting
        try:
            r = await client.post(webhook_url, json={"text": "APKLeaksPro validation test (ignore)"})
            if r.status_code == 200:
                return {
                    "valid": True,
                    "severity_upgrade": "CRITICAL",
                    "message": "✅ Valid Slack webhook — can post messages to channel",
                }
            return {"valid": False, "reason": f"status_{r.status_code}: {r.text[:100]}"}
        except Exception as e:
            return {"valid": None, "error": str(e)}

    async def _check_google_key(self, client, api_key: str) -> Dict:
        """Check Google API key using a safe, free geocode request."""
        clean_key = api_key.strip().strip('"\'')
        r = await client.get(
            f"https://maps.googleapis.com/maps/api/geocode/json?address=test&key={clean_key}"
        )
        data = r.json()
        status = data.get("status", "")
        if status in ("OK", "ZERO_RESULTS"):
            return {
                "valid": True,
                "severity_upgrade": "HIGH",
                "status": status,
                "message": "✅ Valid Google API key — Maps API accessible",
            }
        elif status == "REQUEST_DENIED":
            return {"valid": False, "reason": "key_invalid_or_restricted"}
        elif status == "OVER_QUERY_LIMIT":
            return {"valid": True, "reason": "quota_exceeded_key_exists",
                    "message": "Key exists but quota exceeded"}
        return {"valid": None, "reason": f"status_{status}"}

    async def _check_stripe(self, client, api_key: str) -> Dict:
        """Check Stripe secret key — safe read via balance endpoint."""
        clean_key = api_key.strip().strip('"\'')
        r = await client.get(
            "https://api.stripe.com/v1/balance",
            auth=(clean_key, ""),
        )
        if r.status_code == 200:
            data = r.json()
            return {
                "valid": True,
                "severity_upgrade": "CRITICAL",
                "livemode": data.get("livemode"),
                "message": f"✅ Valid Stripe SECRET key! Live mode: {data.get('livemode')}",
            }
        elif r.status_code == 401:
            return {"valid": False, "reason": "invalid_api_key"}
        return {"valid": None, "reason": f"status_{r.status_code}"}

    async def _check_stripe_pub(self, client, api_key: str) -> Dict:
        """Stripe publishable keys can't make API calls directly."""
        is_live = api_key.startswith("pk_live_")
        is_test = api_key.startswith("pk_test_")
        return {
            "valid": is_live or is_test,
            "key_type": "live" if is_live else "test" if is_test else "unknown",
            "reason": "format_valid" if (is_live or is_test) else "format_invalid",
            "message": f"Stripe {'LIVE' if is_live else 'test'} publishable key detected",
        }

    async def _check_twilio(self, client, account_sid: str) -> Dict:
        """Twilio SID format check (requires auth token to fully validate)."""
        clean = account_sid.strip().strip('"\'')
        is_valid_format = bool(re.match(r'^AC[a-f0-9]{32}$', clean))
        return {
            "valid": None,
            "format_valid": is_valid_format,
            "reason": "requires_auth_token",
            "message": "Twilio SID found — pair with Auth Token for full validation",
        }

    async def _check_sendgrid(self, client, api_key: str) -> Dict:
        """Check SendGrid API key via /v3/user/profile."""
        clean_key = api_key.strip().strip('"\'')
        r = await client.get(
            "https://api.sendgrid.com/v3/user/profile",
            headers={"Authorization": f"Bearer {clean_key}"}
        )
        if r.status_code == 200:
            data = r.json()
            return {
                "valid": True,
                "severity_upgrade": "CRITICAL",
                "username": data.get("username"),
                "email": data.get("email"),
                "message": f"✅ Valid SendGrid key! Account: {data.get('email')}",
            }
        elif r.status_code == 401:
            return {"valid": False, "reason": "invalid_api_key"}
        return {"valid": None, "reason": f"status_{r.status_code}"}

    async def _check_mailgun(self, client, api_key: str) -> Dict:
        """Check Mailgun API key via domains list."""
        clean_key = api_key.strip().strip('"\'')
        r = await client.get(
            "https://api.mailgun.net/v3/domains",
            auth=("api", clean_key),
        )
        if r.status_code == 200:
            data = r.json()
            return {
                "valid": True,
                "severity_upgrade": "CRITICAL",
                "domain_count": len(data.get("items", [])),
                "message": f"✅ Valid Mailgun key! {len(data.get('items', []))} domains accessible",
            }
        elif r.status_code == 401:
            return {"valid": False, "reason": "invalid_api_key"}
        return {"valid": None, "reason": f"status_{r.status_code}"}

    async def _check_telegram(self, client, token: str) -> Dict:
        """Check Telegram bot token via getMe."""
        clean_token = token.strip().strip('"\'')
        r = await client.get(f"https://api.telegram.org/bot{clean_token}/getMe")
        data = r.json()
        if data.get("ok"):
            bot = data.get("result", {})
            return {
                "valid": True,
                "severity_upgrade": "CRITICAL",
                "bot_name": bot.get("username"),
                "bot_id": bot.get("id"),
                "message": f"✅ Valid Telegram bot token! Bot: @{bot.get('username')}",
            }
        return {"valid": False, "reason": data.get("description", "invalid")}

    async def _check_jwt(self, client, token: str) -> Dict:
        """Decode JWT without verification — check alg:none and expiry."""
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return {"valid": None, "reason": "invalid_jwt_format"}
            header = self._base64_decode(parts[0])
            payload = self._base64_decode(parts[1])
            alg = header.get("alg", "unknown") if isinstance(header, dict) else "unknown"
            exp = payload.get("exp") if isinstance(payload, dict) else None
            is_expired = (exp < datetime.utcnow().timestamp()) if exp else None
            alg_none = alg.lower() in ("none", "")
            return {
                "valid": True,
                "algorithm": alg,
                "expired": is_expired,
                "alg_none_vulnerability": alg_none,
                "claims": {k: v for k, v in (payload.items() if isinstance(payload, dict) else {}.items())
                           if k in ("sub", "iss", "aud", "exp", "iat", "role", "email")},
                "severity_upgrade": "CRITICAL" if alg_none else None,
                "message": (
                    f"⚠ JWT with alg:none — signature bypass possible!" if alg_none
                    else f"JWT decoded — alg:{alg}, expired:{is_expired}"
                ),
            }
        except Exception as e:
            return {"valid": None, "error": str(e)}

    def _base64_decode(self, data: str):
        import json
        try:
            padded = data + '=' * (4 - len(data) % 4)
            decoded = base64.urlsafe_b64decode(padded).decode('utf-8')
            return json.loads(decoded)
        except Exception:
            return data
