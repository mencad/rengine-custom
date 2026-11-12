"""JavaScript File Change Monitoring and Secret Extraction (JS Diffing) for reNgine.

Downloads and tracks SHA256 hashes of JavaScript files discovered during
crawling, detects when developers update JS files, and extracts new API endpoints
and sensitive secrets (AWS keys, JWTs, Google API keys, tokens).
"""

import re
import hashlib
import logging
import requests
from datetime import datetime
from typing import Dict, List, Set, Tuple

logger = logging.getLogger('reNgine')

# Regex patterns for sensitive secrets inside JavaScript
SECRET_PATTERNS = {
    "AWS Access Key": r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
    "Google API Key": r'AIza[0-9A-Za-z_-]{30,40}',
    "Slack Webhook": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
    "JWT Token": r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+',
    "GitHub Token": r'gh[pousr]_[A-Za-z0-9_]{36,}',
    "Stripe Secret Key": r'sk_live_[0-9a-zA-Z]{24}',
    "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
    "Generic Authorization Header": r'(?i)authorization\s*:\s*["\'](?:bearer|basic)\s+[a-z0-9._\-~+/]+=*["\']',
}

# Regex patterns for API endpoints inside JavaScript
ENDPOINT_PATTERN = re.compile(
    r"""(?i)(?:['"`])((?:/api/|/v[1-9]/|/rest/|/graphql|/oauth/|/auth/|/v[1-9]\.[0-9]+/)[^'"`\s\)\>]+)(?:['"`])"""
)


def compute_hash(content: bytes) -> str:
    """Compute SHA-256 hash of file content."""
    return hashlib.sha256(content).hexdigest()


def extract_secrets(js_code: str) -> Dict[str, Set[str]]:
    """Scan JS code for secrets, tokens, and sensitive API keys."""
    findings = {}
    for secret_type, pattern in SECRET_PATTERNS.items():
        matches = set(re.findall(pattern, js_code))
        if matches:
            findings[secret_type] = matches
    return findings


def extract_api_endpoints(js_code: str) -> Set[str]:
    """Extract internal API endpoints and routes from JS code."""
    endpoints = set(ENDPOINT_PATTERN.findall(js_code))
    # Filter out common noise
    cleaned = {ep.strip() for ep in endpoints if len(ep.strip()) > 4 and not ep.endswith(('.png', '.svg', '.jpg', '.css'))}
    return cleaned


def fetch_js_content(url: str, timeout: int = 10) -> Tuple[bool, bytes, str]:
    """Download JS content safely."""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        res = requests.get(url, headers=headers, timeout=timeout, verify=False)
        if res.status_code == 200:
            return True, res.content, res.text
    except Exception as e:
        logger.warning(f"[JS Monitor] Failed to fetch {url}: {str(e)}")
    return False, b"", ""


def check_and_diff_js_file(js_url: str, old_hash: str = None) -> Dict:
    """Check a single JS file for changes and new findings."""
    success, raw_bytes, text_content = fetch_js_content(js_url)
    if not success:
        return {"status": "error", "url": js_url}

    new_hash = compute_hash(raw_bytes)
    is_changed = (old_hash is not None and old_hash != new_hash)
    secrets = extract_secrets(text_content)
    endpoints = extract_api_endpoints(text_content)

    return {
        "status": "success",
        "url": js_url,
        "is_changed": is_changed,
        "is_new": (old_hash is None),
        "old_hash": old_hash,
        "new_hash": new_hash,
        "secrets": secrets,
        "endpoints": list(endpoints)[:20],  # top 20 endpoints
    }


def notify_js_change(target_name: str, diff_result: Dict):
    """Send formatted Telegram / Discord alert on JS change."""
    from reNgine.tasks import send_notif

    url = diff_result["url"]
    secrets = diff_result.get("secrets", {})
    endpoints = diff_result.get("endpoints", [])

    msg_lines = [
        f"📄 <b>[JS Diff Alert] JavaScript File Changed!</b>",
        f"🎯 <b>Target:</b> <code>{target_name}</code>",
        f"🔗 <b>File:</b> <code>{url}</code>",
        f"🔑 <b>New Hash:</b> <code>{diff_result['new_hash'][:16]}...</code>\n",
    ]

    if secrets:
        msg_lines.append("🚨 <b>Sensitive Secrets Discovered:</b>")
        for stype, items in secrets.items():
            sample = list(items)[0]
            masked = sample[:6] + "..." + sample[-4:] if len(sample) > 12 else sample
            msg_lines.append(f"• <b>{stype}:</b> <code>{masked}</code>")
        msg_lines.append("")

    if endpoints:
        msg_lines.append("🛣️ <b>Discovered API Endpoints:</b>")
        for ep in endpoints[:8]:
            msg_lines.append(f"• <code>{ep}</code>")

    full_msg = "\n".join(msg_lines)
    logger.info(f"[JS Monitor] Sending alert for {url}")
    send_notif(full_msg)
