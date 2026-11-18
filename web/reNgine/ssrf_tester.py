"""Automated Out-of-Band (OOB) SSRF Testing & Alerting Module for reNgine.

Extracts potential SSRF parameters from discovered endpoints, substitutes them
with unique OOB callback domains (Interactsh / Burp Collaborator), audits endpoints safely,
and dispatches instant Telegram alerts and registers High/Critical vulnerabilities in reNgine.
"""

import logging
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Tuple

logger = logging.getLogger('reNgine')

# Comprehensive list of 160+ SSRF parameters from:
# - Gf-Patterns (1ndianl33t / tomnomnom)
# - HowToHunt & PayloadsAllTheThings
# - SecLists & Bug Bounty real-world research
SSRF_PARAM_NAMES = {
    # Redirection, Forwarding & Navigation
    'url', 'uri', 'dest', 'destination', 'redirect', 'redirect_url', 'redirect_uri',
    'redirect_to', 'redirecturl', 'redirectback', 'redir', 'rurl', 'return',
    'return_url', 'returnurl', 'return_to', 'returnto', 'ret', 'r2', 'r', 'u',
    'next', '_next', 'forward', 'fwd', 'go', 'goto', 'to', 'out', 'from',
    'target', 'targeturl', 'target_url', 'surl', 'newurl', 'old', 'urlsito',
    'cur_url', 'ref_url', 'cancel_url', 'starturl', 'start_url', 'end_url',
    'errorurl', 'error_url', 'authstate', 'location', 'pathlocation', 'successtarget',
    'no_such_entry_redirect', 'logout_redirect_uri', 'logoutredirecturl',
    'aspxerrorpath', 'actioncodeurl', 'continue', 'window', 'navigation',
    'link', 'linkurl', 'r_link', 'href', 'back', 'retour', 'anything',

    # Webhooks, Callbacks & API gateways
    'callback', 'callback_url', 'cb', 'webhook', 'webhook_url', 'hook',
    'endpoint', 'event_url', 'notify', 'notification', 'notification_url',
    'ping', 'pingback', 'pingback_url', 'api', 'api_url', 'api_uri',
    'service', 'relay', 'proxy', 'proxy_url', 'handler', 'receiver',
    'listener', 'subscribe_url', 'publish_url', 'postback', 'postback_url',
    'oauth_callback', 'auth_url', 'token_url', 'sso', 'saml',

    # Fetching, Importing, Downloading & Crawling
    'fetch', 'fetch_url', 'load', 'load_url', 'import', 'import_url',
    'include', 'inc', 'require', 'req', 'request', 'retrieve',
    'download', 'download_url', 'upload', 'upload_url', 'sync', 'sync_url',
    'pull', 'clone', 'clone_url', 'get', 'read', 'preview', 'browse',

    # Media, Documents, Assets & Templates
    'image', 'image_url', 'image_path', 'img', 'img_url', 'pic', 'photo',
    'picture', 'avatar', 'avatar_url', 'icon', 'thumbnail', 'thumb', 'logo',
    'media', 'media_url', 'pdf', 'pdf_url', 'doc', 'doc_url', 'document',
    'file', 'file_url', 'filename', 'attachment', 'asset', 'asset_url',
    'resource', 'resource_url', 'stylesheet', 'css', 'style', 'template',
    'template_url', 'template_path', 'view', 'content', 'content_url',
    'xml', 'json', 'rss', 'feed', 'feed_url',

    # Host, Domain, Origin, Path & Network
    'domain', 'host', 'hostname', 'port', 'ip', 'site', 'address',
    'origin', 'source', 'src', 'ref', 'reference', 'path', 'dir',
    'folder', 'root', 'pg', 'php_path', 'html', 'page', 'open', 'show',

    # Validation, Health & Debugging
    'val', 'validate', 'verify', 'check', 'health', 'test', 'probe',
    'monitor', 'status', 'debug', 'dbg', 'data', 'cfg', 'config', 'log'
}

SSRF_KEYWORDS = (
    'url', 'uri', 'dest', 'link', 'redirect', 'fetch', 'webhook',
    'callback', 'proxy', 'forward', 'endpoint', 'domain', 'host',
    'preview', 'download', 'upload', 'import', 'stream', 'feed',
    'image', 'path', 'target', 'service', 'relay'
)


def is_ssrf_candidate_param(param_name: str) -> bool:
    """Check if query parameter name matches known SSRF candidate keywords."""
    clean_name = param_name.lower().strip()
    if clean_name in SSRF_PARAM_NAMES:
        return True
    return any(k in clean_name for k in SSRF_KEYWORDS)


def extract_ssrf_candidates(urls: List[str]) -> List[Dict]:
    """Parse a list of URLs and extract those containing potential SSRF query parameters.

    Returns:
        List of dicts: [{'url': original_url, 'param': param_name, 'parsed': parsed_obj}, ...]
    """
    candidates = []
    seen = set()

    for u in urls:
        if not u or not isinstance(u, str):
            continue
        try:
            parsed = urlparse(u)
            if not parsed.query:
                continue

            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for param in query_params:
                if is_ssrf_candidate_param(param):
                    key = (parsed.netloc, parsed.path, param)
                    if key not in seen:
                        seen.add(key)
                        candidates.append({
                            'original_url': u,
                            'param': param,
                            'parsed': parsed,
                            'existing_value': query_params[param][0] if query_params[param] else ''
                        })
        except Exception as e:
            logger.debug(f"[SSRF Tester] Error parsing URL {u}: {str(e)}")

    return candidates


def craft_ssrf_payload_url(candidate: Dict, callback_domain: str, tag: str = "") -> str:
    """Replace candidate parameter value with the OOB callback domain.

    Args:
        candidate: Dict from extract_ssrf_candidates
        callback_domain: e.g. 'c123.oast.fun'
        tag: Optional unique identifier for tracking exact request

    Returns:
        Substituted URL string
    """
    parsed = candidate['parsed']
    param_name = candidate['param']

    target_domain = f"{tag}.{callback_domain}" if tag else callback_domain
    payload_url = f"http://{target_domain}"

    query_params = parse_qs(parsed.query, keep_blank_values=True)
    query_params[param_name] = [payload_url]

    new_query = urlencode(query_params, doseq=True)
    new_url_parts = (parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment)
    return urlunparse(new_url_parts)


def send_ssrf_probe(substituted_url: str, timeout: int = 5) -> Tuple[bool, int]:
    """Send probe request safely with custom User-Agent and timeout."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': '*/*'
    }
    try:
        res = requests.get(
            substituted_url,
            headers=headers,
            timeout=timeout,
            verify=False,
            allow_redirects=True
        )
        return True, res.status_code
    except requests.exceptions.Timeout:
        # Timeouts are common in SSRF when server hangs attempting internal/outbound connection
        return True, 504
    except Exception as e:
        logger.debug(f"[SSRF Probe] Error sending probe to {substituted_url}: {str(e)}")
        return False, 0


def record_ssrf_finding(vulnerable_url: str, param_name: str, callback_domain: str, scan_history=None, target_domain=None):
    """Save verified SSRF vulnerability into reNgine database and dispatch Telegram alert."""
    try:
        from startScan.models import Vulnerability
        from reNgine.tasks import send_notif

        desc = (
            f"Server-Side Request Forgery (SSRF) detected.\n"
            f"Target parameter: '{param_name}' triggered an out-of-band network interaction.\n"
            f"Callback listener: {callback_domain}"
        )

        vuln, created = Vulnerability.objects.get_or_create(
            scan_history=scan_history,
            target_domain=target_domain,
            name="Blind SSRF (Out-of-Band Callback Received)",
            http_url=vulnerable_url,
            defaults={
                'severity': 4,  # Critical
                'description': desc,
                'source': 'reNgine SSRF Automator'
            }
        )
        vuln.save()

        # Send instant Telegram Alert
        target_name = target_domain.name if target_domain else urlparse(vulnerable_url).netloc
        msg = (
            f"🚨 <b>[CRITICAL] Blind SSRF Confirmed!</b>\n\n"
            f"🎯 <b>Target:</b> <code>{target_name}</code>\n"
            f"🔗 <b>Vulnerable URL:</b> <code>{vulnerable_url}</code>\n"
            f"📌 <b>Parameter:</b> <code>{param_name}</code>\n"
            f"📡 <b>Callback:</b> Outbound interaction registered!\n"
            f"⚡ <i>Action: Check reNgine Vulnerabilities tab for details.</i>"
        )
        send_notif(msg)
        logger.warning(f"[SSRF CONFIRMED] {vulnerable_url} on param {param_name}")

    except Exception as e:
        logger.error(f"[SSRF Finding Error] Failed to record SSRF finding: {str(e)}")
