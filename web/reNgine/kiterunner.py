"""Kiterunner API Content & Endpoint Discovery Module for reNgine.

Provides context-aware brute-forcing for API routes (REST, GraphQL, Swagger, OAuth)
using Assetnote's Kiterunner (kr) and `.kite` datasets to discover hidden endpoints
prone to IDOR, SSRF, Information Disclosure, and Open Redirect.
"""

import os
import json
import logging
import subprocess
from typing import List, Dict, Optional

logger = logging.getLogger('reNgine')

KITERUNNER_PATH = '/usr/local/bin/kr'
DEFAULT_KITE_WORDLIST = '/usr/src/wordlist/kiterunner/routes-small.kite'
FALLBACK_KITE_WORDLIST = '/usr/src/wordlist/routes-small.kite'


def get_kite_wordlist_path(custom_path: Optional[str] = None) -> str:
    """Resolve the path to the .kite wordlist."""
    if custom_path and os.path.exists(custom_path):
        return custom_path
    if os.path.exists(DEFAULT_KITE_WORDLIST):
        return DEFAULT_KITE_WORDLIST
    if os.path.exists(FALLBACK_KITE_WORDLIST):
        return FALLBACK_KITE_WORDLIST
    return DEFAULT_KITE_WORDLIST


def is_api_candidate(url: str) -> bool:
    """Check if a URL / subdomain looks like an API host or service."""
    url_lower = url.lower()
    keywords = [
        'api', 'rest', 'v1', 'v2', 'v3', 'graphql', 'auth', 'oauth',
        'swagger', 'openapi', 'doc', 'internal', 'admin', 'service',
        'gateway', 'backend', 'dev', 'stage', 'staging', 'stg', 'portal'
    ]
    return any(k in url_lower for k in keywords)


def run_kr_scan(target_url: str, wordlist: Optional[str] = None, concurrency: int = 30) -> List[Dict]:
    """Execute Kiterunner against a target URL and parse JSON results.

    Args:
        target_url: The base HTTP/HTTPS URL (e.g. 'https://api.target.com')
        wordlist: Path to the .kite dataset
        concurrency: Concurrency threads (-j / -x)

    Returns:
        List of dicts representing discovered endpoints:
        [{'url': '...', 'status': 200, 'method': 'GET', 'length': 1234}, ...]
    """
    resolved_wordlist = get_kite_wordlist_path(wordlist)
    if not os.path.exists(KITERUNNER_PATH):
        logger.warning(f"[Kiterunner] Binary not found at {KITERUNNER_PATH}. Skipping.")
        return []

    if not os.path.exists(resolved_wordlist):
        logger.warning(f"[Kiterunner] Wordlist not found at {resolved_wordlist}. Skipping.")
        return []

    cmd = [
        KITERUNNER_PATH,
        'scan',
        target_url,
        '-w', resolved_wordlist,
        '-j', str(concurrency),
        '--fail-status-codes', '400,404,429,500,502,503',
        '-o', 'json'
    ]

    logger.info(f"[Kiterunner] Scanning {target_url} with {os.path.basename(resolved_wordlist)}...")
    discovered = []

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        stdout, stderr = proc.communicate(timeout=600)  # max 10 mins per host

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                url = data.get('url') or data.get('target') or ''
                status = data.get('status', 0)
                method = data.get('method', 'GET')
                length = data.get('length', 0)

                if url:
                    discovered.append({
                        'url': url,
                        'status': int(status),
                        'method': method,
                        'length': int(length)
                    })
            except Exception:
                # Handle raw text output if not JSON
                pass

        logger.info(f"[Kiterunner] Finished {target_url}. Found {len(discovered)} endpoints.")

    except subprocess.TimeoutExpired:
        logger.warning(f"[Kiterunner] Scan timed out for {target_url}")
        proc.kill()
    except Exception as e:
        logger.error(f"[Kiterunner] Error running kr on {target_url}: {str(e)}")

    return discovered
