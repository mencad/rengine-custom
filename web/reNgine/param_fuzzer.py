"""
reNgine Hidden Parameter Discovery Module using x8.

x8 is a fast, accurate hidden parameter discovery tool written in Rust.
It discovers unlinked GET, POST parameters and hidden headers by diffing responses.
This module integrates x8 into reNgine's Celery scan pipeline and SubScan workflows.
"""

import os
import re
import shutil
import logging
import subprocess
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

DEFAULT_PARAM_WORDLIST = '/usr/src/wordlist/parameters.txt'
FALLBACK_PARAM_WORDLIST = '/usr/src/wordlist/dicc.txt'

# Curated list of high-value parameters for IDOR, SSRF, Open Redirect, XSS, and Admin/Debug
EMBEDDED_TOP_PARAMETERS = [
    'id', 'user', 'user_id', 'userid', 'account', 'account_id', 'profile', 'profile_id',
    'uid', 'uuid', 'admin', 'administrator', 'debug', 'test', 'eval', 'dev', 'role',
    'url', 'uri', 'dest', 'destination', 'redirect', 'redirect_url', 'redirect_to',
    'next', 'return', 'return_url', 'target', 'domain', 'host', 'ip', 'callback',
    'webhook', 'feed', 'service', 'site', 'view', 'file', 'path', 'doc', 'document',
    'page', 'page_id', 'template', 'load', 'include', 'q', 'query', 'search', 's',
    'msg', 'message', 'text', 'input', 'data', 'json', 'payload', 'cmd', 'command',
    'exec', 'action', 'do', 'func', 'method', 'token', 'key', 'api_key', 'apikey',
    'auth', 'secret', 'code', 'session', 'session_id', 'config', 'setting', 'format',
    'type', 'ref', 'source', 'state', 'nonce', 'client_id', 'email', 'name', 'password',
    'limit', 'offset', 'order', 'sort', 'filter', 'group', 'lang', 'language', 'locale'
]

STATIC_EXTENSIONS = (
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.css', '.woff', '.woff2',
    '.ttf', '.eot', '.mp4', '.m4a', '.mp3', '.pdf', '.zip', '.tar', '.gz'
)


def resolve_param_wordlist(custom_wordlist=None):
    """
    Resolve wordlist path for x8.
    Fallback to embedded top parameter list if wordlist files do not exist.
    """
    if custom_wordlist and os.path.isfile(custom_wordlist):
        return custom_wordlist
    if os.path.isfile(DEFAULT_PARAM_WORDLIST):
        return DEFAULT_PARAM_WORDLIST
    if os.path.isfile(FALLBACK_PARAM_WORDLIST):
        return FALLBACK_PARAM_WORDLIST

    fallback_file = '/tmp/fallback_parameters.txt'
    if not os.path.isfile(fallback_file):
        try:
            with open(fallback_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(EMBEDDED_TOP_PARAMETERS) + '\n')
        except Exception as e:
            logger.warning(f'[x8 Param Fuzzer] Could not create fallback wordlist: {e}')
    return fallback_file


def filter_candidate_urls(urls, max_urls=30):
    """
    Filter, clean, and rank URLs for hidden parameter discovery.
    Prioritizes URLs without query parameters and ignores static assets.
    """
    candidates = []
    seen = set()

    for u in urls:
        if not u or not isinstance(u, str):
            continue
        u = u.strip()
        if not u.startswith(('http://', 'https://')):
            continue

        parsed = urlparse(u)
        path = parsed.path.lower()
        if any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
            continue

        # Canonical URL without query string for parameter fuzzing
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.path else f"{parsed.scheme}://{parsed.netloc}/"
        if base_url not in seen:
            seen.add(base_url)
            candidates.append(base_url)

    # Prioritize API/Dashboard/Profile/Export endpoints
    def rank_url(url):
        p = url.lower()
        if any(k in p for k in ['/api', '/v1', '/v2', '/user', '/profile', '/admin', '/export', '/download', '/view', '/service']):
            return 0
        return 1

    candidates.sort(key=rank_url)
    return candidates[:max_urls]


def run_x8_pipeline(target_urls, wordlist=None, custom_headers=None, proxy=None, threads=10, results_dir='/tmp', timeout=40):
    """
    Execute x8 against filtered candidate URLs and return discovered parameter-enriched URLs.
    """
    resolved_wordlist = resolve_param_wordlist(wordlist)
    candidates = filter_candidate_urls(target_urls)

    if not candidates:
        logger.info('[x8 Param Fuzzer] No candidate URLs remaining after filtering.')
        return []

    x8_bin = shutil.which('x8') or '/usr/local/bin/x8'
    if not os.path.isfile(x8_bin) and not shutil.which('x8'):
        logger.warning(f'[x8 Param Fuzzer] x8 binary not found at {x8_bin} or in PATH. Skipping parameter discovery.')
        return []

    os.makedirs(results_dir, exist_ok=True)
    discovered_urls = set()

    for idx, target_url in enumerate(candidates):
        output_file = f"{results_dir}/x8_out_{idx}.txt"

        cmd = [
            x8_bin,
            '-u', target_url,
            '-w', resolved_wordlist,
            '-X', 'GET',
            '-O', 'url',
            '-o', output_file,
            '--disable-progress-bar',
            '--disable-colors'
        ]

        if proxy:
            cmd.extend(['-x', str(proxy)])

        if custom_headers:
            for header in custom_headers:
                if header:
                    cmd.extend(['-H', str(header)])

        logger.info(f"[x8 Param Fuzzer] Scanning: {target_url} (wordlist={resolved_wordlist})")
        try:
            subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
                text=True
            )
        except subprocess.TimeoutExpired:
            logger.warning(f"[x8 Param Fuzzer] Timeout while fuzzing {target_url}")
            continue
        except Exception as e:
            logger.error(f"[x8 Param Fuzzer] Execution error on {target_url}: {e}")
            continue

        if os.path.isfile(output_file):
            try:
                with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        # Output format 'url' outputs URLs with parameters (containing '?')
                        if line.startswith(('http://', 'https://')) and '?' in line:
                            discovered_urls.add(line)
            except Exception as read_err:
                logger.error(f"[x8 Param Fuzzer] Error reading output {output_file}: {read_err}")

    logger.info(f"[x8 Param Fuzzer] Found {len(discovered_urls)} parameter-enriched URL(s).")
    return sorted(list(discovered_urls))
