"""
reNgine Virtual Host (VHost) Fuzzing & Discovery Module.

Uses FFUF with auto-calibration (-ac) to fuzz the 'Host' header against a target IP or host,
discovering internal / unlisted virtual hosts configured on the target web server.
"""

import os
import json
import subprocess
import logging

logger = logging.getLogger(__name__)

DEFAULT_VHOST_WORDLIST = '/usr/src/wordlist/subdomains-top5000.txt'
FALLBACK_VHOST_WORDLIST = '/usr/src/wordlist/deepmagic.com-prefixes-top50000.txt'

# Essential internal hostnames for quick fallback if no wordlist file exists
EMBEDDED_TOP_VHOSTS = [
    'admin', 'administrator', 'api', 'app', 'auth', 'backend', 'beta', 'billing',
    'cdn', 'ci', 'cloud', 'corp', 'dashboard', 'database', 'db', 'demo', 'dev',
    'developer', 'development', 'direct', 'dns', 'docs', 'edge', 'email', 'erp',
    'gateway', 'git', 'gitlab', 'grafana', 'helpdesk', 'hub', 'internal', 'intranet',
    'jenkins', 'jira', 'k8s', 'kubernetes', 'ldap', 'login', 'mail', 'manage',
    'management', 'monitoring', 'my', 'nexus', 'oa', 'ops', 'panel', 'portal',
    'private', 'prod', 'production', 'prometheus', 'proxy', 'qa', 'remote',
    's3', 'secure', 'server', 'service', 'services', 'sso', 'stage', 'staging',
    'static', 'status', 'support', 'test', 'testing', 'tools', 'uat', 'vault',
    'vpn', 'vpx', 'webmail', 'wiki', 'ws', 'zabbix'
]


def resolve_vhost_wordlist(custom_wordlist=None):
    """
    Resolve the wordlist path to use for VHost fuzzing.
    If neither file exists, generates a temporary fallback wordlist.
    """
    if custom_wordlist and os.path.isfile(custom_wordlist):
        return custom_wordlist
    if os.path.isfile(DEFAULT_VHOST_WORDLIST):
        return DEFAULT_VHOST_WORDLIST
    if os.path.isfile(FALLBACK_VHOST_WORDLIST):
        return FALLBACK_VHOST_WORDLIST

    fallback_path = '/tmp/vhost_top_fallback.txt'
    if not os.path.isfile(fallback_path):
        try:
            with open(fallback_path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(EMBEDDED_TOP_VHOSTS) + '\n')
        except Exception as e:
            logger.warning(f'[VHost Fuzzer] Could not write fallback wordlist: {e}')
    return fallback_path


def format_target_url(target):
    """Ensure the target has a valid scheme (http:// or https://)."""
    target = target.strip()
    if not target.startswith(('http://', 'https://')):
        # Default to http if no scheme provided
        return f'http://{target}'
    return target


def run_vhost_fuzz(
    target_url,
    domain_name,
    wordlist=None,
    threads=30,
    timeout=5,
    results_dir=None
):
    """
    Execute FFUF VHost fuzzing against target_url with 'Host: FUZZ.{domain_name}'.

    Args:
        target_url (str): The HTTP/HTTPS URL or IP to probe (e.g. 'http://52.1.2.3' or 'https://target.com').
        domain_name (str): The root domain to fuzz hosts for (e.g. 'target.com').
        wordlist (str, optional): Custom wordlist path.
        threads (int): Concurrency level. Default 30.
        timeout (int): Per-request timeout in seconds. Default 5.
        results_dir (str, optional): Directory to store raw JSON results.

    Returns:
        list of dict: Discovered virtual hosts [{
            'vhost': 'admin.target.com',
            'subdomain_prefix': 'admin',
            'status': 200,
            'length': 4120,
            'words': 350,
            'lines': 42,
            'url': 'http://52.1.2.3/'
        }]
    """
    formatted_target = format_target_url(target_url)
    wordlist_path = resolve_vhost_wordlist(wordlist)

    if not results_dir:
        results_dir = '/tmp/rengine_vhost'
    os.makedirs(results_dir, exist_ok=True)

    # Sanitize domain name for filename
    clean_target = formatted_target.replace('://', '_').replace('/', '').replace(':', '_')
    output_json = os.path.join(results_dir, f'vhost_{clean_target}_{domain_name}.json')

    # FFUF Command:
    # -u {target} : base endpoint
    # -H "Host: FUZZ.{domain_name}" : test virtual host headers
    # -w {wordlist} : subdomain wordlist
    # -ac : auto-calibration (crucial to eliminate false-positive catch-alls)
    # -mc all : match all status codes initially, auto-calibration filters anomalies
    # -of json -o {output_json} : output in JSON
    # -t {threads} : thread count
    # -timeout {timeout} : HTTP timeout
    # -s : silent mode
    cmd = [
        'ffuf',
        '-u', formatted_target,
        '-H', f'Host: FUZZ.{domain_name}',
        '-w', wordlist_path,
        '-ac',
        '-mc', 'all',
        '-of', 'json',
        '-o', output_json,
        '-t', str(threads),
        '-timeout', str(timeout),
        '-s'
    ]

    logger.info(f'[VHost Fuzzer] Launching FFUF on {formatted_target} with domain {domain_name}...')
    try:
        subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=3600  # 1 hour max
        )
    except subprocess.TimeoutExpired:
        logger.error(f'[VHost Fuzzer] FFUF command timed out for {formatted_target}')
        return []
    except FileNotFoundError:
        logger.error('[VHost Fuzzer] ffuf binary not found in system PATH!')
        return []
    except Exception as e:
        logger.error(f'[VHost Fuzzer] Error executing ffuf: {e}')
        return []

    # Parse JSON results
    discovered = []
    if not os.path.isfile(output_json):
        logger.info(f'[VHost Fuzzer] No output file produced for {formatted_target}')
        return discovered

    try:
        with open(output_json, 'r', encoding='utf-8') as f:
            data = json.load(f)

        results = data.get('results', [])
        for item in results:
            fuzz_input = item.get('input', {})
            prefix = fuzz_input.get('FUZZ', '').strip()
            if not prefix:
                continue

            vhost_full = f'{prefix}.{domain_name}'.lower()
            status = item.get('status', 0)
            length = item.get('length', 0)
            words = item.get('words', 0)
            lines = item.get('lines', 0)
            result_url = item.get('url', formatted_target)

            discovered.append({
                'vhost': vhost_full,
                'subdomain_prefix': prefix,
                'status': status,
                'length': length,
                'words': words,
                'lines': lines,
                'url': result_url
            })

        logger.info(f'[VHost Fuzzer] Found {len(discovered)} valid virtual host(s) on {formatted_target}')
    except Exception as e:
        logger.error(f'[VHost Fuzzer] Error parsing FFUF output JSON: {e}')

    return discovered
