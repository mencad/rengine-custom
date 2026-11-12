"""Certstream Utility Functions for reNgine.

Provides domain extraction, wildcard cleaning, and matching
against reNgine monitored target domains.
"""

import re
import logging
from typing import List, Dict, Set, Optional

logger = logging.getLogger('reNgine')


def clean_domain(domain: str) -> str:
    """Clean a domain name by removing wildcards, leading dots, and port numbers.

    Args:
        domain: Raw domain string from certificate (e.g., '*.sub.example.com:443')

    Returns:
        Cleaned lowercase domain string (e.g., 'sub.example.com')
    """
    if not domain:
        return ""
    domain = domain.lower().strip()
    # Remove wildcard prefix
    if domain.startswith("*."):
        domain = domain[2:]
    elif domain.startswith("."):
        domain = domain[1:]
    # Remove port if present
    if ":" in domain:
        domain = domain.split(":")[0]
    return domain.strip()


def extract_domains_from_cert(message: Dict) -> Set[str]:
    """Extract all unique domains from a Certstream certificate message.

    Certstream sends JSON messages containing certificate details,
    including Common Name (CN) and Subject Alternative Names (SANs).

    Args:
        message: Dict received from the Certstream websocket.

    Returns:
        Set of unique cleaned domain strings.
    """
    domains: Set[str] = set()

    if not isinstance(message, dict):
        return domains

    data = message.get("data", {})
    leaf_cert = data.get("leaf_cert", {})

    # Extract all_domains if provided by certstream
    all_domains = leaf_cert.get("all_domains", [])
    for d in all_domains:
        cleaned = clean_domain(d)
        if cleaned and "." in cleaned:
            domains.add(cleaned)

    # Extract Subject Common Name
    subject = leaf_cert.get("subject", {})
    cn = subject.get("CN")
    if cn:
        cleaned = clean_domain(cn)
        if cleaned and "." in cleaned:
            domains.add(cleaned)

    # Extract SANs (Subject Alternative Names)
    extensions = leaf_cert.get("extensions", {})
    san_list = extensions.get("subjectAltName", [])
    if isinstance(san_list, list):
        for san in san_list:
            cleaned = clean_domain(san)
            if cleaned and "." in cleaned:
                domains.add(cleaned)
    elif isinstance(san_list, str):
        for part in san_list.split(","):
            part = part.strip()
            if part.startswith("DNS:"):
                part = part[4:]
            cleaned = clean_domain(part)
            if cleaned and "." in cleaned:
                domains.add(cleaned)

    return domains


def match_against_targets(discovered_subdomain: str, monitored_domains: List[str]) -> Optional[str]:
    """Check if a discovered subdomain belongs to any of our monitored targets.

    Args:
        discovered_subdomain: e.g. 'staging-api.ui.com'
        monitored_domains: List of root domains e.g. ['ui.com', 'ubnt.com']

    Returns:
        The matching parent root domain (e.g. 'ui.com') or None.
    """
    sub_lower = discovered_subdomain.lower().strip()
    for root in monitored_domains:
        root_clean = root.lower().strip()
        # Direct match or subdomain match (.root)
        if sub_lower == root_clean or sub_lower.endswith("." + root_clean):
            return root_clean
    return None
