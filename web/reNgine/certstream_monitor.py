"""Certstream Real-time Subdomain Discovery Daemon for reNgine.

Streams Certificate Transparency (CT) logs in real-time, matches
newly issued SSL/TLS certificates against reNgine target domains,
saves new subdomains to the database, and sends immediate alerts to Telegram.
"""

import time
import logging
from datetime import datetime
from django.utils import timezone

from reNgine.certstream_utils import extract_domains_from_cert, match_against_targets

logger = logging.getLogger('reNgine')


class CertstreamMonitor:
    """Real-time CT log monitor connected to reNgine."""

    def __init__(self, callback_alert=True):
        self.callback_alert = callback_alert
        self.cached_targets = {}
        self.last_cache_refresh = 0
        self.cache_ttl = 60  # Refresh target domains from DB every 60 seconds

    def refresh_target_domains(self):
        """Fetch all active target domains from reNgine database."""
        now = time.time()
        if now - self.last_cache_refresh > self.cache_ttl:
            try:
                from targetApp.models import Domain
                domains = Domain.objects.all()
                self.cached_targets = {d.name.lower().strip(): d for d in domains}
                self.last_cache_refresh = now
                logger.info(f"[Certstream] Monitoring {len(self.cached_targets)} target domains.")
            except Exception as e:
                logger.error(f"[Certstream] Failed to load target domains: {str(e)}")
        return self.cached_targets

    def handle_message(self, message, context=None):
        """Callback invoked for every CT log message received from Certstream."""
        if message.get("message_type") != "certificate_update":
            return

        targets_map = self.refresh_target_domains()
        if not targets_map:
            return

        monitored_domain_names = list(targets_map.keys())
        extracted_domains = extract_domains_from_cert(message)

        for subdomain in extracted_domains:
            matched_root = match_against_targets(subdomain, monitored_domain_names)
            if matched_root:
                self.process_discovered_subdomain(subdomain, targets_map[matched_root])

    def process_discovered_subdomain(self, subdomain_name: str, target_domain_obj):
        """Save new subdomain to reNgine and dispatch notifications."""
        try:
            from startScan.models import Subdomain
            from reNgine.tasks import send_notif

            # Check if this subdomain is already known
            exists = Subdomain.objects.filter(
                target_domain=target_domain_obj,
                name__iexact=subdomain_name
            ).exists()

            if exists:
                return

            # Register the new subdomain in reNgine database
            subdomain = Subdomain.objects.create(
                target_domain=target_domain_obj,
                name=subdomain_name,
                discovered_date=timezone.now(),
                is_imported_subdomain=True,
                is_important=True
            )
            subdomain.save()

            msg = (
                f"🚨 <b>[Certstream] New Subdomain Discovered!</b>\n\n"
                f"🎯 <b>Target:</b> <code>{target_domain_obj.name}</code>\n"
                f"🌐 <b>Subdomain:</b> <code>{subdomain_name}</code>\n"
                f"⏰ <b>Discovered At:</b> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
                f"⚡ <i>Source: Real-time Certificate Transparency Stream</i>"
            )

            logger.info(f"[Certstream MATCH] {subdomain_name} for target {target_domain_obj.name}")

            if self.callback_alert:
                send_notif(msg)

        except Exception as e:
            logger.error(f"[Certstream] Error processing subdomain {subdomain_name}: {str(e)}")

    def start(self):
        """Start the certstream listener."""
        import certstream

        logger.info("[Certstream] Starting Real-time Certificate Stream listener...")
        try:
            certstream.listen_for_events(self.handle_message, url='wss://certstream.calidog.io/')
        except Exception as e:
            logger.error(f"[Certstream] Connection terminated: {str(e)}")
            time.sleep(5)
            # Reconnect
            self.start()


def start_certstream_worker():
    """Entry point for Celery task or management command."""
    monitor = CertstreamMonitor()
    monitor.start()


if __name__ == "__main__":
    start_certstream_worker()
