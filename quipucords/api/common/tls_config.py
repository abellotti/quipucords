"""TLS configuration for Lightspeed communications with optional PQC support.

On RHEL 10+ with oqs-provider installed, enables post-quantum key exchange.
Falls back gracefully to standard TLS if PQC is not available.
"""

import logging
import ssl

import requests
from django.conf import settings
from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

logger = logging.getLogger(__name__)

# Modern TLS 1.3 cipher suites
TLS13_CIPHERS = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"

# TLS 1.2 ciphers for backward compatibility
TLS12_CIPHERS = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256"

# Combined cipher list
DEFAULT_CIPHERS = f"{TLS13_CIPHERS}:{TLS12_CIPHERS}"


class TLSAdapter(HTTPAdapter):
    """HTTPAdapter with custom TLS configuration."""

    def __init__(self, ssl_context=None, *args, **kwargs):
        """Initialize adapter with custom SSL context."""
        self.ssl_context = ssl_context
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        """Initialize pool manager with custom SSL context."""
        if self.ssl_context:
            kwargs['ssl_context'] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)


def _create_ssl_context(verify=True, min_tls_version=ssl.TLSVersion.TLSv1_2):
    """Create SSL context with TLS configuration.

    Args:
        verify: Whether to verify SSL certificates
        min_tls_version: Minimum TLS version (TLSv1_2 or TLSv1_3)

    Returns:
        ssl.SSLContext configured for modern TLS
    """
    # Create context with cipher suites
    context = create_urllib3_context(ciphers=DEFAULT_CIPHERS)

    # Set minimum TLS version
    context.minimum_version = min_tls_version
    logger.debug(f"TLS minimum version: {min_tls_version.name}")

    # Configure certificate verification
    if verify:
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        logger.warning("TLS certificate verification DISABLED")

    return context


def get_lightspeed_session(verify=None):
    """Get a requests Session for Lightspeed communications.

    When QUIPUCORDS_ENABLE_PQC_TLS=true:
    - Uses TLS 1.3 minimum
    - On RHEL 10 with oqs-provider: hybrid classical+PQC key exchange
    - Without oqs-provider: standard TLS 1.3

    When QUIPUCORDS_ENABLE_PQC_TLS=false (default):
    - Uses TLS 1.2 minimum (backward compatible)
    - Standard classical cryptography

    Args:
        verify: Whether to verify SSL certificates (default: from settings)

    Returns:
        requests.Session configured for Lightspeed
    """
    if verify is None:
        verify = settings.QUIPUCORDS_LIGHTSPEED_SSL_VERIFY

    session = requests.Session()

    if settings.QUIPUCORDS_ENABLE_PQC_TLS:
        # PQC mode: TLS 1.3 minimum (enables PQC key exchange if oqs-provider available)
        ssl_context = _create_ssl_context(verify=verify, min_tls_version=ssl.TLSVersion.TLSv1_3)
        adapter = TLSAdapter(ssl_context=ssl_context)
        session.mount("https://", adapter)
        logger.debug("Lightspeed session: PQC-enabled TLS 1.3")
    else:
        # Classical mode: TLS 1.2 minimum (backward compatible)
        ssl_context = _create_ssl_context(verify=verify, min_tls_version=ssl.TLSVersion.TLSv1_2)
        adapter = TLSAdapter(ssl_context=ssl_context)
        session.mount("https://", adapter)
        logger.debug("Lightspeed session: Classical TLS 1.2+")

    return session
