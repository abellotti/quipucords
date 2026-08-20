"""JWT signature verification for Lightspeed authentication.

This module provides cryptographic verification of JWT tokens from Lightspeed SSO
using standard RSA and ECDSA signature algorithms.

SECURITY CRITICAL: This module verifies that JWT tokens have not been tampered with.
Never disable signature verification in production.
"""

import datetime
import logging
from logging import getLogger

import jwt
import requests
from django.conf import settings
from django.core.cache import cache
from jwt import PyJWKClient

from api.auth.utils import decode_jwt as decode_jwt_unsafe

logger = getLogger(__name__)

# Cache TTL for JWKS (JSON Web Key Set)
JWKS_CACHE_TTL = 3600  # 1 hour

# JWKS endpoint path
JWKS_ENDPOINT = "/auth/realms/redhat-external/protocol/openid-connect/certs"


class JWTVerificationError(Exception):
    """JWT signature verification failed."""

    def __init__(self, message, *args):
        """Initialize with error message."""
        super().__init__(message, *args)
        self.message = message


def _get_jwks_uri():
    """Get the JWKS URI for the Lightspeed SSO server."""
    lightspeed_sso_server = settings.QUIPUCORDS_LIGHTSPEED_SSO_HOST
    return f"https://{lightspeed_sso_server}{JWKS_ENDPOINT}"


def _get_allowed_algorithms():
    """Get list of allowed JWT signing algorithms.

    Returns:
        list: Allowed JWT signing algorithms (RSA and ECDSA)
    """
    return settings.QUIPUCORDS_LIGHTSPEED_JWT_ALGORITHMS


def verify_and_decode_jwt(jwt_token, verify_signature=None):
    """Verify JWT signature and decode payload.

    Args:
        jwt_token: The JWT token string to verify
        verify_signature: Whether to verify signature (default: from settings)

    Returns:
        dict with keys:
            - header: JWT header
            - payload: JWT payload
            - expires_at: Expiration timestamp as datetime
            - algorithm: Signing algorithm used
            - verified: Whether signature was verified

    Raises:
        JWTVerificationError: If signature verification fails
    """
    if verify_signature is None:
        verify_signature = settings.QUIPUCORDS_LIGHTSPEED_JWT_VERIFY_SIGNATURE

    # Decode header without verification to check algorithm
    try:
        unverified_header = jwt.get_unverified_header(jwt_token)
        algorithm = unverified_header.get("alg")
        logger.debug(f"JWT algorithm: {algorithm}")
    except jwt.DecodeError as err:
        raise JWTVerificationError(f"Invalid JWT format: {err}") from err

    if not verify_signature:
        logger.warning(
            "JWT signature verification is DISABLED - accepting unverified tokens. "
            "This is a CRITICAL security risk in production!"
        )
        # Fall back to unsafe decoding
        decoded = decode_jwt_unsafe(jwt_token)
        if decoded:
            decoded["algorithm"] = algorithm
            decoded["verified"] = False
        return decoded

    # Get allowed algorithms
    allowed_algorithms = _get_allowed_algorithms()

    if algorithm not in allowed_algorithms:
        raise JWTVerificationError(
            f"JWT algorithm '{algorithm}' not allowed. "
            f"Allowed algorithms: {allowed_algorithms}"
        )

    # Fetch JWKS and verify signature
    try:
        jwks_uri = _get_jwks_uri()
        logger.debug(f"Fetching JWKS from {jwks_uri}")

        # Use PyJWKClient to fetch and cache signing keys
        jwks_client = PyJWKClient(
            jwks_uri,
            cache_keys=True,
            timeout=settings.QUIPUCORDS_AUTH_LIGHTSPEED_TIMEOUT,
        )

        # Get signing key from JWKS
        signing_key = jwks_client.get_signing_key_from_jwt(jwt_token)

        # Verify and decode JWT
        payload = jwt.decode(
            jwt_token,
            signing_key.key,
            algorithms=allowed_algorithms,
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_nbf": True,
            },
        )

        # Extract expiration
        exp = payload.get("exp")
        expires_at = (
            datetime.datetime.fromtimestamp(int(exp), datetime.UTC)
            if exp is not None
            else None
        )

        logger.info(f"JWT signature verified successfully (algorithm: {algorithm})")

        return {
            "header": unverified_header,
            "payload": payload,
            "expires_at": expires_at,
            "algorithm": algorithm,
            "verified": True,
        }

    except jwt.ExpiredSignatureError as err:
        raise JWTVerificationError("JWT token has expired") from err
    except jwt.InvalidTokenError as err:
        raise JWTVerificationError(f"JWT validation failed: {err}") from err
    except requests.exceptions.RequestException as err:
        raise JWTVerificationError(f"Failed to fetch JWKS: {err}") from err
    except Exception as err:
        logger.exception("Unexpected error during JWT verification")
        raise JWTVerificationError(f"JWT verification error: {err}") from err


def decode_jwt(jwt_token):
    """Decode and verify JWT token (backward compatible interface).

    Behavior depends on QUIPUCORDS_LIGHTSPEED_JWT_VERIFY_SIGNATURE setting:
    - False (default): Uses unsafe base64 decode (current behavior preserved)
    - True: Verifies cryptographic signature using JWKS from SSO

    Args:
        jwt_token: The JWT token string

    Returns:
        dict or None: Decoded JWT with verification status, or None if invalid
    """
    verify_sig = settings.QUIPUCORDS_LIGHTSPEED_JWT_VERIFY_SIGNATURE

    if not verify_sig:
        # Maintain backward compatibility: use unsafe decoding when verification disabled
        logger.debug("JWT verification disabled - using legacy unsafe decode")
        decoded = decode_jwt_unsafe(jwt_token)
        if decoded:
            # Add verification status for transparency
            decoded["verified"] = False
            try:
                header = jwt.get_unverified_header(jwt_token)
                decoded["algorithm"] = header.get("alg", "unknown")
            except Exception:
                decoded["algorithm"] = "unknown"
        return decoded

    # Verification enabled: use cryptographic validation
    try:
        return verify_and_decode_jwt(jwt_token, verify_signature=True)
    except JWTVerificationError as err:
        logger.error(f"JWT verification failed: {err.message}")
        return None
