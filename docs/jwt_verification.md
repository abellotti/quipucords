# JWT Signature Verification

## Overview

Quipucords now supports cryptographic verification of JWT tokens from Red Hat Lightspeed SSO. This ensures tokens have not been tampered with and protects against token forgery attacks.

## Security Issue Fixed

**Previous Behavior**: The original `decode_jwt()` function performed **no signature verification** - it only decoded the base64-encoded JWT and trusted the contents.

**New Behavior**: When enabled, JWT tokens are cryptographically verified using public keys fetched from the SSO server's JWKS endpoint.

## Backward Compatibility

**IMPORTANT**: JWT signature verification is **disabled by default** to maintain backward compatibility.

### Default Behavior (Verification Disabled)

```bash
# Default setting
QUIPUCORDS_LIGHTSPEED_JWT_VERIFY_SIGNATURE=false
```

**What happens**: Uses legacy base64 decoding without signature verification (current behavior preserved)

⚠️ **Security Warning**: Tokens are accepted without cryptographic validation. This preserves existing behavior but is NOT recommended for production.

### Secure Behavior (Verification Enabled)

```bash
# Enable JWT signature verification
QUIPUCORDS_LIGHTSPEED_JWT_VERIFY_SIGNATURE=true
```

**What happens**:
- JWT signature is cryptographically verified using JWKS from SSO server
- Invalid or tampered tokens are rejected
- Standard RSA and ECDSA algorithms supported

## Configuration

### Enable JWT Verification

Add this environment variable:

```bash
export QUIPUCORDS_LIGHTSPEED_JWT_VERIFY_SIGNATURE=true
```

That's it. No other configuration needed.

## Supported Algorithms

The following industry-standard JWT signing algorithms are supported:

**RSA Signatures:**
- `RS256`: RSA with SHA-256
- `RS384`: RSA with SHA-384
- `RS512`: RSA with SHA-512

**ECDSA Signatures:**
- `ES256`: ECDSA with SHA-256 (P-256 curve)
- `ES384`: ECDSA with SHA-384 (P-384 curve)
- `ES512`: ECDSA with SHA-512 (P-521 curve)

## How It Works

### 1. Token Reception

When Lightspeed SSO returns an access token during authentication:

```json
{
  "access_token": "eyJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### 2. Header Inspection

The JWT header is decoded (without verification) to determine the signing algorithm:

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "abc123"
}
```

### 3. Algorithm Validation

The algorithm is checked against the allowed list (RS256/384/512, ES256/384/512).

### 4. JWKS Fetch

The JSON Web Key Set (JWKS) is fetched from the SSO server:

```
https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/certs
```

The JWKS contains public keys for signature verification. This is cached for performance.

### 5. Signature Verification

The JWT signature is cryptographically verified using the appropriate public key from JWKS.

### 6. Claims Validation

Standard JWT claims are validated:

- **exp**: Token expiration time
- **iat**: Token issued-at time
- **nbf**: Not-before time

## Security Implications

### Without Verification (Current Default)

❌ **Tampering**: Attacker can modify token claims (e.g., change user ID, org ID)
❌ **Forgery**: Attacker can create fake tokens with arbitrary claims
❌ **Replay**: Expired tokens can be manually "renewed"

**Mitigation**: Token is only used over HTTPS, limiting attack surface to MITM scenarios

### With Verification (Recommended)

✅ **Tampering**: Any modification invalidates the signature
✅ **Forgery**: Requires SSO private key (cryptographically infeasible)
✅ **Replay**: Expiration claims are cryptographically verified
✅ **Algorithm confusion**: Only approved algorithms accepted

## Migration Guide

### Phase 1: Current State (No Verification)

```bash
# Existing deployments
QUIPUCORDS_LIGHTSPEED_JWT_VERIFY_SIGNATURE=false  # Default
```

- Tokens are decoded without verification
- No breaking changes from previous behavior

### Phase 2: Enable Verification (Recommended)

```bash
# Enable signature verification
QUIPUCORDS_LIGHTSPEED_JWT_VERIFY_SIGNATURE=true
```

**Testing checklist:**
1. Verify authentication flow completes successfully
2. Check that token metadata is extracted correctly
3. Ensure SSO server JWKS endpoint is reachable from Quipucords
4. Monitor logs for verification failures

**Rollback**: Set `QUIPUCORDS_LIGHTSPEED_JWT_VERIFY_SIGNATURE=false` to restore previous behavior

## Troubleshooting

### Issue: Authentication fails with "JWT validation failed"

**Symptom**:
```
ERROR: JWT verification failed: Signature verification failed
```

**Possible causes:**
1. SSO server JWKS endpoint is unreachable
2. Network/firewall blocking HTTPS to sso.redhat.com
3. Token is actually invalid or tampered with

**Solutions:**
1. Verify SSO connectivity: `curl https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/certs`
2. Check firewall/proxy settings
3. Temporarily disable verification for testing: `QUIPUCORDS_LIGHTSPEED_JWT_VERIFY_SIGNATURE=false`

### Issue: "JWT algorithm not allowed"

**Symptom**:
```
ERROR: JWT algorithm 'HS256' not allowed. Allowed algorithms: ['RS256', 'RS384', ...]
```

**Cause**: SSO is using an algorithm not in the approved list (e.g., HMAC-based HS256)

**Solution**: This is a security feature. Only asymmetric algorithms (RSA, ECDSA) are allowed for JWT verification. Contact SSO administrator if this occurs.

### Issue: Performance degradation

**Symptom**: Slower authentication times

**Cause**: JWKS fetching adds network overhead on first request

**Solution**: JWKS responses are cached. Subsequent verifications are fast. This is expected and normal.

## Monitoring

### Log Analysis

**Verification disabled (default):**
```
DEBUG: JWT verification disabled - using legacy unsafe decode
```

**Verification enabled and successful:**
```
INFO: JWT signature verified successfully (algorithm: RS256)
```

**Verification failed:**
```
ERROR: JWT verification failed: Signature verification failed
```

## Best Practices

1. **Enable Verification**: Set `QUIPUCORDS_LIGHTSPEED_JWT_VERIFY_SIGNATURE=true` in production
2. **Test Thoroughly**: Verify authentication works in staging before production rollout
3. **Monitor Logs**: Watch for verification failures after enabling
4. **Have Rollback Plan**: Know how to quickly disable if issues arise
5. **Network Access**: Ensure Quipucords can reach sso.redhat.com on HTTPS

## Technical Details

### Dependencies

- **PyJWT**: Industry-standard JWT library for Python
- **cryptography**: RSA/ECDSA signature verification backend
- **requests**: HTTPS communication with SSO server

### Performance

- **First verification**: ~100-300ms (JWKS fetch over network)
- **Subsequent verifications**: ~1-5ms (JWKS cached)
- **Cache duration**: Keys are cached per PyJWT defaults

### Standards Compliance

- [RFC 7519: JSON Web Token (JWT)](https://www.rfc-editor.org/rfc/rfc7519)
- [RFC 7517: JSON Web Key (JWK)](https://www.rfc-editor.org/rfc/rfc7517)
- [RFC 7518: JSON Web Algorithms (JWA)](https://www.rfc-editor.org/rfc/rfc7518)

## FAQ

**Q: Will this break existing deployments?**
A: No. Verification is disabled by default. Existing behavior is preserved.

**Q: What happens if SSO server is down when verification is enabled?**
A: Authentication will fail. This is correct security behavior - if we can't verify the token, we shouldn't accept it.

**Q: Can I verify tokens offline?**
A: No. Signature verification requires fetching public keys from the SSO server's JWKS endpoint.

**Q: Does this protect against quantum computer attacks?**
A: No. RSA and ECDSA will be vulnerable to future quantum computers. This provides current industry-standard security.

## References

- [PyJWT Documentation](https://pyjwt.readthedocs.io/)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [JWT.io](https://jwt.io/) - JWT debugger

---

**Last Updated**: 2026-08-20
**Quipucords Version**: 2.7.0+
