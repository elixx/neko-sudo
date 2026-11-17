"""Stdlib-only WebAuthn registration and assertion verifier.

Proves passkey ceremonies with zero third-party dependencies. ES256 and
RS256 only, attestation format "none", UV always required.
Implements the exact subset of WebAuthn Level 2 / COSE (RFC 9053) / CBOR
(RFC 8949) needed to gate the console's sign-in and approvals behind a
platform passkey:

* Base64url encoding/decoding without padding and constant-time comparisons
  via :func:`hmac.compare_digest`.
* Definite-length CBOR decoding for major types 0..5 and simple values
  ``false``/``true``/``null``, with bounded nesting depth and trailing-byte
  rejection.
* COSE public key parsing and validation for ES256 (EC2 P-256, kty=2, alg=-7,
  crv=1) and RS256 (RSA PKCS#1 v1.5 with SHA-256, kty=3, alg=-257, modulus
  >= 2048 bits). Everything else is refused.
* Pure-Python ES256 (strict ASN.1 DER signature decoding + P-256 curve math)
  and RS256 (full EMSA-PKCS1-v1_5 rebuild + constant-time compare).
* ``verify_registration`` (``webauthn.create``, ``fmt == 'none'``, UP+UV+AT)
  and ``verify_assertion`` (``webauthn.get``, UP+UV, signature over
  ``authenticatorData || sha256(clientDataJSON)``, sign-counter progression).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from typing import Any, Optional

# --------------------------------------------------------------- P-256 params
# NIST P-256 (secp256r1) domain parameters (FIPS 186-4 / SEC 2).
P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
P256_A = P256_P - 3
P256_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
P256_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
P256_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
P256_G = (P256_GX, P256_GY)

# COSE identifiers
COSE_KTY_EC2 = 2
COSE_KTY_RSA = 3
COSE_ALG_ES256 = -7
COSE_ALG_RS256 = -257
COSE_CRV_P256 = 1

RSA_MIN_MODULUS_BITS = 2048
RSA_MAX_MODULUS_BITS = 8192

# DER DigestInfo prefix for SHA-256 (RFC 8017 Section 9.2):
# SEQUENCE (0x30 0x31) {
#   SEQUENCE (0x30 0x0d) { OID 2.16.840.1.101.3.4.2.1, NULL }
#   OCTET STRING (0x04 0x20) <32-byte hash>
# }
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex('3031300d060960864801650304020105000420')

# Authenticator data flags (WebAuthn Section 6.1)
FLAG_UP = 0x01   # User Present
FLAG_UV = 0x04   # User Verified
FLAG_AT = 0x40   # Attested credential data included
FLAG_ED = 0x80   # Extension data included

_B64URL_RE = re.compile(r'^[A-Za-z0-9_-]+$')
_CBOR_MAX_COLLECTION_LEN = 65536


class WebAuthnError(ValueError):
    """WebAuthn decoding or verification failure; ``code`` is a machine reason."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# ----------------------------------------------------------- base64url + hmac
def b64url_encode(data: bytes | bytearray) -> str:
    """Encode bytes to unpadded base64url ASCII string."""
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError('b64url_encode expects bytes')
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b'=').decode('ascii')


def b64url_decode(value: Any, *, field: str = 'value', allow_empty: bool = False) -> bytes:
    """Strictly decode an unpadded base64url string to bytes."""
    if not isinstance(value, str):
        raise WebAuthnError('invalid_base64url', f'{field} must be a base64url string')
    if value == '':
        if allow_empty:
            return b''
        raise WebAuthnError('invalid_base64url', f'{field} must not be empty')
    if '=' in value or not _B64URL_RE.fullmatch(value) or len(value) % 4 == 1:
        raise WebAuthnError('invalid_base64url', f'{field} is not valid unpadded base64url')
    padded = value + ('=' * (-len(value) % 4))
    try:
        raw = base64.urlsafe_b64decode(padded.encode('ascii'))
    except Exception as exc:
        raise WebAuthnError('invalid_base64url', f'{field} failed base64url decode') from exc
    # Reject non-canonical trailing padding bits.
    if b64url_encode(raw) != value:
        raise WebAuthnError('invalid_base64url', f'{field} has non-canonical base64url padding bits')
    return raw


def _as_bytes(value: Any, *, field: str) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    return b64url_decode(value, field=field)


def ct_equal(a: str | bytes, b: str | bytes) -> bool:
    """Constant-time equality check via hmac.compare_digest."""
    if type(a) is not type(b):
        return False
    return hmac.compare_digest(a, b)


# --------------------------------------------------------------- CBOR decoder
def _cbor_read_uint(data: bytes, offset: int, ai: int) -> tuple[int, int]:
    """Read definite-length CBOR argument; return ``(value, new_offset)``."""
    if ai < 24:
        return ai, offset
    if ai == 24:
        if offset + 1 > len(data):
            raise WebAuthnError('cbor_truncated', 'CBOR 1-byte uint truncated')
        return data[offset], offset + 1
    if ai == 25:
        if offset + 2 > len(data):
            raise WebAuthnError('cbor_truncated', 'CBOR 2-byte uint truncated')
        return int.from_bytes(data[offset:offset + 2], 'big'), offset + 2
    if ai == 26:
        if offset + 4 > len(data):
            raise WebAuthnError('cbor_truncated', 'CBOR 4-byte uint truncated')
        return int.from_bytes(data[offset:offset + 4], 'big'), offset + 4
    if ai == 27:
        if offset + 8 > len(data):
            raise WebAuthnError('cbor_truncated', 'CBOR 8-byte uint truncated')
        return int.from_bytes(data[offset:offset + 8], 'big'), offset + 8
    if ai == 31:
        raise WebAuthnError('cbor_indefinite_length', 'CBOR indefinite lengths are not allowed')
    raise WebAuthnError('cbor_invalid', f'CBOR reserved additional info {ai}')


def _cbor_decode_item(data: bytes, offset: int, depth: int, max_depth: int) -> tuple[Any, int]:
    if depth > max_depth:
        raise WebAuthnError('cbor_depth_exceeded', f'CBOR nesting depth exceeds {max_depth}')
    if offset >= len(data):
        raise WebAuthnError('cbor_truncated', 'unexpected end of CBOR input')
    initial = data[offset]
    major = initial >> 5
    ai = initial & 0x1f
    pos = offset + 1

    if major == 0:
        val, pos = _cbor_read_uint(data, pos, ai)
        return val, pos
    if major == 1:
        val, pos = _cbor_read_uint(data, pos, ai)
        return -1 - val, pos
    if major == 2:
        length, pos = _cbor_read_uint(data, pos, ai)
        if pos + length > len(data):
            raise WebAuthnError('cbor_truncated', 'CBOR byte string truncated')
        return data[pos:pos + length], pos + length
    if major == 3:
        length, pos = _cbor_read_uint(data, pos, ai)
        if pos + length > len(data):
            raise WebAuthnError('cbor_truncated', 'CBOR text string truncated')
        raw = data[pos:pos + length]
        try:
            text = raw.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise WebAuthnError('cbor_invalid_utf8', 'CBOR text string is not valid UTF-8') from exc
        return text, pos + length
    if major == 4:
        count, pos = _cbor_read_uint(data, pos, ai)
        if count > _CBOR_MAX_COLLECTION_LEN:
            raise WebAuthnError('cbor_invalid', 'CBOR array length exceeds maximum')
        items = []
        for _ in range(count):
            item, pos = _cbor_decode_item(data, pos, depth + 1, max_depth)
            items.append(item)
        return items, pos
    if major == 5:
        count, pos = _cbor_read_uint(data, pos, ai)
        if count > _CBOR_MAX_COLLECTION_LEN:
            raise WebAuthnError('cbor_invalid', 'CBOR map length exceeds maximum')
        mapping: dict[Any, Any] = {}
        seen_keys: set[tuple[type, Any]] = set()
        for _ in range(count):
            key, pos = _cbor_decode_item(data, pos, depth + 1, max_depth)
            if isinstance(key, (list, dict, bool)) or not isinstance(key, (int, str, bytes)):
                raise WebAuthnError('cbor_invalid_map_key', f'unsupported CBOR map key type: {type(key).__name__}')
            typed_key = (type(key), key)
            if typed_key in seen_keys:
                raise WebAuthnError('cbor_duplicate_key', f'duplicate CBOR map key: {key!r}')
            seen_keys.add(typed_key)
            val, pos = _cbor_decode_item(data, pos, depth + 1, max_depth)
            mapping[key] = val
        return mapping, pos
    if major == 7:
        if ai == 20:
            return False, pos
        if ai == 21:
            return True, pos
        if ai == 22:
            return None, pos
        raise WebAuthnError('cbor_unsupported', f'unsupported CBOR simple/float value (ai={ai})')
    raise WebAuthnError('cbor_unsupported', f'unsupported CBOR major type {major}')


def cbor_decode_from(data: bytes, offset: int = 0, *, max_depth: int = 8) -> tuple[Any, int]:
    """Decode one CBOR item starting at ``offset``.

    Returns ``(value, consumed_length)`` where ``consumed_length`` is the
    number of bytes read from ``offset``.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise WebAuthnError('cbor_invalid', 'CBOR input must be bytes')
    raw = bytes(data)
    if offset < 0 or offset >= len(raw):
        raise WebAuthnError('cbor_truncated', 'CBOR offset out of range')
    value, end = _cbor_decode_item(raw, offset, 0, max_depth)
    return value, end - offset


def cbor_decode(data: bytes, *, max_depth: int = 8) -> Any:
    """Decode one complete CBOR item and reject any trailing garbage."""
    if not isinstance(data, (bytes, bytearray)):
        raise WebAuthnError('cbor_invalid', 'CBOR input must be bytes')
    raw = bytes(data)
    value, consumed = cbor_decode_from(raw, 0, max_depth=max_depth)
    if consumed != len(raw):
        raise WebAuthnError('cbor_trailing_bytes',
                            f'CBOR trailing garbage ({len(raw) - consumed} extra bytes)')
    return value


# ----------------------------------------------------------- P-256 curve math
def _p256_is_on_curve(x: int, y: int) -> bool:
    if not (0 <= x < P256_P and 0 <= y < P256_P):
        return False
    if x == 0 and y == 0:
        return False
    lhs = (y * y) % P256_P
    rhs = (pow(x, 3, P256_P) + P256_A * x + P256_B) % P256_P
    return lhs == rhs


def _p256_add(p1: Optional[tuple[int, int]], p2: Optional[tuple[int, int]]) -> Optional[tuple[int, int]]:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P256_P == 0:
            return None
        num = (3 * x1 * x1 + P256_A) % P256_P
        den = (2 * y1) % P256_P
    else:
        num = (y2 - y1) % P256_P
        den = (x2 - x1) % P256_P
    slope = (num * pow(den, -1, P256_P)) % P256_P
    x3 = (slope * slope - x1 - x2) % P256_P
    y3 = (slope * (x1 - x3) - y1) % P256_P
    return (x3, y3)


def _p256_mul(k: int, point: Optional[tuple[int, int]]) -> Optional[tuple[int, int]]:
    if k <= 0 or point is None:
        return None
    result: Optional[tuple[int, int]] = None
    addend: Optional[tuple[int, int]] = point
    while k:
        if k & 1:
            result = _p256_add(result, addend)
        addend = _p256_add(addend, addend)
        k >>= 1
    return result


# ----------------------------------------------------------- COSE key parsing
def parse_cose_key(cose_key: Any) -> dict:
    """Parse and validate a COSE_Key map (ES256 P-256 or RS256 >= 2048-bit).

    Returns ``{'alg': -7|-257, 'public_key': {...}}`` ready for storage.
    """
    if not isinstance(cose_key, dict):
        raise WebAuthnError('invalid_cose_key', 'COSE key must be a CBOR map')
    kty = cose_key.get(1)
    alg = cose_key.get(3)
    if isinstance(kty, bool) or not isinstance(kty, int):
        raise WebAuthnError('invalid_cose_key', 'COSE key missing integer kty (1)')
    if isinstance(alg, bool) or not isinstance(alg, int):
        raise WebAuthnError('invalid_cose_key', 'COSE key missing integer alg (3)')
    if alg not in (COSE_ALG_ES256, COSE_ALG_RS256):
        raise WebAuthnError('unsupported_algorithm', f'unsupported COSE algorithm: {alg}')

    if alg == COSE_ALG_ES256:
        if kty != COSE_KTY_EC2:
            raise WebAuthnError('invalid_cose_key', f'ES256 requires EC2 kty (2), got {kty}')
        crv = cose_key.get(-1)
        if isinstance(crv, bool) or crv != COSE_CRV_P256:
            raise WebAuthnError('invalid_cose_key', f'ES256 requires P-256 curve (crv=1), got {crv!r}')
        x = cose_key.get(-2)
        y = cose_key.get(-3)
        if not isinstance(x, bytes) or not isinstance(y, bytes) or len(x) != 32 or len(y) != 32:
            raise WebAuthnError('invalid_cose_key', 'P-256 public key x and y must be 32-byte byte strings')
        x_int = int.from_bytes(x, 'big')
        y_int = int.from_bytes(y, 'big')
        if not _p256_is_on_curve(x_int, y_int):
            raise WebAuthnError('invalid_cose_key', 'EC2 public key point is not on the P-256 curve')
        return {
            'alg': COSE_ALG_ES256,
            'public_key': {
                'kty': 'EC2',
                'crv': 'P-256',
                'x': b64url_encode(x),
                'y': b64url_encode(y),
            },
        }

    # alg == COSE_ALG_RS256
    if kty != COSE_KTY_RSA:
        raise WebAuthnError('invalid_cose_key', f'RS256 requires RSA kty (3), got {kty}')
    n = cose_key.get(-1)
    e = cose_key.get(-2)
    if not isinstance(n, bytes) or not isinstance(e, bytes) or not n or not e:
        raise WebAuthnError('invalid_cose_key', 'RSA public key n and e must be non-empty byte strings')
    n_int = int.from_bytes(n, 'big')
    e_int = int.from_bytes(e, 'big')
    if n_int.bit_length() < RSA_MIN_MODULUS_BITS:
        raise WebAuthnError('rsa_modulus_too_small',
                            f'RSA modulus must be at least {RSA_MIN_MODULUS_BITS} bits, '
                            f'got {n_int.bit_length()}')
    if n_int.bit_length() > RSA_MAX_MODULUS_BITS or n_int % 2 == 0:
        raise WebAuthnError('invalid_cose_key', 'RSA modulus is invalid')
    if e_int < 3 or e_int % 2 == 0 or e_int >= n_int:
        raise WebAuthnError('invalid_cose_key', 'RSA public exponent is invalid')
    n_canon = n_int.to_bytes((n_int.bit_length() + 7) // 8, 'big')
    e_canon = e_int.to_bytes((e_int.bit_length() + 7) // 8, 'big')
    return {
        'alg': COSE_ALG_RS256,
        'public_key': {
            'kty': 'RSA',
            'n': b64url_encode(n_canon),
            'e': b64url_encode(e_canon),
        },
    }


# ----------------------------------------------------- signature verification
def decode_der_ecdsa_signature(signature: bytes) -> tuple[int, int]:
    """Strictly decode a DER-encoded ECDSA signature ``SEQUENCE { r, s }``."""
    if not isinstance(signature, (bytes, bytearray)) or len(signature) < 8 or len(signature) > 72:
        raise WebAuthnError('signature_invalid', 'invalid DER ECDSA signature length')
    data = bytes(signature)
    if data[0] != 0x30:
        raise WebAuthnError('signature_invalid', 'DER signature must start with SEQUENCE (0x30)')
    seq_len = data[1]
    if (seq_len & 0x80) != 0 or 2 + seq_len != len(data):
        raise WebAuthnError('signature_invalid', 'DER SEQUENCE length mismatch')
    offset = 2
    scalars = []
    for _ in range(2):
        if offset + 2 > len(data) or data[offset] != 0x02:
            raise WebAuthnError('signature_invalid', 'DER INTEGER tag (0x02) expected')
        int_len = data[offset + 1]
        offset += 2
        if int_len < 1 or int_len > 33 or offset + int_len > len(data):
            raise WebAuthnError('signature_invalid', 'invalid DER INTEGER length')
        raw = data[offset:offset + int_len]
        offset += int_len
        if raw[0] & 0x80:
            raise WebAuthnError('signature_invalid', 'DER INTEGER must not be negative')
        if len(raw) > 1 and raw[0] == 0x00 and not (raw[1] & 0x80):
            raise WebAuthnError('signature_invalid', 'DER INTEGER has non-minimal leading zero')
        value = int.from_bytes(raw, 'big')
        if not 1 <= value < P256_N:
            raise WebAuthnError('signature_invalid', 'ECDSA scalar out of range [1, n-1]')
        scalars.append(value)
    if offset != len(data):
        raise WebAuthnError('signature_invalid', 'DER SEQUENCE contains trailing bytes')
    return scalars[0], scalars[1]


def verify_es256(public_key: dict, message: bytes, signature: bytes) -> bool:
    """Verify an ES256 (ECDSA P-256 with SHA-256) DER signature.

    Raises :class:`WebAuthnError` on malformed keys/signatures or mismatch.
    """
    if not isinstance(public_key, dict) or public_key.get('kty') != 'EC2' or public_key.get('crv') != 'P-256':
        raise WebAuthnError('invalid_cose_key', 'ES256 requires a P-256 EC2 public key')
    x_bytes = _as_bytes(public_key.get('x'), field='public_key.x')
    y_bytes = _as_bytes(public_key.get('y'), field='public_key.y')
    if len(x_bytes) != 32 or len(y_bytes) != 32:
        raise WebAuthnError('invalid_cose_key', 'P-256 coordinates must be 32 bytes')
    qx = int.from_bytes(x_bytes, 'big')
    qy = int.from_bytes(y_bytes, 'big')
    if not _p256_is_on_curve(qx, qy):
        raise WebAuthnError('invalid_cose_key', 'EC2 public key point is not on the P-256 curve')
    r, s = decode_der_ecdsa_signature(signature)
    e = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    w = pow(s, -1, P256_N)
    u1 = (e * w) % P256_N
    u2 = (r * w) % P256_N
    point = _p256_add(_p256_mul(u1, P256_G), _p256_mul(u2, (qx, qy)))
    if point is None or (point[0] % P256_N) != r:
        raise WebAuthnError('signature_invalid', 'ES256 signature verification failed')
    return True


def verify_rs256(public_key: dict, message: bytes, signature: bytes) -> bool:
    """Verify an RS256 (RSASSA-PKCS1-v1_5 with SHA-256) signature.

    Raises :class:`WebAuthnError` on malformed keys/signatures or mismatch.
    """
    if not isinstance(public_key, dict) or public_key.get('kty') != 'RSA':
        raise WebAuthnError('invalid_cose_key', 'RS256 requires an RSA public key')
    n_bytes = _as_bytes(public_key.get('n'), field='public_key.n')
    e_bytes = _as_bytes(public_key.get('e'), field='public_key.e')
    if not n_bytes or not e_bytes:
        raise WebAuthnError('invalid_cose_key', 'RSA public key missing modulus or exponent')
    n_int = int.from_bytes(n_bytes, 'big')
    e_int = int.from_bytes(e_bytes, 'big')
    if n_int.bit_length() < RSA_MIN_MODULUS_BITS:
        raise WebAuthnError('rsa_modulus_too_small',
                            f'RSA modulus must be at least {RSA_MIN_MODULUS_BITS} bits')
    if n_int.bit_length() > RSA_MAX_MODULUS_BITS or n_int % 2 == 0:
        raise WebAuthnError('invalid_cose_key', 'RSA modulus is invalid')
    if e_int < 3 or e_int % 2 == 0 or e_int >= n_int:
        raise WebAuthnError('invalid_cose_key', 'RSA public exponent is invalid')
    k = (n_int.bit_length() + 7) // 8
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != k:
        raise WebAuthnError('signature_invalid', 'RS256 signature length does not match modulus')
    s_int = int.from_bytes(signature, 'big')
    if s_int >= n_int:
        raise WebAuthnError('signature_invalid', 'RS256 signature representative out of range')
    m_int = pow(s_int, e_int, n_int)
    em = m_int.to_bytes(k, 'big')
    digest_info = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
    ps_len = k - len(digest_info) - 3
    if ps_len < 8:
        raise WebAuthnError('rsa_modulus_too_small', 'RSA modulus too short for EMSA-PKCS1-v1_5')
    expected_em = b'\x00\x01' + (b'\xff' * ps_len) + b'\x00' + digest_info
    if not hmac.compare_digest(em, expected_em):
        raise WebAuthnError('signature_invalid', 'RS256 signature verification failed')
    return True


# -------------------------------------------- clientDataJSON + authData helpers
def _verify_client_data(raw_client_data: bytes, *, expected_type: str,
                        expected_challenge_b64: str, expected_origin: str) -> dict:
    try:
        text = raw_client_data.decode('utf-8')
        data = json.loads(text)
    except (UnicodeDecodeError, ValueError) as exc:
        raise WebAuthnError('invalid_client_data', 'clientDataJSON is not valid UTF-8 JSON') from exc
    if not isinstance(data, dict):
        raise WebAuthnError('invalid_client_data', 'clientDataJSON must be a JSON object')
    actual_type = data.get('type')
    if not isinstance(actual_type, str) or not ct_equal(actual_type, expected_type):
        raise WebAuthnError('invalid_type',
                            f'clientDataJSON type must be {expected_type!r}, got {actual_type!r}')
    challenge = data.get('challenge')
    if not isinstance(challenge, str):
        raise WebAuthnError('challenge_mismatch', 'clientDataJSON challenge must be a string')
    try:
        challenge_bytes = b64url_decode(challenge, field='clientDataJSON.challenge')
        expected_bytes = b64url_decode(expected_challenge_b64, field='expected_challenge')
    except WebAuthnError as exc:
        raise WebAuthnError('challenge_mismatch', str(exc)) from exc
    if not hmac.compare_digest(challenge_bytes, expected_bytes):
        raise WebAuthnError('challenge_mismatch', 'clientDataJSON challenge does not match')
    origin = data.get('origin')
    if not isinstance(origin, str) or not ct_equal(origin, expected_origin):
        raise WebAuthnError('origin_mismatch',
                            f'clientDataJSON origin {origin!r} does not match {expected_origin!r}')
    cross_origin = data.get('crossOrigin', False)
    if cross_origin is not False:
        raise WebAuthnError('cross_origin', 'cross-origin WebAuthn ceremonies are not permitted')
    return data


def _verify_auth_data_header(auth_data: bytes, *, expected_rp_id: str,
                             require_at: bool = False) -> tuple[int, int]:
    if not isinstance(auth_data, (bytes, bytearray)) or len(auth_data) < 37:
        raise WebAuthnError('invalid_auth_data', 'authenticatorData must be at least 37 bytes')
    rp_id_hash = bytes(auth_data[:32])
    expected_hash = hashlib.sha256(expected_rp_id.encode('utf-8')).digest()
    if not hmac.compare_digest(rp_id_hash, expected_hash):
        raise WebAuthnError('rp_id_mismatch', 'authenticatorData rpIdHash does not match rp_id')
    flags = auth_data[32]
    if not (flags & FLAG_UP):
        raise WebAuthnError('user_presence_required', 'authenticatorData UP flag (0x01) is not set')
    if not (flags & FLAG_UV):
        raise WebAuthnError('user_verification_required', 'authenticatorData UV flag (0x04) is not set')
    if require_at and not (flags & FLAG_AT):
        raise WebAuthnError('missing_attested_credential_data',
                            'authenticatorData AT flag (0x40) is not set')
    sign_count = int.from_bytes(auth_data[33:37], 'big')
    return flags, sign_count


# ------------------------------------------- registration + assertion ceremonies
def verify_registration(*, client_data_json: str | bytes,
                        attestation_object: str | bytes,
                        expected_challenge: str | bytes,
                        expected_origin: str,
                        expected_rp_id: str,
                        credential_id: Optional[str] = None) -> dict:
    """Verify a ``navigator.credentials.create`` response.

    Returns a stored-credential dict:
    ``{'id': <b64url>, 'alg': -7|-257, 'public_key': {...}, 'sign_count': int, 'rp_id': str}``.
    """
    if not isinstance(expected_origin, str) or not expected_origin:
        raise WebAuthnError('origin_mismatch', 'expected_origin must be a non-empty string')
    if not isinstance(expected_rp_id, str) or not expected_rp_id:
        raise WebAuthnError('rp_id_mismatch', 'expected_rp_id must be a non-empty string')
    raw_client_data = _as_bytes(client_data_json, field='client_data_json')
    raw_attestation = _as_bytes(attestation_object, field='attestation_object')
    challenge_b64 = (b64url_encode(expected_challenge)
                     if isinstance(expected_challenge, (bytes, bytearray))
                     else expected_challenge)

    _verify_client_data(raw_client_data, expected_type='webauthn.create',
                        expected_challenge_b64=challenge_b64,
                        expected_origin=expected_origin)

    att_obj = cbor_decode(raw_attestation)
    if not isinstance(att_obj, dict):
        raise WebAuthnError('invalid_attestation', 'attestationObject must be a CBOR map')
    fmt = att_obj.get('fmt')
    if fmt != 'none':
        raise WebAuthnError('unsupported_attestation_fmt',
                            f"attestation format must be 'none', got {fmt!r}")
    att_stmt = att_obj.get('attStmt')
    if not isinstance(att_stmt, dict) or att_stmt:
        raise WebAuthnError('invalid_attestation', "none attestation requires an empty attStmt map")
    auth_data = att_obj.get('authData')
    if not isinstance(auth_data, bytes):
        raise WebAuthnError('invalid_auth_data', 'attestationObject authData must be a byte string')

    flags, sign_count = _verify_auth_data_header(
        auth_data, expected_rp_id=expected_rp_id, require_at=True)

    # Attested credential data: 16-byte aaguid + 2-byte credIdLen + credId + COSE_Key
    if len(auth_data) < 55:
        raise WebAuthnError('invalid_auth_data', 'attestedCredentialData header truncated')
    cred_id_len = int.from_bytes(auth_data[53:55], 'big')
    if cred_id_len < 1 or cred_id_len > 1023 or 55 + cred_id_len >= len(auth_data):
        raise WebAuthnError('invalid_auth_data', 'credentialId length out of range')
    raw_cred_id = auth_data[55:55 + cred_id_len]
    cred_id_b64 = b64url_encode(raw_cred_id)
    if credential_id is not None:
        supplied_raw = _as_bytes(credential_id, field='credential_id')
        if not hmac.compare_digest(raw_cred_id, supplied_raw):
            raise WebAuthnError('credential_id_mismatch',
                                'credential_id does not match authenticatorData credentialId')

    offset = 55 + cred_id_len
    cose_map, consumed = cbor_decode_from(auth_data, offset)
    offset += consumed
    if flags & FLAG_ED:
        if offset >= len(auth_data):
            raise WebAuthnError('invalid_auth_data', 'ED flag set but extension data missing')
        ext_map, ext_consumed = cbor_decode_from(auth_data, offset)
        if not isinstance(ext_map, dict):
            raise WebAuthnError('invalid_auth_data', 'authenticatorData extensions must be a CBOR map')
        offset += ext_consumed
    if offset != len(auth_data):
        raise WebAuthnError('cbor_trailing_bytes', 'trailing bytes in authenticatorData')

    parsed_key = parse_cose_key(cose_map)
    return {
        'id': cred_id_b64,
        'alg': parsed_key['alg'],
        'public_key': parsed_key['public_key'],
        'sign_count': sign_count,
        'rp_id': expected_rp_id,
    }


def verify_assertion(*, credential: dict,
                     client_data_json: str | bytes,
                     authenticator_data: str | bytes,
                     signature: str | bytes,
                     expected_challenge: str | bytes,
                     expected_origin: str,
                     expected_rp_id: str) -> int:
    """Verify a ``navigator.credentials.get`` assertion against a stored credential.

    Returns the new ``sign_count`` (int).
    """
    if not isinstance(credential, dict):
        raise WebAuthnError('unknown_credential', 'credential must be a dict')
    if not isinstance(expected_origin, str) or not expected_origin:
        raise WebAuthnError('origin_mismatch', 'expected_origin must be a non-empty string')
    if not isinstance(expected_rp_id, str) or not expected_rp_id:
        raise WebAuthnError('rp_id_mismatch', 'expected_rp_id must be a non-empty string')
    cred_rp_id = credential.get('rp_id')
    if not isinstance(cred_rp_id, str) or not ct_equal(cred_rp_id, expected_rp_id):
        raise WebAuthnError('rp_id_mismatch', 'credential rp_id does not match expected_rp_id')

    raw_client_data = _as_bytes(client_data_json, field='client_data_json')
    raw_auth_data = _as_bytes(authenticator_data, field='authenticator_data')
    raw_signature = _as_bytes(signature, field='signature')
    challenge_b64 = (b64url_encode(expected_challenge)
                     if isinstance(expected_challenge, (bytes, bytearray))
                     else expected_challenge)

    _verify_client_data(raw_client_data, expected_type='webauthn.get',
                        expected_challenge_b64=challenge_b64,
                        expected_origin=expected_origin)

    _flags, new_sign_count = _verify_auth_data_header(
        raw_auth_data, expected_rp_id=expected_rp_id, require_at=False)

    signed_data = raw_auth_data + hashlib.sha256(raw_client_data).digest()
    alg = credential.get('alg')
    pub = credential.get('public_key')
    if alg == COSE_ALG_ES256:
        verify_es256(pub, signed_data, raw_signature)
    elif alg == COSE_ALG_RS256:
        verify_rs256(pub, signed_data, raw_signature)
    else:
        raise WebAuthnError('unsupported_algorithm', f'unsupported credential algorithm: {alg!r}')

    stored_sign_count = int(credential.get('sign_count', 0) or 0)
    if (stored_sign_count > 0 or new_sign_count > 0) and new_sign_count <= stored_sign_count:
        raise WebAuthnError('sign_count_regressed',
                            f'authenticator sign_count did not advance '
                            f'(stored={stored_sign_count}, received={new_sign_count})')
    return new_sign_count
