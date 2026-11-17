"""Unit and known-answer tests for the stdlib-only WebAuthn verifier.

The ES256 (P-256) and RS256 (2048-bit RSA) known-answer vectors below were
produced by Node's built-in ``node:crypto`` module with this script:

    import crypto from 'node:crypto';
    const message = Buffer.from(
      'neko-sudo WebAuthn known-answer vector payload: authenticatorData||sha256(clientDataJSON)',
      'utf8',
    );
    const ec = crypto.generateKeyPairSync('ec', {namedCurve: 'prime256v1'});
    const ecJwk = ec.publicKey.export({format: 'jwk'});
    const ecSigDer = crypto.sign('sha256', message, {key: ec.privateKey, dsaEncoding: 'der'});
    const rsa = crypto.generateKeyPairSync('rsa', {modulusLength: 2048, publicExponent: 0x10001});
    const rsaJwk = rsa.publicKey.export({format: 'jwk'});
    const rsaSig = crypto.sign('sha256', message, {
      key: rsa.privateKey,
      padding: crypto.constants.RSA_PKCS1_PADDING,
    });
"""
from __future__ import annotations

import hashlib
import json
import struct
from typing import Any

import pytest

from gate.webauthn import (
    COSE_ALG_ES256,
    COSE_ALG_RS256,
    FLAG_AT,
    FLAG_UP,
    FLAG_UV,
    P256_G,
    P256_N,
    P256_P,
    SHA256_DIGEST_INFO_PREFIX,
    WebAuthnError,
    _p256_mul,
    b64url_decode,
    b64url_encode,
    cbor_decode,
    cbor_decode_from,
    decode_der_ecdsa_signature,
    parse_cose_key,
    verify_assertion,
    verify_es256,
    verify_registration,
    verify_rs256,
)

# -------------------------------------- Node-generated known-answer vectors
KAT_MESSAGE = b'neko-sudo WebAuthn known-answer vector payload: authenticatorData||sha256(clientDataJSON)'

KAT_ES256_PUBLIC_KEY = {
    'kty': 'EC2',
    'crv': 'P-256',
    'x': 'zfId4h4tRJ6WneQU727pEYyuWku57bnY6jc19dvW80E',
    'y': '7PvVnTKx6mEcF6WVW3sdjFFuBO90xrA2qfE6GJAVzws',
}
KAT_ES256_SIG_HEX = (
    '30450221009dc499773587f27bf5067abe51011fa892b1d1b311b99c287b5c8b'
    '4c71490e1e02207fe797a40a04e25e2931386abf8fc0bcb95e4d4af011fb3b4b'
    'c7810e7c347f2f'
)
KAT_ES256_SIG = bytes.fromhex(KAT_ES256_SIG_HEX)

KAT_RS256_PUBLIC_KEY = {
    'kty': 'RSA',
    'n': (
        '2VXc-Hx5AJ3HnlcH5DI1lSRXFV_D44BvUcKWH_PnrzDQw6uGCO0mWsE76zQy1yyhX8Pc'
        'NtOkhEtoNN7LPlLJvV3RcUIrcctbuIoLELXIHHgDKxLjxcBJHzhkN8-fkt9D2kxtPrPc'
        'MXe88TDA91IgC83JamlNLel4Oc0RVZi5qEtEsHVO5vaXSQn-hqxvgCB7ETV4Bk7o4Tid'
        'gDxJRB8B5Y4QwsZTfU7PeLmHV-HIdV19QeMlOon0IIvNq67kL-m966Zkn6qgk7J_zVdg'
        '87hITw8uyMufM3a51A3s5yxkEMNmEhWD49vG4KYDLF2eNorynnB60-ku-YwUz0XI27jE'
        'lQ'
    ),
    'e': 'AQAB',
}
KAT_RS256_SIG = b64url_decode(
    'qnjp8GPIkAKD7e9LbhBRJ8aOzNTA5If9npP895wEXioB98-MrXJfgU8egmDIBvT2mSevOpF-'
    'qQblJm-6YcaitMlfNg98zzBCc86lEL0LmEvRUYPZAQwA84BxOILwv_y-7jVGccmmJ76llm72'
    '2vT4SX4laVuN5HOQyG5u1MOqN08XdjocLsT_eFLckS--DjFOMXZaUUeHeMlrmeMiLgj7L_iU'
    '_uNMqCGUsMnMDQvbUWbfA9Z-glNxASOeWMby2_3Cmyh8H4_wOGqe34dueQa_tAQpMo1Dr25t'
    '6IiDFJphjEQ0U1fwX2I9xpYw7dYlz743f_qAQ0PE8rnywwrmUvYErw'
)


# -------------------------------------------- test-only CBOR + ES256 helpers
def cbor_encode_head(major: int, n: int) -> bytes:
    prefix = major << 5
    if n < 24:
        return bytes([prefix | n])
    if n < 0x100:
        return bytes([prefix | 24, n])
    if n < 0x10000:
        return bytes([prefix | 25]) + n.to_bytes(2, 'big')
    if n < 0x100000000:
        return bytes([prefix | 26]) + n.to_bytes(4, 'big')
    return bytes([prefix | 27]) + n.to_bytes(8, 'big')


def cbor_encode(value: Any) -> bytes:
    if value is False:
        return b'\xf4'
    if value is True:
        return b'\xf5'
    if value is None:
        return b'\xf6'
    if isinstance(value, int):
        if value >= 0:
            return cbor_encode_head(0, value)
        return cbor_encode_head(1, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        raw = bytes(value)
        return cbor_encode_head(2, len(raw)) + raw
    if isinstance(value, str):
        raw = value.encode('utf-8')
        return cbor_encode_head(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return cbor_encode_head(4, len(value)) + b''.join(cbor_encode(x) for x in value)
    if isinstance(value, dict):
        parts = []
        for k, v in value.items():
            parts.append(cbor_encode(k))
            parts.append(cbor_encode(v))
        return cbor_encode_head(5, len(value)) + b''.join(parts)
    raise TypeError(f'unsupported test CBOR type: {type(value)}')


def encode_der_int(n: int) -> bytes:
    length = max(1, (n.bit_length() + 7) // 8)
    raw = n.to_bytes(length, 'big')
    if raw[0] & 0x80:
        raw = b'\x00' + raw
    return b'\x02' + bytes([len(raw)]) + raw


def encode_der_ecdsa_sig(r: int, s: int) -> bytes:
    body = encode_der_int(r) + encode_der_int(s)
    return b'\x30' + bytes([len(body)]) + body


class SyntheticES256Signer:
    """Deterministic test-only P-256 ECDSA signer for WebAuthn ceremony tests."""

    def __init__(self, private_scalar: int = 0x1337CAFE42):
        self.d = private_scalar
        point = _p256_mul(self.d, P256_G)
        assert point is not None
        self.x, self.y = point
        self.x_bytes = self.x.to_bytes(32, 'big')
        self.y_bytes = self.y.to_bytes(32, 'big')

    def cose_map(self) -> dict:
        return {
            1: 2,          # kty: EC2
            3: -7,         # alg: ES256
            -1: 1,         # crv: P-256
            -2: self.x_bytes,
            -3: self.y_bytes,
        }

    def public_key_dict(self) -> dict:
        return {
            'kty': 'EC2',
            'crv': 'P-256',
            'x': b64url_encode(self.x_bytes),
            'y': b64url_encode(self.y_bytes),
        }

    def sign(self, message: bytes, k: int = 0x7F3D9C1E55AA) -> bytes:
        e = int.from_bytes(hashlib.sha256(message).digest(), 'big')
        r_pt = _p256_mul(k, P256_G)
        assert r_pt is not None
        r = r_pt[0] % P256_N
        s = (pow(k, -1, P256_N) * (e + r * self.d)) % P256_N
        return encode_der_ecdsa_sig(r, s)


def build_auth_data(*, rp_id: str = 'localhost', flags: int = FLAG_UP | FLAG_UV,
                    sign_count: int = 1, cred_id: bytes | None = None,
                    cose_key: dict | None = None) -> bytes:
    header = hashlib.sha256(rp_id.encode('utf-8')).digest() + bytes([flags]) + struct.pack('>I', sign_count)
    if cred_id is not None and cose_key is not None:
        aaguid = b'\x00' * 16
        attested = aaguid + struct.pack('>H', len(cred_id)) + cred_id + cbor_encode(cose_key)
        return header + attested
    return header


# ----------------------------------------------------------- base64url tests
class TestBase64Url:
    def test_roundtrip_and_no_padding(self):
        for length in (1, 2, 3, 16, 32, 33, 64):
            raw = bytes(range(length))
            encoded = b64url_encode(raw)
            assert '=' not in encoded
            assert b64url_decode(encoded) == raw

    def test_rejects_padding_bad_chars_and_noncanonical_bits(self):
        for bad in ('', 'abc=', 'ab==', 'a', 'ab+c', 'ab/c', 123, None):
            with pytest.raises(WebAuthnError) as err:
                b64url_decode(bad)
            assert err.value.code == 'invalid_base64url'
        # 'AB' has non-zero trailing padding bits for a 1-byte decode ('AA' is canonical for b'\x00').
        with pytest.raises(WebAuthnError) as err:
            b64url_decode('AB')
        assert err.value.code == 'invalid_base64url'


# ---------------------------------------------------------------- CBOR tests
class TestCborDecoder:
    def test_major_types_and_consumed_length(self):
        sample = {
            1: 2,
            3: -7,
            -1: 1,
            -2: b'\xaa' * 32,
            'fmt': 'none',
            'list': [0, 23, 24, 300, 70000, 1 << 40, -1, -257, True, False, None],
        }
        encoded = cbor_encode(sample)
        decoded, consumed = cbor_decode_from(encoded + b'\x99\x88', 0)
        assert consumed == len(encoded)
        assert decoded == sample
        assert cbor_decode(encoded) == sample

    def test_rejects_trailing_garbage_indefinite_depth_and_duplicate_keys(self):
        with pytest.raises(WebAuthnError) as err:
            cbor_decode(cbor_encode({'a': 1}) + b'\x00')
        assert err.value.code == 'cbor_trailing_bytes'

        # Indefinite-length byte string (0x5f) and array (0x9f)
        for raw in (b'\x5f\x41a\xff', b'\x9f\x01\xff', b'\xbf\x61a\x01\xff'):
            with pytest.raises(WebAuthnError) as err:
                cbor_decode(raw)
            assert err.value.code == 'cbor_indefinite_length'

        # Depth limit exceeded
        deep: Any = 1
        for _ in range(10):
            deep = [deep]
        with pytest.raises(WebAuthnError) as err:
            cbor_decode(cbor_encode(deep), max_depth=8)
        assert err.value.code == 'cbor_depth_exceeded'

        # Duplicate map key: {1: 2, 1: 3}
        dup_map = b'\xa2\x01\x02\x01\x03'
        with pytest.raises(WebAuthnError) as err:
            cbor_decode(dup_map)
        assert err.value.code == 'cbor_duplicate_key'

        # Boolean map key is rejected so True cannot collide with int key 1
        bool_key_map = b'\xa1\xf5\x02'
        with pytest.raises(WebAuthnError) as err:
            cbor_decode(bool_key_map)
        assert err.value.code == 'cbor_invalid_map_key'


# ----------------------------------------------------------- COSE key tests
class TestCoseKeyParsing:
    def test_valid_es256_and_rs256_cose_keys(self):
        ec_map = {
            1: 2,
            3: -7,
            -1: 1,
            -2: b64url_decode(KAT_ES256_PUBLIC_KEY['x']),
            -3: b64url_decode(KAT_ES256_PUBLIC_KEY['y']),
        }
        parsed_ec = parse_cose_key(ec_map)
        assert parsed_ec == {'alg': COSE_ALG_ES256, 'public_key': KAT_ES256_PUBLIC_KEY}

        rsa_map = {
            1: 3,
            3: -257,
            -1: b64url_decode(KAT_RS256_PUBLIC_KEY['n']),
            -2: b64url_decode(KAT_RS256_PUBLIC_KEY['e']),
        }
        parsed_rsa = parse_cose_key(rsa_map)
        assert parsed_rsa == {'alg': COSE_ALG_RS256, 'public_key': KAT_RS256_PUBLIC_KEY}

    def test_rejects_unsupported_alg_off_curve_and_small_rsa(self):
        # Unsupported algorithm (-8 EdDSA)
        with pytest.raises(WebAuthnError) as err:
            parse_cose_key({1: 2, 3: -8, -1: 1, -2: b'\x01' * 32, -3: b'\x02' * 32})
        assert err.value.code == 'unsupported_algorithm'

        # Point not on P-256 curve
        with pytest.raises(WebAuthnError) as err:
            parse_cose_key({1: 2, 3: -7, -1: 1, -2: b'\x01' * 32, -3: b'\x02' * 32})
        assert err.value.code == 'invalid_cose_key'

        # Point at infinity (0, 0)
        with pytest.raises(WebAuthnError) as err:
            parse_cose_key({1: 2, 3: -7, -1: 1, -2: b'\x00' * 32, -3: b'\x00' * 32})
        assert err.value.code == 'invalid_cose_key'

        # Small RSA modulus (1024 bits < 2048 bits)
        small_n = ((1 << 1023) | 1).to_bytes(128, 'big')
        with pytest.raises(WebAuthnError) as err:
            parse_cose_key({1: 3, 3: -257, -1: small_n, -2: b'\x01\x00\x01'})
        assert err.value.code == 'rsa_modulus_too_small'


# ------------------------------------------------ Node known-answer vectors
class TestKnownAnswerVectors:
    def test_node_es256_vector_verifies_and_rejects_mutations(self):
        assert verify_es256(KAT_ES256_PUBLIC_KEY, KAT_MESSAGE, KAT_ES256_SIG) is True

        # Flip 1 bit in signature
        bad_sig = bytearray(KAT_ES256_SIG)
        bad_sig[-1] ^= 0x01
        with pytest.raises(WebAuthnError) as err:
            verify_es256(KAT_ES256_PUBLIC_KEY, KAT_MESSAGE, bytes(bad_sig))
        assert err.value.code == 'signature_invalid'

        # Flip 1 bit in message
        bad_msg = bytearray(KAT_MESSAGE)
        bad_msg[0] ^= 0x01
        with pytest.raises(WebAuthnError) as err:
            verify_es256(KAT_ES256_PUBLIC_KEY, bytes(bad_msg), KAT_ES256_SIG)
        assert err.value.code == 'signature_invalid'

        # Flip 1 bit in public key coordinate (point no longer on curve)
        bad_x = bytearray(b64url_decode(KAT_ES256_PUBLIC_KEY['x']))
        bad_x[-1] ^= 0x01
        bad_key = {**KAT_ES256_PUBLIC_KEY, 'x': b64url_encode(bad_x)}
        with pytest.raises(WebAuthnError) as err:
            verify_es256(bad_key, KAT_MESSAGE, KAT_ES256_SIG)
        assert err.value.code in ('invalid_cose_key', 'signature_invalid')

        # Valid curve point from a different keypair
        other = SyntheticES256Signer()
        with pytest.raises(WebAuthnError) as err:
            verify_es256(other.public_key_dict(), KAT_MESSAGE, KAT_ES256_SIG)
        assert err.value.code == 'signature_invalid'

    def test_es256_der_strictness_zero_r_and_out_of_range_s(self):
        r, s = decode_der_ecdsa_signature(KAT_ES256_SIG)
        assert 1 <= r < P256_N and 1 <= s < P256_N

        for bad_r, bad_s in ((0, s), (P256_N, s), (r, 0), (r, P256_N), (r, P256_N + 5)):
            der = encode_der_ecdsa_sig(bad_r, bad_s)
            with pytest.raises(WebAuthnError) as err:
                verify_es256(KAT_ES256_PUBLIC_KEY, KAT_MESSAGE, der)
            assert err.value.code == 'signature_invalid'

        # Trailing byte after DER SEQUENCE
        with pytest.raises(WebAuthnError) as err:
            decode_der_ecdsa_signature(KAT_ES256_SIG + b'\x00')
        assert err.value.code == 'signature_invalid'

    def test_node_rs256_vector_verifies_and_rejects_mutations(self):
        assert verify_rs256(KAT_RS256_PUBLIC_KEY, KAT_MESSAGE, KAT_RS256_SIG) is True

        # Flip 1 bit in RS256 signature
        bad_sig = bytearray(KAT_RS256_SIG)
        bad_sig[-1] ^= 0x01
        with pytest.raises(WebAuthnError) as err:
            verify_rs256(KAT_RS256_PUBLIC_KEY, KAT_MESSAGE, bytes(bad_sig))
        assert err.value.code == 'signature_invalid'

        # Flip 1 bit in message
        with pytest.raises(WebAuthnError) as err:
            verify_rs256(KAT_RS256_PUBLIC_KEY, KAT_MESSAGE + b'!', KAT_RS256_SIG)
        assert err.value.code == 'signature_invalid'

        # Flip bit in modulus (keep odd)
        bad_n = bytearray(b64url_decode(KAT_RS256_PUBLIC_KEY['n']))
        bad_n[10] ^= 0x02
        with pytest.raises(WebAuthnError) as err:
            verify_rs256({**KAT_RS256_PUBLIC_KEY, 'n': b64url_encode(bad_n)},
                         KAT_MESSAGE, KAT_RS256_SIG)
        assert err.value.code == 'signature_invalid'


# ------------------------------------ registration + assertion ceremonies
class TestCeremonyVerification:
    ORIGIN = 'http://localhost:18765'
    RP_ID = 'localhost'
    CHALLENGE = b64url_encode(b'challenge-bytes-32-for-neko-test')
    CRED_ID = b'credential-id-001'

    def _make_registration(self, *, client_overrides: dict | None = None,
                           fmt: str = 'none', rp_id: str = RP_ID,
                           flags: int = FLAG_UP | FLAG_UV | FLAG_AT,
                           sign_count: int = 0, cose_key: dict | None = None):
        signer = SyntheticES256Signer()
        client_data = {
            'type': 'webauthn.create',
            'challenge': self.CHALLENGE,
            'origin': self.ORIGIN,
            'crossOrigin': False,
            **(client_overrides or {}),
        }
        client_bytes = json.dumps(client_data).encode('utf-8')
        auth_data = build_auth_data(
            rp_id=rp_id,
            flags=flags,
            sign_count=sign_count,
            cred_id=self.CRED_ID,
            cose_key=cose_key if cose_key is not None else signer.cose_map(),
        )
        att_obj = cbor_encode({'fmt': fmt, 'attStmt': {}, 'authData': auth_data})
        return b64url_encode(client_bytes), b64url_encode(att_obj), signer

    def test_verify_registration_happy_path_and_all_failure_codes(self):
        cdj, att, signer = self._make_registration(sign_count=1)
        cred = verify_registration(
            client_data_json=cdj,
            attestation_object=att,
            expected_challenge=self.CHALLENGE,
            expected_origin=self.ORIGIN,
            expected_rp_id=self.RP_ID,
            credential_id=b64url_encode(self.CRED_ID),
        )
        assert cred['id'] == b64url_encode(self.CRED_ID)
        assert cred['alg'] == COSE_ALG_ES256
        assert cred['public_key'] == signer.public_key_dict()
        assert cred['sign_count'] == 1
        assert cred['rp_id'] == self.RP_ID

        cases = [
            ({'client_overrides': {'type': 'webauthn.get'}}, 'invalid_type'),
            ({'client_overrides': {'challenge': b64url_encode(b'wrong' * 6)}}, 'challenge_mismatch'),
            ({'client_overrides': {'origin': 'http://evil.example'}}, 'origin_mismatch'),
            ({'client_overrides': {'crossOrigin': True}}, 'cross_origin'),
            ({'fmt': 'packed'}, 'unsupported_attestation_fmt'),
            ({'rp_id': 'other.example'}, 'rp_id_mismatch'),
            ({'flags': FLAG_UV | FLAG_AT}, 'user_presence_required'),
            ({'flags': FLAG_UP | FLAG_AT}, 'user_verification_required'),
            ({'flags': FLAG_UP | FLAG_UV}, 'missing_attested_credential_data'),
            ({'cose_key': {1: 2, 3: -8, -1: 1, -2: b'\x01' * 32, -3: b'\x02' * 32}}, 'unsupported_algorithm'),
            ({'cose_key': {1: 3, 3: -257, -1: ((1 << 1023) | 1).to_bytes(128, 'big'), -2: b'\x01\x00\x01'}},
             'rsa_modulus_too_small'),
        ]
        for kwargs, expected_code in cases:
            bad_cdj, bad_att, _ = self._make_registration(**kwargs)
            with pytest.raises(WebAuthnError) as err:
                verify_registration(
                    client_data_json=bad_cdj,
                    attestation_object=bad_att,
                    expected_challenge=self.CHALLENGE,
                    expected_origin=self.ORIGIN,
                    expected_rp_id=self.RP_ID,
                )
            assert err.value.code == expected_code

    def test_verify_assertion_happy_path_and_all_failure_codes(self):
        cdj_reg, att_reg, signer = self._make_registration(sign_count=5)
        cred = verify_registration(
            client_data_json=cdj_reg,
            attestation_object=att_reg,
            expected_challenge=self.CHALLENGE,
            expected_origin=self.ORIGIN,
            expected_rp_id=self.RP_ID,
        )

        def make_assertion(*, client_overrides: dict | None = None,
                           rp_id: str = self.RP_ID,
                           flags: int = FLAG_UP | FLAG_UV,
                           sign_count: int = 6,
                           corrupt_sig: bool = False):
            client_data = {
                'type': 'webauthn.get',
                'challenge': self.CHALLENGE,
                'origin': self.ORIGIN,
                **(client_overrides or {}),
            }
            raw_cdj = json.dumps(client_data).encode('utf-8')
            raw_auth = build_auth_data(rp_id=rp_id, flags=flags, sign_count=sign_count)
            sig = bytearray(signer.sign(raw_auth + hashlib.sha256(raw_cdj).digest()))
            if corrupt_sig:
                sig[-1] ^= 0x01
            return b64url_encode(raw_cdj), b64url_encode(raw_auth), b64url_encode(sig)

        cdj_get, auth_get, sig_get = make_assertion(sign_count=6)
        new_count = verify_assertion(
            credential=cred,
            client_data_json=cdj_get,
            authenticator_data=auth_get,
            signature=sig_get,
            expected_challenge=self.CHALLENGE,
            expected_origin=self.ORIGIN,
            expected_rp_id=self.RP_ID,
        )
        assert new_count == 6

        # Both stored=0 and new=0 is allowed (authenticators without a counter).
        cred_zero = {**cred, 'sign_count': 0}
        cdj_z, auth_z, sig_z = make_assertion(sign_count=0)
        assert verify_assertion(
            credential=cred_zero,
            client_data_json=cdj_z,
            authenticator_data=auth_z,
            signature=sig_z,
            expected_challenge=self.CHALLENGE,
            expected_origin=self.ORIGIN,
            expected_rp_id=self.RP_ID,
        ) == 0

        failure_cases = [
            ({'client_overrides': {'type': 'webauthn.create'}}, 'invalid_type'),
            ({'client_overrides': {'challenge': b64url_encode(b'other-challenge-32-bytes-padding')}},
             'challenge_mismatch'),
            ({'client_overrides': {'origin': 'http://127.0.0.1:18765'}}, 'origin_mismatch'),
            ({'client_overrides': {'crossOrigin': True}}, 'cross_origin'),
            ({'rp_id': 'wrong.rp'}, 'rp_id_mismatch'),
            ({'flags': FLAG_UV}, 'user_presence_required'),
            ({'flags': FLAG_UP}, 'user_verification_required'),
            ({'sign_count': 5}, 'sign_count_regressed'),
            ({'sign_count': 4}, 'sign_count_regressed'),
            ({'sign_count': 0}, 'sign_count_regressed'),
            ({'corrupt_sig': True}, 'signature_invalid'),
        ]
        for kwargs, expected_code in failure_cases:
            c_b64, a_b64, s_b64 = make_assertion(**kwargs)
            with pytest.raises(WebAuthnError) as err:
                verify_assertion(
                    credential=cred,
                    client_data_json=c_b64,
                    authenticator_data=a_b64,
                    signature=s_b64,
                    expected_challenge=self.CHALLENGE,
                    expected_origin=self.ORIGIN,
                    expected_rp_id=self.RP_ID,
                )
            assert err.value.code == expected_code

    def test_verify_assertion_with_node_rs256_signature(self):
        # Construct an assertion whose authenticatorData || sha256(clientDataJSON)
        # equals KAT_MESSAGE for direct RS256 verification coverage, and also
        # test verify_assertion routing to RS256.
        cred = {
            'id': b64url_encode(b'rsa-cred-1'),
            'alg': COSE_ALG_RS256,
            'public_key': KAT_RS256_PUBLIC_KEY,
            'sign_count': 1,
            'rp_id': self.RP_ID,
        }
        raw_cdj = json.dumps({
            'type': 'webauthn.get',
            'challenge': self.CHALLENGE,
            'origin': self.ORIGIN,
        }).encode('utf-8')
        raw_auth = build_auth_data(rp_id=self.RP_ID, flags=FLAG_UP | FLAG_UV, sign_count=2)
        with pytest.raises(WebAuthnError) as err:
            verify_assertion(
                credential=cred,
                client_data_json=raw_cdj,
                authenticator_data=raw_auth,
                signature=KAT_RS256_SIG,
                expected_challenge=self.CHALLENGE,
                expected_origin=self.ORIGIN,
                expected_rp_id=self.RP_ID,
            )
        assert err.value.code == 'signature_invalid'
