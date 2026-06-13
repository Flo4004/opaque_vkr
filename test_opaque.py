"""End-to-end test for OPAQUE split architecture (no MongoDB, no JS)."""

import base64
import hashlib
import hmac as hm
import os
import struct

import p256
import opaque_core as oc
from kdf import hkdf_expand, hkdf_extract, pbkdf2_sha256


def test_full_flow():
    srv = oc.OPAQUEServer()
    cred_id = "testuser"
    password = b"secret123"

    # ── CLIENT: OPRF Blind ──
    pwd_h = hashlib.sha256(b"OPRF-HashToScalar-" + password).digest()
    pwd_scalar = (int.from_bytes(pwd_h, "big") % (oc.P256_ORDER - 1)) + 1
    blind = p256.generate_private_key()
    blinded = (blind * pwd_scalar) % oc.P256_ORDER
    blinded_b64 = base64.b64encode(blinded.to_bytes(32, "big")).decode()

    # ── SERVER: registration_init ──
    resp = srv.registration_init(cred_id, blinded_b64)
    assert "evaluated_element" in resp
    assert "server_public_key" in resp
    print("[OK] registration_init")

    # ── CLIENT: OPRF Finalize ──
    evaluated = int.from_bytes(base64.b64decode(resp["evaluated_element"]), "big")
    blind_inv = pow(blind, oc.P256_ORDER - 2, oc.P256_ORDER)
    result = (evaluated * blind_inv) % oc.P256_ORDER
    oprf_out = hashlib.sha256(b"OPRF-Finalize-" + password + result.to_bytes(32, "big")).digest()

    rwd = pbkdf2_sha256(oprf_out, salt=b"\x00" * 16, iterations=10_000)

    # ── CLIENT: Create Envelope ──
    nonce = os.urandom(32)
    masking_key = hkdf_expand(rwd, b"MaskingKey", 32)
    auth_key = hkdf_expand(rwd, nonce + b"AuthKey", 32)
    seed = hkdf_expand(rwd, nonce + b"PrivateKey", 32)
    client_sk = (int.from_bytes(seed, "big") % (oc.P256_ORDER - 1)) + 1
    client_pk = p256.encode_point(p256.public_key_from_private(client_sk))
    server_pk = base64.b64decode(resp["server_public_key"])
    cleartext = (server_pk + struct.pack(">H", len(server_pk)) + server_pk
                 + struct.pack(">H", len(client_pk)) + client_pk)
    mac = hm.new(auth_key, nonce + cleartext, hashlib.sha256).digest()
    envelope = nonce + mac

    record = {
        "client_public_key": base64.b64encode(client_pk).decode(),
        "masking_key": base64.b64encode(masking_key).decode(),
        "envelope": base64.b64encode(envelope).decode(),
    }
    rec = oc.OPAQUEServer.registration_record(record)
    print("[OK] registration_finish (envelope created)")

    # ═══════ LOGIN ═══════

    # ── CLIENT: KE1 (re-blind + ephemeral) ──
    blind2 = p256.generate_private_key()
    blinded2 = (blind2 * pwd_scalar) % oc.P256_ORDER
    eph_sk = p256.generate_private_key()
    eph_pk = p256.public_key_from_private(eph_sk)
    client_nonce = os.urandom(32)

    ke1 = {
        "blinded_element": base64.b64encode(blinded2.to_bytes(32, "big")).decode(),
        "client_nonce": base64.b64encode(client_nonce).decode(),
        "client_public_keyshare": base64.b64encode(p256.encode_point(eph_pk)).decode(),
    }

    # ── SERVER: login_init → KE2 ──
    ke2 = srv.login_init(cred_id, rec, ke1)
    assert "server_mac" in ke2
    print("[OK] login_init (KE2)")

    # ── CLIENT: Process KE2, derive keys ──
    eval2 = int.from_bytes(base64.b64decode(ke2["evaluated_element"]), "big")
    blind2_inv = pow(blind2, oc.P256_ORDER - 2, oc.P256_ORDER)
    result2 = (eval2 * blind2_inv) % oc.P256_ORDER
    oprf_out2 = hashlib.sha256(b"OPRF-Finalize-" + password + result2.to_bytes(32, "big")).digest()
    rwd2 = pbkdf2_sha256(oprf_out2, salt=b"\x00" * 16, iterations=10_000)

    # Demask
    masking_key2 = hkdf_expand(rwd2, b"MaskingKey", 32)
    masking_nonce = base64.b64decode(ke2["masking_nonce"])
    masked_response = base64.b64decode(ke2["masked_response"])
    pad = hkdf_expand(masking_key2, masking_nonce + b"CredentialResponsePad", len(masked_response))
    cred_data = bytes(a ^ b for a, b in zip(masked_response, pad))
    client_pk_rec = cred_data[:65]
    envelope_rec = cred_data[65:]

    # Recover envelope
    env_nonce = envelope_rec[:32]
    env_mac = envelope_rec[32:64]
    auth_key2 = hkdf_expand(rwd2, env_nonce + b"AuthKey", 32)
    seed2 = hkdf_expand(rwd2, env_nonce + b"PrivateKey", 32)
    client_sk2 = (int.from_bytes(seed2, "big") % (oc.P256_ORDER - 1)) + 1
    client_pk2 = p256.encode_point(p256.public_key_from_private(client_sk2))
    cleartext2 = (server_pk + struct.pack(">H", len(server_pk)) + server_pk
                  + struct.pack(">H", len(client_pk2)) + client_pk2)
    expected_mac = hm.new(auth_key2, env_nonce + cleartext2, hashlib.sha256).digest()
    assert hm.compare_digest(env_mac, expected_mac), "Envelope MAC mismatch!"
    print("[OK] envelope recovered")

    # 3DH client side
    server_static_pk = p256.decode_point(server_pk)
    server_eph_pk = p256.decode_point(base64.b64decode(ke2["server_public_keyshare"]))
    dh1 = p256.ecdh(eph_sk, server_static_pk)
    dh2 = p256.ecdh(client_sk2, server_eph_pk)
    dh3 = p256.ecdh(eph_sk, server_eph_pk)

    preamble = b"OPAQUE-VKR-v1" + cred_id.encode()
    ikm = dh1 + dh2 + dh3
    prk = hkdf_extract(b"", ikm)
    session_key = hkdf_expand(prk, preamble + b"SessionKey", 32)
    hs = hkdf_expand(prk, preamble + b"HandshakeSecret", 32)
    smk = hkdf_expand(hs, b"ServerMAC", 32)
    cmk = hkdf_expand(hs, b"ClientMAC", 32)

    # Verify server MAC
    transcript = hashlib.sha256(preamble).digest()
    expected_smac = hm.new(smk, transcript, hashlib.sha256).digest()
    server_mac = base64.b64decode(ke2["server_mac"])
    assert hm.compare_digest(server_mac, expected_smac), "Server MAC mismatch!"
    print("[OK] server MAC verified")

    # Client MAC
    client_mac = hm.new(cmk, hashlib.sha256(preamble + server_mac).digest(), hashlib.sha256).digest()

    # Schnorr ZKP
    s = int.from_bytes(session_key, "big")
    S = p256.scalar_mult(s, p256.G)
    r = p256.generate_private_key()
    R = p256.scalar_mult(r, p256.G)
    c_bytes = hashlib.sha256(
        p256.encode_point(p256.G) + p256.encode_point(S) + p256.encode_point(R)
    ).digest()
    c = (int.from_bytes(c_bytes, "big") % (oc.P256_ORDER - 1)) + 1
    z = (r + c * s) % oc.P256_ORDER

    ke3 = {
        "client_mac": base64.b64encode(client_mac).decode(),
        "zkp_proof": {
            "S": base64.b64encode(p256.encode_point(S)).decode(),
            "R": base64.b64encode(p256.encode_point(R)).decode(),
            "z": base64.b64encode(z.to_bytes(32, "big")).decode(),
        },
    }

    # ── SERVER: login_finish ──
    result = srv.login_finish(cred_id, ke3)
    assert result["ok"] is True
    print("[OK] login_finish — ZKP verified!")
    print("[OK] session_key:", base64.b64encode(session_key).decode()[:24] + "...")
    print("\n=== ALL TESTS PASSED ===")


if __name__ == "__main__":
    test_full_flow()
