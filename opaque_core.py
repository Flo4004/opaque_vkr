"""
OPAQUE Protocol — Server-Side Implementation (Split Architecture)

The client performs:  OPRF blind/finalize, Envelope create/recover,
                     3DH client half, Schnorr ZKP proof.
The server performs: OPRF evaluate, masked credential response,
                     3DH server half, ZKP verification.

Registration:  2 round-trips  (reg/init  →  reg/finish)
Login:         2 round-trips  (login/init → login/finish)

Based on RFC 9807 · P-256 · HKDF-SHA256 · HMAC-SHA256
"""

import os
import hashlib
import hmac as hmac_module
import base64

import p256
from kdf import hkdf_expand, hkdf_extract


# ──────────────────────────── Constants ────────────────────────────

Nh  = 32   # hash output
Nn  = 32   # nonce
Nm  = 32   # MAC
Npk = 65   # uncompressed P-256 public key
Nsk = 32   # private key scalar

CONTEXT     = b"OPAQUE-VKR-v1"
P256_ORDER  = p256.N
G           = p256.G


# ──────────────────────────── Primitives ───────────────────────────

def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def hmac256(key: bytes, msg: bytes) -> bytes:
    return hmac_module.new(key, msg, hashlib.sha256).digest()


# ──────────────────────────── EC helpers ───────────────────────────

def _gen_keypair():
    sk = p256.generate_private_key()
    pk = p256.public_key_from_private(sk)
    return sk, pk


def _sk_bytes(sk: int) -> bytes:
    return p256.sk_to_bytes(sk)


def _pk_bytes(pk: tuple) -> bytes:
    return p256.encode_point(pk)


def _bytes_to_sk(data: bytes) -> int:
    val = int.from_bytes(data, "big")
    return (val % (P256_ORDER - 1)) + 1


def _public_key_of(sk: int) -> tuple:
    return p256.public_key_from_private(sk)


def _ecdh(sk: int, pk: tuple) -> bytes:
    return p256.ecdh(sk, pk)


# ──────────────────────────── OPRF (server-side evaluate) ──────────

def _oprf_derive_key(seed: bytes, cred_id: bytes) -> int:
    derived = hkdf_expand(seed, b"OPAQUE-DeriveKeyPair" + cred_id, 32)
    return (int.from_bytes(derived, "big") % (P256_ORDER - 1)) + 1


def oprf_evaluate(seed: bytes, cred_id: bytes, blinded_scalar_bytes: bytes) -> bytes:
    """
    Server evaluates:  result = k * blinded_scalar  mod N
    Returns 32-byte evaluated_element.
    """
    k = _oprf_derive_key(seed, cred_id)
    blinded = int.from_bytes(blinded_scalar_bytes, "big")
    result = (k * blinded) % P256_ORDER
    return result.to_bytes(32, "big")


# ──────────────────────────── 3DH AKE ─────────────────────────────

def _derive_3dh_keys(dh1, dh2, dh3, preamble):
    ikm = dh1 + dh2 + dh3
    prk = hkdf_extract(b"", ikm)
    hs  = hkdf_expand(prk, preamble + b"HandshakeSecret", Nh)
    sk  = hkdf_expand(prk, preamble + b"SessionKey", Nh)
    smk = hkdf_expand(hs,  b"ServerMAC", Nm)
    cmk = hkdf_expand(hs,  b"ClientMAC", Nm)
    return sk, smk, cmk


# ──────────────────────────── Schnorr ZKP ─────────────────────────

def zkp_verify(session_key: bytes, proof: dict) -> bool:
    """
    Verify Schnorr proof that the client holds the same session_key.
    proof = { S: base64(point), R: base64(point), z: base64(scalar) }

    Check:  z · G  ==  R + c · S
    where   c = SHA256(encode(G) || encode(S) || encode(R))
    """
    try:
        S = p256.decode_point(base64.b64decode(proof["S"]))
        R = p256.decode_point(base64.b64decode(proof["R"]))
        z = int.from_bytes(base64.b64decode(proof["z"]), "big")

        # Server computes S_expected = session_key_scalar · G
        s = int.from_bytes(session_key, "big")
        S_expected = p256.scalar_mult(s, G)
        if S != S_expected:
            return False

        challenge_bytes = sha256(
            p256.encode_point(G),
            p256.encode_point(S),
            p256.encode_point(R),
        )
        c = (int.from_bytes(challenge_bytes, "big") % (P256_ORDER - 1)) + 1

        lhs = p256.scalar_mult(z, G)
        rhs = p256.point_add(R, p256.scalar_mult(c, S))
        return lhs == rhs
    except Exception:
        return False


# ──────────────────────── OPAQUE Server ───────────────────────────

class OPAQUEServer:
    """
    Handles split registration and login with client-side crypto.

    Storage is external (MongoDB via app.py); the server object only
    holds the long-lived OPRF seed and static server keypair.
    """

    def __init__(self, oprf_seed: bytes = None, server_sk_bytes: bytes = None):
        self.oprf_seed = oprf_seed or random_bytes(32)
        if server_sk_bytes:
            self._sk = _bytes_to_sk(server_sk_bytes)
            self._pk = _public_key_of(self._sk)
        else:
            self._sk, self._pk = _gen_keypair()
        self.sk_bytes = _sk_bytes(self._sk)
        self.pk_bytes = _pk_bytes(self._pk)

        # ephemeral login state (in-memory, keyed by credential_id)
        self._login_states: dict = {}

    # ── config persistence ──

    def save_config(self) -> dict:
        return {
            "oprf_seed": base64.b64encode(self.oprf_seed).decode(),
            "server_sk": base64.b64encode(self.sk_bytes).decode(),
        }

    @classmethod
    def load_config(cls, cfg: dict) -> "OPAQUEServer":
        return cls(
            oprf_seed=base64.b64decode(cfg["oprf_seed"]),
            server_sk_bytes=base64.b64decode(cfg["server_sk"]),
        )

    # ═══════════════════ REGISTRATION ═══════════════════

    def registration_init(self, credential_id: str,
                          blinded_element_b64: str) -> dict:
        """
        Step 1 — evaluate OPRF, return evaluated element + server public key.
        """
        blinded = base64.b64decode(blinded_element_b64)
        evaluated = oprf_evaluate(
            self.oprf_seed, credential_id.encode(), blinded
        )
        return {
            "evaluated_element": base64.b64encode(evaluated).decode(),
            "server_public_key": base64.b64encode(self.pk_bytes).decode(),
        }

    @staticmethod
    def registration_record(payload: dict) -> dict:
        """
        Step 2 — validate and return the client's record for storage.
        """
        return {
            "client_public_key": payload["client_public_key"],
            "masking_key":       payload["masking_key"],
            "envelope":          payload["envelope"],
        }

    # ═══════════════════ LOGIN ═══════════════════

    def login_init(self, credential_id: str, record: dict,
                   ke1: dict) -> dict:
        """
        Process KE1 → produce KE2.

        ke1 = { blinded_element, client_nonce, client_public_keyshare }
        record = { client_public_key, masking_key, envelope }

        Returns KE2 dict.
        """
        cred_id_bytes = credential_id.encode()

        # OPRF evaluate
        blinded = base64.b64decode(ke1["blinded_element"])
        evaluated = oprf_evaluate(self.oprf_seed, cred_id_bytes, blinded)

        # Mask credential response
        masking_key = base64.b64decode(record["masking_key"])
        client_public_key = base64.b64decode(record["client_public_key"])
        envelope = base64.b64decode(record["envelope"])
        cred_data = client_public_key + envelope

        masking_nonce = random_bytes(Nn)
        pad = hkdf_expand(
            masking_key,
            masking_nonce + b"CredentialResponsePad",
            len(cred_data),
        )
        masked_response = bytes(a ^ b for a, b in zip(cred_data, pad))

        # Server ephemeral keypair
        eph_sk, eph_pk = _gen_keypair()
        server_nonce = random_bytes(Nn)

        # Decode client keys for 3DH
        client_static_pk = p256.decode_point(client_public_key)
        client_eph_pk    = p256.decode_point(
            base64.b64decode(ke1["client_public_keyshare"])
        )

        # 3DH from server perspective
        dh1 = _ecdh(self._sk, client_eph_pk)
        dh2 = _ecdh(eph_sk, client_static_pk)
        dh3 = _ecdh(eph_sk, client_eph_pk)

        preamble = CONTEXT + cred_id_bytes
        session_key, smk, cmk = _derive_3dh_keys(dh1, dh2, dh3, preamble)

        # Server MAC
        transcript = sha256(preamble)
        server_mac = hmac256(smk, transcript)

        # Store state for login_finish
        self._login_states[credential_id] = {
            "session_key": session_key,
            "client_mac_key": cmk,
            "server_mac": server_mac,
            "preamble": preamble,
        }

        return {
            "evaluated_element":      base64.b64encode(evaluated).decode(),
            "server_public_key":      base64.b64encode(self.pk_bytes).decode(),
            "masking_nonce":          base64.b64encode(masking_nonce).decode(),
            "masked_response":        base64.b64encode(masked_response).decode(),
            "server_nonce":           base64.b64encode(server_nonce).decode(),
            "server_public_keyshare": base64.b64encode(_pk_bytes(eph_pk)).decode(),
            "server_mac":             base64.b64encode(server_mac).decode(),
        }

    def login_finish(self, credential_id: str, ke3: dict) -> dict:
        """
        Process KE3 — verify client MAC + Schnorr ZKP.

        ke3 = { client_mac, zkp_proof: { S, R, z } }

        Returns { ok, session_key } or raises.
        """
        state = self._login_states.pop(credential_id, None)
        if state is None:
            raise ValueError("no_pending_login")

        session_key = state["session_key"]
        cmk         = state["client_mac_key"]
        server_mac  = state["server_mac"]
        preamble    = state["preamble"]

        # Verify client MAC
        expected_client_mac = hmac256(
            cmk, sha256(preamble + server_mac)
        )
        received_mac = base64.b64decode(ke3["client_mac"])
        if not hmac_module.compare_digest(expected_client_mac, received_mac):
            raise ValueError("client_mac_mismatch")

        # Verify Schnorr ZKP
        if not zkp_verify(session_key, ke3["zkp_proof"]):
            raise ValueError("zkp_verification_failed")

        return {
            "ok": True,
            "session_key": base64.b64encode(session_key).decode(),
        }
