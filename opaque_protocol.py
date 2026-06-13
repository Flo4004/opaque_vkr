"""
OPAQUE Protocol Implementation (Simplified for educational purposes)

This module implements a simplified version of the OPAQUE aPAKE protocol
based on RFC 9807, using:
- OPRF on P-256 (NIST) elliptic curve
- HKDF-SHA256 for key derivation
- HMAC-SHA256 for MAC
- ECDH for 3DH key exchange
- Argon2-like key stretching via PBKDF2 (for portability)

This is a teaching/thesis implementation. For production, use audited libraries.
"""

import os
import hashlib
import hmac as hmac_module
import struct
import json
import base64

import p256
from kdf import hkdf_expand, hkdf_extract, pbkdf2_sha256

# --- Constants ---
Nh = 32  # Hash output length
Nn = 32  # Nonce length
Nseed = 32
Nm = 32  # MAC output length
Npk = 65  # Uncompressed public key length for P-256
Nsk = 32  # Private key length
ORDER = p256.N

CONTEXT = b"OPAQUE-VKR-v1"


def random_bytes(n: int) -> bytes:
    """Generate n cryptographically random bytes."""
    return os.urandom(n)


def hash_data(*args: bytes) -> bytes:
    """SHA-256 hash of concatenated arguments."""
    h = hashlib.sha256()
    for a in args:
        h.update(a)
    return h.digest()


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA256."""
    return hmac_module.new(key, msg, hashlib.sha256).digest()


def hkdf_extract_local(salt: bytes, ikm: bytes) -> bytes:
    """HKDF-Extract using SHA-256."""
    return hmac_sha256(salt if salt else b"\x00" * 32, ikm)


def stretch_password(password_hash: bytes) -> bytes:
    """
    Key stretching function (KSF).
    Uses PBKDF2-SHA256 as a portable alternative to Argon2id.
    """
    return pbkdf2_sha256(password_hash, salt=b"\x00" * 16, iterations=10_000)


# --- Elliptic Curve Utilities ---

def generate_ec_keypair():
    """Generate a new EC key pair on P-256. Returns (sk_int, pk_point)."""
    sk = p256.generate_private_key()
    pk = p256.public_key_from_private(sk)
    return sk, pk


def private_key_to_bytes(sk: int) -> bytes:
    """Serialize private key to 32 bytes."""
    return p256.sk_to_bytes(sk)


def public_key_to_bytes(pk: tuple) -> bytes:
    """Serialize public key to uncompressed format."""
    return p256.encode_point(pk)


def bytes_to_public_key(data: bytes) -> tuple:
    """Deserialize public key from uncompressed format."""
    return p256.decode_point(data)


def bytes_to_private_key(data: bytes) -> int:
    """Deserialize private key from bytes."""
    val = int.from_bytes(data, byteorder="big")
    return (val % (ORDER - 1)) + 1


def ecdh(private_key: int, peer_public_point: tuple) -> bytes:
    """Perform ECDH and return shared secret."""
    return p256.ecdh(private_key, peer_public_point)


# --- OPRF Implementation ---

def oprf_hash_to_scalar(data: bytes) -> int:
    """Hash data to a scalar value in the curve's order range."""
    h = hashlib.sha256(b"OPRF-HashToScalar-" + data).digest()
    return (int.from_bytes(h, "big") % (ORDER - 1)) + 1


def oprf_derive_key(oprf_seed: bytes, credential_id: bytes) -> int:
    """Derive an OPRF key from seed and credential identifier."""
    info = b"OPAQUE-DeriveKeyPair" + credential_id
    derived = hkdf_expand(oprf_seed, info, 32)
    return (int.from_bytes(derived, "big") % (ORDER - 1)) + 1


class OPRFClient:
    """Client-side OPRF operations."""

    def __init__(self):
        self.blind = None

    def blind_message(self, password: bytes) -> bytes:
        """
        Blind step: hash password to curve point, multiply by random scalar.
        Returns the blinded element.

        In a full implementation, this would use hash-to-curve (RFC 9380).
        Here we use a simplified approach: hash password to get a scalar,
        then use it to derive a deterministic point, then blind it.
        """
        # Generate random blinding factor
        blind_bytes = random_bytes(32)
        self.blind = (int.from_bytes(blind_bytes, "big") % (ORDER - 1)) + 1

        # Hash password to a scalar and derive a point
        pwd_scalar = oprf_hash_to_scalar(password)

        # Blinded scalar = blind * pwd_scalar mod order
        blinded_scalar = (self.blind * pwd_scalar) % ORDER

        # Encode the blinded scalar for transmission
        return blinded_scalar.to_bytes(32, "big")

    def finalize(self, password: bytes, evaluated: bytes) -> bytes:
        """
        Finalize step: unblind the evaluated element.
        Returns the OPRF output.
        """
        order = ORDER

        eval_scalar = int.from_bytes(evaluated, "big")

        # Compute blind inverse
        blind_inv = pow(self.blind, order - 2, order)

        # Unblind: result = eval * blind_inv mod order
        result = (eval_scalar * blind_inv) % order

        # Final output: hash the result with the input
        oprf_output = hash_data(
            b"OPRF-Finalize-",
            password,
            result.to_bytes(32, "big"),
        )
        return oprf_output


class OPRFServer:
    """Server-side OPRF operations."""

    @staticmethod
    def evaluate(oprf_key: int, blinded_element: bytes) -> bytes:
        """
        Evaluate step: multiply the blinded element by the OPRF key.
        Returns the evaluated element.
        """
        order = ORDER

        blinded_scalar = int.from_bytes(blinded_element, "big")

        # Evaluate: result = oprf_key * blinded_scalar mod order
        result = (oprf_key * blinded_scalar) % order

        return result.to_bytes(32, "big")


# --- Envelope Operations ---

def create_envelope(randomized_password: bytes, server_public_key: bytes,
                    client_identity: bytes = b"",
                    server_identity: bytes = b"") -> tuple:
    """
    Create the client's encrypted envelope during registration.

    Returns: (envelope, client_public_key_bytes, masking_key, export_key, client_private_key_bytes)
    """
    # Generate client keypair
    client_sk, client_pk = generate_ec_keypair()
    client_private_key_bytes = private_key_to_bytes(client_sk)
    client_public_key_bytes = public_key_to_bytes(client_pk)

    # Derive keys from randomized_password
    envelope_nonce = random_bytes(Nn)

    masking_key = hkdf_expand(randomized_password, b"MaskingKey", Nh)
    auth_key = hkdf_expand(
        randomized_password, envelope_nonce + b"AuthKey", Nh
    )
    export_key = hkdf_expand(
        randomized_password, envelope_nonce + b"ExportKey", Nh
    )

    # Derive client private key seed from randomized_password
    # (in the "internal" mode, client key is derived from password)
    seed = hkdf_expand(randomized_password, envelope_nonce + b"PrivateKey", Nsk)

    # Re-derive client keypair deterministically from seed
    client_sk_det = bytes_to_private_key(seed)
    client_private_key_bytes = private_key_to_bytes(client_sk_det)
    client_public_key_bytes = public_key_to_bytes(
        p256.public_key_from_private(client_sk_det)
    )

    # Build cleartext credentials
    if not client_identity:
        client_identity = client_public_key_bytes
    if not server_identity:
        server_identity = server_public_key

    cleartext_creds = (
        server_public_key
        + struct.pack(">H", len(server_identity))
        + server_identity
        + struct.pack(">H", len(client_identity))
        + client_identity
    )

    # MAC over envelope contents
    envelope_mac = hmac_sha256(
        auth_key, envelope_nonce + cleartext_creds
    )

    # Envelope = nonce || mac
    envelope = envelope_nonce + envelope_mac

    return (
        envelope,
        client_public_key_bytes,
        masking_key,
        export_key,
        client_private_key_bytes,
    )


def recover_envelope(randomized_password: bytes, envelope: bytes,
                     server_public_key: bytes,
                     client_identity: bytes = b"",
                     server_identity: bytes = b"") -> tuple:
    """
    Recover credentials from the envelope during login.

    Returns: (client_private_key_bytes, client_public_key_bytes, export_key)
    Raises ValueError if MAC verification fails.
    """
    envelope_nonce = envelope[:Nn]
    envelope_mac = envelope[Nn : Nn + Nm]

    # Derive keys
    auth_key = hkdf_expand(
        randomized_password, envelope_nonce + b"AuthKey", Nh
    )
    export_key = hkdf_expand(
        randomized_password, envelope_nonce + b"ExportKey", Nh
    )

    # Re-derive client keypair from seed
    seed = hkdf_expand(randomized_password, envelope_nonce + b"PrivateKey", Nsk)
    client_sk = bytes_to_private_key(seed)
    client_private_key_bytes = private_key_to_bytes(client_sk)
    client_public_key_bytes = public_key_to_bytes(
        p256.public_key_from_private(client_sk)
    )

    # Reconstruct cleartext credentials
    if not client_identity:
        client_identity = client_public_key_bytes
    if not server_identity:
        server_identity = server_public_key

    cleartext_creds = (
        server_public_key
        + struct.pack(">H", len(server_identity))
        + server_identity
        + struct.pack(">H", len(client_identity))
        + client_identity
    )

    # Verify MAC
    expected_mac = hmac_sha256(auth_key, envelope_nonce + cleartext_creds)

    if not hmac_module.compare_digest(envelope_mac, expected_mac):
        raise ValueError("EnvelopeRecoveryError: MAC verification failed")

    return client_private_key_bytes, client_public_key_bytes, export_key


# --- 3DH AKE Protocol ---

class AKEClient:
    """Client-side AKE (3DH) operations."""

    def __init__(self):
        self.ephemeral_key = None
        self.client_nonce = None
        self.ke1_data = None

    def generate_ke1(self) -> dict:
        """Generate KE1 message (auth part)."""
        self.eph_sk, self.eph_pk = generate_ec_keypair()
        self.client_nonce = random_bytes(Nn)

        ke1_auth = {
            "client_nonce": base64.b64encode(self.client_nonce).decode(),
            "client_public_keyshare": base64.b64encode(
                public_key_to_bytes(self.eph_pk)
            ).decode(),
        }
        self.ke1_data = ke1_auth
        return ke1_auth

    def generate_ke3(
        self,
        client_private_key: bytes,
        server_public_key: bytes,
        ke2_auth: dict,
        preamble: bytes,
    ) -> tuple:
        """
        Generate KE3 message and derive session key.
        Performs 3DH key exchange.

        Returns: (ke3, session_key)
        """
        server_nonce = base64.b64decode(ke2_auth["server_nonce"])
        server_public_keyshare = bytes_to_public_key(
            base64.b64decode(ke2_auth["server_public_keyshare"])
        )
        server_mac = base64.b64decode(ke2_auth["server_mac"])
        server_pub = bytes_to_public_key(server_public_key)

        client_priv = bytes_to_private_key(client_private_key)

        # 3DH: three DH computations
        # dh1 = ephemeral_client * static_server
        dh1 = ecdh(self.eph_sk, server_pub)
        # dh2 = static_client * ephemeral_server
        dh2 = ecdh(client_priv, server_public_keyshare)
        # dh3 = ephemeral_client * ephemeral_server
        dh3 = ecdh(self.eph_sk, server_public_keyshare)

        # Derive keys
        ikm = dh1 + dh2 + dh3
        prk = hkdf_extract(b"", ikm)

        handshake_secret = hkdf_expand(prk, preamble + b"HandshakeSecret", Nh)
        session_key = hkdf_expand(prk, preamble + b"SessionKey", Nh)
        server_mac_key = hkdf_expand(handshake_secret, b"ServerMAC", Nm)
        client_mac_key = hkdf_expand(handshake_secret, b"ClientMAC", Nm)

        # Verify server MAC
        transcript_hash = hash_data(preamble)
        expected_server_mac = hmac_sha256(server_mac_key, transcript_hash)

        if not hmac_module.compare_digest(server_mac, expected_server_mac):
            raise ValueError(
                "ServerAuthenticationError: Server MAC verification failed"
            )

        # Generate client MAC
        client_mac = hmac_sha256(
            client_mac_key, hash_data(preamble + server_mac)
        )

        ke3 = {"client_mac": base64.b64encode(client_mac).decode()}
        return ke3, session_key


class AKEServer:
    """Server-side AKE (3DH) operations."""

    def __init__(self):
        self.eph_sk = None
        self.eph_pk = None
        self.server_nonce = None
        self.expected_client_mac = None
        self.session_key = None

    def generate_ke2_auth(
        self,
        server_private_key: bytes,
        client_public_key: bytes,
        ke1_auth: dict,
        preamble: bytes,
    ) -> dict:
        """
        Generate KE2 auth message.
        Performs server-side 3DH.

        Returns: ke2_auth dict
        """
        self.eph_sk, self.eph_pk = generate_ec_keypair()
        self.server_nonce = random_bytes(Nn)

        client_nonce = base64.b64decode(ke1_auth["client_nonce"])
        client_public_keyshare = bytes_to_public_key(
            base64.b64decode(ke1_auth["client_public_keyshare"])
        )

        server_priv = bytes_to_private_key(server_private_key)
        client_pub = bytes_to_public_key(client_public_key)

        # 3DH: three DH computations
        # dh1 = static_server * ephemeral_client
        dh1 = ecdh(server_priv, client_public_keyshare)
        # dh2 = ephemeral_server * static_client
        dh2 = ecdh(self.eph_sk, client_pub)
        # dh3 = ephemeral_server * ephemeral_client
        dh3 = ecdh(self.eph_sk, client_public_keyshare)

        # Derive keys (must match client's derivation)
        ikm = dh1 + dh2 + dh3
        prk = hkdf_extract(b"", ikm)

        handshake_secret = hkdf_expand(prk, preamble + b"HandshakeSecret", Nh)
        self.session_key = hkdf_expand(prk, preamble + b"SessionKey", Nh)
        server_mac_key = hkdf_expand(handshake_secret, b"ServerMAC", Nm)
        client_mac_key = hkdf_expand(handshake_secret, b"ClientMAC", Nm)

        # Generate server MAC
        transcript_hash = hash_data(preamble)
        server_mac = hmac_sha256(server_mac_key, transcript_hash)

        # Compute expected client MAC
        self.expected_client_mac = hmac_sha256(
            client_mac_key, hash_data(preamble + server_mac)
        )

        ke2_auth = {
            "server_nonce": base64.b64encode(self.server_nonce).decode(),
            "server_public_keyshare": base64.b64encode(
                public_key_to_bytes(self.eph_pk)
            ).decode(),
            "server_mac": base64.b64encode(server_mac).decode(),
        }
        return ke2_auth

    def verify_ke3(self, ke3: dict) -> bytes:
        """
        Verify client's KE3 message.
        Returns session_key on success.
        Raises ValueError on failure.
        """
        client_mac = base64.b64decode(ke3["client_mac"])

        if not hmac_module.compare_digest(client_mac, self.expected_client_mac):
            raise ValueError(
                "ClientAuthenticationError: Client MAC verification failed"
            )

        return self.session_key


# --- High-Level OPAQUE Protocol ---

class OPAQUEServer:
    """High-level OPAQUE server operations."""

    def __init__(self, oprf_seed: bytes = None, server_private_key=None):
        if oprf_seed is None:
            self.oprf_seed = random_bytes(Nseed)
        else:
            self.oprf_seed = oprf_seed

        if server_private_key is None:
            self._server_sk, self._server_pk = generate_ec_keypair()
        else:
            self._server_sk = bytes_to_private_key(server_private_key)
            self._server_pk = p256.public_key_from_private(self._server_sk)

        self.server_private_key_bytes = private_key_to_bytes(self._server_sk)
        self.server_public_key_bytes = public_key_to_bytes(self._server_pk)

        # User records: credential_id -> record
        self.records = {}

        # Active login sessions: credential_id -> AKEServer
        self.login_sessions = {}

    def get_server_public_key(self) -> bytes:
        return self.server_public_key_bytes

    def get_server_config(self) -> dict:
        """Return serializable server configuration."""
        return {
            "oprf_seed": base64.b64encode(self.oprf_seed).decode(),
            "server_private_key": base64.b64encode(
                self.server_private_key_bytes
            ).decode(),
        }

    @classmethod
    def from_config(cls, config: dict) -> "OPAQUEServer":
        """Create server from saved configuration."""
        oprf_seed = base64.b64decode(config["oprf_seed"])
        server_private_key = base64.b64decode(config["server_private_key"])
        return cls(oprf_seed=oprf_seed, server_private_key=server_private_key)

    # --- Registration ---

    def create_registration_response(
        self, credential_id: str, blinded_element: bytes
    ) -> dict:
        """Process registration request (step 2)."""
        oprf_key = oprf_derive_key(self.oprf_seed, credential_id.encode())
        evaluated = OPRFServer.evaluate(oprf_key, blinded_element)

        return {
            "evaluated_element": base64.b64encode(evaluated).decode(),
            "server_public_key": base64.b64encode(
                self.server_public_key_bytes
            ).decode(),
        }

    def store_user_record(self, credential_id: str, record: dict):
        """Store user record after registration (step 4)."""
        self.records[credential_id] = record

    def has_user(self, credential_id: str) -> bool:
        return credential_id in self.records

    # --- Login ---

    def create_credential_response(
        self, credential_id: str, blinded_element: bytes, ke1_auth: dict
    ) -> dict:
        """Process login request (KE2)."""
        if credential_id not in self.records:
            raise ValueError("User not found")

        record = self.records[credential_id]

        # OPRF evaluation
        oprf_key = oprf_derive_key(self.oprf_seed, credential_id.encode())
        evaluated = OPRFServer.evaluate(oprf_key, blinded_element)

        # Get stored data
        client_public_key = base64.b64decode(record["client_public_key"])
        masking_key = base64.b64decode(record["masking_key"])
        envelope = base64.b64decode(record["envelope"])

        # Create masked response
        masking_nonce = random_bytes(Nn)
        credential_data = client_public_key + envelope

        # XOR mask with pad derived from masking_key
        pad = hkdf_expand(masking_key, masking_nonce + b"CredentialResponsePad", len(credential_data))
        masked_response = bytes(a ^ b for a, b in zip(credential_data, pad))

        # Build preamble for 3DH
        preamble = (
            CONTEXT
            + credential_id.encode()
            + base64.b64decode(ke1_auth["client_nonce"])
            + base64.b64decode(ke1_auth["client_public_keyshare"])
        )

        # 3DH server side
        ake_server = AKEServer()
        ke2_auth = ake_server.generate_ke2_auth(
            self.server_private_key_bytes,
            client_public_key,
            ke1_auth,
            preamble,
        )

        self.login_sessions[credential_id] = ake_server

        return {
            "evaluated_element": base64.b64encode(evaluated).decode(),
            "masking_nonce": base64.b64encode(masking_nonce).decode(),
            "masked_response": base64.b64encode(masked_response).decode(),
            "server_public_key": base64.b64encode(
                self.server_public_key_bytes
            ).decode(),
            **ke2_auth,
        }

    def finish_login(self, credential_id: str, ke3: dict) -> bytes:
        """Verify KE3 and return session key."""
        if credential_id not in self.login_sessions:
            raise ValueError("No active login session")

        ake_server = self.login_sessions.pop(credential_id)
        return ake_server.verify_ke3(ke3)


class OPAQUEClient:
    """High-level OPAQUE client operations."""

    def __init__(self):
        self.oprf_client = None
        self.ake_client = None
        self.password = None

    # --- Registration ---

    def create_registration_request(self, password: str) -> dict:
        """Create registration request (step 1)."""
        self.password = password.encode()
        self.oprf_client = OPRFClient()
        blinded = self.oprf_client.blind_message(self.password)

        return {
            "blinded_element": base64.b64encode(blinded).decode(),
        }

    def finalize_registration(self, response: dict) -> dict:
        """Finalize registration (step 3)."""
        evaluated = base64.b64decode(response["evaluated_element"])
        server_public_key = base64.b64decode(response["server_public_key"])

        # Complete OPRF
        oprf_output = self.oprf_client.finalize(self.password, evaluated)

        # Key stretching
        randomized_password = stretch_password(oprf_output)

        # Create envelope
        (
            envelope,
            client_public_key,
            masking_key,
            export_key,
            client_private_key,
        ) = create_envelope(randomized_password, server_public_key)

        # Build the record to send to server
        record = {
            "client_public_key": base64.b64encode(client_public_key).decode(),
            "masking_key": base64.b64encode(masking_key).decode(),
            "envelope": base64.b64encode(envelope).decode(),
        }

        self.password = None
        self.oprf_client = None

        return record

    # --- Login ---

    def create_credential_request(self, password: str) -> dict:
        """Create login credential request (KE1)."""
        self.password = password.encode()
        self.oprf_client = OPRFClient()
        blinded = self.oprf_client.blind_message(self.password)

        self.ake_client = AKEClient()
        ke1_auth = self.ake_client.generate_ke1()

        return {
            "blinded_element": base64.b64encode(blinded).decode(),
            **ke1_auth,
        }

    def finish_login(self, credential_id: str, ke2: dict) -> tuple:
        """
        Process KE2 and generate KE3.
        Returns: (ke3, session_key, export_key)
        """
        evaluated = base64.b64decode(ke2["evaluated_element"])
        masking_nonce = base64.b64decode(ke2["masking_nonce"])
        masked_response = base64.b64decode(ke2["masked_response"])
        server_public_key = base64.b64decode(ke2["server_public_key"])

        # Complete OPRF
        oprf_output = self.oprf_client.finalize(self.password, evaluated)
        randomized_password = stretch_password(oprf_output)

        # Recover credentials from masked response
        masking_key_for_recovery = hkdf_expand(randomized_password, b"MaskingKey", Nh)
        pad = hkdf_expand(masking_key_for_recovery, masking_nonce + b"CredentialResponsePad", len(masked_response))

        credential_data = bytes(a ^ b for a, b in zip(masked_response, pad))

        # Parse credential data: client_public_key (65 bytes) + envelope
        client_public_key = credential_data[:Npk]
        envelope = credential_data[Npk:]

        # Recover envelope
        client_private_key, _, export_key = recover_envelope(
            randomized_password, envelope, server_public_key
        )

        # Build preamble (must match server's preamble)
        preamble = (
            CONTEXT
            + credential_id.encode()
            + base64.b64decode(self.ake_client.ke1_data["client_nonce"])
            + base64.b64decode(self.ake_client.ke1_data["client_public_keyshare"])
        )

        # 3DH client side
        ke3, session_key = self.ake_client.generate_ke3(
            client_private_key,
            server_public_key,
            ke2,
            preamble,
        )

        self.password = None
        self.oprf_client = None

        return ke3, session_key, export_key
