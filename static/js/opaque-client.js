/**
 * OPAQUE Client — Pure JS implementation on P-256
 *
 * Implements:  OPRF (blind/finalize), Envelope (create/recover),
 *              3DH AKE (KE1/KE3), Schnorr ZKP for session-key proof
 *
 * All big-integer arithmetic is done via native BigInt.
 * Hashing goes through the Web Crypto API (SHA-256).
 */

const OpaqueClient = (() => {

  /* ────────────── P-256 curve parameters ────────────── */
  const P  = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFn;
  const A  = P - 3n;
  const B  = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604Bn;
  const N  = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;
  const GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296n;
  const GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5n;
  const G  = [GX, GY];
  const INF = null;

  const Nn = 32;
  const Nm = 32;
  const Nh = 32;
  const Nsk = 32;

  /* ────────────── helpers ────────────── */
  function mod(a, m) { return ((a % m) + m) % m; }

  function bigToBytes(n, len = 32) {
    const hex = n.toString(16).padStart(len * 2, '0');
    const b = new Uint8Array(len);
    for (let i = 0; i < len; i++) b[i] = parseInt(hex.substr(i * 2, 2), 16);
    return b;
  }

  function bytesToBig(buf) {
    let r = 0n;
    for (const b of buf) r = (r << 8n) | BigInt(b);
    return r;
  }

  function concat(...arrs) {
    const total = arrs.reduce((s, a) => s + a.length, 0);
    const r = new Uint8Array(total);
    let off = 0;
    for (const a of arrs) { r.set(a, off); off += a.length; }
    return r;
  }

  function u8(str) { return new TextEncoder().encode(str); }
  function b64(buf) { return btoa(String.fromCharCode(...buf)); }
  function unb64(s) { const bin = atob(s); const b = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) b[i] = bin.charCodeAt(i); return b; }

  function randomBytes(n) { const b = new Uint8Array(n); crypto.getRandomValues(b); return b; }

  /* ────────────── modular inverse (extended GCD) ────────────── */
  function modinv(a, m) {
    a = mod(a, m);
    let [old_r, r] = [a, m];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
      const q = old_r / r;
      [old_r, r] = [r, old_r - q * r];
      [old_s, s] = [s, old_s - q * s];
    }
    return mod(old_s, m);
  }

  /* ────────────── P-256 point arithmetic ────────────── */
  function pointEq(p1, p2) {
    if (p1 === INF && p2 === INF) return true;
    if (p1 === INF || p2 === INF) return false;
    return p1[0] === p2[0] && p1[1] === p2[1];
  }

  function pointDouble(pt) {
    if (pt === INF) return INF;
    const [x, y] = pt;
    if (y === 0n) return INF;
    const lam = mod((3n * x * x + A) * modinv(2n * y, P), P);
    const x3 = mod(lam * lam - 2n * x, P);
    const y3 = mod(lam * (x - x3) - y, P);
    return [x3, y3];
  }

  function pointAdd(p1, p2) {
    if (p1 === INF) return p2;
    if (p2 === INF) return p1;
    const [x1, y1] = p1;
    const [x2, y2] = p2;
    if (x1 === x2) {
      if (y1 !== y2) return INF;
      return pointDouble(p1);
    }
    const lam = mod((y2 - y1) * modinv(x2 - x1, P), P);
    const x3 = mod(lam * lam - x1 - x2, P);
    const y3 = mod(lam * (x1 - x3) - y1, P);
    return [x3, y3];
  }

  function scalarMult(k, pt) {
    k = mod(k, N);
    if (k === 0n || pt === INF) return INF;
    let result = INF;
    let addend = pt;
    while (k > 0n) {
      if (k & 1n) result = pointAdd(result, addend);
      addend = pointDouble(addend);
      k >>= 1n;
    }
    return result;
  }

  function encodePoint(pt) {
    if (pt === INF) throw new Error('Cannot encode INF');
    return concat(new Uint8Array([0x04]), bigToBytes(pt[0], 32), bigToBytes(pt[1], 32));
  }

  function decodePoint(buf) {
    if (buf[0] !== 0x04 || buf.length !== 65) throw new Error('Invalid point');
    return [bytesToBig(buf.slice(1, 33)), bytesToBig(buf.slice(33, 65))];
  }

  function genPrivateKey() {
    while (true) {
      const k = bytesToBig(randomBytes(32));
      if (k >= 1n && k < N) return k;
    }
  }

  function ecdh(sk, pk) { const s = scalarMult(sk, pk); return bigToBytes(s[0], 32); }

  /* ────────────── SHA-256 / HMAC-SHA256 ────────────── */
  async function sha256(...parts) {
    const data = concat(...parts);
    const hash = await crypto.subtle.digest('SHA-256', data);
    return new Uint8Array(hash);
  }

  async function hmac256(key, msg) {
    const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', k, msg);
    return new Uint8Array(sig);
  }

  /* ────────────── HKDF (RFC 5869) ────────────── */
  async function hkdfExtract(salt, ikm) {
    if (!salt || salt.length === 0) salt = new Uint8Array(32);
    return hmac256(salt, ikm);
  }

  async function hkdfExpand(prk, info, length) {
    let okm = new Uint8Array(0);
    let t = new Uint8Array(0);
    const n = Math.ceil(length / 32);
    for (let i = 1; i <= n; i++) {
      t = await hmac256(prk, concat(t, info, new Uint8Array([i])));
      okm = concat(okm, t);
    }
    return okm.slice(0, length);
  }

  /* ────────────── PBKDF2-SHA256 ────────────── */
  async function pbkdf2(password, salt, iterations, keyLen) {
    const baseKey = await crypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      baseKey, keyLen * 8
    );
    return new Uint8Array(bits);
  }

  async function stretch(data) {
    return pbkdf2(data, new Uint8Array(16), 10000, 32);
  }

  /* ────────────── OPRF (client-side blind / finalize) ────────────── */
  function oprfHashToScalar(data) {
    // synchronous: uses a sync sha256 for scalar derivation
    // we'll make this async-compatible
    return sha256(u8('OPRF-HashToScalar-'), data).then(h =>
      mod(bytesToBig(h), N - 1n) + 1n
    );
  }

  async function oprfBlind(password) {
    const blindScalar = genPrivateKey();
    const pwdScalar = await oprfHashToScalar(password);
    const blindedScalar = mod(blindScalar * pwdScalar, N);
    return {
      blind: blindScalar,
      blindedElement: bigToBytes(blindedScalar, 32)
    };
  }

  async function oprfFinalize(password, blind, evaluatedElement) {
    const evalScalar = bytesToBig(evaluatedElement);
    const blindInv = modinv(blind, N);
    const result = mod(evalScalar * blindInv, N);
    return sha256(u8('OPRF-Finalize-'), password, bigToBytes(result, 32));
  }

  /* ────────────── Envelope ────────────── */
  function cleartextCreds(serverPk, clientPk) {
    const sLen = new Uint8Array(2);
    sLen[0] = (serverPk.length >> 8) & 0xff; sLen[1] = serverPk.length & 0xff;
    const cLen = new Uint8Array(2);
    cLen[0] = (clientPk.length >> 8) & 0xff; cLen[1] = clientPk.length & 0xff;
    return concat(serverPk, sLen, serverPk, cLen, clientPk);
  }

  function bytesToSk(seed) {
    const val = bytesToBig(seed);
    return mod(val, N - 1n) + 1n;
  }

  async function createEnvelope(rwd, serverPkBytes) {
    const nonce     = randomBytes(Nn);
    const maskingKey = await hkdfExpand(rwd, u8('MaskingKey'), Nh);
    const authKey    = await hkdfExpand(rwd, concat(nonce, u8('AuthKey')), Nh);
    const exportKey  = await hkdfExpand(rwd, concat(nonce, u8('ExportKey')), Nh);
    const seed       = await hkdfExpand(rwd, concat(nonce, u8('PrivateKey')), Nsk);

    const clientSk = bytesToSk(seed);
    const clientPkPoint = scalarMult(clientSk, G);
    const clientPkBytes = encodePoint(clientPkPoint);

    const cleartext = cleartextCreds(serverPkBytes, clientPkBytes);
    const mac = await hmac256(authKey, concat(nonce, cleartext));

    const envelope = concat(nonce, mac);
    return { envelope, clientPkBytes, maskingKey, exportKey, clientSkBytes: bigToBytes(clientSk, 32) };
  }

  async function recoverEnvelope(rwd, envelope, serverPkBytes) {
    const nonce = envelope.slice(0, Nn);
    const mac   = envelope.slice(Nn, Nn + Nm);

    const authKey   = await hkdfExpand(rwd, concat(nonce, u8('AuthKey')), Nh);
    const exportKey = await hkdfExpand(rwd, concat(nonce, u8('ExportKey')), Nh);
    const seed      = await hkdfExpand(rwd, concat(nonce, u8('PrivateKey')), Nsk);

    const clientSk = bytesToSk(seed);
    const clientPkPoint = scalarMult(clientSk, G);
    const clientPkBytes = encodePoint(clientPkPoint);

    const cleartext = cleartextCreds(serverPkBytes, clientPkBytes);
    const expected = await hmac256(authKey, concat(nonce, cleartext));

    let match = true;
    for (let i = 0; i < mac.length; i++) if (mac[i] !== expected[i]) match = false;
    if (!match) throw new Error('EnvelopeRecoveryError');

    return { clientSkBytes: bigToBytes(clientSk, 32), clientPkBytes, exportKey };
  }

  /* ────────────── 3DH AKE ────────────── */
  async function derive3dhKeys(dh1, dh2, dh3, preamble) {
    const ikm = concat(dh1, dh2, dh3);
    const prk = await hkdfExtract(new Uint8Array(0), ikm);
    const hs  = await hkdfExpand(prk, concat(preamble, u8('HandshakeSecret')), Nh);
    const sk  = await hkdfExpand(prk, concat(preamble, u8('SessionKey')), Nh);
    const smk = await hkdfExpand(hs, u8('ServerMAC'), Nm);
    const cmk = await hkdfExpand(hs, u8('ClientMAC'), Nm);
    return { sessionKey: sk, serverMacKey: smk, clientMacKey: cmk };
  }

  /* ────────────── Schnorr ZKP  ────────────── */
  // Proves: "I know s such that S = s·G" without revealing s.
  // S = session_key_scalar · G  (commitment)
  // r random, R = r·G
  // c = H(G, S, R)
  // z = r + c·s   mod N
  // Proof = (S, R, z)
  // Verification: z·G == R + c·S
  async function zkpProve(sessionKeyBytes) {
    const s = bytesToBig(sessionKeyBytes);
    const S = scalarMult(s, G);
    const r = genPrivateKey();
    const R = scalarMult(r, G);

    const challenge = await sha256(
      encodePoint(G), encodePoint(S), encodePoint(R)
    );
    const c = mod(bytesToBig(challenge), N - 1n) + 1n;
    const z = mod(r + c * s, N);

    return {
      S: b64(encodePoint(S)),
      R: b64(encodePoint(R)),
      z: b64(bigToBytes(z, 32))
    };
  }

  /* ════════════════  PUBLIC API  ════════════════ */

  /**
   * Registration flow (client side).
   * Step 1: blind password  → send to server
   * Step 2: receive evaluated_element + server_pk  → build envelope  → send record
   */
  async function registrationStart(password) {
    const pwdBytes = u8(password);
    const { blind, blindedElement } = await oprfBlind(pwdBytes);
    return { blind, blindedElement: b64(blindedElement), _pwdBytes: pwdBytes };
  }

  async function registrationFinish(state, serverResponse) {
    const evaluatedElement = unb64(serverResponse.evaluated_element);
    const serverPkBytes    = unb64(serverResponse.server_public_key);

    const oprfOut = await oprfFinalize(state._pwdBytes, state.blind, evaluatedElement);
    const rwd     = await stretch(oprfOut);

    const { envelope, clientPkBytes, maskingKey, exportKey } =
      await createEnvelope(rwd, serverPkBytes);

    return {
      record: {
        client_public_key: b64(clientPkBytes),
        masking_key:       b64(maskingKey),
        envelope:          b64(envelope)
      },
      exportKey: b64(exportKey)
    };
  }

  /**
   * Login flow (client side).
   * Step 1: blind password + gen ephemeral → send KE1
   * Step 2: receive KE2 → recover envelope → 3DH → verify server MAC → ZKP → send KE3
   */
  async function loginStart(password) {
    const pwdBytes = u8(password);
    const { blind, blindedElement } = await oprfBlind(pwdBytes);
    const ephSk = genPrivateKey();
    const ephPk = scalarMult(ephSk, G);
    const clientNonce = randomBytes(Nn);

    return {
      _pwdBytes: pwdBytes,
      _blind: blind,
      _ephSk: ephSk,
      ke1: {
        blinded_element:       b64(blindedElement),
        client_nonce:          b64(clientNonce),
        client_public_keyshare: b64(encodePoint(ephPk))
      }
    };
  }

  async function loginFinish(state, username, ke2) {
    const evaluatedElement = unb64(ke2.evaluated_element);
    const serverPkBytes    = unb64(ke2.server_public_key);
    const maskedResponse   = unb64(ke2.masked_response);
    const maskingNonce     = unb64(ke2.masking_nonce);
    const serverNonce      = unb64(ke2.server_nonce);
    const serverEphPk      = decodePoint(unb64(ke2.server_public_keyshare));
    const serverMac        = unb64(ke2.server_mac);

    // OPRF finalize
    const oprfOut = await oprfFinalize(state._pwdBytes, state._blind, evaluatedElement);
    const rwd = await stretch(oprfOut);

    // Unmask credential data
    const maskingKey = await hkdfExpand(rwd, u8('MaskingKey'), Nh);
    const pad = await hkdfExpand(maskingKey, concat(maskingNonce, u8('CredentialResponsePad')), maskedResponse.length);
    const credData = new Uint8Array(maskedResponse.length);
    for (let i = 0; i < maskedResponse.length; i++) credData[i] = maskedResponse[i] ^ pad[i];

    const clientPkFromRecord = credData.slice(0, 65);
    const envelope = credData.slice(65);

    // Recover envelope
    const { clientSkBytes, clientPkBytes, exportKey } = await recoverEnvelope(rwd, envelope, serverPkBytes);
    const clientSk = bytesToBig(clientSkBytes);

    // 3DH
    const serverPk = decodePoint(serverPkBytes);
    const dh1 = ecdh(state._ephSk, serverPk);
    const dh2 = ecdh(clientSk, serverEphPk);
    const dh3 = ecdh(state._ephSk, serverEphPk);

    const preamble = concat(u8('OPAQUE-VKR-v1'), u8(username));
    const { sessionKey, serverMacKey, clientMacKey } = await derive3dhKeys(dh1, dh2, dh3, preamble);

    // Verify server MAC
    const transcript = await sha256(preamble);
    const expectedServerMac = await hmac256(serverMacKey, transcript);
    let ok = true;
    for (let i = 0; i < serverMac.length; i++) if (serverMac[i] !== expectedServerMac[i]) ok = false;
    if (!ok) throw new Error('Server MAC verification failed');

    // Client MAC
    const clientMac = await hmac256(clientMacKey, await sha256(concat(preamble, serverMac)));

    // ZKP: prove knowledge of session_key
    const zkpProofData = await zkpProve(sessionKey);

    return {
      ke3: {
        client_mac: b64(clientMac),
        zkp_proof:  zkpProofData
      },
      sessionKey: b64(sessionKey),
      exportKey:  b64(exportKey)
    };
  }

  return { registrationStart, registrationFinish, loginStart, loginFinish };

})();
