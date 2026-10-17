#!/usr/bin/env python3
"""myjb_build.py -- myJB container (.myjb v1) builder.

Pure Python stdlib, no third-party packages.
Format spec: TweakProtection_Design.md section 3.

Examples:
  python myjb_build.py --selftest
  python myjb_build.py --gen-key
  python myjb_build.py --in Tweak.dylib --out Tweak.myjb \
      --id com.example.tweak --version 1.0.0 --min-ios 12.0 --target-jb amethyst \
      --filter SpringBoard --filter MobileSafari \
      --seed-hex 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60 \
      --kdev kdev.bin
  python myjb_build.py --info Tweak.myjb --pubkey-hex d75a9801...511a
"""

import argparse
import hashlib
import hmac as hmaclib
import secrets
import struct
import sys

MYJB_MAGIC = b"MYJB"
FORMAT_VERSION = 1
ALGO_ID = 1
MANIFEST_SIZE = 712
MAX_FILTERS = 8
FILTER_LEN = 64
TWEAK_ID_LEN = 64
VERSION_LEN = 32
KDF_INFO_PREFIX = b"myjb-file-v1:"
TARGET_JB = {"any": 0xFFFF, "checkm8": 1, "amethyst": 2, "taurine": 3}


# ---------------------------------------------------------------- ed25519 ---

_Q = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_B = 256


def _H(m):
    return hashlib.sha512(m).digest()


def _inv(x):
    return pow(x, _Q - 2, _Q)


_D = -121665 * _inv(121666) % _Q
_I = pow(2, (_Q - 1) // 4, _Q)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_D * y * y + 1)
    x = pow(xx, (_Q + 3) // 8, _Q)
    if (x * x - xx) % _Q != 0:
        x = (x * _I) % _Q
    if x % 2 != 0:
        x = _Q - x
    return x


def _edwards(p, q):
    x1, y1 = p
    x2, y2 = q
    d = _D
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - d * x1 * x2 * y1 * y2)
    return [x3 % _Q, y3 % _Q]


def _scalarmult(p, e):
    q = [0, 1]
    while e > 0:
        if e & 1:
            q = _edwards(q, p)
        p = _edwards(p, p)
        e >>= 1
    return q


_BY = 4 * _inv(5) % _Q
_BX = _xrecover(_BY)
_BASEPOINT = [_BX % _Q, _BY % _Q]


def _bit(h, i):
    return (h[i >> 3] >> (i & 7)) & 1


def _encodeint(y):
    return y.to_bytes(32, "little")


def _encodepoint(p):
    x, y = p
    bits = [(y >> i) & 1 for i in range(_B - 1)] + [x & 1]
    return bytes(sum(bits[i * 8 + j] << j for j in range(8)) for i in range(_B // 8))


def _secret_expand(seed):
    h = _H(seed)
    a = 2 ** (_B - 2) + sum(2 ** i * _bit(h, i) for i in range(3, _B - 2))
    return a, h


def ed25519_publickey(seed):
    a, _ = _secret_expand(seed)
    return _encodepoint(_scalarmult(_BASEPOINT, a))


def ed25519_sign(message, seed):
    pk = ed25519_publickey(seed)
    a, h = _secret_expand(seed)
    r = int.from_bytes(_H(h[32:64] + message), "little") % _L
    r_point = _encodepoint(_scalarmult(_BASEPOINT, r))
    hram = int.from_bytes(_H(r_point + pk + message), "little") % _L
    s = (r + hram * a) % _L
    return r_point + _encodeint(s)


def ed25519_verify(signature, public_key, message):
    if len(signature) != 64 or len(public_key) != 32:
        return False
    r_point, s = signature[:32], int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    y = int.from_bytes(r_point, "little") & ((1 << 255) - 1)
    if y >= _Q:
        return False
    try:
        r_check = _xrecover(y)
    except ZeroDivisionError:
        return False
    sign_bit = r_point[31] >> 7
    if r_check & 1 != sign_bit:
        r_check = _Q - r_check
    r_point_dec = [r_check, y]
    pk_y = int.from_bytes(public_key, "little") & ((1 << 255) - 1)
    pk_x = _xrecover(pk_y)
    if pk_x & 1 != public_key[31] >> 7:
        pk_x = _Q - pk_x
    pk_point = [pk_x, pk_y]
    hram = int.from_bytes(_H(r_point + public_key + message), "little") % _L
    lhs = _scalarmult(_BASEPOINT, s)
    rhs = _edwards(r_point_dec, _scalarmult(pk_point, hram))
    return lhs[0] % _Q == rhs[0] % _Q and lhs[1] % _Q == rhs[1] % _Q


# ------------------------------------------------- cha ChaCha20 / Poly1305 ---

def _rotl32(v, c):
    return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF


def _chacha_rounds(state):
    def qr(a, b, c, d):
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] = _rotl32(state[d] ^ state[a], 16)
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] = _rotl32(state[b] ^ state[c], 12)
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] = _rotl32(state[d] ^ state[a], 8)
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] = _rotl32(state[b] ^ state[c], 7)

    for _ in range(10):
        qr(0, 4, 8, 12)
        qr(1, 5, 9, 13)
        qr(2, 6, 10, 14)
        qr(3, 7, 11, 15)
        qr(0, 5, 10, 15)
        qr(1, 6, 11, 12)
        qr(2, 7, 8, 13)
        qr(3, 4, 9, 14)


def chacha20_block(key, counter, nonce12):
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key))
    state += [counter & 0xFFFFFFFF]
    state += list(struct.unpack("<3I", nonce12))
    working = list(state)
    _chacha_rounds(working)
    return struct.pack("<16I", *[(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)])


def hchacha20(key, nonce16):
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key))
    state += list(struct.unpack("<4I", nonce16))
    _chacha_rounds(state)
    return struct.pack("<8I", state[0], state[1], state[2], state[3],
                       state[12], state[13], state[14], state[15])


def chacha20_xor(key, nonce12, data, counter=1):
    out = bytearray()
    for off in range(0, len(data), 64):
        ks = chacha20_block(key, counter + off // 64, nonce12)
        chunk = data[off:off + 64]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


def poly1305_mac(key32, msg):
    r = int.from_bytes(key32[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key32[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block + b"\x01", "little")
        acc = ((acc + n) * r) % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _aead_mac_data(aad, ct):
    return (aad + b"\x00" * (-len(aad) % 16) + ct + b"\x00" * (-len(ct) % 16)
            + struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct)))


def chacha20_poly1305_encrypt(key, nonce12, aad, plaintext):
    otk = chacha20_block(key, 0, nonce12)[:32]
    ct = chacha20_xor(key, nonce12, plaintext, counter=1)
    return ct, poly1305_mac(otk, _aead_mac_data(aad, ct))


def chacha20_poly1305_decrypt(key, nonce12, aad, ciphertext, tag):
    otk = chacha20_block(key, 0, nonce12)[:32]
    if not hmaclib.compare_digest(poly1305_mac(otk, _aead_mac_data(aad, ciphertext)), tag):
        raise ValueError("authentication failed")
    return chacha20_xor(key, nonce12, ciphertext, counter=1)


def xchacha20_poly1305_encrypt(key, nonce24, aad, plaintext):
    subkey = hchacha20(key, nonce24[:16])
    return chacha20_poly1305_encrypt(subkey, b"\x00" * 4 + nonce24[16:24], aad, plaintext)


def xchacha20_poly1305_decrypt(key, nonce24, aad, ciphertext, tag):
    subkey = hchacha20(key, nonce24[:16])
    return chacha20_poly1305_decrypt(subkey, b"\x00" * 4 + nonce24[16:24], aad, ciphertext, tag)


# ---------------------------------------------------------------- hkdf ------

def hkdf_sha256(ikm, salt, info, length=32):
    prk = hmaclib.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmaclib.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def derive_file_key(k_root, salt, tweak_id):
    return hkdf_sha256(k_root, salt, KDF_INFO_PREFIX + tweak_id.encode(), 32)


# ---------------------------------------------------------------- mach-o ----

MH_MAGIC_64 = 0xFEEDFACF
FAT_MAGIC_BE = b"\xca\xfe\xba\xbe"
FAT_MAGIC64_BE = b"\xca\xfe\xba\xbf"
LC_CODE_SIGNATURE = 0x1D


def _macho_slice_signed(data):
    if len(data) < 32:
        return False
    if struct.unpack_from("<I", data, 0)[0] != MH_MAGIC_64:
        return False
    ncmds = struct.unpack_from("<I", data, 16)[0]
    sizeofcmds = struct.unpack_from("<I", data, 20)[0]
    off = 32
    end = min(32 + sizeofcmds, len(data))
    for _ in range(ncmds):
        if off + 8 > end:
            return False
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmdsize < 8:
            return False
        if cmd == LC_CODE_SIGNATURE:
            return True
        off += cmdsize
    return False


def macho_check_signed(data):
    if len(data) < 8:
        return False
    if data[:4] in (FAT_MAGIC_BE, FAT_MAGIC64_BE):
        nfat = int.from_bytes(data[4:8], "big")
        signed_any = False
        for i in range(nfat):
            off = 8 + i * 20
            if off + 20 > len(data):
                return False
            slice_off = int.from_bytes(data[off + 8:off + 12], "big")
            slice_size = int.from_bytes(data[off + 12:off + 16], "big")
            if slice_off + slice_size > len(data):
                return False
            if _macho_slice_signed(data[slice_off:slice_off + slice_size]):
                signed_any = True
        return signed_any
    return _macho_slice_signed(data)


# ------------------------------------------------------------- container ----

def build_manifest(payload_hash, salt, nonce, payload_size, tweak_id, version,
                   min_ios, target_jb, filters):
    tweak_id_b = tweak_id.encode()[:TWEAK_ID_LEN - 1]
    version_b = version.encode()[:VERSION_LEN - 1]
    m = struct.pack("<IHH", min_ios, target_jb, 0)
    m += payload_hash + salt + nonce
    m += struct.pack("<Q", payload_size)
    m += tweak_id_b.ljust(TWEAK_ID_LEN, b"\x00")
    m += version_b.ljust(VERSION_LEN, b"\x00")
    fl = b""
    for f in filters[:MAX_FILTERS]:
        fl += f.encode()[:FILTER_LEN - 1].ljust(FILTER_LEN, b"\x00")
    m += fl.ljust(MAX_FILTERS * FILTER_LEN, b"\x00")
    if len(m) != MANIFEST_SIZE:
        raise ValueError("manifest size mismatch: %d" % len(m))
    return m


def parse_manifest(m):
    (min_ios, target_jb, flags) = struct.unpack_from("<IHH", m, 0)
    payload_hash = m[8:40]
    salt = m[40:72]
    nonce = m[72:96]
    payload_size = struct.unpack_from("<Q", m, 96)[0]
    tweak_id = m[104:168].split(b"\x00")[0].decode()
    version = m[168:200].split(b"\x00")[0].decode()
    filters = []
    for i in range(MAX_FILTERS):
        raw = m[200 + i * FILTER_LEN:200 + (i + 1) * FILTER_LEN]
        f = raw.split(b"\x00")[0].decode()
        if f:
            filters.append(f)
    return {
        "min_ios": min_ios,
        "target_jb": target_jb,
        "flags": flags,
        "payload_hash": payload_hash,
        "salt": salt,
        "nonce": nonce,
        "payload_size": payload_size,
        "tweak_id": tweak_id,
        "version": version,
        "filters": filters,
    }


def build_container(payload, seed, k_root, tweak_id, version, min_ios, target_jb,
                    filters, salt=None, nonce=None):
    if not macho_check_signed(payload):
        raise ValueError("payload is not a signed Mach-O (run: ldid -S <dylib>)")
    salt = salt if salt is not None else secrets.token_bytes(32)
    nonce = nonce if nonce is not None else secrets.token_bytes(24)
    payload_hash = hashlib.sha256(payload).digest()
    manifest = build_manifest(payload_hash, salt, nonce, len(payload), tweak_id,
                              version, min_ios, target_jb, filters)
    header = MYJB_MAGIC + bytes([FORMAT_VERSION, ALGO_ID]) + struct.pack("<HI", 0, MANIFEST_SIZE)
    signed_area = header + manifest
    signature = ed25519_sign(signed_area, seed)
    key = derive_file_key(k_root, salt, tweak_id)
    ciphertext, tag = xchacha20_poly1305_encrypt(key, nonce, signed_area, payload)
    return signed_area + signature + ciphertext + tag


def parse_container(data, pubkey=None):
    if len(data) < 12 + MANIFEST_SIZE + 64 + 16:
        raise ValueError("file too small")
    if data[:4] != MYJB_MAGIC:
        raise ValueError("bad magic")
    if data[4] != FORMAT_VERSION:
        raise ValueError("unsupported format_version %d" % data[4])
    if data[5] != ALGO_ID:
        raise ValueError("unsupported algo_id %d" % data[5])
    manifest_size = struct.unpack_from("<I", data, 8)[0]
    if manifest_size != MANIFEST_SIZE:
        raise ValueError("unsupported manifest_size %d" % manifest_size)
    signed_area = data[:12 + manifest_size]
    signature = data[12 + manifest_size:12 + manifest_size + 64]
    if pubkey is not None and not ed25519_verify(signature, pubkey, signed_area):
        raise ValueError("Ed25519 signature invalid")
    manifest = parse_manifest(data[12:12 + manifest_size])
    ct_off = 12 + manifest_size + 64
    ct_end = ct_off + manifest["payload_size"]
    if len(data) != ct_end + 16:
        raise ValueError("size mismatch: ciphertext+tag != file length")
    manifest["signature"] = signature
    manifest["ciphertext"] = data[ct_off:ct_end]
    manifest["tag"] = data[ct_end:]
    return manifest


def decrypt_container(manifest, k_root, signed_area):
    key = derive_file_key(k_root, manifest["salt"], manifest["tweak_id"])
    return xchacha20_poly1305_decrypt(key, manifest["nonce"], signed_area,
                                      manifest["ciphertext"], manifest["tag"])


# ---------------------------------------------------------------- selftest --

def _hex(s):
    return bytes.fromhex(s)


def selftest():
    failures = 0

    def check(name, cond):
        nonlocal failures
        print(("PASS " if cond else "FAIL ") + name)
        if not cond:
            failures += 1

    seed1 = _hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pk1 = _hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig1 = _hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    check("ed25519 pubkey (RFC 8032 test 1)", ed25519_publickey(seed1) == pk1)
    check("ed25519 sign (RFC 8032 test 1)", ed25519_sign(b"", seed1) == sig1)
    check("ed25519 verify (RFC 8032 test 1)",
          ed25519_verify(sig1, pk1, b"") and not ed25519_verify(sig1, pk1, b"x"))

    seed2 = _hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
    pk2 = _hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
    sig2 = _hex("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00")
    check("ed25519 sign (RFC 8032 test 2)", ed25519_sign(b"\x72", seed2) == sig2)
    check("ed25519 verify (RFC 8032 test 2)", ed25519_verify(sig2, pk2, b"\x72"))

    ks_key = _hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    ks_nonce = _hex("000000090000004a00000000")
    ks_out = _hex("10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                  "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
    check("chacha20 block (RFC 8439 2.3.2)", chacha20_block(ks_key, 1, ks_nonce) == ks_out)

    poly_key = _hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
    poly_msg = b"Cryptographic Forum Research Group"
    poly_tag = _hex("a8061dc1305136c6c22b8baf0c0127a9")
    check("poly1305 (RFC 8439 2.5.2)", poly1305_mac(poly_key, poly_msg) == poly_tag)

    aead_key = _hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    aead_nonce = _hex("070000004041424344454647")
    aead_aad = _hex("50515253c0c1c2c3c4c5c6c7")
    aead_pt = (b"Ladies and Gentlemen of the class of '99: If I could offer you "
               b"only one tip for the future, sunscreen would be it.")
    aead_ct = _hex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
                   "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
                   "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
                   "3ff4def08e4b7a9de576d26586cec64b6116")
    aead_tag = _hex("1ae10b594f09e26a7e902ecbd0600691")
    ct, tag = chacha20_poly1305_encrypt(aead_key, aead_nonce, aead_aad, aead_pt)
    check("aead chacha20-poly1305 encrypt (RFC 8439 2.8.2)", ct == aead_ct and tag == aead_tag)
    check("aead chacha20-poly1305 decrypt (RFC 8439 2.8.2)",
          chacha20_poly1305_decrypt(aead_key, aead_nonce, aead_aad, aead_ct, aead_tag) == aead_pt)

    hc_key = ks_key
    hc_nonce = _hex("000000090000004a0000000031415927")
    hc_out = _hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
    check("hchacha20 (draft-irtf-cfrg-xchacha 2.2.1)", hchacha20(hc_key, hc_nonce) == hc_out)

    x_key = aead_key
    x_nonce = _hex("404142434445464748494a4b4c4d4e4f5051525354555658")
    x_ct, x_tag = xchacha20_poly1305_encrypt(x_key, x_nonce, aead_aad, aead_pt)
    check("xchacha20-poly1305 roundtrip + tamper detect",
          xchacha20_poly1305_decrypt(x_key, x_nonce, aead_aad, x_ct, x_tag) == aead_pt
          and _tamper_fails(x_key, x_nonce, aead_aad, x_ct, x_tag))

    hkdf_ikm = b"\x0b" * 22
    hkdf_salt = _hex("000102030405060708090a0b0c")
    hkdf_info = _hex("f0f1f2f3f4f5f6f7f8f9")
    hkdf_okm = _hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                    "34007208d5b887185865")
    check("hkdf-sha256 (RFC 5869 A.1)",
          hkdf_sha256(hkdf_ikm, hkdf_salt, hkdf_info, 42) == hkdf_okm)

    print("%d failure(s)" % failures)
    return failures


def _tamper_fails(key, nonce, aad, ct, tag):
    bad = bytearray(ct)
    bad[0] ^= 0x01
    try:
        xchacha20_poly1305_decrypt(key, nonce, aad, bytes(bad), tag)
        return False
    except ValueError:
        return True


# ------------------------------------------------------------------- cli -----

def parse_min_ios(s):
    parts = s.split(".")
    major = int(parts[0])
    minor = int(parts[1]) if len(parts) > 1 else 0
    return major * 100 + minor


def load_seed(args):
    if args.seed_hex:
        raw = bytes.fromhex(args.seed_hex)
        if len(raw) != 32:
            raise ValueError("seed must be 32 bytes")
        return raw
    with open(args.seed_file, "rb") as f:
        raw = f.read()
    if len(raw) == 64:
        raw = raw[:32]
    if len(raw) != 32:
        raise ValueError("seed file must contain 32 (or 64) bytes")
    return raw


def load_kdev(args):
    if args.kdev_hex:
        raw = bytes.fromhex(args.kdev_hex)
    else:
        with open(args.kdev, "rb") as f:
            raw = f.read()
    if len(raw) != 32:
        raise ValueError("kdev must be 32 bytes")
    return raw


def cmd_build(args):
    seed = load_seed(args)
    k_root = load_kdev(args)
    with open(args.input, "rb") as f:
        payload = f.read()
    salt = bytes.fromhex(args.salt_hex) if args.salt_hex else None
    nonce = bytes.fromhex(args.nonce_hex) if args.nonce_hex else None
    container = build_container(payload, seed, k_root, args.id, args.version,
                                parse_min_ios(args.min_ios), TARGET_JB[args.target_jb],
                                args.filter or [], salt, nonce)
    with open(args.output, "wb") as f:
        f.write(container)
    pubkey = ed25519_publickey(seed)
    print("container : %s (%d bytes)" % (args.output, len(container)))
    print("tweak_id  : %s  version %s" % (args.id, args.version))
    print("min_ios   : %d  target_jb: %s" % (parse_min_ios(args.min_ios), args.target_jb))
    print("filters   : %s" % (", ".join(args.filter) if args.filter else "(all processes)"))
    print("payload   : %d bytes  sha256 %s" % (len(payload), hashlib.sha256(payload).hexdigest()))
    print("pubkey    : %s" % pubkey.hex())


def cmd_info(args):
    with open(args.info, "rb") as f:
        data = f.read()
    pubkey = bytes.fromhex(args.pubkey_hex) if args.pubkey_hex else None
    manifest = parse_container(data, pubkey)
    print("format_version : %d  algo_id: %d" % (data[4], data[5]))
    print("tweak_id       : %s  version %s" % (manifest["tweak_id"], manifest["version"]))
    print("min_ios        : %d  target_jb: 0x%04x  flags: 0x%04x"
          % (manifest["min_ios"], manifest["target_jb"], manifest["flags"]))
    print("filters        : %s" % (", ".join(manifest["filters"]) or "(all processes)"))
    print("payload_size   : %d  sha256 %s"
          % (manifest["payload_size"], manifest["payload_hash"].hex()))
    print("salt           : %s" % manifest["salt"].hex())
    print("nonce          : %s" % manifest["nonce"].hex())
    print("signature      : %s" % manifest["signature"].hex())
    print("signed_ok      : %s" % ("yes" if pubkey is not None else "not checked (no --pubkey-hex)"))


def main():
    ap = argparse.ArgumentParser(description="myJB container builder")
    ap.add_argument("--selftest", action="store_true", help="run crypto test vectors")
    ap.add_argument("--gen-key", action="store_true", help="generate ed25519 seed + pubkey")
    ap.add_argument("--info", metavar="FILE", help="dump/verify a .myjb container")
    ap.add_argument("--pubkey-hex", help="public key for --info verification")

    ap.add_argument("--in", dest="input", help="input signed dylib")
    ap.add_argument("--out", dest="output", help="output .myjb container")
    ap.add_argument("--id", help="tweak id (reverse-dns)")
    ap.add_argument("--version", default="1.0.0")
    ap.add_argument("--min-ios", default="12.0")
    ap.add_argument("--target-jb", default="amethyst", choices=sorted(TARGET_JB.keys()))
    ap.add_argument("--filter", action="append", help="fnmatch filter (repeatable)")
    ap.add_argument("--seed-hex", help="ed25519 seed (32 bytes hex)")
    ap.add_argument("--seed-file", help="ed25519 seed file (32/64 bytes)")
    ap.add_argument("--kdev", help="K_root file (32 bytes)")
    ap.add_argument("--kdev-hex", help="K_root hex (32 bytes)")
    ap.add_argument("--salt-hex", help="override HKDF salt (32 bytes hex)")
    ap.add_argument("--nonce-hex", help="override XChaCha nonce (24 bytes hex)")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(1 if selftest() else 0)
    if args.gen_key:
        seed = secrets.token_bytes(32)
        print("seed-hex: %s" % seed.hex())
        print("pubkey  : %s" % ed25519_publickey(seed).hex())
        return
    if args.info:
        cmd_info(args)
        return
    if not args.input or not args.output or not args.id:
        ap.error("--in, --out and --id are required (or use --selftest/--gen-key/--info)")
    if not args.seed_hex and not args.seed_file:
        ap.error("--seed-hex or --seed-file is required")
    if not args.kdev and not args.kdev_hex:
        ap.error("--kdev or --kdev-hex is required")
    cmd_build(args)


if __name__ == "__main__":
    main()
