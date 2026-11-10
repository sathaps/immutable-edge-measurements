"""Cost of a dual-signature check in the boot loader.

The boot loader accepts an image only if a classical signature and a
post-quantum signature both verify over the image's SHA-256 digest. This
script measures what that costs: key and signature sizes, verification
time per scheme, and the time to hash a 1 MiB image. It also checks that
the acceptance rule rejects images where either signature, or the image
itself, has been altered.

Classical: RSA-3072 (PKCS#1 v1.5, SHA-256) and ECDSA P-256.
Post-quantum: ML-DSA-44/65/87 (FIPS 204) through OpenSSL.
LMS (RFC 8554) uses lms.py; its verify time is not measured here, only
its sizes and the number of SHA-256 blocks a verification needs.

Usage: python3 measure_verify.py > results.json
"""
import hashlib
import json
import os
import platform
import statistics
import sys
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, mldsa, padding, rsa

import lms

REPS = 400


def median_us(fn, reps=REPS):
    times = []
    for _ in range(reps):
        t0 = time.perf_counter_ns()
        fn()
        times.append(time.perf_counter_ns() - t0)
    return statistics.median(times) / 1000.0


def raw_len(pub):
    return len(pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def flip(data):
    b = bytearray(data)
    b[len(b) // 2] ^= 1
    return bytes(b)


def main():
    out = {
        "openssl": backend.openssl_version_text(),
        "python": sys.version.split()[0],
        "machine": platform.machine(),
        "processor": platform.processor() or "see lscpu",
    }

    image = os.urandom(1 << 20)
    digest = hashlib.sha256(image).digest()
    out["sha256_1MiB_us"] = median_us(lambda: hashlib.sha256(image).digest(), 100)

    rows = []

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    rsa_sig = rsa_key.sign(digest, padding.PKCS1v15(), hashes.SHA256())
    rsa_pub = rsa_key.public_key()
    rows.append({"scheme": "RSA-3072", "pk_bytes": 384, "sig_bytes": len(rsa_sig),
                 "verify_us": median_us(lambda: rsa_pub.verify(rsa_sig, digest, padding.PKCS1v15(), hashes.SHA256()))})

    ec_key = ec.generate_private_key(ec.SECP256R1())
    ec_sig = ec_key.sign(digest, ec.ECDSA(hashes.SHA256()))
    ec_pub = ec_key.public_key()
    rows.append({"scheme": "ECDSA P-256", "pk_bytes": 64, "sig_bytes": 64, "sig_der_bytes": len(ec_sig),
                 "verify_us": median_us(lambda: ec_pub.verify(ec_sig, digest, ec.ECDSA(hashes.SHA256())))})

    pq = {}
    for name, cls in [("ML-DSA-44", mldsa.MLDSA44PrivateKey),
                      ("ML-DSA-65", mldsa.MLDSA65PrivateKey),
                      ("ML-DSA-87", mldsa.MLDSA87PrivateKey)]:
        key = cls.generate()
        sig = key.sign(digest)
        pub = key.public_key()
        rows.append({"scheme": name, "pk_bytes": raw_len(pub), "sig_bytes": len(sig),
                     "verify_us": median_us(lambda: pub.verify(sig, digest))})
        pq[name] = (pub, sig)

    # LMS: sizes and hash work only
    lms_key = lms.LMSKey()
    blocks, lms_sig = [], None
    for _ in range(20):
        lms_sig = lms_key.sign(digest)
        lms.Counter.blocks = 0
        assert lms.lms_verify(lms_key.pub, lms_sig, digest)
        blocks.append(lms.Counter.blocks)
    rows.append({"scheme": "LMS SHA256 H10/W4", "pk_bytes": len(lms_key.pub), "sig_bytes": len(lms_sig),
                 "signatures_per_key": 1 << lms.H,
                 "verify_sha256_blocks_median": statistics.median(blocks),
                 "verify_sha256_blocks_max": max(blocks)})
    out["rows"] = rows

    def accept(img, classical_sig, pq_sig, pq_name="ML-DSA-65"):
        d = hashlib.sha256(img).digest()
        try:
            rsa_pub.verify(classical_sig, d, padding.PKCS1v15(), hashes.SHA256())
            pq[pq_name][0].verify(pq_sig, d)
        except InvalidSignature:
            return False
        return True

    pq_sig = pq["ML-DSA-65"][1]
    out["acceptance_checks"] = {
        "both signatures valid": accept(image, rsa_sig, pq_sig),
        "post-quantum signature altered": accept(image, rsa_sig, flip(pq_sig)),
        "classical signature altered": accept(image, flip(rsa_sig), pq_sig),
        "image altered": accept(flip(image), rsa_sig, pq_sig),
        "LMS valid": lms.lms_verify(lms_key.pub, lms_sig, digest),
        "LMS altered": lms.lms_verify(lms_key.pub, flip(lms_sig), digest),
    }
    out["dual_check_rsa3072_mldsa65_incl_hash_us"] = median_us(lambda: accept(image, rsa_sig, pq_sig), 100)

    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
