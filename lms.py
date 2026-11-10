"""Small LMS / LM-OTS implementation (RFC 8554).

Parameter set: LMS_SHA256_M32_H10 with LMOTS_SHA256_N32_W4, i.e. a tree of
1024 one-time keys. Only what the measurement needs is here: key generation,
signing and verification. Verification counts the SHA-256 compression blocks
it uses, so the cost can be compared with the other schemes.

Not for production use. Private key state is kept in memory and is not
protected or persisted.
"""
import hashlib
import os
import struct

N, W, P, LS, H = 32, 4, 67, 4, 10
LMOTS_TYPE = 4      # LMOTS_SHA256_N32_W4
LMS_TYPE = 6        # LMS_SHA256_M32_H10
D_PBLC, D_MESG, D_LEAF, D_INTR = 0x8080, 0x8181, 0x8282, 0x8383


def u32(x):
    return struct.pack(">I", x)


def u16(x):
    return struct.pack(">H", x)


def u8(x):
    return struct.pack(">B", x)


class Counter:
    blocks = 0
    calls = 0


def sha(data, count=False):
    if count:
        Counter.calls += 1
        Counter.blocks += (len(data) + 9 + 63) // 64
    return hashlib.sha256(data).digest()


def coef(s, i):
    return (s[(i * W) // 8] >> (8 - (W * (i % (8 // W)) + W))) & ((1 << W) - 1)


def cksm(q):
    total = 0
    for i in range((N * 8) // W):
        total += (1 << W) - 1 - coef(q, i)
    return u16(total << LS)


def ots_keygen(I, q, seed):
    x = [sha(I + u32(q) + u16(i) + b"\xff" + seed) for i in range(P)]
    ys = []
    for i in range(P):
        tmp = x[i]
        for j in range((1 << W) - 1):
            tmp = sha(I + u32(q) + u16(i) + u8(j) + tmp)
        ys.append(tmp)
    K = sha(I + u32(q) + u16(D_PBLC) + b"".join(ys))
    return x, K


def ots_sign(I, q, x, msg):
    C = os.urandom(N)
    Q = sha(I + u32(q) + u16(D_MESG) + C + msg)
    Qc = Q + cksm(Q)
    y = []
    for i in range(P):
        tmp = x[i]
        for j in range(coef(Qc, i)):
            tmp = sha(I + u32(q) + u16(i) + u8(j) + tmp)
        y.append(tmp)
    return u32(LMOTS_TYPE) + C + b"".join(y)


def ots_pk_from_sig(I, q, sig, msg):
    C = sig[4:4 + N]
    ys = [sig[4 + N + i * N: 4 + N + (i + 1) * N] for i in range(P)]
    Q = sha(I + u32(q) + u16(D_MESG) + C + msg, True)
    Qc = Q + cksm(Q)
    z = []
    for i in range(P):
        tmp = ys[i]
        for j in range(coef(Qc, i), (1 << W) - 1):
            tmp = sha(I + u32(q) + u16(i) + u8(j) + tmp, True)
        z.append(tmp)
    return sha(I + u32(q) + u16(D_PBLC) + b"".join(z), True)


class LMSKey:
    def __init__(self):
        self.I = os.urandom(16)
        self.seed = os.urandom(32)
        self.q = 0
        self.ots = [ots_keygen(self.I, q, self.seed) for q in range(1 << H)]
        T = {}
        for r in range((1 << (H + 1)) - 1, 0, -1):
            if r >= (1 << H):
                T[r] = sha(self.I + u32(r) + u16(D_LEAF) + self.ots[r - (1 << H)][1])
            else:
                T[r] = sha(self.I + u32(r) + u16(D_INTR) + T[2 * r] + T[2 * r + 1])
        self.T = T
        self.pub = u32(LMS_TYPE) + u32(LMOTS_TYPE) + self.I + T[1]

    def sign(self, msg):
        # each one-time key may only be used once, so the index moves on
        q = self.q
        self.q += 1
        sig_ots = ots_sign(self.I, q, self.ots[q][0], msg)
        r = (1 << H) + q
        path = []
        while r > 1:
            path.append(self.T[r ^ 1])
            r //= 2
        return u32(q) + sig_ots + u32(LMS_TYPE) + b"".join(path)


def lms_verify(pub, sig, msg):
    I, root = pub[8:24], pub[24:56]
    q = struct.unpack(">I", sig[:4])[0]
    ots_len = 4 + N + P * N
    sig_ots = sig[4:4 + ots_len]
    path_raw = sig[4 + ots_len + 4:]
    path = [path_raw[i * N:(i + 1) * N] for i in range(H)]
    Kc = ots_pk_from_sig(I, q, sig_ots, msg)
    r = (1 << H) + q
    tmp = sha(I + u32(r) + u16(D_LEAF) + Kc, True)
    i = 0
    while r > 1:
        if r % 2:
            tmp = sha(I + u32(r // 2) + u16(D_INTR) + path[i] + tmp, True)
        else:
            tmp = sha(I + u32(r // 2) + u16(D_INTR) + tmp + path[i], True)
        r //= 2
        i += 1
    return tmp == root
