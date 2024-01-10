#!/usr/bin/env python3
# https://crypto.stackexchange.com/questions/83308/what-is-the-chainoffools-curveball-attack-on-ecdsa-on-windows-10-cryptoapi
# https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
from ecdsa import SigningKey, VerifyingKey
from ecdsa.curves import Curve
from ecdsa.ellipticcurve import PointJacobi
from ecdsa.util import randrange, sigdecode_string, string_to_number
from pwn import *
from sage.all import EllipticCurve, GF
import hashlib


def connect():
    return remote("manykey.chal.irisc.tf", 10102)


def main():
    with connect() as tube:
        tube.recvuntil(b"Hello, ")
        message = bytes.fromhex(tube.recvline().decode())
        print(f"{message.hex()=}")
        sig = bytes.fromhex(tube.recvline().decode())
        print(f"{sig.hex()=}")
        assert tube.recvline() == b"Here's my public key\n"
        pk_der = bytes.fromhex(tube.recvline().decode())
        print(f"{pk_der.hex()=}")
        pk = VerifyingKey.from_der(pk_der)
        print(f"{pk=}")
        curve = pk.curve
        curve_fp = curve.curve
        n = curve.order
        r, s = sigdecode_string(sig, n)
        print(f"{r=}")
        print(f"{s=}")
        z = string_to_number(hashlib.sha1(message).digest())
        print(f"{z=}")

        gfp = GF(curve_fp.p())
        ec = EllipticCurve(gfp, [curve_fp.a(), curve_fp.b()])
        g = ec(pk.pubkey.generator.x(), pk.pubkey.generator.y())
        assert g.order() == n

        # Verification sequence:
        # u1 = (z * s ^ -1) mod n
        # u2 = (r * s ^ -1) mod n
        # x1, y1 = u1 * g + u2 * pubkey
        # check: r == x1 mod n
        #
        # - The challenge does not validate the curve parameters.
        #   Keep the curve itself, but forge g, privkey and pubkey.
        # - The curve has prime order, so all points have the same order; we
        #   don't have to care about the order of the forged g.
        # - Set x1 to r. Compute y1.
        # - Pick a new random privkey.
        #   Note that pubkey = privkey * g.
        # - So we have the following equation:
        #   x1, y1 = u1 * g + u2 * privkey * g
        #   g = (u1 + u2 * privkey) ^ -1 * g
        # - Now we have everything to trick the remote.

        gfn = GF(n)
        s_inv = gfn(s).inverse_of_unit()
        print(f"{s_inv=}")
        u1 = gfn(z) * s_inv
        print(f"{u1=}")
        u2 = gfn(r) * s_inv
        print(f"{u2=}")

        x1 = gfp(r)
        print(f"{x1=}")
        y1 = (x1**3 + gfp(curve_fp.a()) * x1 + gfp(curve_fp.b())).nth_root(2)
        print(f"{y1=}")
        p1 = ec(x1, y1)
        print(f"{p1=}")
        privkey = gfn(randrange(n))
        print(f"{privkey=}")
        evil_g = int((u1 + u2 * privkey).inverse_of_unit()) * p1
        print(f"{evil_g=}")
        pubkey = int(privkey) * evil_g
        print(f"{pubkey=}")

        assert gfn(r) == gfn(x1)
        assert int(u1) * evil_g + int(u2) * pubkey == p1
        assert evil_g.order() == n

        evil_curve = Curve(
            name="evil",
            curve=curve_fp,
            generator=PointJacobi(
                curve=curve_fp,
                x=evil_g.xy()[0],
                y=evil_g.xy()[1],
                z=1,
                order=n,
                generator=True,
            ),
            oid=None,
            openssl_name=None,
        )
        evil_sk = SigningKey.from_secret_exponent(int(privkey), evil_curve)

        assert (
            evil_sk.privkey.secret_multiplier * evil_sk.curve.generator
            == evil_sk.verifying_key.pubkey.point
        )
        assert evil_sk.verifying_key.verify(sig, message)
        evil_sk.sign(b"")

        tube.sendlineafter(
            b"What was my private key again? (send me DER-encoded hex bytes)",
            evil_sk.to_der().hex().encode(),
        )
        tube.interactive()  # irisctf{key_generating_machine}


if __name__ == "__main__":
    main()
