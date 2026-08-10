"""Audit a client-produced MOS2 container against the file it should encode.

`HrMos2CompFile` emits streams that do not decode back to their input. This
measures the defect instead of eyeballing a hex diff, and reports the one
invariant that pins it down: the encoder consumes exactly `lookahead` = chunk
size input bytes, so the emitted token lengths must sum to the chunk size.

Usage:  mos2_audit.py <container.mos2> <original-file>

Per chunk it prints the decoded length against the expected length, the token
and block counts, and — for a chunk that drifts — the first divergent token.
See docs/MOSSHELL.md 7.4.6.
"""

import struct
import sys
import zlib

import mos2_inflate as M

MAGIC = b"MOS2"


def chunk_bodies(blob):
    """Split a container into per-chunk raw DEFLATE bodies."""
    if not blob.startswith(MAGIC):
        raise ValueError("missing MOS2 magic")
    size = struct.unpack_from("<H", blob, 6)[0]
    total = struct.unpack_from("<I", blob, 8)[0]
    pos, out = 0x14, []
    for _ in range(-(-total // size)):
        length = struct.unpack_from("<I", blob, pos)[0]
        pos += 4
        out.append(blob[pos + 2 : pos + length])
        pos += length
    return size, total, out


def token_stream(body):
    """Decode one chunk, returning (output, tokens, per-block token counts)."""
    b = M.Bits(body)
    out = bytearray()
    tokens, blocks = [], []
    while True:
        final = b.get(1)
        btype = b.get(2)
        count = 0
        if btype == 1:
            ll = [8] * 144 + [9] * 112 + [7] * 24 + [8] * 8
            dl = [5] * 30
        elif btype == 2:
            hlit = b.get(5) + 257
            hdist = b.get(5) + 1
            hclen = b.get(4) + 4
            order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
            cl = [0] * 19
            for i in range(hclen):
                cl[order[i]] = b.get(3)
            ct, cm = M.build(cl)
            lens = []
            while len(lens) < hlit + hdist:
                s = M.decode(b, ct, cm)
                if s < 16:
                    lens.append(s)
                elif s == 16:
                    lens += [lens[-1]] * (b.get(2) + 3)
                elif s == 17:
                    lens += [0] * (b.get(3) + 3)
                else:
                    lens += [0] * (b.get(7) + 11)
            ll, dl = lens[:hlit], lens[hlit:]
        else:
            raise ValueError(f"unexpected block type {btype}")
        lt, lm = M.build(ll)
        dt, dm = M.build(dl)
        while True:
            s = M.decode(b, lt, lm)
            if s == 256:
                break
            count += 1
            if s < 256:
                tokens.append((len(out), "lit", s, 1))
                out.append(s)
            else:
                i = s - 257
                L = M.LBASE[i] + b.get(M.LEXT[i])
                ds = M.decode(b, dt, dm)
                D = M.DBASE[ds] + b.get(M.DEXT[ds])
                tokens.append((len(out), "match", (L, D), L))
                for _ in range(L):
                    out.append(out[-D])
        blocks.append(count)
        if final:
            break
    return bytes(out), tokens, blocks


def audit(container, original):
    size, total, bodies = chunk_bodies(container)
    print(f"{len(bodies)} chunks of {size}, {total} bytes declared")
    bad = 0
    for i, body in enumerate(bodies):
        want = original[i * size : (i + 1) * size]
        got, tokens, blocks = token_stream(body)
        expected = len(want)
        drift = len(got) - expected
        # zlib must agree with the tracer, or the tracer is what is broken.
        z = zlib.decompressobj(-15)
        assert z.decompress(body) + z.flush() == got, "tracer disagrees with zlib"
        state = "OK    " if drift == 0 and got == want else "DRIFT!"
        print(
            f"  chunk {i}: {state} decoded {len(got)} vs {expected} "
            f"(drift {drift:+d}), {sum(blocks)} tokens in {len(blocks)} block(s)"
        )
        if got != want:
            bad += 1
            p = next(k for k in range(min(len(got), len(want))) if got[k] != want[k])
            tok = next(t for t in tokens if t[0] <= p < t[0] + t[3])
            kind = (
                f"literal {tok[2]:#04x}"
                if tok[1] == "lit"
                else f"match len={tok[2][0]} dist={tok[2][1]}"
            )
            print(f"      first divergence at {p}, emitted by {kind} at {tok[0]}")
            print(f"      file has {want[p:p + 8].hex(' ')}")
            print(f"      stream has {got[p:p + 8].hex(' ')}")
    print(f"\n{bad} of {len(bodies)} chunks do not encode their input")
    return 1 if bad else 0


if __name__ == "__main__":
    blob = open(sys.argv[1], "rb").read()
    src = open(sys.argv[2], "rb").read()
    raise SystemExit(audit(blob, src))
