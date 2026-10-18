"""Generate simple shield icons for the extension without any image libraries."""
import struct, zlib, sys, os

def shield(size):
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            u, v = (x + 0.5) / size, (y + 0.5) / size
            half = 0.4 if v < 0.55 else 0.4 * max(0.0, (0.95 - v) / 0.4)
            inside = 0.08 < v < 0.95 and abs(u - 0.5) <= half
            # white check mark inside
            check = inside and (abs(v - (0.55 + (u - 0.32))) < 0.06 and 0.3 < u < 0.47 or
                                abs(v - (0.72 - (u - 0.47) * 1.1)) < 0.06 and 0.45 < u < 0.7)
            row += bytes((255, 255, 255, 255)) if check else bytes((26, 115, 232, 255)) if inside else bytes(4)
        rows.append(bytes(row))
    def chunk(t, d): return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(b"".join(rows))) + chunk(b"IEND", b""))

out = sys.argv[1]
for s in (16, 48, 128):
    with open(os.path.join(out, f"icon{s}.png"), "wb") as f:
        f.write(shield(s))
