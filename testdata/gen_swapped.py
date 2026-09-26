"""Writes bin-swapped.cpio: bin.cpio with each header's 16-bit words byte-swapped.

The old binary variant stores a 16-bit magic in the WRITER's byte order, so the
same two bytes are 0o070707 on one machine and 0o143561 on the other. No tool here
writes the second kind, and it is exactly the variant a reader gets wrong -- so it
is crafted, and the test asserts the two fixtures really carry different magic.

Layout of the 26-byte header, all 16-bit words:
    0 magic  2 dev  4 ino  6 mode  8 uid  10 gid  12 nlink  14 rdev
    16 mtime (two words, HIGH FIRST)  20 namesize  22 filesize (two words, HIGH FIRST)
Names pad to an EVEN length, and so does data -- not to four.
"""

import struct

HDR = 26
d = open("bin.cpio", "rb").read()
out = bytearray()
off = 0
while off + HDR <= len(d):
    hdr = d[off:off + HDR]
    if struct.unpack("<H", hdr[0:2])[0] != 0o070707:
        break
    namesize = struct.unpack("<H", hdr[20:22])[0]
    filesize = (struct.unpack("<H", hdr[22:24])[0] << 16) | struct.unpack("<H", hdr[24:26])[0]
    swapped = bytearray()
    for i in range(0, HDR, 2):
        swapped += bytes([hdr[i + 1], hdr[i]])
    namelen = namesize + (namesize & 1)
    datalen = filesize + (filesize & 1)
    out += swapped + d[off + HDR:off + HDR + namelen + datalen]
    name = d[off + HDR:off + HDR + namesize - 1]
    off += HDR + namelen + datalen
    if name == b"TRAILER!!!":
        break

first = struct.unpack("<H", out[0:2])[0]
assert first == 0o143561, f"first word reads 0o{first:o}, want 0o143561"
open("bin-swapped.cpio", "wb").write(bytes(out))
print(f"bin-swapped.cpio: {len(out)} bytes")
