# cpio

Reads the records of a **cpio** archive, in all four variants, and stops there —
pure Go, `CGO_ENABLED=0`, builds for every target Go builds for.

```go
recs, err := cpio.Records(ra, size)
```

| variant | magic | fields | padding |
|---|---|---|---|
| newc (SVR4, the initramfs one) | `070701` | 8 hex digits | name **and** data to four |
| crc | `070702` | 8 hex digits | as newc; the checksum is not verified |
| odc (POSIX.1) | `070707` | 6 octal digits | **none** |
| old binary | `0o070707` as a 16-bit **word** | 16-bit words | name and data to an **even** length |

## Why records and not a filesystem

Two packages needed this parser and they need different filesystems over it:
[`go-filesystems/unarchive`](https://github.com/go-filesystems/unarchive) indexes
into an `io.ReaderAt` it keeps open, and
[`go-filesystems/rpm`](https://github.com/go-filesystems/rpm) has the whole payload
decompressed in memory. Sharing the filesystem would have meant one of them
accepting the other's shape. Sharing the parser costs neither anything.

And the parser is where the defects live. `Record` carries the name, the mode, the
size, the **offset of the data in the reader**, a symbolic link's target and the
mtime — everything the header said, and nothing invented.

## The traps, each of them measured

- **newc pads the name AND the data to four bytes**, from the start of the archive.
  Forgetting either puts every later header one to three bytes out.
- **odc pads nothing at all.** A reader that applies newc's rule to it reads
  garbage from the second record onward.
- **The old binary variant's magic is `0o070707` as a 16-bit word**, so the same two
  bytes mean it on the machine that wrote them and `0o143561` on one of the other
  endianness. Both exist, and the order is **detected**, never assumed.
- **That variant's 32-bit fields are two words, high word first**, whatever the byte
  order of each word — and it pads to an **even** length, not to four.
- **A symbolic link's target is its DATA**, not a header field, so it is read here:
  a `Record` carries the target rather than an offset to it.
- **A reader that computes the next offset rather than being handed it** returned
  zero once, and the walk re-read record one for ever. The suite reported a
  ten-minute timeout, not a failure.

## The inode is read, and is not portable across the variants

`Record.Inode` is the number the header records, because a consumer reads it —
`go-filesystems/rpm` reports it in `Stat` — and a parser that dropped it would
force that consumer to invent one.

⛔ **It does not mean the same thing in every variant.** odc's field is six octal
digits and the old binary variant's is a 16-bit word, so neither can hold a real
inode: `cpio(1)` **renumbers** them 1..n when it writes those. Measured on one tree —
`257757054` in newc, `1` in both of the others. A caller using it as an identity
across two archives of the same files will be wrong.

It is also not unique within one archive: a cpio records hard links by repeating an
inode.

## `Record.Name` is the name as recorded

Not a clean path. GNU cpio writes `./real.txt` where other writers write
`real.txt`, and an archive made on Windows can carry backslashes. Normalising is
left to the caller, because both callers already do it — for lookups as well as for
listing — and a parser that silently rewrote names would make their two spellings
disagree with this one.

## `FileMode` is a translation, not a cast

`os.ModeDir` is `1 << 31`; POSIX's `S_IFDIR` is `0o040000`. Narrowing one to the
other drops every type bit. `FileMode` maps the seven `S_IF*` kinds, **and** setuid,
setgid and sticky — an archive records those, and a setuid binary read back as an
ordinary one is a mode meaning something other than what was packed.

## Two functions, because the two consumers are each right

```go
recs, err := cpio.Records(ra, size)       // an initramfs: block-padded, tolerant
recs, err := cpio.RecordsExact(ra, size)  // an RPM payload: exact length, strict
```

| | `Records` | `RecordsExact` |
|---|---|---|
| zero padding after the trailer | accepted | accepted |
| **non-zero** bytes after the trailer | accepted, stops there | **refused** |
| junk where a header should be | accepted, stops there | **refused** |
| no trailer at all | accepted | **refused** |

An initramfs is padded to a block, so refusing the zeros after its trailer would
refuse every one there is. An RPM payload has a length known exactly — from the end
of the header to the end of the file — so anything unparsed in it is damage, and a
reader that stops early and reports success hands back a package with files missing.

⛔ `RecordsExact` first required the archive to end *exactly* at the trailer, which
refuses everything `cpio(1)` writes: one clean fixture here has its trailer ending at
756 inside a 1024-byte file. The rule is that the tail must be **zeros**, which keeps
the padding and refuses the junk.

## Every numeric field is checked

Not the three the parser happens to use. A header field that is not a number means
the header is not a header, and reading it as zero gives a record that looks ordinary
and is not — an mtime of 1970 and an inode of 0 are both perfectly representable.

⛔ The two readers this package replaced **disagreed** about that: `rpm` checked all
of them, `unarchive` ignored the errors on inode and mtime. The strict one is right,
and it was the one tested against real packages. Consolidating on the lenient
behaviour would have been a regression that no test in either repository could see.

## Errors

| | |
|---|---|
| `ErrNotCpio` | the bytes begin with no cpio magic — try another reader |
| `ErrTruncated` | a header, a name or a record's data runs past the end — this archive is damaged |

They say different things and a caller acts differently on them, so six bytes of
newc magic and nothing else is **truncated**, not unrecognised.

A read failure from underneath is returned **as itself**, wrapped in neither: a
failing disk must not read as a damaged file.

## Fixtures

`testdata/gen.sh` rebuilds them, and asserts its own premise — `cpio` must read each
one back before it is kept. `bin-swapped.cpio` is crafted by
`testdata/gen_swapped.py`, because no tool here writes the other byte order, and the
test asserts the two binary fixtures really carry **different** magic words.

The four are read by `TestEveryVariantReadsTheSameArchive`, which is the assertion
no single-variant test can make: four header formats over one tree must agree about
every record, compared entry by entry.

## Licence

BSD-3-Clause.
