// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

// Package cpio reads the records of a cpio archive, in all four variants, and
// stops there.
//
// It returns records rather than a filesystem, and that is the whole design. Two
// packages needed this parser -- go-filesystems/unarchive for an initramfs and a
// .deb's data member, go-filesystems/rpm for a payload -- and they need DIFFERENT
// filesystems over it: unarchive indexes into an io.ReaderAt it keeps open, rpm has
// the whole payload decompressed in memory. Sharing the filesystem would have meant
// one of them accepting the other's shape; sharing the parser costs neither
// anything.
//
// And the parser is where the defects live. Every trap below was measured, and
// each one had been got wrong at least once:
//
//   - newc pads the name AND the data to four bytes, from the start of the
//     archive. Forgetting either puts every later header one to three bytes out.
//   - odc pads nothing at all.
//   - the old binary variant's magic is 0o070707 as a 16-bit WORD, so the same two
//     bytes mean it on the machine that wrote them and 0o143561 on one of the other
//     endianness. Both orders exist and the order is DETECTED, not assumed.
//   - that variant's 32-bit fields are two words, HIGH WORD FIRST, whatever the
//     byte order of each word -- and it pads to an even length, not to four.
//   - a reader that returns the next offset as a computed value rather than a
//     parameter returned zero once, and the walk re-read record one for ever. The
//     suite reported a ten-minute timeout, not a failure.
//
// CGO is not used, so this builds for every target Go builds for.
package cpio

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	iofs "io/fs"
	"strconv"
	"strings"
	"time"
)

// ErrNotCpio is returned when the bytes do not begin with any cpio magic.
var ErrNotCpio = errors.New("cpio: not a cpio archive")

// ErrTruncated is returned when a header or a name runs past the end.
var ErrTruncated = errors.New("cpio: the archive ends inside a record")

// Record is one entry, with its data left where it lies.
//
// Offset points into the reader Records was given, so a caller can hand out a
// section of it rather than copying anything.
type Record struct {
	// Name is the name AS RECORDED, which is not the same as a clean path: GNU
	// cpio writes "./real.txt" where other writers write "real.txt", and an
	// archive made on Windows can carry backslashes. Normalising is left to the
	// caller because both callers already do it, for lookups as well as for
	// listing, and a parser that silently rewrote names would make their two
	// spellings disagree with this one.
	Name string
	// Mode carries the permissions AND the type bits, already translated from
	// POSIX st_mode -- see FileMode for why that translation is not a cast.
	Mode iofs.FileMode
	Size int64
	// Offset is where this record's data begins in the reader.
	Offset int64
	// Link is the target of a symbolic link, read from the record's data. A cpio
	// stores it there rather than in the header, which is why it is read here and
	// not left to the caller.
	Link  string
	MTime time.Time
}

// Records reads every record in the archive.
//
// The variant is decided per record from its own magic, because an archive
// concatenated from two others is a thing that exists. Trailing padding after the
// trailer is normal -- an initramfs is padded to a block -- so what follows the
// trailer is ignored rather than refused.
func Records(ra io.ReaderAt, size int64) ([]Record, error) {
	var recs []Record
	off := int64(0)
	for off+6 <= size {
		magic := make([]byte, 6)
		if _, err := ra.ReadAt(magic, off); err != nil {
			return nil, fmt.Errorf("cpio: header at %d: %w", off, err)
		}
		var (
			r    *Record
			next int64
			err  error
		)
		switch string(magic) {
		case magicNewc, magicCRC:
			r, next, err = readNewc(ra, size, off)
		case magicODC:
			r, next, err = readODC(ra, size, off)
		default:
			order := binaryOrder(magic[:2])
			if order == nil {
				if off == 0 {
					return nil, fmt.Errorf("cpio: %q is no cpio magic this reads: %w",
						magic, ErrNotCpio)
				}
				// Trailing padding after the trailer is normal. Stopping with what
				// was read beats refusing the whole archive.
				return done(recs)
			}
			r, next, err = readBinary(ra, size, off, order)
		}
		if err != nil {
			return nil, err
		}
		if r == nil {
			return done(recs)
		}
		recs = append(recs, *r)
		off = next
	}
	return done(recs)
}

func done(recs []Record) ([]Record, error) {
	if len(recs) == 0 {
		return nil, fmt.Errorf("cpio: no entries: %w", ErrNotCpio)
	}
	return recs, nil
}

// The cpio variants this reads, by the six bytes each begins its headers with.
//
// All three are ASCII, which is what makes them readable without knowing the
// machine that wrote them. The fourth variant -- "old binary" -- stores a 16-bit
// magic in the writer's own byte order, so the same file means different things on
// different machines; it is recognised and refused rather than guessed at.
const (
	magicNewc   = "070701" // SVR4, the initramfs one: fields are 8 hex digits
	magicCRC    = "070702" // the same, with a checksum field that is filled in
	magicODC    = "070707" // POSIX.1 "odc": fields are 6 octal digits
	trailerName = "TRAILER!!!"
)

// binaryMagic is 0o070707 as a 16-bit WORD, which is what makes the old binary
// format byte-order dependent: the same two bytes are 0o070707 on the machine that
// wrote them and 0o143561 on one of the other endianness.
//
// So the order is DETECTED from the magic rather than assumed, and both are read.
// Guessing silently misreads every field of an archive written on the other kind of
// machine.
// The magics and the trailer name, exported because a WRITER needs them and they
// are facts about the format rather than about this reader.
//
// go-filesystems/unarchive writes newc, and had its own copies of these three until
// the parser moved here -- which is the duplication this package exists to end, one
// string constant included.
const (
	MagicNewc = magicNewc
	MagicCRC  = magicCRC
	MagicODC  = magicODC
	// TrailerName is the name of the record that ends an archive. It is the NAME,
	// not a magic: the trailer is an ordinary header whose name says stop.
	TrailerName = trailerName
)

const binaryMagic = 0o070707

// binaryHeaderLen is thirteen 16-bit words.
const binaryHeaderLen = 26

// readNewc reads one SVR4 header. A nil record means the trailer was reached.
func readNewc(ra io.ReaderAt, size, off int64) (*Record, int64, error) {
	const headerLen = 110
	if off+headerLen > size {
		return nil, 0, fmt.Errorf("cpio: header at %d runs past the end: %w", off, ErrTruncated)
	}
	h := make([]byte, headerLen)
	if _, err := ra.ReadAt(h, off); err != nil {
		return nil, 0, err
	}
	field := func(i int) (int64, error) {
		return strconv.ParseInt(string(h[6+i*8:6+i*8+8]), 16, 64)
	}
	mode, err := field(1)
	if err != nil {
		return nil, 0, fmt.Errorf("cpio: mode at %d: %w", off, err)
	}
	mtime, _ := field(5)
	fileSize, err := field(6)
	if err != nil {
		return nil, 0, fmt.Errorf("cpio: size at %d: %w", off, err)
	}
	nameSize, err := field(11)
	if err != nil {
		return nil, 0, fmt.Errorf("cpio: name size at %d: %w", off, err)
	}
	if nameSize <= 0 || off+headerLen+nameSize > size {
		return nil, 0, fmt.Errorf("cpio: name at %d is %d bytes: %w", off, nameSize, ErrTruncated)
	}
	nameBuf := make([]byte, nameSize)
	if _, err := ra.ReadAt(nameBuf, off+headerLen); err != nil {
		return nil, 0, err
	}
	name := strings.TrimRight(string(nameBuf), "\x00")
	// ⛔ Both the name and the data are padded to a multiple of four, and the
	// padding is counted from the START of the header rather than from the field.
	// Rounding the wrong origin puts every later header one to three bytes out,
	// which reads as a corrupt archive somewhere else entirely.
	dataOff := round4(off + headerLen + nameSize)
	next := round4(dataOff + fileSize)
	if name == trailerName {
		return nil, next, nil
	}
	if dataOff+fileSize > size {
		return nil, 0, fmt.Errorf("cpio: %s says %d bytes, past the end: %w",
			name, fileSize, ErrTruncated)
	}
	return newRecord(ra, name, mode, fileSize, dataOff, mtime, next)
}

// readODC reads one POSIX.1 octal header.
func readODC(ra io.ReaderAt, size, off int64) (*Record, int64, error) {
	const headerLen = 76
	if off+headerLen > size {
		return nil, 0, fmt.Errorf("cpio: header at %d runs past the end: %w", off, ErrTruncated)
	}
	h := make([]byte, headerLen)
	if _, err := ra.ReadAt(h, off); err != nil {
		return nil, 0, err
	}
	// Field widths differ from newc's: 6 for most, 11 for mtime and filesize.
	oct := func(start, width int) (int64, error) {
		return strconv.ParseInt(strings.TrimSpace(string(h[start:start+width])), 8, 64)
	}
	mode, err := oct(18, 6)
	if err != nil {
		return nil, 0, fmt.Errorf("cpio: mode at %d: %w", off, err)
	}
	nameSize, err := oct(59, 6)
	if err != nil {
		return nil, 0, fmt.Errorf("cpio: name size at %d: %w", off, err)
	}
	mtime, _ := oct(48, 11)
	fileSize, err := oct(65, 11)
	if err != nil {
		return nil, 0, fmt.Errorf("cpio: size at %d: %w", off, err)
	}
	if nameSize <= 0 || off+headerLen+nameSize > size {
		return nil, 0, fmt.Errorf("cpio: name at %d is %d bytes: %w", off, nameSize, ErrTruncated)
	}
	nameBuf := make([]byte, nameSize)
	if _, err := ra.ReadAt(nameBuf, off+headerLen); err != nil {
		return nil, 0, err
	}
	name := strings.TrimRight(string(nameBuf), "\x00")
	// odc pads NOTHING, which is the difference from newc that matters most.
	dataOff := off + headerLen + nameSize
	next := dataOff + fileSize
	if name == trailerName {
		return nil, next, nil
	}
	if dataOff+fileSize > size {
		return nil, 0, fmt.Errorf("cpio: %s says %d bytes, past the end: %w",
			name, fileSize, ErrTruncated)
	}
	return newRecord(ra, name, mode, fileSize, dataOff, mtime, next)
}

// newRecord turns one parsed header into a record, reading a symlink's target.
// ⛔ next is a PARAMETER. It used to be returned as 0 from here while the callers
// did `return newRecord(...)`, so the next offset came back zero and the outer
// loop read header one for ever -- the suite reported a ten-minute TIMEOUT rather
// than a failure. Same shape as the joined reader's loop the same afternoon:
// a position that the data is allowed to leave unchanged.
func newRecord(ra io.ReaderAt, name string, mode, fileSize, dataOff, mtime, next int64) (*Record, int64, error) {
	r := &Record{
		Name:   name,
		Mode:   FileMode(mode),
		Size:   fileSize,
		Offset: dataOff,
		MTime:  time.Unix(mtime, 0),
	}
	// A symlink's target IS its data, and the size is the target's length. It has
	// to be read now, because a record carries the target and not an offset.
	if r.Mode&iofs.ModeSymlink != 0 && fileSize > 0 && fileSize < 1<<16 {
		buf := make([]byte, fileSize)
		if _, err := ra.ReadAt(buf, dataOff); err != nil {
			return nil, 0, err
		}
		r.Link = strings.TrimRight(string(buf), "\x00")
		r.Size = 0
	}
	return r, next, nil
}

// FileMode turns a POSIX st_mode into an iofs.FileMode.
//
// ⛔ The type is in the HIGH bits of the octal value, not in iofs.FileMode's own
// places: S_IFDIR is 0o040000 while iofs.ModeDir is 1<<31. Narrowing one into the
// other without this switch leaves every directory looking like a file with
// peculiar permissions.
func FileMode(m int64) iofs.FileMode {
	mode := iofs.FileMode(m & 0o777)
	switch m & 0o170000 {
	case 0o040000:
		mode |= iofs.ModeDir
	case 0o120000:
		mode |= iofs.ModeSymlink
	case 0o010000:
		mode |= iofs.ModeNamedPipe
	case 0o020000:
		mode |= iofs.ModeDevice | iofs.ModeCharDevice
	case 0o060000:
		mode |= iofs.ModeDevice
	case 0o140000:
		mode |= iofs.ModeSocket
	}
	// ⛔ setuid, setgid and sticky, which a translation that stopped at the type
	// bits would drop -- and an archive records them. A setuid binary read back as
	// an ordinary one is a mode that means something different from what was
	// packed, and the caller has no way to recover it.
	if m&0o4000 != 0 {
		mode |= iofs.ModeSetuid
	}
	if m&0o2000 != 0 {
		mode |= iofs.ModeSetgid
	}
	if m&0o1000 != 0 {
		mode |= iofs.ModeSticky
	}
	return mode
}

// round4 rounds up to the next multiple of four.
func round4(n int64) int64 { return (n + 3) &^ 3 }

// binaryOrder says which byte order reads these two bytes as the binary cpio
// magic, or nil if neither does.
func binaryOrder(b []byte) binary.ByteOrder {
	if binary.LittleEndian.Uint16(b) == binaryMagic {
		return binary.LittleEndian
	}
	if binary.BigEndian.Uint16(b) == binaryMagic {
		return binary.BigEndian
	}
	return nil
}

// readBinary reads one old-binary header. A nil record means the trailer.
//
// ⛔ The 32-bit fields -- mtime and filesize -- are stored as TWO 16-bit words with
// the HIGH word FIRST, whatever the byte order of each word is. That is a PDP-11
// inheritance and it is independent of the endianness detected from the magic: a
// reader that assembles them low-word-first gets an mtime in the far future and a
// filesize that is either zero or enormous. Measured against cpio(1)'s own output,
// where a six-byte file reads as the words (0, 6).
//
// The `bin` and `pwb` variants of cpio(1) on this machine produce BYTE-IDENTICAL
// headers -- compared field by field -- so one implementation serves both. Worth
// saying, because libarchive lists them separately.
func readBinary(ra io.ReaderAt, size, off int64, order binary.ByteOrder) (*Record, int64, error) {
	if off+binaryHeaderLen > size {
		return nil, 0, fmt.Errorf("cpio: binary header at %d runs past the end: %w",
			off, ErrTruncated)
	}
	h := make([]byte, binaryHeaderLen)
	if _, err := ra.ReadAt(h, off); err != nil {
		return nil, 0, err
	}
	word := func(i int) int64 { return int64(order.Uint16(h[i*2 : i*2+2])) }
	long := func(i int) int64 { return word(i)<<16 | word(i+1) } // high word first

	mode := word(3)
	mtime := long(8)
	nameSize := word(10)
	fileSize := long(11)

	if nameSize <= 0 || off+binaryHeaderLen+nameSize > size {
		return nil, 0, fmt.Errorf("cpio: binary name at %d is %d bytes: %w",
			off, nameSize, ErrTruncated)
	}
	nameBuf := make([]byte, nameSize)
	if _, err := ra.ReadAt(nameBuf, off+binaryHeaderLen); err != nil {
		return nil, 0, err
	}
	name := strings.TrimRight(string(nameBuf), "\x00")

	// The name and the data are each padded to an EVEN offset, not to four as newc
	// does. Rounding to four reads the data two bytes late on half the entries.
	dataOff := round2(off + binaryHeaderLen + nameSize)
	next := round2(dataOff + fileSize)
	if name == trailerName {
		return nil, next, nil
	}
	if dataOff+fileSize > size {
		return nil, 0, fmt.Errorf("cpio: %s says %d bytes, past the end: %w",
			name, fileSize, ErrTruncated)
	}
	return newRecord(ra, name, mode, fileSize, dataOff, mtime, next)
}

// round2 rounds up to the next even number.
func round2(n int64) int64 { return (n + 1) &^ 1 }
