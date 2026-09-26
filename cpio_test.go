// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package cpio

import (
	"bytes"
	"embed"
	"encoding/binary"
	"errors"
	iofs "io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Four archives of the same tree, one per variant:
//
//	newc.cpio         cpio -o -H newc    fields are 8 hex digits, name and data
//	                                     padded to four
//	odc.cpio          cpio -o -H odc     fields are 6 octal digits, nothing padded
//	bin.cpio          cpio -o -H bin     16-bit words in the writer's byte order
//	bin-swapped.cpio  testdata/gen.py    the same, words byte-swapped
//
// The last one is crafted because no tool here writes the other endianness, and
// that is exactly the variant a reader gets wrong. Its premise is asserted: the
// two must carry DIFFERENT magic words and yield IDENTICAL records.
//
// The crc variant (070702) is absent: macOS cpio refuses -H crc. It differs from
// newc only in a checksum field this reader does not verify, and the switch treats
// the two magics alike, which TestTheCRCMagicIsReadAsNewc pins by rewriting the
// magic of the real newc archive.
//
//go:embed testdata/newc.cpio testdata/odc.cpio
//go:embed testdata/bin.cpio testdata/bin-swapped.cpio
var archives embed.FS

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := archives.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

func records(t *testing.T, b []byte) []Record {
	t.Helper()
	recs, err := Records(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	return recs
}

// TestEveryVariantReadsTheSameArchive is the assertion no single-variant test can
// make: four different header formats over one tree must agree about every record.
//
// A reader that mishandles one variant's padding, field width or byte order
// produces a different set here -- and the sets are compared entry by entry rather
// than by length, because four archives of five records each have the same length
// whatever the names came out as.
func TestEveryVariantReadsTheSameArchive(t *testing.T) {
	want := records(t, read(t, "newc.cpio"))
	if len(want) < 4 {
		t.Fatalf("the reference archive holds %d records, which is too few to "+
			"distinguish anything", len(want))
	}
	// The tree has to contain the shapes that separate the variants.
	var dirs, files, links int
	for _, r := range want {
		switch {
		case r.Mode.IsDir():
			dirs++
		case r.Mode&iofs.ModeSymlink != 0:
			links++
		default:
			files++
		}
	}
	if dirs == 0 || files == 0 || links == 0 {
		t.Fatalf("the archive holds %d dirs, %d files, %d links: a variant that "+
			"misreads one of those kinds would not be caught", dirs, files, links)
	}

	for _, other := range []string{"odc.cpio", "bin.cpio", "bin-swapped.cpio"} {
		t.Run(other, func(t *testing.T) {
			got := records(t, read(t, other))
			if len(got) != len(want) {
				t.Fatalf("%d records, want %d", len(got), len(want))
			}
			for i := range got {
				// Offset is NOT compared: it is where the data lies in this
				// archive, and each variant lays it out differently. Everything
				// that describes the entry itself must match.
				if got[i].Name != want[i].Name {
					t.Errorf("record %d name = %q, want %q", i, got[i].Name, want[i].Name)
				}
				if got[i].Mode != want[i].Mode {
					t.Errorf("%s mode = %v, want %v", got[i].Name, got[i].Mode, want[i].Mode)
				}
				if got[i].Size != want[i].Size {
					t.Errorf("%s size = %d, want %d", got[i].Name, got[i].Size, want[i].Size)
				}
				if got[i].Link != want[i].Link {
					t.Errorf("%s link = %q, want %q", got[i].Name, got[i].Link, want[i].Link)
				}
			}
		})
	}
}

// TestTheTwoBinaryFixturesReallyDifferInTheirByteOrder. Without this the test above
// would pass on two copies of the same file, and the byte-order detection -- the one
// rule no local tool can exercise -- would be untested while looking tested.
func TestTheTwoBinaryFixturesReallyDifferInTheirByteOrder(t *testing.T) {
	native, swapped := read(t, "bin.cpio"), read(t, "bin-swapped.cpio")
	if bytes.Equal(native, swapped) {
		t.Fatal("the two binary fixtures are the same bytes")
	}
	nativeWord := binary.LittleEndian.Uint16(native[:2])
	swappedWord := binary.LittleEndian.Uint16(swapped[:2])
	if nativeWord != binaryMagic {
		t.Errorf("bin.cpio's first word reads 0o%o little-endian, want 0o%o",
			nativeWord, binaryMagic)
	}
	// 0o143561 is 0o070707 with its bytes the other way round.
	const otherOrder = 0o143561
	if swappedWord != otherOrder {
		t.Errorf("bin-swapped.cpio's first word reads 0o%o little-endian, want "+
			"0o%o -- the whole point is that it is NOT the native magic",
			swappedWord, otherOrder)
	}
}

// TestTheCRCMagicIsReadAsNewc. 070702 is newc plus a checksum field, and this
// reader does not verify checksums -- so it reads it as newc rather than refusing
// an archive it can in fact parse. macOS cpio will not write one, hence the rewrite.
func TestTheCRCMagicIsReadAsNewc(t *testing.T) {
	b := append([]byte(nil), read(t, "newc.cpio")...)
	want := records(t, b)
	// Only the first record's magic is changed, which is enough: the switch is per
	// record, so a reader that refused 070702 would stop at entry one.
	copy(b[:6], magicCRC)
	got := records(t, b)
	if len(got) != len(want) {
		t.Fatalf("%d records after rewriting the magic to %s, want %d",
			len(got), magicCRC, len(want))
	}
	for i := range got {
		if got[i].Name != want[i].Name || got[i].Size != want[i].Size {
			t.Errorf("record %d differs: %+v vs %+v", i, got[i], want[i])
		}
	}
}

// TestNewcPadsAndODCDoesNot pins the difference that puts every later header out by
// one to three bytes when it is forgotten.
func TestNewcPadsAndODCDoesNot(t *testing.T) {
	newc := records(t, read(t, "newc.cpio"))
	odc := records(t, read(t, "odc.cpio"))

	for _, r := range newc {
		if r.Offset%4 != 0 {
			t.Errorf("newc: %s data starts at %d, which is not a multiple of four",
				r.Name, r.Offset)
		}
	}
	// And odc's are not, or the two rules would be indistinguishable here.
	unaligned := 0
	for _, r := range odc {
		if r.Offset%4 != 0 {
			unaligned++
		}
	}
	if unaligned == 0 {
		t.Error("every odc offset happens to be four-aligned, so this archive " +
			"cannot tell the padded rule from the unpadded one")
	}
}

func TestRefusals(t *testing.T) {
	newc := read(t, "newc.cpio")
	for _, c := range []struct {
		name string
		in   []byte
		want error
	}{
		{"not a cpio at all", []byte("this is prose, and long enough"), ErrNotCpio},
		{"empty", nil, ErrNotCpio},
		// Six bytes of newc magic IS cpio, and cut off -- so truncated, not
		// unrecognised. The two sentinels say different things and a caller acts
		// differently on them: one means "try another reader", the other means
		// "this archive is damaged".
		{"six bytes of magic and nothing else", []byte(magicNewc), ErrTruncated},
		{"a newc header cut short", newc[:60], ErrTruncated},
		// 111 bytes, not 112: at 112 the first record is COMPLETE -- its name is
		// "." and one NUL -- and Records rightly returns it. Measured, after this
		// case first asserted a failure that was not one.
		{"the name cut off after the header", newc[:111], ErrTruncated},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := Records(bytes.NewReader(c.in), int64(len(c.in)))
			if !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}
		})
	}
}

// TestTrailingPaddingAfterTheTrailerIsFine. An initramfs is padded to a block, so
// what follows the trailer is not an error -- but it must not be read as records
// either.
func TestTrailingPaddingAfterTheTrailerIsFine(t *testing.T) {
	b := read(t, "newc.cpio")
	want := records(t, b)
	padded := append(append([]byte(nil), b...), make([]byte, 2048)...)
	got := records(t, padded)
	if len(got) != len(want) {
		t.Errorf("%d records with 2 KiB of padding after the trailer, want %d",
			len(got), len(want))
	}
}

func TestFileMode(t *testing.T) {
	for _, c := range []struct {
		posix int64
		want  iofs.FileMode
	}{
		{0o100644, 0o644},
		{0o040755, iofs.ModeDir | 0o755},
		{0o120777, iofs.ModeSymlink | 0o777},
		{0o010644, iofs.ModeNamedPipe | 0o644},
		{0o020600, iofs.ModeDevice | iofs.ModeCharDevice | 0o600},
		{0o060600, iofs.ModeDevice | 0o600},
		{0o140666, iofs.ModeSocket | 0o666},
		{0o104755, iofs.ModeSetuid | 0o755},
		{0o102755, iofs.ModeSetgid | 0o755},
		{0o101777, iofs.ModeSticky | 0o777},
	} {
		if got := FileMode(c.posix); got != c.want {
			t.Errorf("FileMode(0o%o) = %v, want %v", c.posix, got, c.want)
		}
	}
}

// failAt refuses any read that REACHES past a point, which is how the ReadAt error
// branches are got at: a size check guards each of them, so a short slice cannot.
//
// ⛔ It fails on off+len(p) and not on off alone. The first version refused only
// reads STARTING past the mark, and a 110-byte header read from offset 0 therefore
// succeeded whatever the mark was -- so three of the branches this type exists for
// stayed unreached while the tests using it passed.
type failAt struct {
	b     []byte
	after int64
}

func (f failAt) ReadAt(p []byte, off int64) (int, error) {
	if off+int64(len(p)) > f.after {
		return 0, errors.New("the disk said no")
	}
	n := copy(p, f.b[off:])
	return n, nil
}

// corrupt returns the archive with one field overwritten.
func corrupt(t *testing.T, name string, at int, with string) []byte {
	t.Helper()
	b := append([]byte(nil), read(t, name)...)
	if at+len(with) > len(b) {
		t.Fatalf("%d+%d past the end of %s", at, len(with), name)
	}
	copy(b[at:], with)
	return b
}

// TestAFieldThatIsNotANumberIsRefused.
//
// ⛔ newc's fields are hex and odc's are octal, both as ASCII, and a header full of
// digits that do not parse is what a file which merely BEGINS with cpio magic looks
// like. Each field is named in its own error, because "malformed header" sends
// nobody anywhere.
//
// The offsets are the field layout: newc puts eight-hex-digit fields from byte 6,
// odc six-octal-digit fields from byte 6.
func TestAFieldThatIsNotANumberIsRefused(t *testing.T) {
	for _, c := range []struct {
		name     string
		archive  string
		at       int
		with     string
		wantWord string
	}{
		{"newc mode", "newc.cpio", 6 + 1*8, "zzzzzzzz", "mode"},
		{"newc size", "newc.cpio", 6 + 6*8, "zzzzzzzz", "size"},
		{"newc name size", "newc.cpio", 6 + 11*8, "zzzzzzzz", "name size"},
		{"odc mode", "odc.cpio", 6 + 2*6, "zzzzzz", "mode"},
		{"odc name size", "odc.cpio", 6 + 8*6, "zzzzzz", "name size"},
		{"odc size", "odc.cpio", 6 + 9*6 + 5, "zzzzzzzzzzz", "size"},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := corrupt(t, c.archive, c.at, c.with)
			_, err := Records(bytes.NewReader(b), int64(len(b)))
			if err == nil {
				t.Fatalf("a %s of %q was accepted", c.wantWord, c.with)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(c.wantWord)) {
				t.Errorf("err = %v, want it to name the %s field", err, c.wantWord)
			}
		})
	}
}

// TestADeclaredLengthPastTheEndIsRefused. A record saying it holds more bytes than
// the archive has is the allocation trap as well as a parse error: the length comes
// from the file.
func TestADeclaredLengthPastTheEndIsRefused(t *testing.T) {
	for _, c := range []struct {
		name, archive string
		at            int
		with          string
	}{
		{"newc data", "newc.cpio", 6 + 6*8, "7fffffff"},
		{"newc name", "newc.cpio", 6 + 11*8, "0000ffff"},
		{"odc name", "odc.cpio", 6 + 8*6, "077777"},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := corrupt(t, c.archive, c.at, c.with)
			_, err := Records(bytes.NewReader(b), int64(len(b)))
			if !errors.Is(err, ErrTruncated) {
				t.Errorf("err = %v, want ErrTruncated", err)
			}
		})
	}
}

// TestABinaryHeaderCutShortIsRefused, and its name likewise. The binary variant
// pads to an EVEN length rather than to four, so its sizes are not the others'.
func TestABinaryHeaderCutShortIsRefused(t *testing.T) {
	b := read(t, "bin.cpio")
	for _, n := range []int{8, 20, 25, 27} {
		_, err := Records(bytes.NewReader(b[:n]), int64(n))
		if !errors.Is(err, ErrTruncated) && !errors.Is(err, ErrNotCpio) {
			t.Errorf("first %d bytes gave %v, want a refusal", n, err)
		}
	}
	// A name length that reaches past the end.
	swapped := append([]byte(nil), b...)
	binary.LittleEndian.PutUint16(swapped[20:22], 0xFFFF)
	if _, err := Records(bytes.NewReader(swapped), int64(len(swapped))); !errors.Is(err, ErrTruncated) {
		t.Errorf("a binary name of 65535 bytes gave %v, want ErrTruncated", err)
	}
	// And a data length past the end.
	long := append([]byte(nil), b...)
	binary.LittleEndian.PutUint16(long[22:24], 0x7FFF)
	if _, err := Records(bytes.NewReader(long), int64(len(long))); !errors.Is(err, ErrTruncated) {
		t.Errorf("a binary record of 2 GiB gave %v, want ErrTruncated", err)
	}
}

// TestAReadFailureIsReportedAsItself. A checksum or a length can be wrong; a disk
// can also simply fail, and the two must not read alike. Every ReadAt in the parser
// sits behind a size check, so a short slice cannot reach these -- hence failAt.
//
// ⚠ These thresholds are fixture-dependent: regenerating testdata moves the offsets,
// and a case can then fail at an EARLIER read than the one it names while still
// passing. What catches that is the 100% coverage gate -- a case that stops reaching
// its branch shows up as a drop, not as a green test. One of them did exactly that
// and is derived from the archive now; see TestAFailureReadingASymlinkTargetIsReported.
func TestAReadFailureIsReportedAsItself(t *testing.T) {
	for _, c := range []struct {
		name    string
		archive string
		after   int64
	}{
		{"the magic", "newc.cpio", 3},
		{"a newc header", "newc.cpio", 60},
		{"a newc name", "newc.cpio", 111},

		{"an odc header", "odc.cpio", 40},
		{"an odc name", "odc.cpio", 77},
		{"a binary header", "bin.cpio", 20},
		{"a binary name", "bin.cpio", 27},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := read(t, c.archive)
			_, err := Records(failAt{b: b, after: c.after}, int64(len(b)))
			if err == nil {
				t.Fatal("a read failure was reported as a successful parse")
			}
			if errors.Is(err, ErrNotCpio) || errors.Is(err, ErrTruncated) {
				t.Errorf("err = %v, and it should be the read failure rather than a "+
					"verdict about the archive: a failing disk must not read as a "+
					"damaged file", err)
			}
		})
	}
}

// TestJunkAfterARecordStopsTheWalk. Trailing padding is tolerated after the
// TRAILER; this is the other case -- bytes that are not cpio magic following a real
// record, with no trailer in between. Stopping with what was read beats refusing an
// archive whose entries all parsed.
func TestJunkAfterARecordStopsTheWalk(t *testing.T) {
	b := read(t, "newc.cpio")
	// The first record alone: header, name, and its (empty) data.
	first := records(t, b)[0]
	cut := int(first.Offset + first.Size)
	truncated := append(append([]byte(nil), b[:cut]...), []byte("not a cpio header at all")...)

	recs, err := Records(bytes.NewReader(truncated), int64(len(truncated)))
	if err != nil {
		t.Fatalf("Records: %v", err)
	}
	if len(recs) != 1 {
		t.Errorf("%d records, want the 1 that parsed before the junk", len(recs))
	}
}

// TestAnODCHeaderCutShortIsRefused. odc's header is 76 bytes where newc's is 110,
// so the size check is a different number and a test of newc does not reach it.
func TestAnODCHeaderCutShortIsRefused(t *testing.T) {
	b := read(t, "odc.cpio")
	for _, n := range []int{10, 50, 75} {
		if _, err := Records(bytes.NewReader(b[:n]), int64(n)); !errors.Is(err, ErrTruncated) {
			t.Errorf("first %d bytes gave %v, want ErrTruncated", n, err)
		}
	}
}

// TestAnODCRecordDeclaringDataPastTheEnd. The data check sits after the name check,
// so an over-long name never reaches it -- the name has to fit and the data not.
func TestAnODCRecordDeclaringDataPastTheEnd(t *testing.T) {
	b := corrupt(t, "odc.cpio", 6+9*6+5, "77777777777")
	if _, err := Records(bytes.NewReader(b), int64(len(b))); !errors.Is(err, ErrTruncated) {
		t.Errorf("err = %v, want ErrTruncated", err)
	}
}

// TestTheExportedMagicsAreTheOnesTheParserSwitchesOn. Two spellings of one constant
// is the duplication this package removed; a copy inside it would be the same
// defect at a shorter distance.
func TestTheExportedMagicsAreTheOnesTheParserSwitchesOn(t *testing.T) {
	for _, c := range []struct{ exported, internal, name string }{
		{MagicNewc, magicNewc, "MagicNewc"},
		{MagicCRC, magicCRC, "MagicCRC"},
		{MagicODC, magicODC, "MagicODC"},
		{TrailerName, trailerName, "TrailerName"},
	} {
		if c.exported != c.internal {
			t.Errorf("%s = %q but the parser switches on %q", c.name, c.exported, c.internal)
		}
	}
	// And a writer using them produces something this parser reads: the magic is
	// what the switch above dispatches on, so an archive written with MagicNewc
	// must come back as records rather than as ErrNotCpio.
	b := append([]byte(nil), read(t, "newc.cpio")...)
	copy(b[:6], MagicNewc)
	if _, err := Records(bytes.NewReader(b), int64(len(b))); err != nil {
		t.Errorf("an archive whose magic is MagicNewc was refused: %v", err)
	}
}

// TestAFailureReadingASymlinkTargetIsReported.
//
// ⛔ The threshold is DERIVED from the archive rather than written down. It was a
// constant at first, and regenerating the fixtures moved the link's data offset from
// 488 to 624 -- so the case went on passing while failing at the NAME read instead,
// and the branch it exists for stopped being reached.
//
// A symlink's target is its data, so this is the one read the parser makes that a
// caller cannot make for itself.
func TestAFailureReadingASymlinkTargetIsReported(t *testing.T) {
	b := read(t, "newc.cpio")
	var link Record
	for _, r := range records(t, b) {
		if r.Link != "" {
			link = r
			break
		}
	}
	if link.Link == "" {
		t.Fatal("the archive holds no symbolic link, so this cannot test reading one")
	}
	// Everything up to the target's last byte is readable; the target is not.
	after := link.Offset + int64(len(link.Link)) - 1

	_, err := Records(failAt{b: b, after: after}, int64(len(b)))
	if err == nil {
		t.Fatal("a failed read of a link target was reported as a successful parse")
	}
	if errors.Is(err, ErrNotCpio) || errors.Is(err, ErrTruncated) {
		t.Errorf("err = %v, want the read failure itself", err)
	}
	// Premise: one byte more and it succeeds, so the failure is about THAT read.
	if _, err := Records(failAt{b: b, after: int64(len(b))}, int64(len(b))); err != nil {
		t.Errorf("the same archive fails with nothing withheld: %v", err)
	}
}

// TestBinAndPwbAreTheSameFormatHere.
//
// ⛔ A measurement carried over from go-filesystems/unarchive, where the parser used
// to live. libarchive lists `bin` and `pwb` as separate cpio formats, so it was
// worth asking rather than assuming -- and on this machine cpio(1) writes
// BYTE-IDENTICAL headers for both. One implementation therefore serves both, and
// that is a fact about the tool rather than a claim about the formats in general.
//
// It is asserted rather than left in a comment, because a cpio(1) that started
// distinguishing them would otherwise be discovered by a user rather than here.
func TestBinAndPwbAreTheSameFormatHere(t *testing.T) {
	bin, err := exec.LookPath("cpio")
	if err != nil {
		t.Skip("no cpio here to compare the two variants with")
	}
	tree := t.TempDir()
	if err := os.WriteFile(filepath.Join(tree, "one.txt"), []byte("a body"), 0o644); err != nil {
		t.Fatal(err)
	}

	write := func(variant string) []byte {
		t.Helper()
		cmd := exec.Command(bin, "-o", "-H", variant)
		cmd.Dir = tree
		cmd.Stdin = strings.NewReader("one.txt\n")
		out, err := cmd.Output()
		if err != nil {
			t.Skipf("cpio -H %s: %v", variant, err)
		}
		return out
	}
	a, b := write("bin"), write("pwb")

	// The mtime is in the header, so two runs a second apart differ legitimately.
	// The comparison is of the FIELDS that describe the format, which is the first
	// 16 bytes plus the name and data sizes -- everything but mtime.
	const hdr = binaryHeaderLen
	if len(a) < hdr || len(b) < hdr {
		t.Fatalf("headers are %d and %d bytes, want at least %d", len(a), len(b), hdr)
	}
	if !bytes.Equal(a[:16], b[:16]) {
		t.Errorf("bin and pwb differ in their first 16 header bytes:\n  bin % x\n  pwb % x",
			a[:16], b[:16])
	}
	if !bytes.Equal(a[20:26], b[20:26]) {
		t.Errorf("bin and pwb differ in their name and data sizes:\n  bin % x\n  pwb % x",
			a[20:26], b[20:26])
	}

	// And both parse to the same record, which is the answer that matters.
	ra, errA := Records(bytes.NewReader(a), int64(len(a)))
	rb, errB := Records(bytes.NewReader(b), int64(len(b)))
	if errA != nil || errB != nil {
		t.Fatalf("bin: %v, pwb: %v", errA, errB)
	}
	if len(ra) != len(rb) {
		t.Fatalf("%d records from bin, %d from pwb", len(ra), len(rb))
	}
	for i := range ra {
		if ra[i].Name != rb[i].Name || ra[i].Size != rb[i].Size || ra[i].Mode != rb[i].Mode {
			t.Errorf("record %d differs: %+v vs %+v", i, ra[i], rb[i])
		}
	}
}
