// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package cpio

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"runtime"
	"testing"
)

// Bombs: inputs a few hundred bytes long that made the parser allocate, or loop,
// without bound. Each road is built by hand, header field by header field, because
// no cpio(1) writes a negative size.
//
// Reference for the bounds: the Linux kernel's init/initramfs.c (do_header refuses
// name_len <= 0 || name_len > PATH_MAX, and a symlink body > PATH_MAX) and
// libarchive's archive_read_support_format_cpio.c (CPIO_PATHNAME_MAX = 1 MiB, and
// "symlink contents exceed 1 megabyte").

// runaway counts reads and fails after limit: a parser stuck re-reading the same
// header for ever must end the test with a verdict, not a ten-minute timeout.
type runaway struct {
	r     io.ReaderAt
	reads int
	limit int
}

var errRunaway = errors.New("probe: the parser is still reading after the budget")

func (r *runaway) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	if r.reads > r.limit {
		return 0, errRunaway
	}
	return r.r.ReadAt(p, off)
}

// allocated runs f and returns the bytes the runtime allocated meanwhile.
func allocated(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

func newcHeader(ino, mode, mtime, size, nameSize string) []byte {
	// 13 fields of 8 characters: ino mode uid gid nlink mtime filesize devmajor
	// devminor rdevmajor rdevminor namesize check
	f := []string{ino, mode, "00000000", "00000000", "00000001", mtime, size,
		"00000000", "00000000", "00000000", "00000000", nameSize, "00000000"}
	var b bytes.Buffer
	b.WriteString(magicNewc)
	for _, s := range f {
		b.WriteString(s)
	}
	return b.Bytes()
}

func odcHeader(ino, mode, mtime, size, nameSize string) []byte {
	// magic dev ino mode uid gid nlink rdev mtime namesize filesize
	return []byte(magicODC + "000000" + ino + mode + "000000" + "000000" + "000001" +
		"000000" + mtime + nameSize + size)
}

// binaryRecord is the smallest old-binary record: a 26-byte header and the name
// "a\0", which is already even.
func binaryRecord() []byte {
	h := make([]byte, 28)
	h[0], h[1] = 0xc7, 0x71 // 0o070707 as a little-endian word
	h[20] = 2               // name size
	h[26] = 'a'
	return h
}

// TestANegativeSizeCannotMakeTheWalkGoBackwards is the loop: a size of -112 puts
// the next header at offset 0, and the walk reads record one for ever, appending a
// record each time. ParseInt accepts a sign; the field is unsigned.
func TestANegativeSizeCannotMakeTheWalkGoBackwards(t *testing.T) {
	// newc: 110 + 2 = 112 = the data offset, so -0x70 lands on 0.
	newc := append(newcHeader("00000001", "000081a4", "00000000", "-0000070", "00000002"), 'a', 0)
	// odc: 76 + 2 = 78 = 0o116, so -0o116 lands on 0 (an 11-character field).
	odc := append(odcHeader("000001", "100644", "00000000000", "-0000000116", "000002"), 'a', 0)
	for name, arch := range map[string][]byte{"newc": newc, "odc": odc} {
		t.Run(name, func(t *testing.T) {
			ra := &runaway{r: bytes.NewReader(arch), limit: 10000}
			_, err := Records(ra, int64(len(arch)))
			if err == nil {
				t.Fatalf("a negative size was accepted")
			}
			if errors.Is(err, errRunaway) {
				t.Fatalf("the walk went round in circles: %d reads for a %d-byte input",
					ra.reads, len(arch))
			}
		})
	}
}

// TestASignIsRefusedInEveryNumericField pins the whole class: "-" and "+" in front
// of a number, in each field the parser reads.
func TestASignIsRefusedInEveryNumericField(t *testing.T) {
	for _, bad := range []string{"-0000001", "+0000001"} {
		for i := range 5 {
			ino, mode, mtime, size, name := "00000001", "000081a4", "00000000", "00000000", "00000002"
			switch i {
			case 0:
				ino = bad
			case 1:
				mode = bad
			case 2:
				mtime = bad
			case 3:
				size = bad
			case 4:
				name = bad
			}
			h := append(newcHeader(ino, mode, mtime, size, name), 'a', 0)
			if _, err := Records(bytes.NewReader(h), int64(len(h))); err == nil {
				t.Errorf("newc field %d = %q accepted", i, bad)
			}
		}
	}
}

// TestANameLargerThanTheCeilingIsRefusedBeforeItIsRead: at the ceiling a name
// passes, one over is refused with ErrTooLarge, and the refusal allocates nothing
// of the name's size.
func TestANameLargerThanTheCeilingIsRefusedBeforeItIsRead(t *testing.T) {
	build := func(n int) []byte {
		h := newcHeader("00000001", "000081a4", "00000000", "00000000", fmt.Sprintf("%08x", n))
		h = append(h, bytes.Repeat([]byte{'a'}, n-1)...)
		h = append(h, 0)
		for len(h)%4 != 0 { // newc pads the name to four
			h = append(h, 0)
		}
		return h
	}
	ok := build(MaxNameSize)
	if _, err := Records(bytes.NewReader(ok), int64(len(ok))); err != nil {
		t.Fatalf("a name of exactly MaxNameSize was refused: %v", err)
	}
	over := build(MaxNameSize + 1)
	var err error
	got := allocated(func() { _, err = Records(bytes.NewReader(over), int64(len(over))) })
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("a name one byte over the ceiling: %v, want ErrTooLarge", err)
	}
	if got > 64<<10 {
		t.Errorf("refusing the oversized name allocated %d bytes", got)
	}
}

// TestAnErrorDoesNotCarryTheWholeName: the name is the attacker's, up to
// MaxNameSize long, and it used to be formatted into the "past the end" message.
func TestAnErrorDoesNotCarryTheWholeName(t *testing.T) {
	n := 100000
	h := newcHeader("00000001", "000081a4", "00000000", "00001000", fmt.Sprintf("%08x", n))
	h = append(h, bytes.Repeat([]byte{'a'}, n-1)...)
	h = append(h, 0)
	for len(h)%4 != 0 {
		h = append(h, 0)
	}
	_, err := Records(bytes.NewReader(h), int64(len(h)))
	if err == nil {
		t.Fatal("data past the end was accepted")
	}
	if len(err.Error()) > 512 {
		t.Errorf("the error is %d bytes long", len(err.Error()))
	}
	if short := shown("abc"); short != "abc" {
		t.Errorf("shown(abc) = %q", short)
	}
}

// TestTheNameCeilingIsOnlyReachableByNewc: a 16-bit binary name size is at most
// 65535 and an odc one, six octal digits, at most 262143 -- both below the
// ceiling -- so only newc needs the check. The test says so rather than leave the
// reader to wonder why the other two do not have one.
func TestTheNameCeilingIsOnlyReachableByNewc(t *testing.T) {
	if 0xffff >= MaxNameSize {
		t.Fatalf("MaxNameSize %d is reachable by a binary header; it needs its own check", MaxNameSize)
	}
	if 0o777777 >= MaxNameSize {
		t.Fatalf("MaxNameSize %d is reachable by an odc header; it needs its own check", MaxNameSize)
	}
}

// TestManyRecordsCostBoundedMemory: records are the one allocation that grows with
// the input, and it must grow LINEARLY with a small constant. The smallest record
// of each variant is the worst case.
func TestManyRecordsCostBoundedMemory(t *testing.T) {
	const input = 4 << 20
	cases := map[string][]byte{
		"newc": append(newcHeader("00000001", "000081a4", "00000000", "00000000", "00000002"), 'a', 0, 0, 0),
		"odc":  append(odcHeader("000001", "100644", "00000000000", "00000000000", "000002"), 'a', 0),
		"bin":  binaryRecord(),
	}
	for name, rec := range cases {
		t.Run(name, func(t *testing.T) {
			arch := bytes.Repeat(rec, input/len(rec))
			var recs []Record
			var err error
			got := allocated(func() { recs, err = Records(bytes.NewReader(arch), int64(len(arch))) })
			if err != nil {
				t.Fatalf("Records: %v", err)
			}
			t.Logf("%s: %d bytes in, %d records, %d bytes allocated (%.1fx)",
				name, len(arch), len(recs), got, float64(got)/float64(len(arch)))
			// Measured worst case: 21x for the 28-byte binary record (a Record is about
			// 100 bytes kept, plus the slice's doubling and per-record header buffers
			// that die at once). The bound is that, rounded up: a regression to a
			// per-record copy of something large would cross it.
			if got > 32*uint64(len(arch)) {
				t.Errorf("%d bytes allocated for %d bytes of input", got, len(arch))
			}
		})
	}
}

// TestASymlinkTargetPastTheEndAllocatesNothing: the header claims a 64 KiB target
// the archive does not carry; the past-the-end test refuses it before the buffer.
func TestASymlinkTargetPastTheEndAllocatesNothing(t *testing.T) {
	h := newcHeader("00000001", "0000a1ff", "00000000", "0000ffff", "00000002")
	h = append(h, 'a', 0, 0, 0) // name, padded to 112
	var err error
	got := allocated(func() { _, err = Records(bytes.NewReader(h), int64(len(h))) })
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("a symlink claiming a target past the end: %v", err)
	}
	if got > 64<<10 {
		t.Errorf("allocated %d bytes for a target that is not there", got)
	}
}
