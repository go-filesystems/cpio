// Copyright (c) 2026, go-filesystems
// SPDX-License-Identifier: BSD-3-Clause

package cpio

import (
	"bytes"
	"io"
	"testing"
)

// FuzzRecords feeds both entry points arbitrary bytes. The invariants are the ones
// a hostile archive could break: no panic, no read after a budget proportional to
// the input (the walk always moves forward), and every Record lies inside the
// archive.
//
// The corpus is the four real fixtures; crashers found go to testdata/fuzz AND get
// a named unit test, because the emulated CI lanes run a compiled test binary away
// from testdata/.
func FuzzRecords(f *testing.F) {
	for _, name := range []string{"newc.cpio", "odc.cpio", "bin.cpio", "bin-swapped.cpio"} {
		b, err := archives.ReadFile("testdata/" + name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Add(append(newcHeader("00000001", "000081a4", "00000000", "-0000070", "00000002"), 'a', 0))
	f.Fuzz(func(t *testing.T, b []byte) {
		size := int64(len(b))
		// Every header read advances at least headerLen bytes, so len(b) reads of
		// each kind is a generous ceiling; a walk that exceeds it is going round.
		for _, walk := range []func(io.ReaderAt, int64) ([]Record, error){Records, RecordsExact} {
			ra := &runaway{r: bytes.NewReader(b), limit: 8*len(b) + 64}
			recs, err := walk(ra, size)
			if err == errRunaway {
				t.Fatalf("the walk did not terminate: %d reads for %d bytes", ra.reads, len(b))
			}
			for _, r := range recs {
				if r.Offset < 0 || r.Size < 0 || r.Offset+r.Size > size {
					t.Fatalf("record %q lies outside the archive: offset %d size %d of %d",
						r.Name, r.Offset, r.Size, size)
				}
			}
		}
	})
}
