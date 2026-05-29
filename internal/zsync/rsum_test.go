package zsync

import (
	"math/rand"
	"testing"
	"testing/quick"
)

// TestCalcRsumKnownVectors pins down a handful of inputs where the rolling
// checksum's value is computable by hand.
func TestCalcRsumKnownVectors(t *testing.T) {
	// Empty input: a=0, b=0.
	if r := CalcRsum(nil); r.A != 0 || r.B != 0 {
		t.Fatalf("empty: got %+v", r)
	}
	if r := CalcRsum([]byte{}); r.A != 0 || r.B != 0 {
		t.Fatalf("empty slice: got %+v", r)
	}
	// Single byte 1: a=1, b=1.
	if r := CalcRsum([]byte{1}); r.A != 1 || r.B != 1 {
		t.Fatalf("[1]: got %+v", r)
	}
	// Two bytes 1,2: a=3, b = 2*1 + 1*2 = 4.
	if r := CalcRsum([]byte{1, 2}); r.A != 3 || r.B != 4 {
		t.Fatalf("[1,2]: got %+v", r)
	}
	// All-zero block of any length has Rsum{0,0}.
	if r := CalcRsum(make([]byte, 4096)); r.A != 0 || r.B != 0 {
		t.Fatalf("zero block: got %+v", r)
	}
}

// TestRsumQuickEquivalence is a property test: for randomly generated
// block-sized windows, the byte-wise incremental update produces the same
// (A,B) pair as a from-scratch recompute. This is the load-bearing
// invariant of the rolling-checksum scheme.
func TestRsumQuickEquivalence(t *testing.T) {
	for _, bs := range []int{16, 64, 256, 1024, 4096} {
		bs := bs
		prop := func(seed int64, slideBytes uint16) bool {
			rng := rand.New(rand.NewSource(seed))
			// Up to 2*bs+1 bytes worth of slide so we cross block boundaries.
			n := bs + int(slideBytes%uint16(bs*2+1))
			data := make([]byte, bs+n)
			rng.Read(data)
			r := CalcRsum(data[:bs])
			for x := 0; x < n; x++ {
				oldc := data[x]
				newc := data[x+bs]
				r.A = r.A + uint16(newc) - uint16(oldc)
				r.B = r.B + r.A - uint16(uint32(oldc)*uint32(bs))
				want := CalcRsum(data[x+1 : x+1+bs])
				if r != want {
					t.Logf("bs=%d x=%d got %+v want %+v", bs, x, r, want)
					return false
				}
			}
			return true
		}
		if err := quick.Check(prop, &quick.Config{MaxCount: 50}); err != nil {
			t.Fatalf("bs=%d: %v", bs, err)
		}
	}
}

func TestRsumAMaskTable(t *testing.T) {
	cases := []struct {
		rb   int
		mask uint16
	}{
		{0, 0},
		{1, 0},
		{2, 0},
		{3, 0xff},
		{4, 0xffff},
		{5, 0xffff}, // anything >=4 stays full
	}
	for _, c := range cases {
		if got := RsumAMask(c.rb); got != c.mask {
			t.Errorf("RsumAMask(%d)=0x%x, want 0x%x", c.rb, got, c.mask)
		}
	}
}

func TestComputeHashLengthsKnownPoints(t *testing.T) {
	// Empty/degenerate fall-back.
	if hl := ComputeHashLengths(0, 2048); hl != (HashLengths{1, 2, 3}) {
		t.Errorf("zero length: %+v", hl)
	}
	if hl := ComputeHashLengths(-1, 2048); hl != (HashLengths{1, 2, 3}) {
		t.Errorf("negative length: %+v", hl)
	}

	// A file equal to one block has seq_matches == 1.
	if hl := ComputeHashLengths(2048, 2048); hl.SeqMatches != 1 {
		t.Errorf("single-block: seq=%d, want 1", hl.SeqMatches)
	}

	// A large file should clamp rsum_bytes to <=4 and checksum_bytes to <=16.
	hl := ComputeHashLengths(1<<40, 4096)
	if hl.RsumBytes < 2 || hl.RsumBytes > 4 {
		t.Errorf("huge file: rsum=%d", hl.RsumBytes)
	}
	if hl.ChecksumBytes < 3 || hl.ChecksumBytes > 16 {
		t.Errorf("huge file: cs=%d", hl.ChecksumBytes)
	}
	if hl.SeqMatches != 2 {
		t.Errorf("huge file: seq=%d", hl.SeqMatches)
	}

	// Tiny but non-zero file: at the smallest legal floors.
	hl = ComputeHashLengths(1, 1)
	if hl.RsumBytes != 2 || hl.ChecksumBytes < 3 {
		t.Errorf("tiny: %+v", hl)
	}
}

// TestComputeHashLengthsClamps drives the explicit upper-bound clamps in the
// per-file sizing formulae by feeding pathologically large dimensions.
func TestComputeHashLengthsClamps(t *testing.T) {
	// rsum > 4 before clamping: log2(length*blocksize) needs to be huge.
	hl := ComputeHashLengths(1<<60, 1<<20)
	if hl.RsumBytes != 4 {
		t.Errorf("rsum clamp: got %d, want 4", hl.RsumBytes)
	}
	// The cs<3 floor is engaged when nBlocks is tiny and length is tiny.
	// length=2, blocksize=1 gives nBlocks=3, log2 small → cs1 small.
	hl = ComputeHashLengths(2, 1)
	if hl.ChecksumBytes < 3 {
		t.Errorf("cs floor: got %d, want >=3", hl.ChecksumBytes)
	}
}

func TestPutBE16(t *testing.T) {
	got := PutBE16(0xCAFE)
	if got[0] != 0xCA || got[1] != 0xFE {
		t.Fatalf("PutBE16: %x", got)
	}
}

func TestMD4ZeroBlock(t *testing.T) {
	// The MD4 of an empty input is well-known.
	d := MD4(nil)
	want := [16]byte{
		0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31,
		0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0,
	}
	if d != want {
		t.Fatalf("MD4(\"\") = %x, want %x", d, want)
	}
}
