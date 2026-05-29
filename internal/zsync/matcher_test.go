package zsync

import (
	"bytes"
	"errors"
	"io"
	"math/rand"
	"testing"
	"time"
)

func makeCF(t *testing.T, data []byte, blocksize int) *ControlFile {
	t.Helper()
	cf, err := Make(bytes.NewReader(data), int64(len(data)), blocksize, "x.bin",
		time.Time{}, []string{"x.bin"})
	if err != nil {
		t.Fatal(err)
	}
	return cf
}

func TestMatcherEmptyTarget(t *testing.T) {
	cf := makeCF(t, nil, 2048)
	m := NewMatcher(cf)
	if m.TotalBlocks() != 0 {
		t.Fatalf("TotalBlocks=%d", m.TotalBlocks())
	}
	// Feeding any seed at all should be a no-op.
	if err := m.FeedSeed(bytes.NewReader([]byte("garbage"))); err != nil {
		t.Fatalf("FeedSeed empty target: %v", err)
	}
	if m.AcceptedBlocks() != 0 {
		t.Fatalf("AcceptedBlocks=%d", m.AcceptedBlocks())
	}
	if len(m.MissingRanges()) != 0 {
		t.Fatalf("expected no missing ranges for empty target")
	}
}

func TestMatcherSingleByteFile(t *testing.T) {
	target := []byte{42}
	cf := makeCF(t, target, 2048)
	m := NewMatcher(cf)
	if err := m.FeedSeed(bytes.NewReader(target)); err != nil {
		t.Fatal(err)
	}
	if m.AcceptedBlocks() != 1 {
		t.Fatalf("AcceptedBlocks=%d, want 1", m.AcceptedBlocks())
	}
	if !bytes.Equal(m.Out(), target) {
		t.Fatalf("Out=%v, want %v", m.Out(), target)
	}
}

func TestMatcherFullSeedMatchesAll(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	target := make([]byte, 4096*4) // exactly 4 blocks at bs=4096
	rng.Read(target)
	cf := makeCF(t, target, 4096)
	m := NewMatcher(cf)
	if err := m.FeedSeed(bytes.NewReader(target)); err != nil {
		t.Fatal(err)
	}
	if m.AcceptedBlocks() != m.TotalBlocks() {
		t.Fatalf("AcceptedBlocks=%d/%d", m.AcceptedBlocks(), m.TotalBlocks())
	}
	if !bytes.Equal(m.Out(), target) {
		t.Fatal("Out != target after full match")
	}
	if len(m.MissingRanges()) != 0 {
		t.Fatalf("MissingRanges=%v", m.MissingRanges())
	}
}

func TestMatcherFullyMutatedSeedMatchesNothing(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	target := make([]byte, 4096*4)
	rng.Read(target)
	seed := make([]byte, len(target))
	rng2 := rand.New(rand.NewSource(3)) // entirely different random stream
	rng2.Read(seed)

	cf := makeCF(t, target, 4096)
	m := NewMatcher(cf)
	if err := m.FeedSeed(bytes.NewReader(seed)); err != nil {
		t.Fatal(err)
	}
	if m.AcceptedBlocks() != 0 {
		t.Fatalf("AcceptedBlocks=%d, want 0 (everything should be missing)", m.AcceptedBlocks())
	}
	mr := m.MissingRanges()
	if len(mr) != 1 || mr[0][0] != 0 || mr[0][1] != m.TotalBlocks() {
		t.Fatalf("MissingRanges=%v, want one full-range entry", mr)
	}
}

func TestMatcherInsertionShift(t *testing.T) {
	// Insert bytes into the seed at offset blocksize. The matcher should
	// still find the blocks that are at *unshifted* positions.
	rng := rand.New(rand.NewSource(4))
	bs := 512
	target := make([]byte, bs*8)
	rng.Read(target)
	seed := make([]byte, 0, len(target)+5)
	seed = append(seed, target[:bs]...)
	seed = append(seed, []byte("EXTRA")...) // 5-byte insertion
	seed = append(seed, target[bs:]...)

	cf := makeCF(t, target, bs)
	m := NewMatcher(cf)
	if err := m.FeedSeed(bytes.NewReader(seed)); err != nil {
		t.Fatal(err)
	}
	// Most blocks should still match because the rolling checksum re-aligns.
	if m.AcceptedBlocks() == 0 {
		t.Fatal("AcceptedBlocks=0 after small insertion; rolling checksum failed to re-align")
	}
}

func TestMatcherDeletion(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	bs := 512
	target := make([]byte, bs*8)
	rng.Read(target)
	// Delete 7 bytes in block 2.
	seed := make([]byte, 0, len(target)-7)
	seed = append(seed, target[:bs]...)
	seed = append(seed, target[bs+7:]...)

	cf := makeCF(t, target, bs)
	m := NewMatcher(cf)
	if err := m.FeedSeed(bytes.NewReader(seed)); err != nil {
		t.Fatal(err)
	}
	if m.AcceptedBlocks() == 0 {
		t.Fatal("AcceptedBlocks=0 after small deletion; rolling checksum failed to re-align")
	}
}

func TestMatcherExactBlockBoundaries(t *testing.T) {
	rng := rand.New(rand.NewSource(6))
	bs := 256
	for _, mult := range []int{1, 2, 3, 7} {
		target := make([]byte, bs*mult)
		rng.Read(target)
		cf := makeCF(t, target, bs)
		m := NewMatcher(cf)
		if err := m.FeedSeed(bytes.NewReader(target)); err != nil {
			t.Fatal(err)
		}
		if m.AcceptedBlocks() != m.TotalBlocks() {
			t.Fatalf("mult=%d: %d/%d", mult, m.AcceptedBlocks(), m.TotalBlocks())
		}
	}
}

func TestMatcherFeedSeedShortInput(t *testing.T) {
	// Seed shorter than blocksize is padded; matcher still tries window 0.
	bs := 1024
	target := make([]byte, bs)
	for i := range target {
		target[i] = byte(i)
	}
	cf := makeCF(t, target, bs)
	m := NewMatcher(cf)
	// Seed is only 100 bytes, mostly zeros after padding — should match nothing.
	if err := m.FeedSeed(bytes.NewReader([]byte("hello"))); err != nil {
		t.Fatal(err)
	}
	if m.AcceptedBlocks() != 0 {
		t.Fatalf("AcceptedBlocks=%d, want 0", m.AcceptedBlocks())
	}
}

func TestMatcherFeedSeedReadError(t *testing.T) {
	cf := makeCF(t, []byte("hello"), 1024)
	m := NewMatcher(cf)
	want := errors.New("blow up")
	if err := m.FeedSeed(errReader{err: want}); err == nil {
		t.Fatal("expected error")
	}
}

func TestGotAndHaveBlock(t *testing.T) {
	cf := makeCF(t, make([]byte, 4096), 1024)
	m := NewMatcher(cf)
	if m.Got(-1) || m.Got(1000) {
		t.Fatal("Got out-of-range returned true")
	}
	if m.Got(0) {
		t.Fatal("Got(0) true before HaveBlock")
	}
	m.HaveBlock(0)
	if !m.Got(0) {
		t.Fatal("Got(0) false after HaveBlock")
	}
}

func TestAcceptBlockOutOfRange(t *testing.T) {
	cf := makeCF(t, make([]byte, 1024), 1024)
	m := NewMatcher(cf)
	// acceptBlock is unexported but exercised via AcceptDownloadedBlock.
	if err := m.AcceptDownloadedBlock(-1, make([]byte, 1024)); err == nil {
		t.Fatal("expected oob error")
	}
	if err := m.AcceptDownloadedBlock(10, make([]byte, 1024)); err == nil {
		t.Fatal("expected oob error")
	}
}

func TestAcceptDownloadedBlockBadSize(t *testing.T) {
	cf := makeCF(t, make([]byte, 1024), 1024)
	m := NewMatcher(cf)
	if err := m.AcceptDownloadedBlock(0, make([]byte, 512)); err == nil {
		t.Fatal("expected wrong-size error")
	}
}

func TestAcceptDownloadedBlockBadMD4(t *testing.T) {
	cf := makeCF(t, bytes.Repeat([]byte{1}, 1024), 1024)
	m := NewMatcher(cf)
	if err := m.AcceptDownloadedBlock(0, bytes.Repeat([]byte{2}, 1024)); err == nil {
		t.Fatal("expected MD4 mismatch error")
	}
}

func TestAcceptBlockShortTailBlock(t *testing.T) {
	// Last block is shorter than blocksize and must only be partially
	// copied into the output buffer (the rest is padding).
	bs := 1024
	target := make([]byte, bs+13) // one full block + 13 bytes
	for i := range target {
		target[i] = byte(i)
	}
	cf := makeCF(t, target, bs)
	m := NewMatcher(cf)
	if err := m.FeedSeed(bytes.NewReader(target)); err != nil {
		t.Fatal(err)
	}
	if m.AcceptedBlocks() != m.TotalBlocks() {
		t.Fatalf("tail: %d/%d", m.AcceptedBlocks(), m.TotalBlocks())
	}
	if !bytes.Equal(m.Out(), target) {
		t.Fatal("tail block not preserved")
	}
}

// TestMatcherRsumCollisionPath verifies that a candidate whose hashRsum
// bucket matches but whose (A,B) doesn't is rejected without an MD4
// call. We hand-build a ControlFile with a phantom block whose rsum
// collides on hashRsum but differs in (A, B). We force rsum_bytes=4 so
// the A-mask is nonzero and the equality check is meaningful.
func TestMatcherRsumCollisionPath(t *testing.T) {
	bs := 16
	target := make([]byte, bs*2)
	for i := range target {
		target[i] = byte(i)
	}
	cf := &ControlFile{
		Blocksize:   bs,
		Length:      int64(len(target)),
		HashLengths: HashLengths{SeqMatches: 1, RsumBytes: 4, ChecksumBytes: 3},
		Blocks:      nil,
	}
	for i := 0; i < 2; i++ {
		blk := target[i*bs : (i+1)*bs]
		r := CalcRsum(blk)
		md := MD4(blk)
		cf.Blocks = append(cf.Blocks, BlockChecksum{Rsum: r, Checksum: append([]byte(nil), md[:3]...)})
	}

	mask := RsumAMask(4)
	real0 := cf.Blocks[0].Rsum
	// Find an (A',B') != real0 with hashRsum(A',B') == hashRsum(real0).
	// hashRsum(r) = r.B ^ ((r.A & mask) << 3); pick A' = A^1, B' = B^(1<<3).
	phantom := Rsum{A: real0.A ^ 1, B: real0.B ^ (1 << 3)}
	mtmp := &Matcher{aMask: mask}
	if mtmp.hashRsum(real0) != mtmp.hashRsum(phantom) {
		t.Fatalf("hash construction broken")
	}
	if (phantom.A&mask) == (real0.A&mask) && phantom.B == real0.B {
		t.Fatalf("phantom equals real0 under mask")
	}
	cf.Blocks = append(cf.Blocks, BlockChecksum{Rsum: phantom, Checksum: make([]byte, 3)})

	m := NewMatcher(cf)
	if err := m.FeedSeed(bytes.NewReader(target)); err != nil {
		t.Fatal(err)
	}
	// The two real blocks should match; the phantom should not have stolen any.
	if m.AcceptedBlocks() != 2 {
		t.Errorf("collision path: got %d accepted, want 2", m.AcceptedBlocks())
	}
}

func TestMissingRangesMixed(t *testing.T) {
	cf := &ControlFile{
		Blocksize:   1024,
		Length:      1024 * 8,
		HashLengths: HashLengths{1, 2, 3},
	}
	cf.Blocks = make([]BlockChecksum, 8)
	m := NewMatcher(cf)
	// Mark blocks 0, 3, 4, 7 as "got".
	m.HaveBlock(0)
	m.HaveBlock(3)
	m.HaveBlock(4)
	m.HaveBlock(7)
	got := m.MissingRanges()
	want := [][2]int{{1, 3}, {5, 7}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("range %d: got %v want %v", i, got[i], want[i])
		}
	}
}

func TestMatcherFeedSeedRereadIdempotent(t *testing.T) {
	// FeedSeed twice in a row should not "double-count" the accepted-blocks
	// counter (the m.got check before acceptance prevents it).
	bs := 1024
	target := make([]byte, bs*3)
	for i := range target {
		target[i] = byte(i)
	}
	cf := makeCF(t, target, bs)
	m := NewMatcher(cf)
	if err := m.FeedSeed(bytes.NewReader(target)); err != nil {
		t.Fatal(err)
	}
	n1 := m.AcceptedBlocks()
	if err := m.FeedSeed(bytes.NewReader(target)); err != nil {
		t.Fatal(err)
	}
	if m.AcceptedBlocks() != n1 {
		t.Fatalf("re-feed inflated AcceptedBlocks: %d -> %d", n1, m.AcceptedBlocks())
	}
}

// Compile-time check: errReader is reused from control_test.go.
var _ io.Reader = errReader{}
