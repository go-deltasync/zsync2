package zsync

import (
	"encoding/binary"
	"math"

	"golang.org/x/crypto/md4" //nolint:staticcheck // zsync wire format requires MD4
)

// Rsum is the rsync-style rolling weak checksum used by zsync.
//
// For a block b[0..n) of bytes:
//
//	a = sum_{i=0..n-1}  b[i]                  (mod 2^16)
//	b = sum_{i=0..n-1}  (n - i) * b[i]        (mod 2^16)
//
// Equivalently, b can be updated incrementally when sliding a window of width
// n forward by one byte:
//
//	a' = a + new - old
//	b' = b + a' - n * old   ( = b + a' - (old << blockshift) when n = 1<<blockshift )
//
// On the wire the (a, b) pair is written big-endian as two uint16s, then
// truncated to the trailing `rsum_bytes` bytes per the .zsync Hash-Lengths
// header. The leading bytes (i.e. high byte of a) are dropped first because
// the b half carries more entropy.
type Rsum struct {
	A, B uint16
}

// CalcRsum computes the rolling-checksum of an entire block.
// blocksize is the nominal block size; if len(data) < blocksize the C
// implementation zero-pads, so callers should hand in an already-padded slice.
func CalcRsum(data []byte) Rsum {
	var a, b uint16
	n := uint16(len(data))
	for i, c := range data {
		a += uint16(c)
		b += uint16(uint32(n)-uint32(i)) * uint16(c) //nolint:gosec // intentional mod-2^16 wrap
	}
	return Rsum{A: a, B: b}
}

// MD4 returns the 16-byte MD4 digest of data. zsync stores only the leading
// `checksum_bytes` of this per block, per the Hash-Lengths header.
func MD4(data []byte) [16]byte {
	h := md4.New()
	_, _ = h.Write(data)
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// PutBE16 writes a big-endian uint16 (helper for tests).
func PutBE16(v uint16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return b[:]
}

// HashLengths is the (seq_matches, rsum_bytes, checksum_bytes) tuple from
// the .zsync "Hash-Lengths:" header.
type HashLengths struct {
	SeqMatches    int // 1 or 2
	RsumBytes     int // 2..4
	ChecksumBytes int // 3..16
}

// ComputeHashLengths reproduces the C reference's per-file sizing.
// This matches make.c exactly so we generate byte-identical .zsync files
// (modulo headers).
func ComputeHashLengths(length int64, blocksize int) HashLengths {
	seq := 1
	if length > int64(blocksize) {
		seq = 2
	}
	// log(0) is -inf and explodes the sizing formulae; for empty or
	// degenerate inputs fall back to the smallest legal Hash-Lengths.
	if length <= 0 {
		return HashLengths{SeqMatches: 1, RsumBytes: 2, ChecksumBytes: 3}
	}
	lnLen := math.Log(float64(length))
	lnBs := math.Log(float64(blocksize))
	ln2 := math.Log(2)
	rsumLen := int(math.Ceil(((lnLen+lnBs)/ln2 - 8.6) / float64(seq) / 8))
	if rsumLen > 4 {
		rsumLen = 4
	}
	if rsumLen < 2 {
		rsumLen = 2
	}
	nBlocks := 1 + length/int64(blocksize)
	cs1 := math.Ceil((20 + (lnLen+math.Log(float64(nBlocks)))/ln2) / float64(seq) / 8)
	cs2 := (7.9 + 20 + math.Log(float64(nBlocks))/ln2) / 8
	csLen := int(cs1)
	if int(cs2) > csLen {
		csLen = int(cs2)
	}
	// The C reference clamps csLen to [3, 16] here. With int64 inputs neither
	// clamp can actually fire (the formulas saturate well inside that range
	// for any non-degenerate length/blocksize pair), so the wire-spec range is
	// enforced on Read by Hash-Lengths sanity-checking instead of here.
	return HashLengths{SeqMatches: seq, RsumBytes: rsumLen, ChecksumBytes: csLen}
}

// RsumAMask is the mask applied to Rsum.A before storing/comparing, per
// rcksum_state.rsum_a_mask in the C source. When rsum_bytes < 3 the A half is
// entirely ignored (only B is kept on the wire).
func RsumAMask(rsumBytes int) uint16 {
	switch {
	case rsumBytes < 3:
		return 0
	case rsumBytes == 3:
		return 0xff
	default:
		return 0xffff
	}
}
