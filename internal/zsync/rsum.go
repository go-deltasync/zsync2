package zsync

import (
	"encoding/binary"
	"fmt"
	"math"

	"golang.org/x/crypto/md4" //nolint:staticcheck // zsync wire format requires MD4
	"lukechampine.com/blake3"
)

// Strong-hash algorithm identifiers used inside ControlFile and on the wire
// (Hash-Algorithm: header in zsync2: 1.0). The string values match the
// header's case-sensitive spelling.
const (
	HashAlgoMD4    = "MD4"
	HashAlgoBLAKE3 = "BLAKE3"
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

// BLAKE3 returns the 32-byte BLAKE3-256 digest of data. The zsync2: 1.0
// wire format stores only the leading `checksum_bytes` of this per block.
func BLAKE3(data []byte) [32]byte {
	return blake3.Sum256(data)
}

// blake3Hasher matches the subset of hash.Hash that Make uses to stream the
// file-wide BLAKE3 digest. Exposed via blake3New for symmetry with
// crypto/sha1.New().
type blake3Hasher interface {
	Write(p []byte) (int, error)
	Sum(b []byte) []byte
	Reset()
}

// blake3New returns a streaming BLAKE3-256 hasher. Used to compute the
// file-wide File-Hash: BLAKE3:<hex> digest as Make consumes its input.
func blake3New() blake3Hasher {
	return blake3.New(32, nil)
}

// strongHash returns the full strong-hash digest of blk under the given
// algorithm. The caller truncates to the per-block `checksum_bytes` width
// from Hash-Lengths. Returns:
//   - 16 bytes for MD4 (the zsync: 0.6 wire format)
//   - 32 bytes for BLAKE3 (the zsync2: 1.0 wire format)
//
// An empty algo string is treated as MD4 for backward compatibility, to keep
// callers that predate the algorithm field working unchanged.
func strongHash(algo string, blk []byte) []byte {
	switch algo {
	case "", HashAlgoMD4:
		d := MD4(blk)
		return d[:]
	case HashAlgoBLAKE3:
		d := BLAKE3(blk)
		return d[:]
	default:
		// Caller is responsible for vetting `algo`; panic here is a bug.
		panic(fmt.Sprintf("zsync: unknown strong-hash algorithm %q", algo))
	}
}

// StrongHashFullLen returns the full digest width (bytes) for the given
// algorithm. Used by ComputeHashLengths to clamp checksum_bytes to the
// natural ceiling of the hash.
func StrongHashFullLen(algo string) int {
	switch algo {
	case "", HashAlgoMD4:
		return 16
	case HashAlgoBLAKE3:
		return 32
	default:
		panic(fmt.Sprintf("zsync: unknown strong-hash algorithm %q", algo))
	}
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
	ChecksumBytes int // 3..16 for MD4, 3..32 for BLAKE3
}

// ComputeHashLengths reproduces the C reference's per-file sizing for the
// classic MD4 wire format. This matches make.c exactly so we generate
// byte-identical .zsync files (modulo headers).
//
// For backward compatibility callers that don't pass an algorithm get the
// classic MD4-clamped behaviour.
func ComputeHashLengths(length int64, blocksize int) HashLengths {
	return ComputeHashLengthsAlgo(length, blocksize, HashAlgoMD4)
}

// ComputeHashLengthsAlgo is the algorithm-aware variant of ComputeHashLengths.
//
// The per-block checksum_bytes sizing formula (Phipps' birthday-bound formula
// from make.c) is identical for both MD4 and BLAKE3: it depends on file
// length and block count, not on the strong-hash algorithm. What changes:
//
//   - The natural ceiling. MD4 emits 16 bytes total per digest so the
//     per-block prefix tops out at 16; BLAKE3 emits 32 bytes total, so we
//     can carry up to 32 bytes of per-block strong digest on the wire.
//   - A BLAKE3-only floor of 16 bytes per block (128-bit birthday bound on
//     accidental collision). The proposal calls for this so that a typical
//     1 GB target lands at `Hash-Lengths: 2 4 16`; the Phipps formula by
//     itself would still return ~5 bytes there because it was tuned around
//     MD4 prefix sizing. MD4 is unaffected.
func ComputeHashLengthsAlgo(length int64, blocksize int, algo string) HashLengths {
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
	// BLAKE3 floor: see comment above on the proposal's stated target.
	if algo == HashAlgoBLAKE3 && csLen < 16 {
		csLen = 16
	}
	// Ceiling clamp at the algorithm's full-digest width.
	maxCs := StrongHashFullLen(algo)
	if csLen > maxCs {
		csLen = maxCs
	}
	if csLen < 3 {
		csLen = 3
	}
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
