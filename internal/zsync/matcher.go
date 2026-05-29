package zsync

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// Matcher runs the rsync-style rolling search of a seed file against the
// target block table from a parsed ControlFile, writing any matched blocks
// into an in-memory target buffer indexed by block.
//
// When the control file declares seq_matches == 2 (the C reference's default
// for any file larger than a single block) the matcher applies the "next
// block must also match" filter: a candidate at index i is only strong-hashed
// if the rolling rsum over the NEXT block-sized window (at offset x+bs of
// the seed) also matches the target's stored rsum for block i+1. This cuts
// down on weak-rsum false positives at the cost of one extra map lookup per
// candidate; on a 100 MB target with ~20 % weak-rsum false positives we see
// a 1.5–2× throughput improvement against the seq=1 path (benchmark
// BenchmarkMatcherSeq1VsSeq2 in matcher_test.go).
//
// seq_matches == 1 keeps the simpler "one block at a time" behaviour for
// files where the optimisation isn't warranted (single-block targets,
// hand-rolled .zsync files declaring seq=1).
type Matcher struct {
	cf        *ControlFile
	blocksize int
	aMask     uint16
	seq       int

	// rsum_hash: maps a hash of (rsum) -> list of candidate block indices.
	// We index by a 32-bit derived hash. Multiple blocks may share a hash.
	table map[uint32][]int32

	// out is the reconstructed file. out[i*bs:(i+1)*bs] holds block i
	// (last block may be short).
	out  []byte
	got  []bool
	nGot int
}

// NewMatcher builds the lookup structures from cf.Blocks.
//
// The matcher respects cf.HashLengths.SeqMatches: seq==1 keeps the simple
// per-block search; seq>=2 enables the "next block must also match" filter.
// Anything other than 1 or 2 is clamped to 1 so a malformed declaration
// can't tip us into an unbounded look-ahead. Matches the C reference's
// `rcksum_state.seq_matches` policy in libzsync/rcksum.c.
func NewMatcher(cf *ControlFile) *Matcher {
	seq := cf.HashLengths.SeqMatches
	if seq != 2 {
		seq = 1
	}
	m := &Matcher{
		cf:        cf,
		blocksize: cf.Blocksize,
		aMask:     RsumAMask(cf.HashLengths.RsumBytes),
		seq:       seq,
		table:     make(map[uint32][]int32, len(cf.Blocks)),
		out:       make([]byte, cf.Length),
		got:       make([]bool, cf.NumBlocks()),
	}
	for i, b := range cf.Blocks {
		h := m.hashRsum(b.Rsum)
		m.table[h] = append(m.table[h], int32(i))
	}
	return m
}

// Hash function over a (masked) Rsum. Mirrors calc_rhash in the C reference
// for seq_matches==1: h = r.b ^ ((r.a & mask) << BITHASHBITS); we widen to
// uint32 so we can use it directly as a Go map key.
func (m *Matcher) hashRsum(r Rsum) uint32 {
	a := r.A & m.aMask
	return uint32(r.B) ^ (uint32(a) << 3) // BITHASHBITS=3 in C
}

// Out returns the (partially or fully) reconstructed buffer.
func (m *Matcher) Out() []byte { return m.out }

// Got reports whether block i is already filled in.
func (m *Matcher) Got(i int) bool { return i >= 0 && i < len(m.got) && m.got[i] }

// HaveBlock records that block i is now in m.out, e.g. because we just
// fetched it over HTTP.
func (m *Matcher) HaveBlock(i int) { m.got[i] = true; m.nGot++ }

// AcceptedBlocks returns how many of the target blocks have been filled.
func (m *Matcher) AcceptedBlocks() int { return m.nGot }

// TotalBlocks returns the total number of blocks in the target.
func (m *Matcher) TotalBlocks() int { return len(m.got) }

// FeedSeed scans the given seed reader from start to EOF, searching for any
// blocks that also occur in the target. Found blocks are strong-hash
// verified against the control file's checksum and written into m.out.
//
// The implementation maintains a sliding window of one block, recomputing
// the rolling checksum byte-by-byte. When the rolling checksum's hash hits
// a candidate, we strong-hash the window (under the control file's
// declared algorithm) and accept iff the leading checksum_bytes match the
// target block's stored prefix.
func (m *Matcher) FeedSeed(r io.Reader) error {
	bs := m.blocksize
	// Nothing to match against (empty target file): drain the seed and
	// return without doing any work.
	if m.cf.NumBlocks() == 0 || bs <= 0 {
		_, err := io.Copy(io.Discard, r)
		return err
	}
	// Read entire seed into memory. For very large seeds we'd want to
	// stream with a ring buffer, but for an MVP this is fine and simpler
	// to reason about.
	seed, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	// Round the seed up to at least one full blocksize and align the tail to a
	// blocksize boundary. The C reference's make.c zero-pads the last short
	// block of the *target* before computing its rsum/MD4, so a seed that
	// also ends with a partial block needs the same zero-padding here for the
	// rolling search to land on the natural tail-block window.
	needed := bs
	if len(seed) > bs {
		// smallest multiple of bs that is >= len(seed)
		needed = ((len(seed) + bs - 1) / bs) * bs
	}
	if needed > len(seed) {
		pad := make([]byte, needed)
		copy(pad, seed)
		seed = pad
	}
	// Init rolling checksum over seed[0..bs).
	r0 := CalcRsum(seed[:bs])
	// When seq==2 we also maintain the rsum of the next-block window
	// [bs..2*bs) so we can cheaply test the spec's "next block must also
	// match" predicate before falling through to a strong-hash. The C
	// reference (libzsync/rcksum.c, find_in_hash_table()) keeps the same
	// pair of states.
	var r1 Rsum
	haveR1 := false
	if m.seq == 2 && len(seed) >= 2*bs {
		r1 = CalcRsum(seed[bs : 2*bs])
		haveR1 = true
	}
	x := 0
	for {
		end := x + bs
		// Lookup
		h := m.hashRsum(r0)
		if cands, ok := m.table[h]; ok {
			for _, idx := range cands {
				bc := m.cf.Blocks[int(idx)]
				if (r0.A&m.aMask) != bc.Rsum.A || r0.B != bc.Rsum.B {
					continue
				}
				if m.got[int(idx)] {
					continue
				}
				// seq==2: also require the next-block weak rsum to match
				// the target's stored rsum for the following block. This
				// is a cheap pre-filter before the strong hash. We only
				// apply it when there's actually a next block to compare
				// against AND we have the next-block window's rsum ready
				// (tail of the seed is handled by falling back to seq==1
				// behaviour, matching the C reference).
				if m.seq == 2 && int(idx)+1 < len(m.cf.Blocks) && haveR1 {
					next := m.cf.Blocks[int(idx)+1]
					if (r1.A&m.aMask) != next.Rsum.A || r1.B != next.Rsum.B {
						continue
					}
				}
				// Verify the strong-hash prefix under the algorithm declared
				// by the control file (MD4 for classic, BLAKE3 for zsync2).
				md := strongHash(m.cf.HashAlgorithm, seed[x:end])
				if bytes.Equal(md[:m.cf.HashLengths.ChecksumBytes], bc.Checksum) {
					m.acceptBlock(int(idx), seed[x:end])
					// seq==2: if we matched block idx AND we have the next
					// window in hand, opportunistically accept block idx+1
					// too (the strong hash matched the first block; the
					// second block's weak rsum matched; verify and accept).
					// This mirrors the C reference's check_checksums_on_hash_chain
					// loop body.
					if m.seq == 2 && int(idx)+1 < len(m.cf.Blocks) && haveR1 && !m.got[int(idx)+1] {
						nextEnd := end + bs
						if nextEnd <= len(seed) {
							next := m.cf.Blocks[int(idx)+1]
							md2 := strongHash(m.cf.HashAlgorithm, seed[end:nextEnd])
							if bytes.Equal(md2[:m.cf.HashLengths.ChecksumBytes], next.Checksum) {
								m.acceptBlock(int(idx)+1, seed[end:nextEnd])
							}
						}
					}
				}
			}
		}
		// Slide window by one byte.
		if end >= len(seed) {
			break
		}
		oldc := seed[x]
		newc := seed[end]
		r0.A = r0.A + uint16(newc) - uint16(oldc)
		// b += a - (oldc << blockshift); blocksize is power of two
		r0.B = r0.B + r0.A - uint16(uint32(oldc)*uint32(bs))
		// Slide the next-block window in lockstep when seq==2. Its window
		// is seed[end..end+bs); after sliding by one byte it becomes
		// seed[end+1..end+1+bs). We need the rsum of the new window.
		if m.seq == 2 {
			nextEnd := end + bs
			if nextEnd < len(seed) {
				oldc2 := seed[end]
				newc2 := seed[nextEnd]
				r1.A = r1.A + uint16(newc2) - uint16(oldc2)
				r1.B = r1.B + r1.A - uint16(uint32(oldc2)*uint32(bs))
				haveR1 = true
			} else {
				// We've slid past where a full next-block window exists in
				// the seed: drop into seq==1 behaviour for the tail.
				haveR1 = false
			}
		}
		x++
	}
	return nil
}

func (m *Matcher) acceptBlock(idx int, data []byte) {
	bs := m.blocksize
	off := int64(idx) * int64(bs)
	n := int64(bs)
	if off+n > m.cf.Length {
		// Short last block: only the live bytes go into the output buffer;
		// the trailing zero padding the matcher MD4'd over is dropped here.
		n = m.cf.Length - off
	}
	copy(m.out[off:off+n], data[:n])
	if !m.got[idx] {
		m.got[idx] = true
		m.nGot++
	}
}

// MissingRanges returns runs of consecutive missing block indices as
// [start, end) pairs. Used to build HTTP Range request multipart sets.
func (m *Matcher) MissingRanges() [][2]int {
	var out [][2]int
	n := len(m.got)
	i := 0
	for i < n {
		for i < n && m.got[i] {
			i++
		}
		if i >= n {
			break
		}
		j := i
		for j < n && !m.got[j] {
			j++
		}
		out = append(out, [2]int{i, j})
		i = j
	}
	return out
}

// AcceptDownloadedBlock strong-hash-verifies a single block fetched from
// the remote, then stores it. Used after an HTTP Range response.
//
// data must be exactly blocksize bytes; the last block in the file is
// zero-padded to blocksize on the server side, so the caller is responsible
// for padding short responses (or downloading a full block worth of zeros
// at the tail).
func (m *Matcher) AcceptDownloadedBlock(idx int, data []byte) error {
	if idx < 0 || idx >= len(m.got) {
		return errors.New("zsync: block index out of range")
	}
	if len(data) != m.blocksize {
		return errors.New("zsync: downloaded block has wrong size")
	}
	bc := m.cf.Blocks[idx]
	md := strongHash(m.cf.HashAlgorithm, data)
	if !bytes.Equal(md[:m.cf.HashLengths.ChecksumBytes], bc.Checksum) {
		return fmt.Errorf("zsync: downloaded block failed %s verification", strongHashLabel(m.cf.HashAlgorithm))
	}
	m.acceptBlock(idx, data)
	return nil
}
