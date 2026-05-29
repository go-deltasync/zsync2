package zsync

import (
	"bytes"
	"errors"
	"io"
)

// Matcher runs the rsync-style rolling search of a seed file against the
// target block table from a parsed ControlFile, writing any matched blocks
// into an in-memory target buffer indexed by block.
//
// This MVP implements seq_matches == 1 (the simple "single block match"
// path). The C reference uses seq_matches == 2 for files larger than one
// block, which adds a "next block must also match" constraint to cut down
// on false positive weak-checksum hits; with the default Hash-Lengths sizing
// that's a tuning, not a correctness, choice for our purposes — we ignore
// seq_matches==2 on read and accept the slightly higher MD4-verification
// cost.
type Matcher struct {
	cf        *ControlFile
	blocksize int
	aMask     uint16

	// rsum_hash: maps a hash of (rsum) -> list of candidate block indices.
	// We index by a 32-bit derived hash. Multiple blocks may share a hash.
	table map[uint32][]int32

	// out is the reconstructed file. out[i*bs:(i+1)*bs] holds block i
	// (last block may be short).
	out []byte
	got []bool
	nGot int
}

// NewMatcher builds the lookup structures from cf.Blocks.
func NewMatcher(cf *ControlFile) *Matcher {
	m := &Matcher{
		cf:        cf,
		blocksize: cf.Blocksize,
		aMask:     RsumAMask(cf.HashLengths.RsumBytes),
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
// blocks that also occur in the target. Found blocks are MD4-verified
// against the control file's checksum and written into m.out.
//
// The implementation maintains a sliding window of one block, recomputing
// the rolling checksum byte-by-byte. When the rolling checksum's hash hits
// a candidate, we MD4 the window and accept iff it matches the target
// block's stored MD4 prefix.
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
	// Init rolling checksum over seed[0..bs)
	r0 := CalcRsum(seed[:bs])
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
				// Verify MD4 prefix
				md := MD4(seed[x:end])
				if bytes.Equal(md[:m.cf.HashLengths.ChecksumBytes], bc.Checksum) {
					m.acceptBlock(int(idx), seed[x:end])
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

// AcceptDownloadedBlock checks an MD4-verifies a single block fetched from
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
	md := MD4(data)
	if !bytes.Equal(md[:m.cf.HashLengths.ChecksumBytes], bc.Checksum) {
		return errors.New("zsync: downloaded block failed MD4 verification")
	}
	m.acceptBlock(idx, data)
	return nil
}
