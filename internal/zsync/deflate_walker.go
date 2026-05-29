package zsync

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// newSeekingByteReader returns an io.Reader over gzData. The name is a
// historical leftover from when this was an io.ReadSeeker; the walker
// only needs forward reads now.
func newSeekingByteReader(gzData []byte) io.Reader {
	return bytes.NewReader(gzData)
}

// newGzipPayloadReader returns a reader over the decompressed payload
// of a gzip stream. The caller is responsible for Close()ing it.
func newGzipPayloadReader(gzData []byte) (io.ReadCloser, error) {
	return gzip.NewReader(bytes.NewReader(gzData))
}

// makeFromReaderWithAlgo is a thin shim onto MakeWithAlgo for the
// MakeWithZMap2 entry point. It exists so MakeWithZMap2's signature
// can hide the `int64 totalSize` parameter — for a gzip payload we
// don't know the uncompressed size up front; MakeWithAlgo's
// `ComputeHashLengthsAlgo(totalSize, ...)` is sized off the *expected*
// size, but we're happy to pay the cost of streaming first and
// re-hashing the same payload through Make under the discovered size.
func makeFromReaderWithAlgo(r io.Reader, blocksize int, filename string, mtime interface{}, urls []string, algo string) (*ControlFile, error) {
	// Read the whole payload so we can pass a real totalSize to
	// MakeWithAlgo. For multi-GB targets a streaming variant would be
	// nicer; the Z-Map2 path is in practice used for AppImage-sized
	// payloads where this is acceptable.
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var t time.Time
	if mt, ok := mtime.(time.Time); ok {
		t = mt
	}
	return MakeWithAlgo(bytes.NewReader(data), int64(len(data)), blocksize, filename, t, urls, algo)
}

// This file implements the deflate-bitstream walker that drives Z-Map2
// generation. Z-Map2 records the (compressed-bit-offset, uncompressed-byte-
// offset) pair for every deflate block start (plus periodic mid-block
// checkpoints) so a zsync client can fetch a small gz byte range, reset
// the decompressor at the recorded bit boundary, and feed only the
// freshly-decompressed bytes into the matcher.
//
// We deliberately do NOT use compress/flate here: the stdlib reader is a
// stream-oriented decompressor with no public hooks for "tell me the bit
// offset of every block boundary". The standalone walker is a few hundred
// lines and stays self-contained against RFC 1951.
//
// Where RFC 1951 and zlib differ on edge cases (e.g. a zero-length stored
// block) we follow zlib's behaviour because that's what the deployed
// universe of gzip files was produced by. Spec ambiguity points are
// flagged in inline comments.

// gzbCheckpointInterval is the uncompressed-byte interval at which the
// walker drops a mid-block checkpoint inside a long deflate block. The
// C reference's libzsync/zmap.c uses 32768 (32 KB), matching deflate's
// default window. The exact number is a tuning, not a correctness,
// choice — a smaller value bloats the Z-Map2 table; a larger value forces
// the client to decode more bytes per restart.
const gzbCheckpointInterval = 32 * 1024

// gzbWireDeltaMargin caps the compressed-bit delta we let accumulate
// between consecutive Z-Map2 entries before forcing a checkpoint. The
// wire format gives each entry's inbitoffset 16 bits, so any two entries
// more than 65535 bits (~ 8 KB compressed) apart cannot be encoded as
// a single delta. We checkpoint earlier than that to leave headroom.
const gzbWireDeltaMargin = 60000 // bits

// gzipMagic is the two-byte gzip identifier at the head of every gzip
// member, RFC 1952 §2.3.1.
var gzipMagic = [2]byte{0x1f, 0x8b}

// gzip header flag bits, RFC 1952 §2.3.1.
const (
	gzFlagText    = 1 << 0
	gzFlagHCRC    = 1 << 1
	gzFlagExtra   = 1 << 2
	gzFlagName    = 1 << 3
	gzFlagComment = 1 << 4
)

// skipGzipHeader reads the gzip header from r, returning the number of
// bytes consumed (so the caller knows where the deflate stream starts in
// the gz file). The function does not validate the trailing CRC32 / ISIZE
// fields — those sit after the deflate payload and are out of scope here.
func skipGzipHeader(r io.Reader) (int64, error) {
	var n int64
	var hdr [10]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return n, fmt.Errorf("zsync: gzip header read: %w", err)
	}
	n += 10
	if hdr[0] != gzipMagic[0] || hdr[1] != gzipMagic[1] {
		return n, fmt.Errorf("zsync: not a gzip stream (magic = %02x%02x)", hdr[0], hdr[1])
	}
	if hdr[2] != 8 { // CM == deflate, RFC 1952 §2.3.1.2
		return n, fmt.Errorf("zsync: gzip compression method %d (want 8)", hdr[2])
	}
	flg := hdr[3]
	// FEXTRA: 2-byte length + XLEN bytes of extra data.
	if flg&gzFlagExtra != 0 {
		var xlenBuf [2]byte
		if _, err := io.ReadFull(r, xlenBuf[:]); err != nil {
			return n, fmt.Errorf("zsync: gzip FEXTRA read: %w", err)
		}
		n += 2
		xlen := int(binary.LittleEndian.Uint16(xlenBuf[:]))
		if _, err := io.CopyN(io.Discard, r, int64(xlen)); err != nil {
			return n, fmt.Errorf("zsync: gzip FEXTRA skip: %w", err)
		}
		n += int64(xlen)
	}
	// FNAME / FCOMMENT: NUL-terminated strings.
	skipZ := func(label string) error {
		one := make([]byte, 1)
		for {
			if _, err := io.ReadFull(r, one); err != nil {
				return fmt.Errorf("zsync: gzip %s read: %w", label, err)
			}
			n++
			if one[0] == 0 {
				return nil
			}
		}
	}
	if flg&gzFlagName != 0 {
		if err := skipZ("FNAME"); err != nil {
			return n, err
		}
	}
	if flg&gzFlagComment != 0 {
		if err := skipZ("FCOMMENT"); err != nil {
			return n, err
		}
	}
	// FHCRC: 2 trailing bytes.
	if flg&gzFlagHCRC != 0 {
		if _, err := io.CopyN(io.Discard, r, 2); err != nil {
			return n, fmt.Errorf("zsync: gzip FHCRC read: %w", err)
		}
		n += 2
	}
	return n, nil
}

// bitReader is a bit-oriented byte stream reader matching RFC 1951's
// little-endian "least-significant bit first within a byte" convention.
//
// Each Read call pulls the requested number of bits from the buffered
// byte stream; the reader maintains a 64-bit accumulator and a count of
// valid bits so it can answer multi-bit reads cheaply.
type bitReader struct {
	r       io.Reader
	buf     uint64
	bits    uint // number of valid bits in buf
	bytePos int64 // absolute byte position into the deflate stream
	bitPos  uint64 // absolute bit position into the deflate stream
	err     error
}

func newBitReader(r io.Reader) *bitReader { return &bitReader{r: r} }

// ensure makes sure the accumulator has at least `n` bits available.
func (br *bitReader) ensure(n uint) error {
	if br.err != nil {
		return br.err
	}
	for br.bits < n {
		var one [1]byte
		if _, err := io.ReadFull(br.r, one[:]); err != nil {
			br.err = err
			return err
		}
		br.buf |= uint64(one[0]) << br.bits
		br.bits += 8
		br.bytePos++
	}
	return nil
}

// Read returns the next n bits (LSB-first) from the stream. Returns the
// value and any underlying read error.
func (br *bitReader) Read(n uint) (uint64, error) {
	if err := br.ensure(n); err != nil {
		return 0, err
	}
	v := br.buf & ((1 << n) - 1)
	br.buf >>= n
	br.bits -= n
	br.bitPos += uint64(n)
	return v, nil
}

// AlignToByte discards any partially-consumed bits so the next read
// happens on a byte boundary, RFC 1951 §3.2.4 (the rule for type 0
// stored blocks).
func (br *bitReader) AlignToByte() {
	drop := br.bits % 8
	br.buf >>= drop
	br.bits -= drop
	br.bitPos += uint64(drop)
}

// BitPos returns the absolute bit position into the deflate stream of
// the *next* bit to be consumed. A Z-Map2 entry's `Compressed` field is
// this value at the moment the entry is recorded.
func (br *bitReader) BitPos() uint64 { return br.bitPos }

// ReadBytes consumes exactly nBytes from the underlying byte stream,
// bypassing the bit accumulator. It is only valid after AlignToByte()
// and is used to read the body of a type 0 stored block. The bytes are
// returned to the caller; the bit position is advanced by 8*nBytes.
func (br *bitReader) ReadBytes(nBytes int) ([]byte, error) {
	if br.bits%8 != 0 {
		return nil, fmt.Errorf("zsync: ReadBytes called with %d unaligned bits", br.bits%8)
	}
	// Drain any whole bytes left in the accumulator first.
	out := make([]byte, 0, nBytes)
	for nBytes > 0 && br.bits >= 8 {
		out = append(out, byte(br.buf&0xff))
		br.buf >>= 8
		br.bits -= 8
		br.bitPos += 8
		nBytes--
	}
	if nBytes > 0 {
		need := make([]byte, nBytes)
		if _, err := io.ReadFull(br.r, need); err != nil {
			return nil, err
		}
		out = append(out, need...)
		br.bytePos += int64(nBytes)
		br.bitPos += uint64(8 * nBytes)
	}
	return out, nil
}

// DeflateWalker drives the bit-level traversal of a deflate stream,
// recording one ZMapEntry at each block boundary and every
// gzbCheckpointInterval uncompressed bytes within a long block.
//
// The walker is not a decompressor proper — it never materialises the
// uncompressed bytes — but it MUST track the uncompressed byte count so
// the ZMapEntry.Inflated field reflects "decompressed bytes emitted
// since the start of the stream". For dynamic / fixed Huffman blocks
// that means walking every literal/length pair and adding (literal:1 |
// length:N) bytes to the running counter.
type DeflateWalker struct {
	br *bitReader

	// inflated is the cumulative number of uncompressed bytes produced.
	inflated uint64

	// entries is the accumulator for the produced Z-Map2 table.
	entries []ZMapEntry

	// blockCount tracks the position within the current deflate block
	// (0 for a fresh block, 1, 2, ... for mid-block checkpoints).
	blockCount int

	// lastCheckpointInflated / lastCheckpointBitPos pace mid-block
	// checkpoints against both the uncompressed and compressed budgets
	// (see maybeCheckpoint).
	lastCheckpointInflated uint64
	lastCheckpointBitPos   uint64
}

// Walk consumes the deflate stream from r (positioned at the first
// deflate byte — call skipGzipHeader first to position correctly) and
// returns the accumulated Z-Map2 entries.
//
// The walker's running offsets are bit-relative to r's first byte, so
// the caller is responsible for tracking the gz file offset of the
// deflate-stream start and combining it with the Z-Map2 if it wants
// absolute gz-file bit offsets (the C reference does NOT do this — the
// Z-Map2 Compressed field is documented as "into the deflate stream",
// not "into the gz file").
func Walk(r io.Reader) ([]ZMapEntry, error) {
	w := &DeflateWalker{br: newBitReader(r)}
	if err := w.walk(); err != nil {
		return nil, err
	}
	return w.entries, nil
}

func (w *DeflateWalker) emit(isBlockStart bool) {
	bc := w.blockCount
	if isBlockStart {
		bc = 0
	} else {
		w.blockCount++
		bc = w.blockCount
	}
	w.entries = append(w.entries, ZMapEntry{
		Inflated:     w.inflated,
		Compressed:   w.br.BitPos(),
		IsBlockStart: isBlockStart,
		BlockCount:   bc,
	})
	w.lastCheckpointInflated = w.inflated
	w.lastCheckpointBitPos = w.br.BitPos()
}

// maybeCheckpoint emits a mid-block checkpoint when either:
//   - We have travelled gzbCheckpointInterval uncompressed bytes since
//     the previous entry (matches libzsync/zmap.c's pacing rule).
//   - We have travelled gzbWireDeltaMargin compressed bits since the
//     previous entry. This guarantees consecutive Z-Map2 entries fit
//     into the 16-bit inbitoffset delta field, even for low-compression
//     payloads where 32 KB of output may take more than 8 KB of input.
func (w *DeflateWalker) maybeCheckpoint() {
	if w.inflated-w.lastCheckpointInflated >= gzbCheckpointInterval ||
		w.br.BitPos()-w.lastCheckpointBitPos >= gzbWireDeltaMargin {
		w.emit(false)
	}
}

// walk runs the block loop until BFINAL=1 is seen, then returns.
func (w *DeflateWalker) walk() error {
	for {
		// Block header: BFINAL (1) + BTYPE (2)
		w.blockCount = 0
		w.emit(true)
		bfinal, err := w.br.Read(1)
		if err != nil {
			return fmt.Errorf("zsync: deflate BFINAL: %w", err)
		}
		// BTYPE's 2 bits always come from the same buffered byte as
		// BFINAL (bitReader.ensure pulls a full byte at a time), so a
		// successful BFINAL read guarantees BTYPE has its bits ready.
		btype, _ := w.br.Read(2)
		var berr error
		switch btype {
		case 0:
			berr = w.walkStored()
		case 1:
			berr = w.walkFixedHuffman()
		case 2:
			berr = w.walkDynamicHuffman()
		case 3:
			return fmt.Errorf("zsync: deflate reserved BTYPE=3")
		}
		if berr != nil {
			return berr
		}
		if bfinal == 1 {
			return nil
		}
	}
}

// walkStored handles a type-0 (stored) block per RFC 1951 §3.2.4. The
// stored body is byte-aligned; we follow zlib in accepting zero-length
// stored blocks (RFC is silent on that edge case).
func (w *DeflateWalker) walkStored() error {
	w.br.AlignToByte()
	hdrBytes, err := w.br.ReadBytes(4)
	if err != nil {
		return fmt.Errorf("zsync: stored block LEN/NLEN: %w", err)
	}
	lenVal := int(binary.LittleEndian.Uint16(hdrBytes[0:2]))
	nlen := int(binary.LittleEndian.Uint16(hdrBytes[2:4]))
	if lenVal != (^nlen & 0xffff) {
		return fmt.Errorf("zsync: stored block LEN/NLEN mismatch: %d / %d", lenVal, nlen)
	}
	if lenVal == 0 {
		// zlib accepts a zero-length stored block; the RFC doesn't reject
		// it explicitly so we follow zlib. Nothing to copy, no inflated
		// bytes produced, no mid-block checkpoint warranted.
		return nil
	}
	// We need to advance both the bit position by 8*lenVal and the
	// inflated counter by lenVal. We use ReadBytes so the underlying
	// reader is consumed correctly; the byte payload is discarded —
	// we don't actually decompress here.
	//
	// Chunk size: maybeCheckpoint is called only at chunk boundaries,
	// so we choose the chunk small enough (256 bytes == 2048 bits) that
	// the worst-case overshoot beyond gzbWireDeltaMargin (60000 bits)
	// still fits in the 16-bit inbitoffset delta field (0xffff = 65535
	// bits). Concretely: when BitPos hits 60000, the NEXT chunk takes
	// us to at most 62048, well under 65535.
	const chunk = 256
	remaining := lenVal
	for remaining > 0 {
		k := remaining
		if k > chunk {
			k = chunk
		}
		if _, err := w.br.ReadBytes(k); err != nil {
			return fmt.Errorf("zsync: stored block payload: %w", err)
		}
		w.inflated += uint64(k)
		remaining -= k
		w.maybeCheckpoint()
	}
	return nil
}

// fixedLitLenLengths returns the canonical fixed-Huffman literal/length
// code lengths per RFC 1951 §3.2.6. 288 codes:
//
//	0..143  : 8 bits
//	144..255: 9 bits
//	256..279: 7 bits
//	280..287: 8 bits
func fixedLitLenLengths() []int {
	lens := make([]int, 288)
	for i := 0; i <= 143; i++ {
		lens[i] = 8
	}
	for i := 144; i <= 255; i++ {
		lens[i] = 9
	}
	for i := 256; i <= 279; i++ {
		lens[i] = 7
	}
	for i := 280; i <= 287; i++ {
		lens[i] = 8
	}
	return lens
}

// fixedDistLengths returns the fixed-Huffman distance code lengths (all 5).
func fixedDistLengths() []int {
	lens := make([]int, 30)
	for i := range lens {
		lens[i] = 5
	}
	return lens
}

// walkFixedHuffman handles a type-1 block.
func (w *DeflateWalker) walkFixedHuffman() error {
	lit := buildCanonicalCode(fixedLitLenLengths())
	dist := buildCanonicalCode(fixedDistLengths())
	return w.decodeBlockBody(lit, dist)
}

// walkDynamicHuffman handles a type-2 block per RFC 1951 §3.2.7.
func (w *DeflateWalker) walkDynamicHuffman() error {
	hlit, err := w.br.Read(5)
	if err != nil {
		return fmt.Errorf("zsync: HLIT: %w", err)
	}
	hdist, err := w.br.Read(5)
	if err != nil {
		return fmt.Errorf("zsync: HDIST: %w", err)
	}
	// HCLEN's 4 bits draw from the same byte HDIST consumed (HDIST ends
	// at bit 10 of 16 buffered; HCLEN's 4 bits fit comfortably without
	// further I/O), so a successful HDIST implies HCLEN succeeds too.
	hclen, _ := w.br.Read(4)
	nLit := int(hlit) + 257
	nDist := int(hdist) + 1
	nCode := int(hclen) + 4

	// Code-length code lengths, in the strange order from §3.2.7.
	clOrder := []int{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}
	clLens := make([]int, 19)
	for i := 0; i < nCode; i++ {
		v, err := w.br.Read(3)
		if err != nil {
			return fmt.Errorf("zsync: CL code length %d: %w", i, err)
		}
		clLens[clOrder[i]] = int(v)
	}
	clCode := buildCanonicalCode(clLens)

	// Decode the (nLit + nDist) lengths.
	total := nLit + nDist
	lens := make([]int, total)
	i := 0
	for i < total {
		sym, err := decodeSymbol(w.br, clCode)
		if err != nil {
			return fmt.Errorf("zsync: dyn lens symbol: %w", err)
		}
		switch {
		case sym < 16:
			lens[i] = sym
			i++
		case sym == 16:
			// Repeat previous length 3..6 times (2 extra bits).
			if i == 0 {
				return fmt.Errorf("zsync: dyn lens code 16 with no previous")
			}
			// The 2 extra bits draw from the same buffered byte as the
			// code itself, so a successful decodeSymbol guarantees the
			// Read won't I/O-fail. Same for codes 17 (3 extra) and 18
			// (7 extra) — all fit inside the 64-bit accumulator that
			// decodeSymbol left primed.
			extra, _ := w.br.Read(2)
			n := int(extra) + 3
			if i+n > total {
				return fmt.Errorf("zsync: dyn lens code 16 overruns table")
			}
			prev := lens[i-1]
			for j := 0; j < n; j++ {
				lens[i+j] = prev
			}
			i += n
		case sym == 17:
			extra, _ := w.br.Read(3)
			n := int(extra) + 3
			if i+n > total {
				return fmt.Errorf("zsync: dyn lens code 17 overruns table")
			}
			i += n // zeros (lens already zero-initialised)
		case sym == 18:
			extra, _ := w.br.Read(7)
			n := int(extra) + 11
			if i+n > total {
				return fmt.Errorf("zsync: dyn lens code 18 overruns table")
			}
			i += n
		}
		// No default branch: buildCanonicalCode is fed at most 19 CL
		// lengths, so decodeSymbol can only return 0..18 here. Anything
		// outside that range would already have failed decodeSymbol's
		// "no symbol within 15 bits" check.
	}
	lit := buildCanonicalCode(lens[:nLit])
	dist := buildCanonicalCode(lens[nLit:])
	return w.decodeBlockBody(lit, dist)
}

// decodeBlockBody walks literal / length / distance symbols until the
// end-of-block marker (literal/length code 256).
//
// Length / distance base values and extra-bit counts are from RFC 1951
// §3.2.5.
func (w *DeflateWalker) decodeBlockBody(litCode, distCode *huffmanCode) error {
	for {
		sym, err := decodeSymbol(w.br, litCode)
		if err != nil {
			return err
		}
		switch {
		case sym < 256:
			w.inflated++
			// Mid-block checkpoint pacing — fire every
			// gzbCheckpointInterval uncompressed bytes.
			w.maybeCheckpoint()
		case sym == 256:
			return nil
		case sym <= 285:
			length, err := decodeLength(w.br, sym)
			if err != nil {
				return err
			}
			distSym, err := decodeSymbol(w.br, distCode)
			if err != nil {
				return err
			}
			if distSym > 29 {
				return fmt.Errorf("zsync: distance symbol %d out of range", distSym)
			}
			// Skip extra distance bits (we don't need the value itself).
			if _, err := decodeDistance(w.br, distSym); err != nil {
				return err
			}
			w.inflated += uint64(length)
			w.maybeCheckpoint()
		default:
			return fmt.Errorf("zsync: literal/length symbol %d > 285", sym)
		}
	}
}

// lengthBase / lengthExtra are RFC 1951 §3.2.5 Table-1: codes 257..285.
var lengthBase = [29]int{
	3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
	67, 83, 99, 115, 131, 163, 195, 227, 258,
}
var lengthExtra = [29]uint{
	0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,
	4, 4, 4, 4, 5, 5, 5, 5, 0,
}

func decodeLength(br *bitReader, sym int) (int, error) {
	idx := sym - 257
	if idx < 0 || idx >= len(lengthBase) {
		return 0, fmt.Errorf("zsync: length symbol %d out of range", sym)
	}
	extra, err := br.Read(lengthExtra[idx])
	if err != nil {
		return 0, err
	}
	return lengthBase[idx] + int(extra), nil
}

// distanceBase / distanceExtra are RFC 1951 §3.2.5 Table-2.
var distanceBase = [30]int{
	1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769,
	1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
}
var distanceExtra = [30]uint{
	0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8,
	9, 9, 10, 10, 11, 11, 12, 12, 13, 13,
}

func decodeDistance(br *bitReader, sym int) (int, error) {
	if sym < 0 || sym >= len(distanceBase) {
		return 0, fmt.Errorf("zsync: distance symbol %d out of range", sym)
	}
	extra, err := br.Read(distanceExtra[sym])
	if err != nil {
		return 0, err
	}
	return distanceBase[sym] + int(extra), nil
}

// huffmanCode is a decoded canonical Huffman table. We use the
// length-indexed lookup variant from RFC 1951 §3.2.2: codes ordered by
// (length, symbol) yields the canonical encoding; decoding walks
// length-by-length comparing the accumulated code value against the
// first code at each length.
type huffmanCode struct {
	// codes[L] = list of (symbol, code) pairs at length L+1.
	codes [16]struct {
		first int
		count int
		// syms holds the symbols of codes at this length, ordered by code.
		syms []int
	}
}

func buildCanonicalCode(lens []int) *huffmanCode {
	hc := &huffmanCode{}
	// Count codes per length.
	var blCount [16]int
	for _, l := range lens {
		if l > 0 {
			blCount[l]++
		}
	}
	// First-code-at-each-length per RFC 1951 §3.2.2.
	var nextCode [16]int
	code := 0
	for bits := 1; bits < 16; bits++ {
		code = (code + blCount[bits-1]) << 1
		nextCode[bits] = code
		hc.codes[bits-1].first = code
		hc.codes[bits-1].count = blCount[bits]
		hc.codes[bits-1].syms = make([]int, blCount[bits])
	}
	// Bucket the symbols into their per-length lists in code order.
	idx := [16]int{}
	for sym, l := range lens {
		if l <= 0 {
			continue
		}
		hc.codes[l-1].syms[idx[l-1]] = sym
		idx[l-1]++
	}
	return hc
}

// decodeSymbol reads one Huffman code from br and returns the decoded
// symbol. Implements the length-indexed scheme:
//
//   - read bits one at a time, MSB-first within the accumulated code
//     value;
//   - at each length L, compare the running code against
//     codes[L].first; if (code - first) < count, the symbol is
//     codes[L].syms[code - first].
//
// RFC 1951 §3.2.2's "code lengths come in canonical order" guarantees
// the per-length first values are monotone, so the linear walk over
// 1..15 bit lengths is correct.
func decodeSymbol(br *bitReader, hc *huffmanCode) (int, error) {
	code := 0
	for L := 1; L <= 15; L++ {
		b, err := br.Read(1)
		if err != nil {
			return 0, err
		}
		code = (code << 1) | int(b)
		bucket := &hc.codes[L-1]
		if bucket.count > 0 {
			off := code - bucket.first
			if off >= 0 && off < bucket.count {
				return bucket.syms[off], nil
			}
		}
	}
	return 0, fmt.Errorf("zsync: invalid Huffman code (no symbol within 15 bits)")
}

// MakeWithZMap2 is the gzip-aware counterpart of Make / MakeWithAlgo: it
// reads a .gz file, walks its deflate stream to build a Z-Map2 restart
// table, then decompresses the same gz bytes and runs the per-block
// hashing over the decompressed payload. The resulting ControlFile
// carries everything a client needs to fetch the gzipped target by byte
// range and reconstruct the uncompressed file:
//
//   - URL(s): point at the uncompressed file (caller supplied via urls).
//   - Z-URL: point at the gzipped file (caller supplied via zURLs).
//   - Z-Map2 restart table: walker output.
//   - Block table: computed over the decompressed payload.
//
// totalUncompressedSize is the expected size of the decompressed
// payload; pass 0 to let the function discover it from the gzip stream.
// blocksize, filename, mtime, urls, algo match Make's semantics.
//
// gzData must be the full .gz file content (header + deflate + trailer);
// the function reads it twice, once for walking and once for hashing.
// It is rejected if the format is FormatZsync2 (BLAKE3 + Z-Map2 is
// intentionally unspecified — see Read).
func MakeWithZMap2(gzData []byte, blocksize int, filename string, mtime interface{},
	urls []string, zURLs []string, algo string) (*ControlFile, error) {

	if algo == HashAlgoBLAKE3 {
		// Match the Read-side rejection at applyHeader: Z-Map2 on a
		// zsync2 file is unspecified. Bail rather than silently emit
		// something we'll later have to call wrong.
		return nil, fmt.Errorf("zsync: Z-Map2 with BLAKE3 (zsync2) is unspecified")
	}

	// 1) Walk the deflate stream.
	r := newSeekingByteReader(gzData)
	if _, err := skipGzipHeader(r); err != nil {
		return nil, fmt.Errorf("zsync: gzip header: %w", err)
	}
	entries, err := Walk(r)
	if err != nil {
		return nil, fmt.Errorf("zsync: deflate walk: %w", err)
	}
	rawZMap, err := EncodeZMap2(entries)
	if err != nil {
		return nil, fmt.Errorf("zsync: encode Z-Map2: %w", err)
	}

	// 2) Decompress the gz to get the payload, then run Make over it.
	// newGzipPayloadReader can only fail on a malformed gzip header,
	// which Walk has already accepted via skipGzipHeader; treat any
	// error here defensively but don't expect it.
	zr, err := newGzipPayloadReader(gzData)
	if err != nil {
		return nil, fmt.Errorf("zsync: gzip payload: %w", err)
	}
	defer zr.Close()
	cf, err := makeFromReaderWithAlgo(zr, blocksize, filename, mtime, urls, algo)
	if err != nil {
		// Hit when the gz body is corrupt past the deflate-walker's
		// trust horizon (e.g. CRC32 trailer mismatch surfaced by
		// gzip.Reader's final Read).
		return nil, fmt.Errorf("zsync: Make over gzip payload: %w", err)
	}
	// 3) Attach the Z-URL list and Z-Map2 payload.
	cf.ZURLs = append([]string(nil), zURLs...)
	cf.ZMap2Raw = rawZMap
	cf.ZMap = entries
	return cf, nil
}

// EncodeZMap2 serialises a list of ZMapEntry values into the on-the-wire
// Z-Map2 delta-encoded payload (4 bytes per entry, network byte order):
// (inbitoffset delta as uint16, outbyteoffset delta as uint16 with high
// bit set when the entry is NOT a block start).
//
// Returns the raw byte slice ready to be assigned to ControlFile.ZMap2Raw.
//
// Inflated deltas wider than 0x7fff are rejected (the wire field is
// 15 bits effective); compressed-bit deltas wider than 0xffff are
// rejected likewise. zsyncmake (the C reference) inserts mid-block
// checkpoints precisely to keep both deltas under those bounds.
func EncodeZMap2(entries []ZMapEntry) ([]byte, error) {
	out := make([]byte, 4*len(entries))
	var prevIn, prevOut uint64
	for i, e := range entries {
		inDelta := e.Compressed - prevIn
		outDelta := e.Inflated - prevOut
		if inDelta > 0xffff {
			return nil, fmt.Errorf("zsync: Z-Map2 inbitoffset delta %d exceeds 0xffff at entry %d", inDelta, i)
		}
		if outDelta > 0x7fff {
			return nil, fmt.Errorf("zsync: Z-Map2 outbyteoffset delta %d exceeds 0x7fff at entry %d", outDelta, i)
		}
		binary.BigEndian.PutUint16(out[4*i:4*i+2], uint16(inDelta))
		ob := uint16(outDelta)
		if !e.IsBlockStart {
			ob |= gzbNotBlockStart
		}
		binary.BigEndian.PutUint16(out[4*i+2:4*i+4], ob)
		prevIn = e.Compressed
		prevOut = e.Inflated
	}
	return out, nil
}
