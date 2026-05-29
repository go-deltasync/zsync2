package zsync

import (
	"bufio"
	"crypto/sha1" //nolint:gosec // zsync wire format requires SHA-1
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// Format identifies the on-the-wire .zsync flavour parsed/emitted by this
// package.
//
//   - FormatZsync is Colin Phipps' classic 2005 wire format. The first
//     header line is `zsync: <version>`; the strong block hash is MD4 and
//     the file-wide hash is SHA-1.
//   - FormatZsync2 is the upgraded wire format proposed in
//     https://go-deltasync.github.io/zsync2/proposal-blake3/. The first
//     header line is `zsync2: <version>`; the strong block hash and the
//     file-wide hash both default to BLAKE3, switchable via
//     `Hash-Algorithm:` and `File-Hash:` headers.
const (
	FormatZsync  = "zsync"
	FormatZsync2 = "zsync2"
)

// DefaultVersionZsync is the default version emitted on the
// `zsync: ` magic line when Format == FormatZsync.
const DefaultVersionZsync = "0.6.2"

// DefaultVersionZsync2 is the default version emitted on the
// `zsync2: ` magic line when Format == FormatZsync2.
const DefaultVersionZsync2 = "1.0"

// ControlFile is the in-memory representation of a parsed .zsync (or
// .zsync2) file.
//
// The classic wire format, as written by Phipps' make.c, is:
//
//	zsync: <version>\n
//	[Min-Version: ...\n]
//	[Safe: ...\n]
//	[Z-Filename: ...\n]
//	Filename: <fname>\n
//	[MTime: <RFC822>\n]
//	Blocksize: <int>\n
//	Length: <int>\n
//	Hash-Lengths: <seq>,<rsum_bytes>,<checksum_bytes>\n
//	URL: <url>\n        (one or more)
//	[Z-URL: ...\n]      (zero or more)
//	SHA-1: <hex>\n
//	[Recompress: ...\n]
//	[Z-Map2: <n>\n + n * 4 raw bytes]
//	\n                  (blank line: end of header)
//	<block-table>       (blocks * (rsum_bytes + checksum_bytes) raw bytes)
//
// The zsync2 wire format adds two optional headers (`Hash-Algorithm:` and
// `File-Hash:`) and bumps the magic to `zsync2:`. The block-table layout
// stays the same; only the meaning of the strong-hash prefix changes
// (MD4 -> BLAKE3).
type ControlFile struct {
	// Format is "zsync" (classic, default) or "zsync2" (BLAKE3-capable).
	Format string

	// HashAlgorithm is "MD4" (classic, default) or "BLAKE3". Drives the
	// per-block strong-hash computation and the file-wide File-Hash header.
	HashAlgorithm string

	// FileHash is the raw bytes of the file-wide strong digest, decoded
	// from the `File-Hash: <algo>:<hex>` header on zsync2 files. For
	// classic zsync files this is empty and SHA1Hex carries the digest.
	FileHash []byte

	Version     string
	Filename    string
	ZFilename   string
	MTime       time.Time
	HasMTime    bool
	Blocksize   int
	Length      int64
	HashLengths HashLengths
	URLs        []string
	ZURLs       []string
	SHA1Hex     string
	Safe        string
	MinVersion  string
	Recompress  string
	// ZMap2 bytes (4 bytes per entry). Present iff the original was a gzip;
	// not interpreted by this implementation.
	ZMap2 []byte

	// Blocks is the per-block checksum table, in target-file order.
	Blocks []BlockChecksum

	// HeaderRaw is the verbatim header bytes (everything up to and including
	// the trailing blank line). Useful for debugging.
	HeaderRaw []byte
}

// BlockChecksum holds the (already-truncated) per-block checksums.
type BlockChecksum struct {
	Rsum     Rsum   // A is masked per RsumAMask(rsum_bytes); when rsum_bytes<3 A==0.
	Checksum []byte // leading checksum_bytes of the strong hash (MD4 or BLAKE3)
}

// NumBlocks returns the number of blocks the target file decomposes into.
func (c *ControlFile) NumBlocks() int {
	if c.Blocksize <= 0 {
		return 0
	}
	return int((c.Length + int64(c.Blocksize) - 1) / int64(c.Blocksize))
}

// Read parses a .zsync (or .zsync2) stream.
//
// The first non-empty line must be either `zsync: <version>` (the classic
// Phipps wire format) or `zsync2: <version>` (the BLAKE3-capable upgrade
// described in proposal-blake3). Anything else is rejected with a
// "not a zsync file"-style error.
func Read(r io.Reader) (*ControlFile, error) {
	br := bufio.NewReaderSize(r, 1<<16)
	cf := &ControlFile{
		Format:        FormatZsync,
		HashAlgorithm: HashAlgoMD4,
		HashLengths:   HashLengths{SeqMatches: 1, RsumBytes: 4, ChecksumBytes: 16},
	}

	var headerBuf strings.Builder
	first := true

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) && line == "" {
				return nil, fmt.Errorf("zsync: unexpected EOF in header")
			}
			if !errors.Is(err, io.EOF) {
				return nil, fmt.Errorf("zsync: header read: %w", err)
			}
		}
		headerBuf.WriteString(line)
		// blank line terminates the header
		if line == "\n" || line == "\r\n" {
			break
		}
		trimmed := strings.TrimRight(line, "\r\n ")
		if trimmed == "" {
			break
		}
		colon := strings.IndexByte(trimmed, ':')
		if colon < 0 {
			return nil, fmt.Errorf("zsync: malformed header line %q", trimmed)
		}
		key := trimmed[:colon]
		// The C parser requires "Key: " (colon + space) before the value.
		if colon+1 >= len(trimmed) || trimmed[colon+1] != ' ' {
			return nil, fmt.Errorf("zsync: malformed header (missing space) %q", trimmed)
		}
		val := trimmed[colon+2:]

		// The very first header line must be the magic, and the magic must
		// be either "zsync" or "zsync2". This is the safety property called
		// out in the proposal: anything else is "not a zsync file".
		if first {
			first = false
			switch key {
			case "zsync":
				cf.Format = FormatZsync
				cf.HashAlgorithm = HashAlgoMD4
				cf.Version = val
				continue
			case "zsync2":
				cf.Format = FormatZsync2
				cf.HashAlgorithm = HashAlgoBLAKE3
				cf.Version = val
				continue
			default:
				return nil, fmt.Errorf("zsync: not a zsync file (first header is %q, expected \"zsync\" or \"zsync2\")", key)
			}
		}
		if err := cf.applyHeader(key, val, br); err != nil {
			return nil, err
		}
	}

	cf.HeaderRaw = []byte(headerBuf.String())

	if first {
		// We never saw any header at all (empty input / blank line only).
		return nil, fmt.Errorf("zsync: empty header")
	}
	if cf.Blocksize <= 0 {
		return nil, fmt.Errorf("zsync: missing required Blocksize")
	}
	if cf.Length < 0 {
		return nil, fmt.Errorf("zsync: negative Length")
	}
	if cf.Blocksize&(cf.Blocksize-1) != 0 {
		return nil, fmt.Errorf("zsync: blocksize %d is not a power of two", cf.Blocksize)
	}

	// Read the per-block checksum table.
	n := cf.NumBlocks()
	cf.Blocks = make([]BlockChecksum, n)
	rsumBytes := cf.HashLengths.RsumBytes
	csBytes := cf.HashLengths.ChecksumBytes
	// Algorithm-aware ceiling on checksum_bytes. MD4 tops out at 16, BLAKE3
	// at 32. The lower floor (3) is shared.
	maxCs := StrongHashFullLen(cf.HashAlgorithm)
	if rsumBytes < 1 || rsumBytes > 4 || csBytes < 3 || csBytes > maxCs {
		return nil, fmt.Errorf("zsync: nonsensical Hash-Lengths %+v for algorithm %s", cf.HashLengths, cf.HashAlgorithm)
	}
	var raw [4]byte
	for i := 0; i < n; i++ {
		// rsum: trailing rsumBytes of a 4-byte big-endian (a_hi a_lo b_hi b_lo);
		// the leading (4-rsumBytes) bytes are not on the wire and are zero.
		for j := range raw {
			raw[j] = 0
		}
		if _, err := io.ReadFull(br, raw[4-rsumBytes:]); err != nil {
			return nil, fmt.Errorf("zsync: short read on block %d rsum: %w", i, err)
		}
		a := binary.BigEndian.Uint16(raw[0:2])
		b := binary.BigEndian.Uint16(raw[2:4])
		cs := make([]byte, csBytes)
		if _, err := io.ReadFull(br, cs); err != nil {
			return nil, fmt.Errorf("zsync: short read on block %d checksum: %w", i, err)
		}
		cf.Blocks[i] = BlockChecksum{Rsum: Rsum{A: a, B: b}, Checksum: cs}
	}
	return cf, nil
}

func (c *ControlFile) applyHeader(key, val string, br *bufio.Reader) error {
	switch key {
	case "zsync", "zsync2":
		// A duplicate magic line is a malformed file.
		return fmt.Errorf("zsync: duplicate %q header", key)
	case "Min-Version":
		c.MinVersion = val
	case "Length":
		v, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return fmt.Errorf("zsync: bad Length %q: %w", val, err)
		}
		c.Length = v
	case "Filename":
		c.Filename = val
	case "Z-Filename":
		c.ZFilename = val
	case "URL":
		c.URLs = append(c.URLs, val)
	case "Z-URL":
		c.ZURLs = append(c.ZURLs, val)
	case "Blocksize":
		v, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("zsync: bad Blocksize %q: %w", val, err)
		}
		c.Blocksize = v
	case "Hash-Lengths":
		parts := strings.Split(val, ",")
		if len(parts) != 3 {
			return fmt.Errorf("zsync: bad Hash-Lengths %q", val)
		}
		seq, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
		rb, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
		cb, err3 := strconv.Atoi(strings.TrimSpace(parts[2]))
		if err1 != nil || err2 != nil || err3 != nil {
			return fmt.Errorf("zsync: bad Hash-Lengths %q", val)
		}
		c.HashLengths = HashLengths{SeqMatches: seq, RsumBytes: rb, ChecksumBytes: cb}
	case "Hash-Algorithm":
		// Only valid on zsync2 files; reject for classic.
		if c.Format != FormatZsync2 {
			return fmt.Errorf("zsync: Hash-Algorithm header is only allowed on zsync2 files")
		}
		switch val {
		case HashAlgoMD4, HashAlgoBLAKE3:
			c.HashAlgorithm = val
		default:
			return fmt.Errorf("zsync: unknown Hash-Algorithm %q", val)
		}
	case "File-Hash":
		// "<algo>:<hex>" -- only valid on zsync2 files.
		if c.Format != FormatZsync2 {
			return fmt.Errorf("zsync: File-Hash header is only allowed on zsync2 files")
		}
		sep := strings.IndexByte(val, ':')
		if sep <= 0 {
			return fmt.Errorf("zsync: bad File-Hash %q (need <algo>:<hex>)", val)
		}
		algo := val[:sep]
		hexed := val[sep+1:]
		want := 0
		switch algo {
		case HashAlgoMD4:
			want = 16
		case HashAlgoBLAKE3:
			want = 32
		default:
			return fmt.Errorf("zsync: unknown File-Hash algorithm %q", algo)
		}
		raw, err := hex.DecodeString(hexed)
		if err != nil {
			return fmt.Errorf("zsync: bad File-Hash hex: %w", err)
		}
		if len(raw) != want {
			return fmt.Errorf("zsync: File-Hash %s width=%d, want %d", algo, len(raw), want)
		}
		c.FileHash = raw
		// If the file didn't carry an explicit Hash-Algorithm yet, align it
		// to whatever the File-Hash declares.
		if c.HashAlgorithm == HashAlgoBLAKE3 && algo == HashAlgoMD4 {
			// downgrade-compat: zsync2 file but legacy MD4 file-hash; keep
			// the block-strong-hash at the format default (BLAKE3) but
			// remember the file-wide algo via the FileHash bytes alone.
		} else {
			c.HashAlgorithm = algo
		}
	case "SHA-1":
		c.SHA1Hex = val
	case "Safe":
		c.Safe = val
	case "Recompress":
		c.Recompress = val
	case "MTime":
		t, err := parseRFC822(val)
		if err == nil {
			c.MTime = t
			c.HasMTime = true
		}
	case "Z-Map2":
		n, err := strconv.Atoi(val)
		if err != nil || n < 0 {
			return fmt.Errorf("zsync: bad Z-Map2 %q", val)
		}
		c.ZMap2 = make([]byte, 4*n)
		if _, err := io.ReadFull(br, c.ZMap2); err != nil {
			return fmt.Errorf("zsync: short read on Z-Map2: %w", err)
		}
	default:
		// Ignore unknown keys if listed in "Safe:", else bail like the C code.
		if c.Safe == "" || !strings.Contains(c.Safe, key) {
			return fmt.Errorf("zsync: unrecognised header %q (need newer client?)", key)
		}
	}
	return nil
}

var rfc822Layouts = []string{
	"Mon, 02 Jan 2006 15:04:05 -0700",
	"02 Jan 2006 15:04:05 -0700",
	time.RFC1123Z,
}

func parseRFC822(s string) (time.Time, error) {
	for _, l := range rfc822Layouts {
		if t, err := time.Parse(l, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("zsync: bad RFC822 date %q", s)
}

// Write serialises the ControlFile back to a .zsync stream. It writes a
// header layout matching the C reference's make.c closely enough that
// `zsync` (the original C client) will accept it. When Format is
// FormatZsync2 the upgraded BLAKE3-capable layout is emitted instead;
// see proposal-blake3.md.
func (c *ControlFile) Write(w io.Writer) error {
	bw := bufio.NewWriter(w)
	writeKV := func(k, v string) {
		fmt.Fprintf(bw, "%s: %s\n", k, v) //nolint:errcheck // surfaced via bw.Flush below
	}

	format := c.Format
	if format == "" {
		format = FormatZsync
	}
	zsync2 := format == FormatZsync2

	// Backfill version defaults so a CF built field-by-field still emits a
	// valid file.
	if c.Version == "" {
		if zsync2 {
			c.Version = DefaultVersionZsync2
		} else {
			c.Version = DefaultVersionZsync
		}
	}
	// Same for HashAlgorithm on zsync2: default to BLAKE3.
	if zsync2 && c.HashAlgorithm == "" {
		c.HashAlgorithm = HashAlgoBLAKE3
	}

	if zsync2 {
		writeKV("zsync2", c.Version)
	} else {
		writeKV("zsync", c.Version)
	}
	if c.MinVersion != "" {
		writeKV("Min-Version", c.MinVersion)
	}
	if c.Filename != "" {
		writeKV("Filename", c.Filename)
	}
	if c.HasMTime {
		writeKV("MTime", c.MTime.UTC().Format("Mon, 02 Jan 2006 15:04:05 -0700"))
	}
	writeKV("Blocksize", strconv.Itoa(c.Blocksize))
	writeKV("Length", strconv.FormatInt(c.Length, 10))
	writeKV("Hash-Lengths", fmt.Sprintf("%d,%d,%d",
		c.HashLengths.SeqMatches, c.HashLengths.RsumBytes, c.HashLengths.ChecksumBytes))
	if zsync2 {
		writeKV("Hash-Algorithm", c.HashAlgorithm)
	}
	for _, u := range c.URLs {
		writeKV("URL", u)
	}
	if zsync2 && len(c.FileHash) > 0 {
		writeKV("File-Hash", fmt.Sprintf("%s:%s", c.HashAlgorithm, hex.EncodeToString(c.FileHash)))
	}
	if c.SHA1Hex != "" {
		writeKV("SHA-1", c.SHA1Hex)
	}
	// End of headers.
	bw.WriteString("\n") //nolint:errcheck // surfaced via bw.Flush below

	// Block table.
	rsumBytes := c.HashLengths.RsumBytes
	csBytes := c.HashLengths.ChecksumBytes
	var be [4]byte
	for _, b := range c.Blocks {
		if len(b.Checksum) < csBytes {
			return fmt.Errorf("zsync: block checksum too short (%d < %d)", len(b.Checksum), csBytes)
		}
		binary.BigEndian.PutUint16(be[0:2], b.Rsum.A)
		binary.BigEndian.PutUint16(be[2:4], b.Rsum.B)
		bw.Write(be[4-rsumBytes:])     //nolint:errcheck // surfaced via bw.Flush below
		bw.Write(b.Checksum[:csBytes]) //nolint:errcheck // surfaced via bw.Flush below
	}
	return bw.Flush()
}

// Make builds a ControlFile by reading every byte of src and computing the
// block table under the classic MD4 wire format. Equivalent to
// MakeWithAlgo(..., HashAlgoMD4); see MakeWithAlgo for the algo-aware variant.
//
// blocksize must be a power of two; if 0 a sane default is chosen
// (2048 for files <100MB, 4096 otherwise).
//
// urls is the list of HTTP locations from which the *target* file can be
// fetched as raw bytes. filename and mtime are recorded in the header
// (filename may be ""; mtime may be the zero time).
func Make(src io.Reader, totalSize int64, blocksize int, filename string, mtime time.Time, urls []string) (*ControlFile, error) {
	return MakeWithAlgo(src, totalSize, blocksize, filename, mtime, urls, HashAlgoMD4)
}

// MakeWithAlgo is the algorithm-aware variant of Make. The algo argument
// must be HashAlgoMD4 ("MD4") or HashAlgoBLAKE3 ("BLAKE3"); an empty
// algo string is treated as HashAlgoMD4 for backward compatibility, which
// keeps callers that predate the format upgrade working unchanged.
//
// The returned ControlFile has Format and HashAlgorithm set so a subsequent
// Write produces the correct on-the-wire layout (classic `zsync: 0.6`
// header for MD4, new `zsync2: 1.0` header for BLAKE3).
func MakeWithAlgo(src io.Reader, totalSize int64, blocksize int, filename string, mtime time.Time, urls []string, algo string) (*ControlFile, error) {
	if algo == "" {
		algo = HashAlgoMD4
	}
	switch algo {
	case HashAlgoMD4, HashAlgoBLAKE3:
	default:
		return nil, fmt.Errorf("zsync: unknown strong-hash algorithm %q", algo)
	}
	if blocksize == 0 {
		if totalSize < 100_000_000 {
			blocksize = 2048
		} else {
			blocksize = 4096
		}
	}
	if blocksize <= 0 || blocksize&(blocksize-1) != 0 {
		return nil, fmt.Errorf("zsync: blocksize %d must be a power of two", blocksize)
	}

	hl := ComputeHashLengthsAlgo(totalSize, blocksize, algo)
	aMask := RsumAMask(hl.RsumBytes)

	buf := make([]byte, blocksize)
	pad := make([]byte, blocksize)

	// Two file-wide streaming hashers run side-by-side: SHA-1 is kept for
	// the classic path's `SHA-1:` header (and emitted in addition to
	// `File-Hash:` on zsync2 when desired), BLAKE3 is only used on the
	// upgraded path. The cost of running both for the MD4 path is one
	// SHA-1 over the source bytes, which we already paid.
	sha := sha1.New() //nolint:gosec // wire format
	b3 := blake3New()

	var blocks []BlockChecksum
	var totalRead int64
	for {
		n, err := io.ReadFull(src, buf)
		if n > 0 {
			// File-wide hashes are computed over the unpadded file bytes only.
			sha.Write(buf[:n])
			_, _ = b3.Write(buf[:n])
			totalRead += int64(n)

			// Pad the short last block with zeros for rsum/strong-hash.
			blk := buf
			if n < blocksize {
				copy(pad, buf[:n])
				for i := n; i < blocksize; i++ {
					pad[i] = 0
				}
				blk = pad
			}
			r := CalcRsum(blk)
			r.A &= aMask
			strong := strongHash(algo, blk)
			cs := make([]byte, hl.ChecksumBytes)
			copy(cs, strong[:hl.ChecksumBytes])
			blocks = append(blocks, BlockChecksum{Rsum: r, Checksum: cs})
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("zsync: read source: %w", err)
		}
	}

	cf := &ControlFile{
		Blocksize:     blocksize,
		Length:        totalRead,
		HashLengths:   hl,
		URLs:          append([]string(nil), urls...),
		Blocks:        blocks,
		Filename:      filename,
		HashAlgorithm: algo,
	}
	switch algo {
	case HashAlgoMD4:
		cf.Format = FormatZsync
		cf.Version = DefaultVersionZsync
		cf.SHA1Hex = hex.EncodeToString(sha.Sum(nil))
	case HashAlgoBLAKE3:
		cf.Format = FormatZsync2
		cf.Version = DefaultVersionZsync2
		cf.FileHash = b3.Sum(nil)
	}
	if !mtime.IsZero() {
		cf.MTime = mtime
		cf.HasMTime = true
	}
	return cf, nil
}
