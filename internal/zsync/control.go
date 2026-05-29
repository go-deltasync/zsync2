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

// ControlFile is the in-memory representation of a parsed .zsync file.
//
// The wire format, as written by Phipps' make.c, is:
//
//   zsync: <version>\n
//   [Min-Version: ...\n]
//   [Safe: ...\n]
//   [Z-Filename: ...\n]
//   Filename: <fname>\n
//   [MTime: <RFC822>\n]
//   Blocksize: <int>\n
//   Length: <int>\n
//   Hash-Lengths: <seq>,<rsum_bytes>,<checksum_bytes>\n
//   URL: <url>\n        (one or more)
//   [Z-URL: ...\n]      (zero or more)
//   SHA-1: <hex>\n
//   [Recompress: ...\n]
//   [Z-Map2: <n>\n + n * 4 raw bytes]
//   \n                  (blank line: end of header)
//   <block-table>       (blocks * (rsum_bytes + checksum_bytes) raw bytes)
//
// The block table: per block, big-endian uint32 truncated to its trailing
// rsum_bytes (so for rsum_bytes=2 you get just the B half of the Rsum), then
// the leading checksum_bytes of the MD4 of the block.
//
// Notes:
//   - Headers are case-sensitive and "Key: value" (note the space).
//   - The C parser only requires Blocksize and Length to be present.
//   - "Z-Map2" indicates a transparently-decompressed target served from a
//     gzip file. This pure-Go MVP does not implement the zmap path.
type ControlFile struct {
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
	Checksum []byte // leading checksum_bytes of MD4
}

// NumBlocks returns the number of blocks the target file decomposes into.
func (c *ControlFile) NumBlocks() int {
	if c.Blocksize <= 0 {
		return 0
	}
	return int((c.Length + int64(c.Blocksize) - 1) / int64(c.Blocksize))
}

// Read parses a .zsync stream.
func Read(r io.Reader) (*ControlFile, error) {
	br := bufio.NewReaderSize(r, 1<<16)
	cf := &ControlFile{
		HashLengths: HashLengths{SeqMatches: 1, RsumBytes: 4, ChecksumBytes: 16},
	}

	var headerBuf strings.Builder

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
		if err := cf.applyHeader(key, val, br); err != nil {
			return nil, err
		}
	}

	cf.HeaderRaw = []byte(headerBuf.String())

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
	if rsumBytes < 1 || rsumBytes > 4 || csBytes < 3 || csBytes > 16 {
		return nil, fmt.Errorf("zsync: nonsensical Hash-Lengths %+v", cf.HashLengths)
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
	case "zsync":
		c.Version = val
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
// `zsync` (the original C client) will accept it.
func (c *ControlFile) Write(w io.Writer) error {
	bw := bufio.NewWriter(w)
	writeKV := func(k, v string) {
		fmt.Fprintf(bw, "%s: %s\n", k, v) //nolint:errcheck // surfaced via bw.Flush below
	}

	if c.Version == "" {
		c.Version = "0.6.2"
	}
	writeKV("zsync", c.Version)
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
	for _, u := range c.URLs {
		writeKV("URL", u)
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
		bw.Write(be[4-rsumBytes:])      //nolint:errcheck // surfaced via bw.Flush below
		bw.Write(b.Checksum[:csBytes]) //nolint:errcheck // surfaced via bw.Flush below
	}
	return bw.Flush()
}

// Make builds a ControlFile by reading every byte of src and computing the
// block table. blocksize must be a power of two; if 0 a sane default is
// chosen (2048 for files <100MB, 4096 otherwise).
//
// urls is the list of HTTP locations from which the *target* file can be
// fetched as raw bytes. filename and mtime are recorded in the header
// (filename may be ""; mtime may be the zero time).
func Make(src io.Reader, totalSize int64, blocksize int, filename string, mtime time.Time, urls []string) (*ControlFile, error) {
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

	hl := ComputeHashLengths(totalSize, blocksize)
	aMask := RsumAMask(hl.RsumBytes)

	buf := make([]byte, blocksize)
	pad := make([]byte, blocksize)
	sha := sha1.New() //nolint:gosec // wire format

	var blocks []BlockChecksum
	var totalRead int64
	for {
		n, err := io.ReadFull(src, buf)
		if n > 0 {
			// SHA-1 is computed over the unpadded file bytes only.
			sha.Write(buf[:n])
			totalRead += int64(n)

			// Pad the short last block with zeros for rsum/MD4.
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
			md := MD4(blk)
			cs := make([]byte, hl.ChecksumBytes)
			copy(cs, md[:hl.ChecksumBytes])
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
		Version:     "0.6.2",
		Filename:    filename,
		Blocksize:   blocksize,
		Length:      totalRead,
		HashLengths: hl,
		URLs:        append([]string(nil), urls...),
		SHA1Hex:     hex.EncodeToString(sha.Sum(nil)),
		Blocks:      blocks,
	}
	if !mtime.IsZero() {
		cf.MTime = mtime
		cf.HasMTime = true
	}
	return cf, nil
}
