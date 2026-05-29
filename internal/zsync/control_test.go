package zsync

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"
)

// errReader returns the supplied error on the first read.
type errReader struct{ err error }

func (e errReader) Read(_ []byte) (int, error) { return 0, e.err }

func TestReadMinimal(t *testing.T) {
	// The smallest legal .zsync: one block of (2 rsum + 3 checksum) = 5
	// bytes. The block-table bytes can be anything for parser purposes.
	const hdr = "zsync: 0.6.2\nBlocksize: 2048\nLength: 2048\nHash-Lengths: 1,2,3\nURL: /x.bin\n\n"
	body := append([]byte(hdr), make([]byte, 5)...)
	cf, err := Read(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if cf.NumBlocks() != 1 {
		t.Errorf("NumBlocks=%d", cf.NumBlocks())
	}
	if cf.Version != "0.6.2" {
		t.Errorf("Version=%q", cf.Version)
	}
	if len(cf.URLs) != 1 || cf.URLs[0] != "/x.bin" {
		t.Errorf("URLs=%v", cf.URLs)
	}
	if len(cf.HeaderRaw) == 0 {
		t.Errorf("HeaderRaw empty")
	}
}

func TestReadEmptyTarget(t *testing.T) {
	// Zero-length target: parser must accept (NumBlocks==0).
	const hdr = "zsync: 0.6.2\nBlocksize: 2048\nLength: 0\nHash-Lengths: 1,2,3\nURL: /x.bin\n\n"
	cf, err := Read(strings.NewReader(hdr))
	if err != nil {
		t.Fatalf("Read empty target: %v", err)
	}
	if cf.NumBlocks() != 0 {
		t.Errorf("NumBlocks=%d, want 0", cf.NumBlocks())
	}
}

func TestReadAllHeaders(t *testing.T) {
	// Every recognised header set, plus Safe: + a custom-but-Safe-listed key.
	hdr := strings.Join([]string{
		"zsync: 0.6.2",
		"Min-Version: 0.6.0",
		"Safe: Custom-Header",
		"Custom-Header: opaque",
		"Z-Filename: target.bin.gz",
		"Filename: target.bin",
		"MTime: Mon, 02 Jan 2024 03:04:05 +0000",
		"Blocksize: 2048",
		"Length: 2048",
		"Hash-Lengths: 1,2,3",
		"URL: a.bin",
		"URL: b.bin",
		"Z-URL: a.bin.gz",
		"SHA-1: da39a3ee5e6b4b0d3255bfef95601890afd80709",
		"Recompress: --best",
		"", // blank: end of headers
	}, "\n") + "\n"
	body := append([]byte(hdr), make([]byte, 5)...)
	cf, err := Read(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if cf.MinVersion != "0.6.0" {
		t.Errorf("MinVersion=%q", cf.MinVersion)
	}
	if cf.ZFilename != "target.bin.gz" {
		t.Errorf("ZFilename=%q", cf.ZFilename)
	}
	if cf.Recompress != "--best" {
		t.Errorf("Recompress=%q", cf.Recompress)
	}
	if cf.SHA1Hex != "da39a3ee5e6b4b0d3255bfef95601890afd80709" {
		t.Errorf("SHA1Hex=%q", cf.SHA1Hex)
	}
	if !cf.HasMTime || cf.MTime.Year() != 2024 {
		t.Errorf("MTime not parsed: %+v", cf.MTime)
	}
	if len(cf.URLs) != 2 {
		t.Errorf("URLs=%v", cf.URLs)
	}
	if len(cf.ZURLs) != 1 || cf.ZURLs[0] != "a.bin.gz" {
		t.Errorf("ZURLs=%v", cf.ZURLs)
	}
}

func TestReadRejectsBadHeaders(t *testing.T) {
	cases := []struct {
		name string
		hdr  string
	}{
		{"missing-colon", "zsync 0.6.2\n\n"},
		{"missing-space-after-colon", "zsync:0.6.2\n\n"},
		{"unknown-key", "zsync: 0.6.2\nFoo-Bar: baz\n\n"},
		{"bad-blocksize", "zsync: 0.6.2\nBlocksize: notanint\n\n"},
		{"bad-length", "zsync: 0.6.2\nBlocksize: 2048\nLength: nope\n\n"},
		{"bad-hash-lengths-fields", "zsync: 0.6.2\nBlocksize: 2048\nLength: 1\nHash-Lengths: 1,2\nURL: /x\n\n"},
		{"bad-hash-lengths-num", "zsync: 0.6.2\nBlocksize: 2048\nLength: 1\nHash-Lengths: x,y,z\nURL: /x\n\n"},
		{"non-power-of-two-blocksize", "zsync: 0.6.2\nBlocksize: 1000\nLength: 1000\nHash-Lengths: 1,2,3\nURL: /x\n\n"},
		{"missing-blocksize", "zsync: 0.6.2\nLength: 100\nURL: /x\n\n"},
		{"negative-length", "zsync: 0.6.2\nBlocksize: 2048\nLength: -1\nHash-Lengths: 1,2,3\nURL: /x\n\n"},
		{"bad-zmap2", "zsync: 0.6.2\nBlocksize: 2048\nLength: 2048\nHash-Lengths: 1,2,3\nZ-Map2: notanint\nURL: /x\n\n"},
		{"bad-hl-rsum-range", "zsync: 0.6.2\nBlocksize: 2048\nLength: 2048\nHash-Lengths: 1,9,3\nURL: /x\n\n"},
		{"bad-hl-cs-range", "zsync: 0.6.2\nBlocksize: 2048\nLength: 2048\nHash-Lengths: 1,2,99\nURL: /x\n\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Read(strings.NewReader(c.hdr))
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestReadSafeListedUnknownPasses(t *testing.T) {
	// Listing the unknown header in "Safe:" should make the parser accept it.
	const hdr = "zsync: 0.6.2\nSafe: X-Custom\nX-Custom: hello\nBlocksize: 2048\nLength: 2048\nHash-Lengths: 1,2,3\nURL: /x\n\n"
	body := append([]byte(hdr), make([]byte, 5)...)
	if _, err := Read(bytes.NewReader(body)); err != nil {
		t.Fatalf("Read with Safe-listed unknown: %v", err)
	}
}

func TestReadShortBlockTable(t *testing.T) {
	// Header promises 2 blocks but only one row of data is present.
	const hdr = "zsync: 0.6.2\nBlocksize: 2048\nLength: 4096\nHash-Lengths: 1,2,3\nURL: /x\n\n"
	body := append([]byte(hdr), make([]byte, 5)...) // one row, but we need two
	_, err := Read(bytes.NewReader(body))
	if err == nil {
		t.Fatal("expected short-read error")
	}
}

func TestReadShortRsumPrefix(t *testing.T) {
	// Header promises one block; first row is truncated mid-rsum.
	const hdr = "zsync: 0.6.2\nBlocksize: 2048\nLength: 2048\nHash-Lengths: 1,4,3\nURL: /x\n\n"
	body := append([]byte(hdr), 0, 0) // only 2 of 4 rsum bytes
	_, err := Read(bytes.NewReader(body))
	if err == nil {
		t.Fatal("expected short-read error on rsum prefix")
	}
}

func TestReadWhitespaceOnlyLineTerminatesHeader(t *testing.T) {
	// A line of pure whitespace counts as the end-of-headers blank line
	// after TrimRight (matches the C reference's lenient parser).
	hdr := "zsync: 0.6.2\nBlocksize: 2048\nLength: 2048\nHash-Lengths: 1,2,3\nURL: /x\n   \n"
	body := append([]byte(hdr), make([]byte, 5)...)
	if _, err := Read(bytes.NewReader(body)); err != nil {
		t.Fatalf("whitespace-only blank: %v", err)
	}
}

func TestReadShortChecksum(t *testing.T) {
	// Header promises one block; first row is complete rsum, truncated checksum.
	const hdr = "zsync: 0.6.2\nBlocksize: 2048\nLength: 2048\nHash-Lengths: 1,2,16\nURL: /x\n\n"
	// 2 rsum bytes + 16 checksum bytes = 18; supply 2 + 4 only.
	body := append([]byte(hdr), 0, 0, 0, 0, 0, 0)
	_, err := Read(bytes.NewReader(body))
	if err == nil {
		t.Fatal("expected short-read error on checksum")
	}
}

func TestReadUnexpectedEOFNoBlankLine(t *testing.T) {
	// Headers with no terminating blank line.
	body := "zsync: 0.6.2\nBlocksize: 2048\nLength: 2048\nHash-Lengths: 1,2,3\nURL: /x\n"
	_, err := Read(strings.NewReader(body))
	if err == nil {
		t.Fatal("expected error for unterminated header")
	}
}

func TestReadPropagatesUnderlyingError(t *testing.T) {
	want := errors.New("boom")
	_, err := Read(errReader{err: want})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestReadZMap2Roundtrip(t *testing.T) {
	// Z-Map2: <n> then n*4 raw bytes that must be consumed before the
	// next header line.
	body := bytes.NewBuffer(nil)
	body.WriteString("zsync: 0.6.2\nBlocksize: 2048\nLength: 2048\nHash-Lengths: 1,2,3\nZ-Map2: 2\n")
	body.Write(make([]byte, 8)) // 2*4 raw bytes
	body.WriteString("URL: /x\n\n")
	body.Write(make([]byte, 5)) // single block payload
	cf, err := Read(body)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(cf.ZMap2Raw) != 8 {
		t.Errorf("ZMap2Raw len=%d", len(cf.ZMap2Raw))
	}
	if len(cf.ZMap) != 2 {
		t.Errorf("ZMap len=%d, want 2 entries", len(cf.ZMap))
	}
}

func TestReadZMap2Truncated(t *testing.T) {
	body := bytes.NewBuffer(nil)
	body.WriteString("zsync: 0.6.2\nBlocksize: 2048\nLength: 2048\nHash-Lengths: 1,2,3\nZ-Map2: 2\n")
	body.Write(make([]byte, 3)) // need 8, supply 3
	_, err := Read(body)
	if err == nil {
		t.Fatal("expected short Z-Map2 error")
	}
}

func TestReadBadRFC822Ignored(t *testing.T) {
	// Bad MTime is silently ignored (HasMTime stays false), matching the C
	// reference's lenient behaviour.
	const hdr = "zsync: 0.6.2\nBlocksize: 2048\nLength: 2048\nHash-Lengths: 1,2,3\nMTime: not-a-date\nURL: /x\n\n"
	body := append([]byte(hdr), make([]byte, 5)...)
	cf, err := Read(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if cf.HasMTime {
		t.Errorf("HasMTime should be false on bad MTime")
	}
}

func TestParseRFC822Layouts(t *testing.T) {
	for _, s := range []string{
		"Mon, 02 Jan 2006 15:04:05 -0700",
		"02 Jan 2006 15:04:05 -0700",
	} {
		if _, err := parseRFC822(s); err != nil {
			t.Errorf("layout %q: %v", s, err)
		}
	}
	if _, err := parseRFC822("garbage"); err == nil {
		t.Errorf("garbage parsed as date")
	}
}

func TestWriteRejectsShortChecksum(t *testing.T) {
	cf := &ControlFile{
		Version:     "0.6.2",
		Blocksize:   2048,
		Length:      2048,
		HashLengths: HashLengths{1, 2, 5},
		Blocks:      []BlockChecksum{{Rsum: Rsum{A: 1, B: 2}, Checksum: []byte{1, 2}}},
	}
	var buf bytes.Buffer
	if err := cf.Write(&buf); err == nil {
		t.Fatal("expected error from too-short checksum")
	}
}

func TestWriteOptionalHeaders(t *testing.T) {
	cf := &ControlFile{
		Blocksize:   2048,
		Length:      2048,
		HashLengths: HashLengths{1, 2, 3},
		URLs:        []string{"a", "b"},
		SHA1Hex:     "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		MinVersion:  "0.6.0",
		Filename:    "t.bin",
		HasMTime:    true,
		MTime:       time.Date(2024, time.January, 2, 3, 4, 5, 0, time.UTC),
	}
	var buf bytes.Buffer
	if err := cf.Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	s := buf.String()
	for _, want := range []string{
		"zsync: 0.6.2", "Min-Version: 0.6.0", "Filename: t.bin",
		"MTime: ", "Blocksize: 2048", "Length: 2048",
		"Hash-Lengths: 1,2,3", "URL: a", "URL: b",
		"SHA-1: da39a3ee5e6b4b0d3255bfef95601890afd80709",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing header %q in:\n%s", want, s)
		}
	}
}

func TestMakeRejectsBadBlocksize(t *testing.T) {
	if _, err := Make(strings.NewReader("x"), 1, 1000, "", time.Time{}, nil); err == nil {
		t.Fatal("expected error for non-power-of-two blocksize")
	}
	if _, err := Make(strings.NewReader("x"), 1, -2, "", time.Time{}, nil); err == nil {
		t.Fatal("expected error for negative blocksize")
	}
}

func TestMakePicksDefaultBlocksize(t *testing.T) {
	// Small file: default 2048.
	cf, err := Make(bytes.NewReader(make([]byte, 100)), 100, 0, "", time.Time{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cf.Blocksize != 2048 {
		t.Errorf("small-file blocksize=%d, want 2048", cf.Blocksize)
	}
	// >=100MB: default 4096. We don't actually have to feed 100MB; the
	// branch is selected purely from totalSize.
	cf, err = Make(bytes.NewReader(nil), 100_000_001, 0, "", time.Time{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cf.Blocksize != 4096 {
		t.Errorf("large-file blocksize=%d, want 4096", cf.Blocksize)
	}
}

func TestMakeReaderError(t *testing.T) {
	want := errors.New("kaboom")
	// We need a reader that returns (n>=blocksize) of data once then errors.
	r := &errAfterReader{n: 4096, err: want}
	_, err := Make(r, 1<<20, 2048, "", time.Time{}, nil)
	if err == nil || !strings.Contains(err.Error(), "read source") {
		t.Fatalf("expected read source error, got %v", err)
	}
}

func TestMakeWriteReadRoundtripSizes(t *testing.T) {
	// Exercise edge sizes: empty, 1 byte, < blocksize, == blocksize,
	// multi-block, multi-block with a short last block.
	bs := 256
	sizes := []int{0, 1, bs - 1, bs, bs + 1, 2 * bs, 3*bs + 17}
	for _, n := range sizes {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			data := make([]byte, n)
			for i := range data {
				data[i] = byte(i)
			}
			cf, err := Make(bytes.NewReader(data), int64(n), bs, "x.bin",
				time.Time{}, []string{"x.bin"})
			if err != nil {
				t.Fatal(err)
			}
			if int64(n) != cf.Length {
				t.Errorf("Length=%d, want %d", cf.Length, n)
			}
			// Round-trip via Write/Read.
			var buf bytes.Buffer
			if err := cf.Write(&buf); err != nil {
				t.Fatal(err)
			}
			cf2, err := Read(&buf)
			if err != nil {
				t.Fatal(err)
			}
			if cf2.Length != cf.Length {
				t.Errorf("rt Length: got %d want %d", cf2.Length, cf.Length)
			}
			if len(cf2.Blocks) != len(cf.Blocks) {
				t.Errorf("rt block count: got %d want %d", len(cf2.Blocks), len(cf.Blocks))
			}
		})
	}
}

func TestNumBlocksZeroBlocksize(t *testing.T) {
	cf := &ControlFile{Blocksize: 0, Length: 1024}
	if got := cf.NumBlocks(); got != 0 {
		t.Errorf("NumBlocks with bs=0: got %d", got)
	}
}

// errAfterReader returns `n` bytes of data then `err` on the next read.
type errAfterReader struct {
	n   int
	err error
}

func (e *errAfterReader) Read(p []byte) (int, error) {
	if e.n > 0 {
		k := len(p)
		if k > e.n {
			k = e.n
		}
		e.n -= k
		return k, nil
	}
	return 0, e.err
}

// Sanity-check that io.ReadFull is what we expect: when the underlying
// reader returns (0, err), ReadFull surfaces the error.
func TestReadFullUnderlying(t *testing.T) {
	_, err := io.ReadFull(errReader{err: io.ErrClosedPipe}, make([]byte, 1))
	if err == nil {
		t.Fatal("ReadFull should not have succeeded")
	}
}
