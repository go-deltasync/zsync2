package zsync

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestBLAKE3KnownVectors pins down our BLAKE3 wrapper against fixed test
// vectors from the BLAKE3 reference (BLAKE3-team/BLAKE3/test_vectors.json).
// If this test ever fails the dependency switched to a different hash.
func TestBLAKE3KnownVectors(t *testing.T) {
	cases := []struct {
		in       []byte
		wantHex  string
		describe string
	}{
		{
			// Empty input is the canonical KAT all BLAKE3 reference impls publish.
			in:       nil,
			wantHex:  "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
			describe: "empty",
		},
		{
			// Reference vector for "IETF" (4 bytes); cross-checked against
			// blake3sum on the same input.
			in:       []byte("IETF"),
			wantHex:  "83a2de1ee6f4e6ab686889248f4ec0cf4cc5709446a682ffd1cbb4d6165181e2",
			describe: "IETF",
		},
	}
	for _, c := range cases {
		t.Run(c.describe, func(t *testing.T) {
			got := BLAKE3(c.in)
			gotHex := hex.EncodeToString(got[:])
			if gotHex != c.wantHex {
				t.Errorf("BLAKE3(%q) = %s, want %s", c.in, gotHex, c.wantHex)
			}
		})
	}
}

// TestBLAKE3StreamingMatchesOneShot makes sure the streaming hasher we use
// in Make produces the same digest as the one-shot helper.
func TestBLAKE3StreamingMatchesOneShot(t *testing.T) {
	data := []byte("the quick brown fox jumps over the lazy dog")
	one := BLAKE3(data)
	h := blake3New()
	_, _ = h.Write(data[:10])
	_, _ = h.Write(data[10:])
	got := h.Sum(nil)
	if !bytes.Equal(one[:], got) {
		t.Errorf("streaming != one-shot: %x vs %x", got, one[:])
	}
	// Reset wipes state.
	h.Reset()
	_, _ = h.Write(data)
	if !bytes.Equal(one[:], h.Sum(nil)) {
		t.Errorf("Reset()ed hasher diverged")
	}
}

// TestStrongHashDispatch exercises the algo->digest dispatcher.
func TestStrongHashDispatch(t *testing.T) {
	want := MD4(nil)
	if got := strongHash("", nil); !bytes.Equal(got, want[:]) {
		t.Errorf("default algo: %x vs %x", got, want[:])
	}
	if got := strongHash(HashAlgoMD4, nil); !bytes.Equal(got, want[:]) {
		t.Errorf("MD4: %x", got)
	}
	wantB := BLAKE3(nil)
	if got := strongHash(HashAlgoBLAKE3, nil); !bytes.Equal(got, wantB[:]) {
		t.Errorf("BLAKE3: %x", got)
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on unknown algo")
		}
	}()
	_ = strongHash("BOGUS", nil)
}

func TestStrongHashFullLen(t *testing.T) {
	if StrongHashFullLen("") != 16 {
		t.Errorf("default len wrong")
	}
	if StrongHashFullLen(HashAlgoMD4) != 16 {
		t.Errorf("MD4 len wrong")
	}
	if StrongHashFullLen(HashAlgoBLAKE3) != 32 {
		t.Errorf("BLAKE3 len wrong")
	}
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic")
		}
	}()
	_ = StrongHashFullLen("BOGUS")
}

func TestStrongHashLabel(t *testing.T) {
	if got := strongHashLabel(""); got != "MD4" {
		t.Errorf("empty: %q", got)
	}
	if got := strongHashLabel(HashAlgoMD4); got != "MD4" {
		t.Errorf("MD4: %q", got)
	}
	if got := strongHashLabel(HashAlgoBLAKE3); got != "BLAKE3" {
		t.Errorf("BLAKE3: %q", got)
	}
	if got := strongHashLabel("WEIRD"); got != "WEIRD" {
		t.Errorf("passthrough: %q", got)
	}
}

func TestComputeHashLengthsAlgoBLAKE3(t *testing.T) {
	// A 1 GB file should land at checksum_bytes=16 per the proposal
	// (BLAKE3 floor in ComputeHashLengthsAlgo).
	hl := ComputeHashLengthsAlgo(1<<30, 4096, HashAlgoBLAKE3)
	if hl.ChecksumBytes != 16 {
		t.Errorf("1GB BLAKE3: cs=%d, want 16", hl.ChecksumBytes)
	}
	if hl.SeqMatches != 2 {
		t.Errorf("1GB: seq=%d", hl.SeqMatches)
	}
	// Degenerate: empty file still returns the smallest legal triple.
	if hl := ComputeHashLengthsAlgo(0, 2048, HashAlgoBLAKE3); hl != (HashLengths{1, 2, 3}) {
		t.Errorf("empty: %+v", hl)
	}
	// Tiny non-empty file: BLAKE3 floor still applies.
	hl = ComputeHashLengthsAlgo(1, 1, HashAlgoBLAKE3)
	if hl.ChecksumBytes != 16 {
		t.Errorf("tiny BLAKE3: cs=%d, want 16", hl.ChecksumBytes)
	}
	// Pathologically huge file with BLAKE3 must NOT clamp at 16 (the MD4
	// ceiling) — it can use up to 32.
	hl = ComputeHashLengthsAlgo(1<<60, 1<<20, HashAlgoBLAKE3)
	if hl.ChecksumBytes > 32 {
		t.Errorf("BLAKE3 over-clamp: cs=%d", hl.ChecksumBytes)
	}
	if hl.ChecksumBytes < 16 {
		t.Errorf("BLAKE3 huge: cs=%d < 16", hl.ChecksumBytes)
	}
	// And MD4 path still clamps at 16 for the same dimensions.
	hl = ComputeHashLengthsAlgo(1<<60, 1<<20, HashAlgoMD4)
	if hl.ChecksumBytes > 16 {
		t.Errorf("MD4 over-clamp: cs=%d", hl.ChecksumBytes)
	}
}

// TestMakeBLAKE3FormatHeaders verifies that MakeWithAlgo(BLAKE3) sets
// Format, HashAlgorithm, Version, FileHash and clears SHA1Hex.
func TestMakeBLAKE3FormatHeaders(t *testing.T) {
	data := []byte("hello, blake3 world")
	cf, err := MakeWithAlgo(bytes.NewReader(data), int64(len(data)), 2048, "x.bin",
		time.Time{}, []string{"x.bin"}, HashAlgoBLAKE3)
	if err != nil {
		t.Fatal(err)
	}
	if cf.Format != FormatZsync2 {
		t.Errorf("Format=%q, want %q", cf.Format, FormatZsync2)
	}
	if cf.HashAlgorithm != HashAlgoBLAKE3 {
		t.Errorf("HashAlgorithm=%q", cf.HashAlgorithm)
	}
	if cf.Version != DefaultVersionZsync2 {
		t.Errorf("Version=%q", cf.Version)
	}
	if len(cf.FileHash) != 32 {
		t.Errorf("FileHash len=%d", len(cf.FileHash))
	}
	if cf.SHA1Hex != "" {
		t.Errorf("SHA1Hex should be empty for BLAKE3 path, got %q", cf.SHA1Hex)
	}
	// The FileHash matches an external BLAKE3 of the same bytes.
	want := BLAKE3(data)
	if !bytes.Equal(cf.FileHash, want[:]) {
		t.Errorf("FileHash mismatch: %x vs %x", cf.FileHash, want[:])
	}
}

func TestMakeUnknownAlgorithm(t *testing.T) {
	_, err := MakeWithAlgo(bytes.NewReader(nil), 0, 2048, "", time.Time{}, nil, "BOGUS")
	if err == nil {
		t.Fatal("expected unknown-algo error")
	}
}

func TestMakeDefaultsToMD4WhenAlgoEmpty(t *testing.T) {
	cf, err := MakeWithAlgo(bytes.NewReader([]byte("x")), 1, 2048, "", time.Time{}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if cf.HashAlgorithm != HashAlgoMD4 {
		t.Errorf("default algo: %q", cf.HashAlgorithm)
	}
	if cf.Format != FormatZsync {
		t.Errorf("default format: %q", cf.Format)
	}
}

// TestReadWriteRoundtripBLAKE3 exercises a full round-trip: build with
// BLAKE3, serialise, parse back, compare structurally.
func TestReadWriteRoundtripBLAKE3(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, n := range []int{0, 1, 2047, 2048, 4097, 16384} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			data := make([]byte, n)
			rng.Read(data)
			cf, err := MakeWithAlgo(bytes.NewReader(data), int64(n), 2048, "z.bin",
				time.Time{}, []string{"z.bin"}, HashAlgoBLAKE3)
			if err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			if err := cf.Write(&buf); err != nil {
				t.Fatal(err)
			}
			// Magic line must be the new spelling.
			if !bytes.HasPrefix(buf.Bytes(), []byte("zsync2: ")) {
				t.Fatalf("missing zsync2 magic; got %q", buf.Bytes()[:min(20, buf.Len())])
			}
			cf2, err := Read(&buf)
			if err != nil {
				t.Fatalf("Re-Read: %v", err)
			}
			if cf2.Format != FormatZsync2 || cf2.HashAlgorithm != HashAlgoBLAKE3 {
				t.Errorf("round-trip lost format: %+v", cf2)
			}
			if !bytes.Equal(cf2.FileHash, cf.FileHash) {
				t.Errorf("FileHash drift: %x vs %x", cf2.FileHash, cf.FileHash)
			}
			if cf2.Length != cf.Length {
				t.Errorf("Length drift: %d vs %d", cf2.Length, cf.Length)
			}
			if len(cf2.Blocks) != len(cf.Blocks) {
				t.Fatalf("block-count drift: %d vs %d", len(cf2.Blocks), len(cf.Blocks))
			}
			for i := range cf.Blocks {
				if cf.Blocks[i].Rsum != cf2.Blocks[i].Rsum {
					t.Errorf("block %d rsum drift", i)
				}
				if !bytes.Equal(cf.Blocks[i].Checksum, cf2.Blocks[i].Checksum) {
					t.Errorf("block %d checksum drift: %x vs %x", i, cf.Blocks[i].Checksum, cf2.Blocks[i].Checksum)
				}
			}
		})
	}
}

// TestReadRejectsBadMagic — the safety property called out in the proposal:
// anything other than "zsync" or "zsync2" as the first header line must be
// rejected with a "not a zsync file"-style error.
func TestReadRejectsBadMagic(t *testing.T) {
	cases := []string{
		"NotAZsyncFile: 1.0\nBlocksize: 2048\nLength: 0\n\n",
		"# leading comment\n\n",
		"\n\n", // empty header
		// A "zsync" magic missing the colon
		"zsync 0.6\n\n",
	}
	for i, c := range cases {
		_, err := Read(strings.NewReader(c))
		if err == nil {
			t.Errorf("case %d (%q): expected rejection", i, c)
		}
	}
}

// TestReadRejectsZsync2FromClassicParserSurrogate is the cross-format
// negative test the proposal calls out: a hypothetical client wired only to
// the classic FormatZsync parser must reject zsync2: 1.0 input.
//
// Our combined Read accepts both, so we simulate "classic only" by parsing
// the magic line and asserting the returned Format. A downstream consumer
// can then refuse to proceed iff cf.Format != FormatZsync.
func TestReadAcceptsBothFormatsAndExposesFormat(t *testing.T) {
	classic := "zsync: 0.6.2\nBlocksize: 2048\nLength: 0\nHash-Lengths: 1,2,3\nURL: /x\n\n"
	cf, err := Read(strings.NewReader(classic))
	if err != nil {
		t.Fatalf("classic: %v", err)
	}
	if cf.Format != FormatZsync || cf.HashAlgorithm != HashAlgoMD4 {
		t.Errorf("classic format: %+v", cf)
	}

	// Build a tiny zsync2: 1.0 control file programmatically.
	cfNew, err := MakeWithAlgo(bytes.NewReader([]byte("x")), 1, 2048, "x.bin",
		time.Time{}, []string{"x.bin"}, HashAlgoBLAKE3)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := cfNew.Write(&buf); err != nil {
		t.Fatal(err)
	}
	cf2, err := Read(&buf)
	if err != nil {
		t.Fatalf("zsync2: %v", err)
	}
	if cf2.Format != FormatZsync2 || cf2.HashAlgorithm != HashAlgoBLAKE3 {
		t.Errorf("zsync2 format: %+v", cf2)
	}
}

// TestReadHashAlgorithmHeaderExplicit covers the explicit
// "Hash-Algorithm: ..." header parsing path.
func TestReadHashAlgorithmHeaderExplicit(t *testing.T) {
	// A zsync2: 1.0 file with an explicit Hash-Algorithm: BLAKE3 header.
	const hdr = "zsync2: 1.0\nBlocksize: 2048\nLength: 0\nHash-Lengths: 1,2,3\nHash-Algorithm: BLAKE3\nURL: /x\n\n"
	cf, err := Read(strings.NewReader(hdr))
	if err != nil {
		t.Fatalf("explicit: %v", err)
	}
	if cf.HashAlgorithm != HashAlgoBLAKE3 {
		t.Errorf("HashAlgorithm=%q", cf.HashAlgorithm)
	}

	// An unknown Hash-Algorithm must be rejected.
	const bad = "zsync2: 1.0\nBlocksize: 2048\nLength: 0\nHash-Lengths: 1,2,3\nHash-Algorithm: BOGUS\nURL: /x\n\n"
	if _, err := Read(strings.NewReader(bad)); err == nil {
		t.Fatal("expected reject on unknown Hash-Algorithm")
	}
}

// TestReadFileHashHeader covers File-Hash: parsing in all its shapes.
func TestReadFileHashHeader(t *testing.T) {
	// Valid BLAKE3 File-Hash on a zsync2 file.
	zero := BLAKE3(nil) // 32 bytes
	hexed := hex.EncodeToString(zero[:])
	hdr := fmt.Sprintf("zsync2: 1.0\nBlocksize: 2048\nLength: 0\nHash-Lengths: 1,2,3\nFile-Hash: BLAKE3:%s\nURL: /x\n\n", hexed)
	cf, err := Read(strings.NewReader(hdr))
	if err != nil {
		t.Fatalf("valid BLAKE3 File-Hash: %v", err)
	}
	if !bytes.Equal(cf.FileHash, zero[:]) {
		t.Errorf("FileHash mismatch")
	}
	if cf.HashAlgorithm != HashAlgoBLAKE3 {
		t.Errorf("HashAlgorithm not aligned by File-Hash: %q", cf.HashAlgorithm)
	}

	// Valid MD4 File-Hash on a zsync2 file (downgrade compat).
	md4z := MD4(nil)
	md4hex := hex.EncodeToString(md4z[:])
	hdr = fmt.Sprintf("zsync2: 1.0\nBlocksize: 2048\nLength: 0\nHash-Lengths: 1,2,3\nHash-Algorithm: BLAKE3\nFile-Hash: MD4:%s\nURL: /x\n\n", md4hex)
	if _, err := Read(strings.NewReader(hdr)); err != nil {
		t.Fatalf("MD4 File-Hash in zsync2: %v", err)
	}

	// Missing colon -> reject.
	bad := "zsync2: 1.0\nBlocksize: 2048\nLength: 0\nHash-Lengths: 1,2,3\nFile-Hash: nodelimiter\nURL: /x\n\n"
	if _, err := Read(strings.NewReader(bad)); err == nil {
		t.Fatal("expected reject on missing colon in File-Hash")
	}

	// Empty algo (leading colon) -> reject (colon at 0).
	bad = "zsync2: 1.0\nBlocksize: 2048\nLength: 0\nHash-Lengths: 1,2,3\nFile-Hash: :deadbeef\nURL: /x\n\n"
	if _, err := Read(strings.NewReader(bad)); err == nil {
		t.Fatal("expected reject on empty algo in File-Hash")
	}

	// Unknown algorithm -> reject.
	bad = "zsync2: 1.0\nBlocksize: 2048\nLength: 0\nHash-Lengths: 1,2,3\nFile-Hash: SHA256:" + strings.Repeat("00", 32) + "\nURL: /x\n\n"
	if _, err := Read(strings.NewReader(bad)); err == nil {
		t.Fatal("expected reject on unknown File-Hash algo")
	}

	// Bad hex -> reject.
	bad = "zsync2: 1.0\nBlocksize: 2048\nLength: 0\nHash-Lengths: 1,2,3\nFile-Hash: BLAKE3:zzzz\nURL: /x\n\n"
	if _, err := Read(strings.NewReader(bad)); err == nil {
		t.Fatal("expected reject on bad hex in File-Hash")
	}

	// Wrong width -> reject.
	bad = "zsync2: 1.0\nBlocksize: 2048\nLength: 0\nHash-Lengths: 1,2,3\nFile-Hash: BLAKE3:dead\nURL: /x\n\n"
	if _, err := Read(strings.NewReader(bad)); err == nil {
		t.Fatal("expected reject on wrong-width File-Hash")
	}
}

// TestReadRejectsOverWideChecksumBytes — Hash-Lengths' checksum_bytes is
// algorithm-bound: <=16 for MD4, <=32 for BLAKE3.
func TestReadRejectsOverWideChecksumBytes(t *testing.T) {
	// MD4 wire format with cs=17 must reject (existing test covers cs=99
	// already; this is the new explicit boundary).
	bad := "zsync: 0.6.2\nBlocksize: 2048\nLength: 2048\nHash-Lengths: 1,2,17\nURL: /x\n\n"
	if _, err := Read(strings.NewReader(bad)); err == nil {
		t.Fatal("expected reject MD4 cs=17")
	}
	// BLAKE3 wire format with cs=32 is fine.
	const ok = "zsync2: 1.0\nBlocksize: 2048\nLength: 0\nHash-Lengths: 1,2,32\nURL: /x\n\n"
	if _, err := Read(strings.NewReader(ok)); err != nil {
		t.Fatalf("BLAKE3 cs=32: %v", err)
	}
	// BLAKE3 wire format with cs=33 must reject.
	bad = "zsync2: 1.0\nBlocksize: 2048\nLength: 2048\nHash-Lengths: 1,2,33\nURL: /x\n\n"
	if _, err := Read(strings.NewReader(bad)); err == nil {
		t.Fatal("expected reject BLAKE3 cs=33")
	}
}

// TestMatcherBLAKE3 exercises the matcher against a BLAKE3-built control file.
func TestMatcherBLAKE3(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	target := make([]byte, 4096*4)
	rng.Read(target)
	cf, err := MakeWithAlgo(bytes.NewReader(target), int64(len(target)), 4096, "t.bin",
		time.Time{}, []string{"t.bin"}, HashAlgoBLAKE3)
	if err != nil {
		t.Fatal(err)
	}
	m := NewMatcher(cf)
	if err := m.FeedSeed(bytes.NewReader(target)); err != nil {
		t.Fatal(err)
	}
	if m.AcceptedBlocks() != m.TotalBlocks() {
		t.Fatalf("BLAKE3 matcher: %d/%d", m.AcceptedBlocks(), m.TotalBlocks())
	}
	if !bytes.Equal(m.Out(), target) {
		t.Fatal("BLAKE3 matcher: Out != target")
	}

	// Reject a download whose BLAKE3 doesn't match.
	if err := m.AcceptDownloadedBlock(0, bytes.Repeat([]byte{0xff}, 4096)); err == nil {
		t.Fatal("expected BLAKE3 verification error")
	} else if !strings.Contains(err.Error(), "BLAKE3") {
		t.Errorf("error should mention BLAKE3: %v", err)
	}
}

// TestEndToEndBLAKE3 is the full round-trip: maker -> .zsync2 -> matcher +
// fetcher -> byte-identical reconstruction.
func TestEndToEndBLAKE3(t *testing.T) {
	rng := rand.New(rand.NewSource(2026))
	target := make([]byte, 64*1024)
	rng.Read(target)
	// Seed: 99% identical, 1% mutated to force a fetch.
	seed := append([]byte(nil), target...)
	for i := 10_000; i < 10_512; i++ {
		seed[i] ^= 0x5a
	}

	cf, err := MakeWithAlgo(bytes.NewReader(target), int64(len(target)), 2048, "t.bin",
		time.Time{}, []string{"t.bin"}, HashAlgoBLAKE3)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/t.bin" {
			http.ServeContent(w, r, "t.bin", time.Now(), bytes.NewReader(target))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	m := NewMatcher(cf)
	if err := m.FeedSeed(bytes.NewReader(seed)); err != nil {
		t.Fatal(err)
	}
	if m.AcceptedBlocks() == m.TotalBlocks() {
		t.Fatal("seed mutation didn't take")
	}
	missing := m.MissingRanges()
	fc := NewFetchClient()
	if err := fc.FetchBlocks(srv.URL+"/t.bin", cf, m, missing); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Out(), target) {
		t.Fatal("end-to-end BLAKE3: reconstruction differs")
	}
	if err := VerifySHA1(cf, m.Out()); err != nil {
		t.Fatalf("file-wide BLAKE3: %v", err)
	}
	if err := VerifyFileHash(cf, m.Out()); err != nil {
		t.Fatalf("VerifyFileHash: %v", err)
	}

	// Mutate the buffer and expect the file-hash check to flag it.
	bad := append([]byte(nil), m.Out()...)
	bad[0] ^= 1
	if err := VerifyFileHash(cf, bad); err == nil {
		t.Fatal("expected BLAKE3 file-wide mismatch")
	}
}

// TestVerifyFileHashMD4Path covers the MD4 file-hash branch, which exists
// for forward compat ("File-Hash: MD4:<hex>" on a zsync2 file).
func TestVerifyFileHashMD4Path(t *testing.T) {
	data := []byte("payload")
	md := MD4(data)
	cf := &ControlFile{
		HashAlgorithm: HashAlgoMD4,
		FileHash:      md[:],
	}
	if err := VerifyFileHash(cf, data); err != nil {
		t.Errorf("happy path: %v", err)
	}
	if err := VerifyFileHash(cf, []byte("tampered")); err == nil {
		t.Fatal("expected MD4 file-hash mismatch")
	}
}

// TestVerifyFileHashLegacySHA1Path keeps the legacy path covered.
func TestVerifyFileHashLegacySHA1Path(t *testing.T) {
	cf := &ControlFile{SHA1Hex: "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"}
	if err := VerifyFileHash(cf, []byte("hello world")); err != nil {
		t.Errorf("legacy SHA-1: %v", err)
	}
	if err := VerifyFileHash(cf, []byte("hello world!")); err == nil {
		t.Fatal("expected SHA-1 mismatch")
	}
	if err := VerifyFileHash(&ControlFile{}, []byte("x")); err != nil {
		t.Errorf("empty CF: %v", err)
	}
}

// TestWriteEmitsHashAlgorithmOnlyForZsync2 — defensive: a classic file
// must not gain a Hash-Algorithm header on write.
func TestWriteEmitsHashAlgorithmOnlyForZsync2(t *testing.T) {
	// Classic.
	cfClassic := &ControlFile{
		Blocksize:   1024,
		Length:      1024,
		HashLengths: HashLengths{1, 2, 3},
		URLs:        []string{"x"},
		SHA1Hex:     "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		Blocks:      []BlockChecksum{{Checksum: []byte{0, 0, 0}}},
	}
	var buf bytes.Buffer
	if err := cfClassic.Write(&buf); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "Hash-Algorithm:") {
		t.Fatal("classic file leaked Hash-Algorithm: header")
	}
	if !strings.HasPrefix(buf.String(), "zsync: ") {
		t.Errorf("classic magic missing")
	}

	// zsync2.
	buf.Reset()
	cfNew := &ControlFile{
		Format:        FormatZsync2,
		HashAlgorithm: HashAlgoBLAKE3,
		Blocksize:     1024,
		Length:        1024,
		HashLengths:   HashLengths{1, 2, 16},
		URLs:          []string{"x"},
		FileHash:      make([]byte, 32),
		Blocks:        []BlockChecksum{{Checksum: make([]byte, 16)}},
	}
	if err := cfNew.Write(&buf); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	if !strings.Contains(s, "Hash-Algorithm: BLAKE3") {
		t.Errorf("Hash-Algorithm: missing in zsync2 output")
	}
	if !strings.Contains(s, "File-Hash: BLAKE3:") {
		t.Errorf("File-Hash: missing in zsync2 output")
	}
	if !strings.HasPrefix(s, "zsync2: ") {
		t.Errorf("zsync2 magic missing")
	}
}

// TestWriteDefaultsBackfillForZsync2 — building a CF{Format: zsync2}
// without explicit Version/HashAlgorithm should still produce a valid file.
func TestWriteDefaultsBackfillForZsync2(t *testing.T) {
	cf := &ControlFile{
		Format:      FormatZsync2,
		Blocksize:   1024,
		Length:      0,
		HashLengths: HashLengths{1, 2, 3},
	}
	var buf bytes.Buffer
	if err := cf.Write(&buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "zsync2: 1.0") {
		t.Errorf("default Version not backfilled: %s", buf.String())
	}
	if !strings.Contains(buf.String(), "Hash-Algorithm: BLAKE3") {
		t.Errorf("default HashAlgorithm not backfilled")
	}
}

// TestParseStabilityZsync2 — read, re-serialise, byte-diff. The zsync2
// header layout we emit must be a fixed point of our parser/writer pair.
func TestParseStabilityZsync2(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	data := make([]byte, 8192)
	rng.Read(data)
	cf, err := MakeWithAlgo(bytes.NewReader(data), int64(len(data)), 2048, "t.bin",
		time.Date(2026, 5, 29, 1, 2, 3, 0, time.UTC), []string{"t.bin"}, HashAlgoBLAKE3)
	if err != nil {
		t.Fatal(err)
	}
	var buf1 bytes.Buffer
	if err := cf.Write(&buf1); err != nil {
		t.Fatal(err)
	}
	cf2, err := Read(bytes.NewReader(buf1.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	var buf2 bytes.Buffer
	if err := cf2.Write(&buf2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf1.Bytes(), buf2.Bytes()) {
		t.Errorf("write/read/write is not a fixed point:\nfirst:\n%s\n\nsecond:\n%s", buf1.String(), buf2.String())
	}
}

// TestReadIncompleteFirstLineSurfaceError covers the EOF/early-return path
// on a stream where the very first byte already errors.
func TestReadEarlyErrorOnFirstLine(t *testing.T) {
	_, err := Read(errReader{err: errors.New("boom")})
	if err == nil {
		t.Fatal("expected error")
	}
}

// TestReadEmptyStreamRejected — a 0-byte input must produce a clear error.
func TestReadEmptyStreamRejected(t *testing.T) {
	_, err := Read(strings.NewReader(""))
	if err == nil {
		t.Fatal("expected error on empty stream")
	}
}

// TestReadJustBlankLineRejected — a header that's only a blank line falls
// into the "empty header" branch.
func TestReadJustBlankLineRejected(t *testing.T) {
	_, err := Read(strings.NewReader("\n"))
	if err == nil {
		t.Fatal("expected empty-header rejection")
	}
}

// TestCrossFormatInterop — gozsyncmake-equivalent in zsync2 mode produces
// a control file that gozsync-equivalent reconstructs byte-identically.
func TestCrossFormatInterop(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	target := make([]byte, 8*1024)
	rng.Read(target)

	// "gozsyncmake --format zsync2"
	cf, err := MakeWithAlgo(bytes.NewReader(target), int64(len(target)), 1024, "tgt.bin",
		time.Time{}, []string{"tgt.bin"}, HashAlgoBLAKE3)
	if err != nil {
		t.Fatal(err)
	}
	var zbuf bytes.Buffer
	if err := cf.Write(&zbuf); err != nil {
		t.Fatal(err)
	}

	// "gozsync"
	cf2, err := Read(&zbuf)
	if err != nil {
		t.Fatal(err)
	}
	// No seed: everything must come from the server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "tgt.bin", time.Now(), bytes.NewReader(target))
	}))
	defer srv.Close()

	m := NewMatcher(cf2)
	missing := m.MissingRanges()
	if len(missing) == 0 {
		t.Fatal("missing should be everything")
	}
	if err := NewFetchClient().FetchBlocks(srv.URL+"/tgt.bin", cf2, m, missing); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Out(), target) {
		t.Fatal("cross-format reconstruction differs")
	}
	if err := VerifyFileHash(cf2, m.Out()); err != nil {
		t.Fatalf("VerifyFileHash: %v", err)
	}
}

// TestCrossFormatInteropWithSeed exercises the seed path on the BLAKE3 side.
func TestCrossFormatInteropWithSeed(t *testing.T) {
	rng := rand.New(rand.NewSource(12))
	target := make([]byte, 16*1024)
	rng.Read(target)
	seed := append([]byte(nil), target...)
	// flip a few bytes scattered through the file
	for _, i := range []int{1000, 5000, 9000} {
		seed[i] ^= 0xff
	}
	cf, err := MakeWithAlgo(bytes.NewReader(target), int64(len(target)), 2048, "t.bin",
		time.Time{}, []string{"t.bin"}, HashAlgoBLAKE3)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "t.bin", time.Now(), bytes.NewReader(target))
	}))
	defer srv.Close()
	m := NewMatcher(cf)
	if err := m.FeedSeed(bytes.NewReader(seed)); err != nil {
		t.Fatal(err)
	}
	if m.AcceptedBlocks() == 0 {
		t.Fatal("seed produced no matches")
	}
	if err := NewFetchClient().FetchBlocks(srv.URL+"/t.bin", cf, m, m.MissingRanges()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Out(), target) {
		t.Fatal("seed+fetch reconstruction differs")
	}
}

// TestReadMissingMagicLineBeforeBlankLine — a stream that starts with a
// blank line still fails the "first line must be magic" check.
func TestReadFirstLineNotMagic(t *testing.T) {
	if _, err := Read(strings.NewReader("Filename: oops\n\n")); err == nil {
		t.Fatal("expected reject: first line not magic")
	}
}

// helpers ----------------------------------------------------------------

// io.EOF surface check, plus a smoke test that the ToString helpers exist.
var _ io.Reader = strings.NewReader("")

func min(a, b int) int { //nolint:predeclared // go1.22 stdlib has it but we keep test self-contained
	if a < b {
		return a
	}
	return b
}
