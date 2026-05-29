package zsync

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // wire format
	"encoding/hex"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestRsumIncrementalMatchesFullRecompute checks that the byte-wise update
// rule reproduces the same Rsum as a from-scratch computation. This is the
// linchpin of the whole rolling-checksum scheme.
func TestRsumIncrementalMatchesFullRecompute(t *testing.T) {
	const bs = 1024
	rng := rand.New(rand.NewSource(42))
	data := make([]byte, bs*4)
	rng.Read(data)
	r := CalcRsum(data[:bs])
	for x := 0; x < len(data)-bs-1; x++ {
		// slide by 1
		oldc := data[x]
		newc := data[x+bs]
		r.A = r.A + uint16(newc) - uint16(oldc)
		r.B = r.B + r.A - uint16(uint32(oldc)*uint32(bs))
		want := CalcRsum(data[x+1 : x+1+bs])
		if r != want {
			t.Fatalf("at x=%d: incremental %+v != full %+v", x+1, r, want)
		}
	}
}

func TestComputeHashLengths(t *testing.T) {
	// For files larger than blocksize, seq_matches must be 2.
	hl := ComputeHashLengths(10_000_000, 2048)
	if hl.SeqMatches != 2 {
		t.Errorf("seq_matches=%d, want 2 for 10MB file", hl.SeqMatches)
	}
	if hl.RsumBytes < 2 || hl.RsumBytes > 4 {
		t.Errorf("rsum_bytes=%d out of [2,4]", hl.RsumBytes)
	}
	if hl.ChecksumBytes < 3 || hl.ChecksumBytes > 16 {
		t.Errorf("checksum_bytes=%d out of [3,16]", hl.ChecksumBytes)
	}
}

// TestRoundTripMakeRead exercises the .zsync writer + parser as a pair.
func TestRoundTripMakeRead(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	data := make([]byte, 50_000)
	rng.Read(data)
	cf, err := Make(bytes.NewReader(data), int64(len(data)), 2048, "data.bin",
		time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC), []string{"data.bin"})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := cf.Write(&buf); err != nil {
		t.Fatal(err)
	}
	cf2, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if cf2.Length != cf.Length || cf2.Blocksize != cf.Blocksize {
		t.Fatalf("header mismatch: %+v vs %+v", cf2, cf)
	}
	if len(cf2.Blocks) != len(cf.Blocks) {
		t.Fatalf("block count: got %d, want %d", len(cf2.Blocks), len(cf.Blocks))
	}
	for i := range cf.Blocks {
		if cf.Blocks[i].Rsum != cf2.Blocks[i].Rsum {
			t.Fatalf("block %d rsum mismatch", i)
		}
		if !bytes.Equal(cf.Blocks[i].Checksum, cf2.Blocks[i].Checksum) {
			t.Fatalf("block %d checksum mismatch", i)
		}
	}
}

// TestEndToEnd builds a target, writes the .zsync, mutates a few bytes to
// create a seed, serves the target over HTTP, runs the client, and checks
// the reconstruction is byte-identical.
func TestEndToEnd(t *testing.T) {
	rng := rand.New(rand.NewSource(2024))
	target := make([]byte, 256*1024) // 256 KB
	rng.Read(target)
	// Build the seed: 95% identical, 5% mutated to force fetches.
	seed := make([]byte, len(target))
	copy(seed, target)
	mutOff := 100_000
	for i := 0; i < 4096; i++ {
		seed[mutOff+i] ^= 0xff
	}

	cf, err := Make(bytes.NewReader(target), int64(len(target)), 2048, "target.bin", time.Time{}, []string{"target.bin"})
	if err != nil {
		t.Fatal(err)
	}

	// Serve the target file at /target.bin and the .zsync at /target.bin.zsync.
	var zbuf bytes.Buffer
	if err := cf.Write(&zbuf); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/target.bin":
			http.ServeContent(w, r, "target.bin", time.Now(), bytes.NewReader(target))
		case "/target.bin.zsync":
			w.Write(zbuf.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Fetch the .zsync over HTTP, run the matcher with the seed, fetch missing blocks.
	resp, err := http.Get(srv.URL + "/target.bin.zsync")
	if err != nil {
		t.Fatal(err)
	}
	cf2, err := Read(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}

	m := NewMatcher(cf2)
	if err := m.FeedSeed(bytes.NewReader(seed)); err != nil {
		t.Fatal(err)
	}
	t.Logf("matched %d/%d blocks from seed", m.AcceptedBlocks(), m.TotalBlocks())
	if m.AcceptedBlocks() == 0 {
		t.Fatal("expected to match most blocks from the seed")
	}
	if m.AcceptedBlocks() == m.TotalBlocks() {
		t.Fatal("matched everything? seed mutation didn't take")
	}
	missing := m.MissingRanges()
	targetURLs, err := ResolveTargetURL(cf2, srv.URL+"/target.bin.zsync")
	if err != nil {
		t.Fatal(err)
	}
	fc := NewFetchClient()
	if err := fc.FetchBlocksMulti(targetURLs, cf2, m, missing); err != nil {
		t.Fatal(err)
	}
	if got := m.AcceptedBlocks(); got != m.TotalBlocks() {
		t.Fatalf("after fetch: %d/%d blocks", got, m.TotalBlocks())
	}
	if !bytes.Equal(m.Out(), target) {
		t.Fatalf("reconstruction differs from target")
	}
	if err := VerifySHA1(cf2, m.Out()); err != nil {
		t.Fatal(err)
	}

	// Also double-check the SHA-1 in the .zsync matches the target.
	h := sha1.New() //nolint:gosec // wire format
	h.Write(target)
	if want := hex.EncodeToString(h.Sum(nil)); want != cf2.SHA1Hex {
		t.Errorf("SHA-1: control=%s actual=%s", cf2.SHA1Hex, want)
	}
}

func TestParseContentRange(t *testing.T) {
	cases := []struct {
		in    string
		start int64
		end   int64
		ok    bool
	}{
		{"bytes 0-499/1234", 0, 499, true},
		{"bytes 500-999/*", 500, 999, true},
		{"foo", 0, 0, false},
	}
	for _, c := range cases {
		s, e, err := parseContentRange(c.in)
		if c.ok && err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if !c.ok && err == nil {
			t.Errorf("%q: expected error", c.in)
			continue
		}
		if c.ok && (s != c.start || e != c.end) {
			t.Errorf("%q: got %d-%d, want %d-%d", c.in, s, e, c.start, c.end)
		}
	}
}

// TestEmptyHeaderRead is a smoke test for the parser on a hand-rolled .zsync.
func TestEmptyHeaderRead(t *testing.T) {
	const minimal = "zsync: 0.6.2\nBlocksize: 2048\nLength: 2048\nHash-Lengths: 1,2,16\nURL: /x.bin\n\n"
	body := []byte(minimal)
	// one block worth of (rsum_bytes=2 + checksum_bytes=16) = 18 bytes
	body = append(body, make([]byte, 18)...)
	_, err := Read(strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
}
