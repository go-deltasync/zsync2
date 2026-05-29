package zsync

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestResolveCompressedURLs covers the Z-Map2 Z-URL list resolver.
func TestResolveCompressedURLs(t *testing.T) {
	cf := &ControlFile{ZURLs: []string{"target.gz", "https://cdn.example.com/target.gz"}}
	got, err := ResolveCompressedURLs(cf, "http://example.com/dir/target.bin.zsync")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d urls, want 2", len(got))
	}
	if got[0] != "http://example.com/dir/target.gz" {
		t.Errorf("relative not resolved: %q", got[0])
	}
	if got[1] != "https://cdn.example.com/target.gz" {
		t.Errorf("absolute not preserved: %q", got[1])
	}

	// Empty ZURLs → clear error.
	if _, err := ResolveCompressedURLs(&ControlFile{}, "http://x/"); err == nil {
		t.Fatal("expected error for empty ZURLs")
	}
	// Bad base URL.
	if _, err := ResolveCompressedURLs(&ControlFile{ZURLs: []string{"a"}}, "://bad"); err == nil {
		t.Fatal("expected error for bad zsync URL")
	}
	// Bad embedded URL.
	if _, err := ResolveCompressedURLs(&ControlFile{ZURLs: []string{"://bad"}}, "http://x/"); err == nil {
		t.Fatal("expected error for bad embedded URL")
	}
}

// TestFailoverErrorUnwrap pins the errors.Is / errors.As behaviour around
// the wrapped failoverError so callers can interrogate the underlying
// transport / HTTP error without poking at our private struct directly.
func TestFailoverErrorUnwrap(t *testing.T) {
	root := errors.New("root cause")
	wrapped := &failoverError{status: 503, err: fmt.Errorf("http 503: %w", root)}
	if !errors.Is(wrapped, root) {
		t.Fatal("errors.Is should reach the root cause through failoverError.Unwrap")
	}
	if errors.Unwrap(wrapped) == nil {
		t.Fatal("Unwrap should not return nil")
	}
	// Message passthrough.
	if !strings.Contains(wrapped.Error(), "root cause") {
		t.Fatalf("Error() should contain root cause: %q", wrapped.Error())
	}
}

// TestShouldFailoverFailsFastOn4xxOther covers the policy branch that
// stops failover on 4xx-other-than-404: a 403 / 401 / 400 means the
// URL list is wrong and retrying against the next URL of the same kind
// won't help.
func TestShouldFailoverFailsFastOn4xxOther(t *testing.T) {
	cases := []struct {
		status   int
		failover bool
	}{
		{403, false},
		{401, false},
		{400, false},
		{404, true},
		{500, true},
		{502, true},
		{503, true},
	}
	for _, tc := range cases {
		fe := &failoverError{status: tc.status, err: fmt.Errorf("status %d", tc.status)}
		if got := shouldFailover(fe); got != tc.failover {
			t.Errorf("status %d: got failover=%v, want %v", tc.status, got, tc.failover)
		}
	}
}

// TestFetchBlocksMultiFailoverThroughStatuses exercises the
// network-level failover loop: server #1 returns 503 (failover), server
// #2 returns 404 (failover), server #3 serves the bytes. Result must be
// a successful reconstruction reading exclusively from #3.
func TestFetchBlocksMultiFailoverThroughStatuses(t *testing.T) {
	// Build a target + a matching control file.
	target := bytes.Repeat([]byte("ABCD"), 1024) // 4096 bytes, exactly 1 block of 4096
	cf, err := Make(bytes.NewReader(target), int64(len(target)), 4096, "t.bin", time.Time{}, []string{"t.bin"})
	if err != nil {
		t.Fatal(err)
	}

	srv503 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv503.Close()
	srv404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv404.Close()
	hits := 0
	srvOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeContent(w, r, "t.bin", time.Time{}, bytes.NewReader(target))
	}))
	defer srvOK.Close()

	urls := []string{srv503.URL + "/t.bin", srv404.URL + "/t.bin", srvOK.URL + "/t.bin"}

	m := NewMatcher(cf)
	missing := m.MissingRanges()
	if len(missing) == 0 {
		t.Fatal("expected at least one missing range without a seed")
	}
	fc := NewFetchClient()
	if err := fc.FetchBlocksMulti(urls, cf, m, missing); err != nil {
		t.Fatalf("FetchBlocksMulti: %v", err)
	}
	if hits == 0 {
		t.Fatal("the third server should have been hit")
	}
	if !bytes.Equal(m.Out(), target) {
		t.Fatalf("reconstruction differs from target")
	}
}

// TestZMap2RoundTrip writes a synthetic ControlFile carrying a Z-Map2
// + Z-URL header set, reads it back, and verifies the parsed entries
// match what we wrote. This exercises the Z-Map2 emission/parse branches
// in Write/applyHeader.
func TestZMap2RoundTrip(t *testing.T) {
	cf := &ControlFile{
		Format:        FormatZsync,
		HashAlgorithm: HashAlgoMD4,
		Version:       "0.6.2",
		Filename:      "target.bin",
		Length:        16384,
		Blocksize:     4096,
		HashLengths:   HashLengths{SeqMatches: 2, RsumBytes: 4, ChecksumBytes: 16},
		URLs:          []string{"target.bin"},
		ZURLs:         []string{"target.gz"},
		SHA1Hex:       strings.Repeat("a", 40),
		Blocks: []BlockChecksum{
			{Rsum: Rsum{A: 0x1111, B: 0x2222}, Checksum: bytes.Repeat([]byte{1}, 16)},
			{Rsum: Rsum{A: 0x3333, B: 0x4444}, Checksum: bytes.Repeat([]byte{2}, 16)},
			{Rsum: Rsum{A: 0x5555, B: 0x6666}, Checksum: bytes.Repeat([]byte{3}, 16)},
			{Rsum: Rsum{A: 0x7777, B: 0x8888}, Checksum: bytes.Repeat([]byte{4}, 16)},
		},
		ZMap: []ZMapEntry{
			{Inflated: 0, Compressed: 0, IsBlockStart: true, BlockCount: 0},
			{Inflated: 4096, Compressed: 8 * 1024, IsBlockStart: true, BlockCount: 0},
			{Inflated: 8192, Compressed: 8 * 2048, IsBlockStart: true, BlockCount: 0},
		},
	}
	// Z-Map2 emission requires the matching raw bytes (writer copies them
	// verbatim from ZMap2Raw). Build the raw form from the parsed entries
	// using the deltas-encoded wire format documented in control.go.
	var raw bytes.Buffer
	prevIn, prevOut := uint64(0), uint64(0)
	for _, e := range cf.ZMap {
		inDelta := e.Compressed - prevIn
		outDelta := e.Inflated - prevOut
		raw.WriteByte(byte(inDelta >> 8))
		raw.WriteByte(byte(inDelta))
		ob := uint16(outDelta)
		if !e.IsBlockStart {
			ob |= 0x8000
		}
		raw.WriteByte(byte(ob >> 8))
		raw.WriteByte(byte(ob))
		prevIn, prevOut = e.Compressed, e.Inflated
	}
	cf.ZMap2Raw = raw.Bytes()

	var buf bytes.Buffer
	if err := cf.Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(got.ZURLs) != 1 || got.ZURLs[0] != "target.gz" {
		t.Errorf("Z-URL not round-tripped: %v", got.ZURLs)
	}
	if len(got.ZMap) != len(cf.ZMap) {
		t.Fatalf("ZMap length: got %d want %d", len(got.ZMap), len(cf.ZMap))
	}
	for i, want := range cf.ZMap {
		g := got.ZMap[i]
		if g.Inflated != want.Inflated || g.Compressed != want.Compressed || g.IsBlockStart != want.IsBlockStart {
			t.Errorf("ZMap[%d]: got %+v, want %+v", i, g, want)
		}
	}
}
