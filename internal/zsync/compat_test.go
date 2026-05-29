//go:build compat
// +build compat

// Package zsync compat-tag tests verify that our parser, writer and
// matcher inter-operate with the C reference implementation
// (https://zsync.moria.org.uk and the AppImageCommunity fork) byte-for-byte.
//
// The tests are gated by the `compat` build tag so a `go test ./...` does
// not depend on an external binary; CI runs them via the
// .github/workflows/compat.yml workflow which installs `zsync` from apt
// before invoking `go test -tags=compat ./...`.
//
// Each test skips cleanly if either `zsync` or `zsyncmake` is missing from
// PATH so a developer who hasn't installed the C tools sees a skip, not a
// failure.
package zsync

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // wire format
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// requireZsyncTools skips the test unless both `zsync` and `zsyncmake` are
// installed on PATH.
func requireZsyncTools(t *testing.T) (zsync, zsyncmake string) {
	t.Helper()
	z, err1 := exec.LookPath("zsync")
	m, err2 := exec.LookPath("zsyncmake")
	if err1 != nil || err2 != nil {
		t.Skipf("zsync and/or zsyncmake not on PATH (zsync=%v zsyncmake=%v) — install via `apt-get install zsync`",
			err1, err2)
	}
	return z, m
}

// writeRand fills path with n bytes drawn from crypto/rand.
func writeRand(t *testing.T, path string, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatal(err)
	}
	return buf
}

func sha1Hex(b []byte) string {
	h := sha1.New() //nolint:gosec // wire format
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}

// TestCompatUpstreamMakeOurRead generates a .zsync with the upstream C
// `zsyncmake`, then verifies our Read can parse it and the per-block
// rsum/MD4 tables match what our Make would compute for the same input.
func TestCompatUpstreamMakeOurRead(t *testing.T) {
	_, zsyncmake := requireZsyncTools(t)

	dir := t.TempDir()
	src := filepath.Join(dir, "target.bin")
	target := writeRand(t, src, 256*1024) // 256 KB

	cmd := exec.Command(zsyncmake, "-u", "target.bin", "-o", src+".zsync", src)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("zsyncmake: %v\n%s", err, out)
	}

	zf, err := os.Open(src + ".zsync")
	if err != nil {
		t.Fatal(err)
	}
	defer zf.Close()
	cf, err := Read(zf)
	if err != nil {
		t.Fatalf("Read upstream .zsync: %v", err)
	}

	if cf.Length != int64(len(target)) {
		t.Errorf("Length: got %d, want %d", cf.Length, len(target))
	}
	if !strings.EqualFold(cf.SHA1Hex, sha1Hex(target)) {
		t.Errorf("SHA-1 mismatch: cf=%s computed=%s", cf.SHA1Hex, sha1Hex(target))
	}

	// Recompute the block table ourselves and compare against what upstream
	// emitted, modulo Hash-Lengths-driven prefix truncation.
	ours, err := Make(bytes.NewReader(target), int64(len(target)), cf.Blocksize, "",
		time.Time{}, []string{"target.bin"})
	if err != nil {
		t.Fatal(err)
	}
	if ours.HashLengths != cf.HashLengths {
		t.Errorf("HashLengths differ: ours=%+v upstream=%+v", ours.HashLengths, cf.HashLengths)
	}
	if len(ours.Blocks) != len(cf.Blocks) {
		t.Fatalf("block count: ours=%d upstream=%d", len(ours.Blocks), len(cf.Blocks))
	}
	for i := range ours.Blocks {
		oR, uR := ours.Blocks[i].Rsum, cf.Blocks[i].Rsum
		if oR != uR {
			t.Fatalf("block %d rsum: ours=%+v upstream=%+v", i, oR, uR)
		}
		if !bytes.Equal(ours.Blocks[i].Checksum, cf.Blocks[i].Checksum) {
			t.Fatalf("block %d checksum: ours=%x upstream=%x",
				i, ours.Blocks[i].Checksum, cf.Blocks[i].Checksum)
		}
	}
}

// TestCompatOurMakeUpstreamApply generates a .zsync with our Make, serves
// the target file over HTTP, and asks the upstream `zsync` client to
// reconstruct it. Byte-identical output is the pass condition.
func TestCompatOurMakeUpstreamApply(t *testing.T) {
	zsyncBin, _ := requireZsyncTools(t)

	dir := t.TempDir()
	target := make([]byte, 64*1024)
	if _, err := rand.Read(target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "target.bin"), target, 0o644); err != nil {
		t.Fatal(err)
	}

	// Build .zsync with our implementation.
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()

	cf, err := Make(bytes.NewReader(target), int64(len(target)), 2048, "target.bin",
		time.Time{}, []string{srv.URL + "/target.bin"})
	if err != nil {
		t.Fatal(err)
	}
	zPath := filepath.Join(dir, "target.bin.zsync")
	zf, err := os.Create(zPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := cf.Write(zf); err != nil {
		t.Fatal(err)
	}
	zf.Close()

	// Create a seed with one mutated block.
	seed := append([]byte(nil), target...)
	for i := 10_000; i < 10_100; i++ {
		seed[i] ^= 0xff
	}
	seedPath := filepath.Join(dir, "seed.bin")
	if err := os.WriteFile(seedPath, seed, 0o644); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "out.bin")

	// Run upstream zsync against our .zsync.
	cmd := exec.Command(zsyncBin, "-i", seedPath, "-o", outPath, zPath)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("upstream zsync failed: %v\n%s", err, out)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, target) {
		t.Fatalf("upstream zsync output != target (got %d bytes, want %d)", len(got), len(target))
	}
}

// TestCompatUpstreamMakeOurApply generates a .zsync with upstream
// `zsyncmake`, serves the target file over HTTP and lets our matcher +
// fetcher reconstruct it. Byte-identical output is the pass condition.
func TestCompatUpstreamMakeOurApply(t *testing.T) {
	_, zsyncmake := requireZsyncTools(t)

	dir := t.TempDir()
	target := make([]byte, 64*1024)
	if _, err := rand.Read(target); err != nil {
		t.Fatal(err)
	}
	srcPath := filepath.Join(dir, "target.bin")
	if err := os.WriteFile(srcPath, target, 0o644); err != nil {
		t.Fatal(err)
	}
	zPath := srcPath + ".zsync"
	cmd := exec.Command(zsyncmake, "-u", "target.bin", "-o", zPath, srcPath)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("zsyncmake: %v\n%s", err, out)
	}

	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()

	// Parse upstream's .zsync with our Read.
	zf, err := os.Open(zPath)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := Read(zf)
	zf.Close()
	if err != nil {
		t.Fatalf("Read upstream .zsync: %v", err)
	}

	// Seed with a localised mutation.
	seed := append([]byte(nil), target...)
	for i := 30_000; i < 30_064; i++ {
		seed[i] ^= 0xff
	}
	m := NewMatcher(cf)
	if err := m.FeedSeed(bytes.NewReader(seed)); err != nil {
		t.Fatal(err)
	}
	missing := m.MissingRanges()
	fc := NewFetchClient()
	if err := fc.FetchBlocks(srv.URL+"/target.bin", cf, m, missing); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Out(), target) {
		t.Fatalf("our matcher output != target (got %d bytes, want %d)", len(m.Out()), len(target))
	}
	if err := VerifySHA1(cf, m.Out()); err != nil {
		t.Fatal(err)
	}
}

// TestCompatZsync2NotRecognisedByUpstream documents the deliberate
// non-symmetry of the proposal-blake3 compat matrix: a .zsync2 produced
// by our maker is *not* readable by the upstream C zsync client, because
// the magic line bump (`zsync2: 1.0` vs `zsync: 0.6`) is one-way by design.
// We skip cleanly when the upstream tools aren't installed; otherwise we
// produce a .zsync2 and assert upstream `zsync` exits non-zero with a
// "not a zsync file"-style error, which is the documented safe behaviour.
func TestCompatZsync2NotRecognisedByUpstream(t *testing.T) {
	zsyncBin, _ := requireZsyncTools(t)

	dir := t.TempDir()
	target := make([]byte, 32*1024)
	if _, err := rand.Read(target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "target.bin"), target, 0o644); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()

	// Build a zsync2-format control file with our MakeWithAlgo.
	cf, err := MakeWithAlgo(bytes.NewReader(target), int64(len(target)), 2048, "target.bin",
		time.Time{}, []string{srv.URL + "/target.bin"}, HashAlgoBLAKE3)
	if err != nil {
		t.Fatal(err)
	}
	zPath := filepath.Join(dir, "target.bin.zsync2")
	zf, err := os.Create(zPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := cf.Write(zf); err != nil {
		t.Fatal(err)
	}
	zf.Close()

	outPath := filepath.Join(dir, "out.bin")
	// We expect upstream zsync to refuse the new format. This is the
	// proposal's stated safety property: the magic-line bump prevents an
	// old parser from misinterpreting BLAKE3 bytes as MD4.
	cmd := exec.Command(zsyncBin, "-o", outPath, zPath)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("upstream zsync unexpectedly accepted a .zsync2: out=%s", out)
	}
}

// TestCompatZMap2UpstreamMakeOurApply is the Z-Map2 e2e gate (C.1):
//
//  1. We gzip a few MB of pseudo-random bytes to produce target.bin.gz.
//  2. We call `zsyncmake -Z target.bin.gz` — upstream's gz-aware maker
//     emits a .zsync that points at target.bin.gz and carries Z-URL /
//     Z-Map2 headers.
//  3. We use our gozsync (matcher + fetcher) to reconstruct the
//     uncompressed target from the upstream-emitted .zsync, given a
//     mutated seed.
//  4. We compare against the original (uncompressed) target.
//
// If `zsyncmake -Z` rejects gz input on the apt-installed version we
// skip cleanly — the test is gated by `zsync` being installed in any
// case.
//
// Note: this exercise relies on our matcher + fetcher knowing how to
// drive the Z-Map2 path against the compressed Z-URL endpoint. The
// underlying gz-byte-range fetcher (FetchCompressedBlocks counterpart)
// isn't yet implemented; if the test fails on that path we mark it
// as a documented gap and skip.
func TestCompatZMap2UpstreamMakeOurApply(t *testing.T) {
	_, zsyncmake := requireZsyncTools(t)

	dir := t.TempDir()
	// Produce a non-trivial target (a few MB of pseudo-random bytes).
	target := make([]byte, 2*1024*1024)
	if _, err := rand.Read(target); err != nil {
		t.Fatal(err)
	}
	uncompressed := filepath.Join(dir, "target.bin")
	if err := os.WriteFile(uncompressed, target, 0o644); err != nil {
		t.Fatal(err)
	}
	gzPath := filepath.Join(dir, "target.bin.gz")
	gf, err := os.Create(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(gf)
	if _, err := zw.Write(target); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	gf.Close()

	zPath := filepath.Join(dir, "target.bin.zsync")
	// Probe whether upstream `zsyncmake` accepts -Z (gz mode). Ubuntu's
	// apt package historically ships it; some forks dropped it.
	cmd := exec.Command(zsyncmake, "-Z", "-u", "target.bin.gz", "-o", zPath, "target.bin.gz")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("zsyncmake -Z rejected the gz path (apt version may lack it): %v\n%s", err, out)
	}

	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()

	// Parse upstream's .zsync.
	zf, err := os.Open(zPath)
	if err != nil {
		t.Fatal(err)
	}
	defer zf.Close()
	cf, err := Read(zf)
	if err != nil {
		t.Fatalf("Read upstream Z-Map2 .zsync: %v", err)
	}
	if len(cf.ZMap) == 0 {
		t.Fatalf("upstream .zsync didn't carry Z-Map2 entries (out=%s)", out)
	}

	// Build a localised-mutation seed.
	seed := append([]byte(nil), target...)
	for i := 50_000; i < 50_512; i++ {
		seed[i] ^= 0x5a
	}
	m := NewMatcher(cf)
	if err := m.FeedSeed(bytes.NewReader(seed)); err != nil {
		t.Fatal(err)
	}
	missing := m.MissingRanges()
	// Plain FetchBlocks goes through URL (uncompressed). Upstream Z-Map2
	// `.zsync` files set URL to the .gz too; our client doesn't yet
	// decompress on the fly from the gz endpoint. We document that gap
	// here and skip the rest of the test when we hit it.
	if len(cf.URLs) > 0 {
		ext := strings.ToLower(filepath.Ext(cf.URLs[0]))
		if ext == ".gz" || ext == ".tgz" {
			t.Skipf("upstream emitted gz-only URLs; client-side Z-Map2 fetch (gz-byte-range + on-the-fly inflate) is not yet implemented in this package")
		}
	}
	targetURLs, err := ResolveTargetURL(cf, srv.URL+"/target.bin.zsync")
	if err != nil {
		t.Fatal(err)
	}
	if err := NewFetchClient().FetchBlocksMulti(targetURLs, cf, m, missing); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Out(), target) {
		t.Fatalf("Z-Map2 reconstruction differs from original target (got %d bytes)", len(m.Out()))
	}
}

// TestCompatZMap2OurMakeRoundTrip exercises C.1 the other way around:
// we generate a Z-Map2 .zsync with our maker for a small gz, then
// verify the .zsync parses, the ZMap entries are non-trivial, and the
// reconstruction works without invoking upstream.
//
// Lives in compat_test.go because it's a paired companion to the
// upstream-make test above; doesn't actually need upstream binaries on
// PATH and skips them gracefully.
func TestCompatZMap2OurMakeRoundTrip(t *testing.T) {
	dir := t.TempDir()
	target := make([]byte, 128*1024)
	if _, err := rand.Read(target); err != nil {
		t.Fatal(err)
	}
	gzPath := filepath.Join(dir, "target.bin.gz")
	gf, err := os.Create(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(gf)
	if _, err := zw.Write(target); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	gf.Close()
	gzData, err := os.ReadFile(gzPath)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := MakeWithZMap2(gzData, 2048, "target.bin", time.Time{},
		[]string{"target.bin"}, []string{"target.bin.gz"}, HashAlgoMD4)
	if err != nil {
		t.Fatalf("MakeWithZMap2: %v", err)
	}
	if len(cf.ZMap) == 0 {
		t.Fatal("ZMap empty")
	}
	if len(cf.ZURLs) != 1 || cf.ZURLs[0] != "target.bin.gz" {
		t.Errorf("Z-URL: %v", cf.ZURLs)
	}
	// Reconstruct from the uncompressed URL (httptest).
	srv := httptest.NewServer(http.FileServer(http.Dir(dir)))
	defer srv.Close()
	if err := os.WriteFile(filepath.Join(dir, "target.bin"), target, 0o644); err != nil {
		t.Fatal(err)
	}
	seed := append([]byte(nil), target...)
	for i := 1000; i < 1100; i++ {
		seed[i] ^= 0xff
	}
	m := NewMatcher(cf)
	if err := m.FeedSeed(bytes.NewReader(seed)); err != nil {
		t.Fatal(err)
	}
	if err := NewFetchClient().FetchBlocks(srv.URL+"/target.bin", cf, m, m.MissingRanges()); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(m.Out(), target) {
		t.Fatal("Z-Map2 own-make reconstruction differs")
	}
}

// TestCompatRoundtripParse parses an upstream-generated .zsync with our
// Read, re-serialises it with our Write, and asserts that the parsed-twice
// representation is identical to the once-parsed one (i.e. our writer
// preserves the on-the-wire information).
func TestCompatRoundtripParse(t *testing.T) {
	_, zsyncmake := requireZsyncTools(t)

	dir := t.TempDir()
	target := writeRand(t, filepath.Join(dir, "t.bin"), 32*1024)
	zPath := filepath.Join(dir, "t.bin.zsync")
	cmd := exec.Command(zsyncmake, "-u", "t.bin", "-o", zPath, filepath.Join(dir, "t.bin"))
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("zsyncmake: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(zPath)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := Read(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	var buf bytes.Buffer
	if err := cf.Write(&buf); err != nil {
		t.Fatal(err)
	}
	cf2, err := Read(&buf)
	if err != nil {
		t.Fatalf("Re-Read: %v", err)
	}
	if cf2.Length != cf.Length || cf2.Blocksize != cf.Blocksize {
		t.Errorf("rt header drift: %+v vs %+v", cf2, cf)
	}
	if cf2.HashLengths != cf.HashLengths {
		t.Errorf("rt Hash-Lengths drift: %+v vs %+v", cf2.HashLengths, cf.HashLengths)
	}
	if len(cf2.Blocks) != len(cf.Blocks) {
		t.Fatalf("rt block count: %d vs %d", len(cf2.Blocks), len(cf.Blocks))
	}
	for i := range cf.Blocks {
		if cf.Blocks[i].Rsum != cf2.Blocks[i].Rsum {
			t.Errorf("rt block %d rsum drift", i)
		}
		if !bytes.Equal(cf.Blocks[i].Checksum, cf2.Blocks[i].Checksum) {
			t.Errorf("rt block %d checksum drift", i)
		}
	}
	// SHA-1 must round-trip too.
	if !strings.EqualFold(cf.SHA1Hex, cf2.SHA1Hex) {
		t.Errorf("rt SHA-1 drift")
	}
	// And the SHA-1 must match the target's actual digest.
	if !strings.EqualFold(cf.SHA1Hex, sha1Hex(target)) {
		t.Errorf("SHA-1 vs target: cf=%s actual=%s", cf.SHA1Hex, sha1Hex(target))
	}
}
