package zsync

import (
	"strings"
	"testing"
)

// TestReadRejectsDuplicateMagic covers the defensive duplicate-"zsync:"
// branch in applyHeader: a malformed file that repeats the magic line
// after the first must be rejected.
func TestReadRejectsDuplicateMagic(t *testing.T) {
	const dup = "zsync: 0.6.2\nzsync: 0.6.2\nBlocksize: 2048\nLength: 0\nHash-Lengths: 1,2,3\nURL: /x\n\n"
	if _, err := Read(strings.NewReader(dup)); err == nil {
		t.Fatal("expected reject on duplicate zsync header")
	}
	const dup2 = "zsync2: 1.0\nzsync2: 1.0\nBlocksize: 2048\nLength: 0\nHash-Lengths: 1,2,3\nURL: /x\n\n"
	if _, err := Read(strings.NewReader(dup2)); err == nil {
		t.Fatal("expected reject on duplicate zsync2 header")
	}
}

// TestReadRejectsZsync2HeadersOnClassicFile covers the safety check that
// Hash-Algorithm: and File-Hash: only appear on zsync2 files. A classic
// "zsync: 0.6.2" file carrying these new headers must be rejected.
func TestReadRejectsZsync2HeadersOnClassicFile(t *testing.T) {
	classicWithAlgo := "zsync: 0.6.2\nBlocksize: 2048\nLength: 0\nHash-Lengths: 1,2,3\nHash-Algorithm: BLAKE3\nURL: /x\n\n"
	if _, err := Read(strings.NewReader(classicWithAlgo)); err == nil {
		t.Fatal("expected reject: Hash-Algorithm on classic file")
	}
	classicWithFH := "zsync: 0.6.2\nBlocksize: 2048\nLength: 0\nHash-Lengths: 1,2,3\nFile-Hash: BLAKE3:" +
		"af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" +
		"\nURL: /x\n\n"
	if _, err := Read(strings.NewReader(classicWithFH)); err == nil {
		t.Fatal("expected reject: File-Hash on classic file")
	}
}

// TestVerifyFileHashEmptyAlgoDefaultsToMD4 covers the "algo == \"\"" fallback
// inside VerifyFileHash: a ControlFile carrying FileHash bytes but no
// HashAlgorithm should be treated as MD4 for back-compat.
func TestVerifyFileHashEmptyAlgoDefaultsToMD4(t *testing.T) {
	data := []byte("hello")
	md := MD4(data)
	cf := &ControlFile{FileHash: md[:]} // HashAlgorithm intentionally empty
	if err := VerifyFileHash(cf, data); err != nil {
		t.Errorf("empty-algo MD4 path: %v", err)
	}
	if err := VerifyFileHash(cf, []byte("tampered")); err == nil {
		t.Fatal("expected mismatch on empty-algo MD4 path")
	}
}

