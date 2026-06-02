package zsync2_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/go-deltasync/zsync2"
)

// TestFacadeControlFileRoundTrip drives the public API: build a control file and
// parse it back, confirming the façade is wired to the internal package.
func TestFacadeControlFileRoundTrip(t *testing.T) {
	data := bytes.Repeat([]byte("go-deltasync zsync2 facade payload "), 1000)
	cf, err := zsync2.Make(bytes.NewReader(data), int64(len(data)), 2048, "file.bin", time.Unix(0, 0).UTC(), []string{"http://example.com/file.bin"})
	if err != nil {
		t.Fatalf("Make: %v", err)
	}
	var buf bytes.Buffer
	if err := cf.Write(&buf); err != nil {
		t.Fatalf("ControlFile.Write: %v", err)
	}
	cf2, err := zsync2.Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if cf2.Blocksize != cf.Blocksize || cf2.Length != cf.Length {
		t.Fatalf("round-trip mismatch: blocksize %d/%d length %d/%d", cf2.Blocksize, cf.Blocksize, cf2.Length, cf.Length)
	}
	if m := zsync2.NewMatcher(cf2); m.TotalBlocks() != cf2.NumBlocks() {
		t.Fatalf("matcher blocks %d != control blocks %d", m.TotalBlocks(), cf2.NumBlocks())
	}
}
