package zsync

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

func TestResolveTargetURL(t *testing.T) {
	cf := &ControlFile{URLs: []string{"target.bin"}}
	got, err := ResolveTargetURL(cf, "http://example.com/dir/target.bin.zsync")
	if err != nil {
		t.Fatal(err)
	}
	if got != "http://example.com/dir/target.bin" {
		t.Errorf("got %q", got)
	}

	// Absolute URL in the control file wins.
	cf = &ControlFile{URLs: []string{"https://cdn.example.com/x.bin"}}
	got, err = ResolveTargetURL(cf, "http://example.com/x.zsync")
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://cdn.example.com/x.bin" {
		t.Errorf("got %q", got)
	}
}

func TestResolveTargetURLErrors(t *testing.T) {
	if _, err := ResolveTargetURL(&ControlFile{}, "http://x"); err == nil {
		t.Fatal("expected error for empty URLs")
	}
	// Invalid zsync URL.
	if _, err := ResolveTargetURL(&ControlFile{URLs: []string{"a"}}, "://bad"); err == nil {
		t.Fatal("expected error for bad zsync URL")
	}
	// Invalid embedded URL.
	if _, err := ResolveTargetURL(&ControlFile{URLs: []string{"://bad"}}, "http://x/"); err == nil {
		t.Fatal("expected error for bad embedded URL")
	}
}

func TestVerifySHA1(t *testing.T) {
	data := []byte("hello world")
	// No SHA-1 stored: no-op.
	if err := VerifySHA1(&ControlFile{}, data); err != nil {
		t.Errorf("empty SHA1Hex: %v", err)
	}
	// Mismatch.
	if err := VerifySHA1(&ControlFile{SHA1Hex: "00"}, data); err == nil {
		t.Errorf("expected mismatch")
	}
	// Match.
	cf := &ControlFile{SHA1Hex: "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed"}
	if err := VerifySHA1(cf, data); err != nil {
		t.Errorf("expected match: %v", err)
	}
}

func TestParseContentRangeCases(t *testing.T) {
	if _, _, err := parseContentRange(""); err == nil {
		t.Error("empty CR should fail")
	}
	if _, _, err := parseContentRange("bytes 12345"); err == nil {
		t.Error("missing slash should fail")
	}
	if _, _, err := parseContentRange("bytes 12345/100"); err == nil {
		t.Error("missing dash should fail")
	}
	if _, _, err := parseContentRange("bytes notanint-100/100"); err == nil {
		t.Error("bad start should fail")
	}
	if _, _, err := parseContentRange("bytes 0-notanint/100"); err == nil {
		t.Error("bad end should fail")
	}
	s, e, err := parseContentRange("bytes 100-200/500")
	if err != nil || s != 100 || e != 200 {
		t.Errorf("good case: s=%d e=%d err=%v", s, e, err)
	}
}

// servePartial serves byte ranges for the target file with 206. Used to
// exercise the standard happy path.
func servePartial(data []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "target.bin", time.Now(), bytes.NewReader(data))
	})
}

// serveAlways200 returns the entire body with a 200 OK regardless of any
// Range header (this is what Python's http.server does).
func serveAlways200(data []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.Header.Get("Range") // observe but ignore
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
	})
}

func TestFetchBlocks206(t *testing.T) {
	bs := 256
	target := make([]byte, bs*4)
	for i := range target {
		target[i] = byte(i)
	}
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "target.bin",
		time.Time{}, []string{"target.bin"})

	srv := httptest.NewServer(servePartial(target))
	defer srv.Close()

	m := NewMatcher(cf)
	fc := NewFetchClient()
	if err := fc.FetchBlocks(srv.URL+"/target.bin", cf, m, [][2]int{{0, 4}}); err != nil {
		t.Fatal(err)
	}
	if m.AcceptedBlocks() != m.TotalBlocks() {
		t.Fatalf("206 path: %d/%d", m.AcceptedBlocks(), m.TotalBlocks())
	}
	if !bytes.Equal(m.Out(), target) {
		t.Fatal("206 path: Out != target")
	}
}

func TestFetchBlocks200Fallback(t *testing.T) {
	bs := 256
	target := make([]byte, bs*4)
	for i := range target {
		target[i] = byte(i ^ 0x55)
	}
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})

	srv := httptest.NewServer(serveAlways200(target))
	defer srv.Close()

	m := NewMatcher(cf)
	fc := NewFetchClient()
	if err := fc.FetchBlocks(srv.URL+"/t.bin", cf, m, [][2]int{{1, 3}}); err != nil {
		t.Fatal(err)
	}
	for i := 1; i < 3; i++ {
		if !m.Got(i) {
			t.Fatalf("block %d not got", i)
		}
	}
}

func TestFetchBlocksRangeCappedAtEOF(t *testing.T) {
	bs := 256
	target := make([]byte, bs*3+50) // last block is short
	for i := range target {
		target[i] = byte(i)
	}
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})

	srv := httptest.NewServer(servePartial(target))
	defer srv.Close()

	m := NewMatcher(cf)
	fc := NewFetchClient()
	// Request the last (short) block.
	if err := fc.FetchBlocks(srv.URL+"/t.bin", cf, m, [][2]int{{3, 4}}); err != nil {
		t.Fatal(err)
	}
	if !m.Got(3) {
		t.Fatal("short tail block not got")
	}
}

func TestFetchBlocksBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	bs := 256
	target := make([]byte, bs*2)
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})
	m := NewMatcher(cf)
	fc := NewFetchClient()
	err := fc.FetchBlocks(srv.URL, cf, m, [][2]int{{0, 1}})
	if err == nil {
		t.Fatal("expected status error")
	}
	if !strings.Contains(err.Error(), "unexpected status") {
		t.Errorf("error message: %v", err)
	}
}

func TestFetchBlocksBadURL(t *testing.T) {
	bs := 256
	target := make([]byte, bs*2)
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})
	m := NewMatcher(cf)
	fc := NewFetchClient()
	// "%" is invalid in a URL and http.NewRequest will reject it.
	err := fc.FetchBlocks("http://%/garbage", cf, m, [][2]int{{0, 1}})
	if err == nil {
		t.Fatal("expected NewRequest error on bad URL")
	}
}

func TestFetchBlocksTransportError(t *testing.T) {
	// Point at a port that nothing's listening on.
	bs := 256
	target := make([]byte, bs*2)
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})
	m := NewMatcher(cf)
	fc := NewFetchClient()
	err := fc.FetchBlocks("http://127.0.0.1:1/", cf, m, [][2]int{{0, 1}})
	if err == nil {
		t.Fatal("expected transport error")
	}
}

func TestFetchBlocksWrongMD4FromServer(t *testing.T) {
	bs := 256
	target := make([]byte, bs*2)
	for i := range target {
		target[i] = byte(i)
	}
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})

	// Serve garbage at all ranges.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, len(target)))
	}))
	defer srv.Close()

	m := NewMatcher(cf)
	fc := NewFetchClient()
	if err := fc.FetchBlocks(srv.URL, cf, m, [][2]int{{0, 1}}); err == nil {
		t.Fatal("expected MD4 mismatch")
	}
}

// shortBodyHandler closes the connection without writing any body when the
// client asks for a Range. It exercises the "n <= 0" guard.
type shortBodyHandler struct{}

func (shortBodyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Range") != "" {
		w.Header().Set("Content-Range", "bytes 0-0/2")
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusPartialContent)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func TestFetchBlocksShortBody(t *testing.T) {
	bs := 256
	target := make([]byte, bs*2)
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})

	srv := httptest.NewServer(shortBodyHandler{})
	defer srv.Close()

	m := NewMatcher(cf)
	fc := NewFetchClient()
	if err := fc.FetchBlocks(srv.URL, cf, m, [][2]int{{0, 1}}); err == nil {
		t.Fatal("expected short-body error")
	}
}

// brokenBodyReader serves a body that errors mid-read.
type brokenBodyHandler struct{}

func (brokenBodyHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	conn, bw, err := hj.Hijack()
	if err != nil {
		return
	}
	// Send a malformed HTTP response (no body, but says Content-Length: 4096).
	_, _ = fmt.Fprintf(bw, "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n")
	_ = bw.Flush()
	_ = conn.Close()
}

func TestFetchBlocksBodyReadError(t *testing.T) {
	bs := 256
	target := make([]byte, bs*2)
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})

	srv := httptest.NewServer(brokenBodyHandler{})
	defer srv.Close()

	m := NewMatcher(cf)
	fc := NewFetchClient()
	if err := fc.FetchBlocks(srv.URL, cf, m, [][2]int{{0, 1}}); err == nil {
		t.Fatal("expected read-body error")
	}
}

func TestParseMultipartByteRanges(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	addPart := func(cr string, body []byte) {
		h := textproto.MIMEHeader{}
		h.Set("Content-Range", cr)
		h.Set("Content-Type", "application/octet-stream")
		p, err := mw.CreatePart(h)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = p.Write(body)
	}
	addPart("bytes 0-3/8", []byte("ABCD"))
	addPart("bytes 4-7/8", []byte("EFGH"))
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	ct := "multipart/byteranges; boundary=" + mw.Boundary()
	parts, err := parseMultipartByteRanges(ct, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) != 2 {
		t.Fatalf("got %d parts, want 2", len(parts))
	}
	if string(parts[0].Body) != "ABCD" || parts[0].Start != 0 || parts[0].End != 3 {
		t.Errorf("part 0: %+v / %q", parts[0], parts[0].Body)
	}
	if string(parts[1].Body) != "EFGH" || parts[1].Start != 4 || parts[1].End != 7 {
		t.Errorf("part 1: %+v / %q", parts[1], parts[1].Body)
	}
}

func TestParseMultipartByteRangesBadContentType(t *testing.T) {
	if _, err := parseMultipartByteRanges("\x7f", strings.NewReader("")); err == nil {
		t.Fatal("expected media-type parse error")
	}
}

func TestParseMultipartByteRangesNoBoundary(t *testing.T) {
	if _, err := parseMultipartByteRanges("multipart/byteranges", strings.NewReader("")); err == nil {
		t.Fatal("expected missing-boundary error")
	}
}

func TestParseMultipartByteRangesNextPartError(t *testing.T) {
	// Truncated body: NextPart sees data but never reaches a boundary.
	ct := "multipart/byteranges; boundary=ZZZ"
	body := strings.NewReader("garbage without a boundary marker")
	if _, err := parseMultipartByteRanges(ct, body); err == nil {
		t.Fatal("expected NextPart error on truncated body")
	}
}

// errBodyReader returns an error after a few bytes; used to drive the
// "io.ReadAll inside multipart" error branch.
type errBodyReader struct {
	left []byte
	err  error
}

func (r *errBodyReader) Read(p []byte) (int, error) {
	if len(r.left) > 0 {
		n := copy(p, r.left)
		r.left = r.left[n:]
		return n, nil
	}
	return 0, r.err
}

func TestParseMultipartByteRangesPartReadError(t *testing.T) {
	// Build a partial multipart prefix that gives the parser a single part
	// header but errors before delivering the part's body.
	prefix := "--BBB\r\nContent-Range: bytes 0-3/8\r\nContent-Type: application/octet-stream\r\n\r\n"
	r := &errBodyReader{left: []byte(prefix), err: io.ErrUnexpectedEOF}
	if _, err := parseMultipartByteRanges("multipart/byteranges; boundary=BBB", r); err == nil {
		t.Fatal("expected part-body read error")
	}
}

func TestParseMultipartByteRangesBadContentRange(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := textproto.MIMEHeader{}
	h.Set("Content-Range", "garbage")
	p, _ := mw.CreatePart(h)
	_, _ = p.Write([]byte("xx"))
	mw.Close()
	ct := "multipart/byteranges; boundary=" + mw.Boundary()
	if _, err := parseMultipartByteRanges(ct, &buf); err == nil {
		t.Fatal("expected bad Content-Range error")
	}
}

// failingWriter rejects every write. Used to exercise the
// error-propagation paths in ControlFile.Write (after bufio's buffer fills
// up and triggers a flush).
type failingWriter struct{}

func (failingWriter) Write(_ []byte) (int, error) { return 0, io.ErrShortWrite }

func TestControlFileWriteErrorBaseline(t *testing.T) {
	// A CF with enough payload to force bufio to flush mid-Write.
	cf := &ControlFile{
		Blocksize:   1024,
		Length:      1024 * 4096,
		HashLengths: HashLengths{1, 2, 16},
		// 4096 blocks * 18 bytes = 73K of block table; will far exceed any
		// bufio buffer and force a flush, surfacing the failing-writer error.
		Blocks: func() []BlockChecksum {
			out := make([]BlockChecksum, 4096)
			for i := range out {
				out[i] = BlockChecksum{
					Rsum:     Rsum{A: 0, B: uint16(i)},
					Checksum: make([]byte, 16),
				}
			}
			return out
		}(),
	}
	if err := cf.Write(failingWriter{}); err == nil {
		t.Fatal("expected write error to surface")
	}
}

func TestControlFileWriteHugeHeaderErrors(t *testing.T) {
	// A CF whose *header* alone overflows bufio's 4096-byte buffer, so the
	// first writeKV that emits the giant URL drives a flush and surfaces the
	// failing-writer's error.
	bigURL := strings.Repeat("a", 8192)
	cf := &ControlFile{
		Blocksize:   1024,
		Length:      1024,
		HashLengths: HashLengths{1, 2, 3},
		URLs:        []string{bigURL},
		SHA1Hex:     "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		MinVersion:  "0.6.0",
		Filename:    "x.bin",
		HasMTime:    true,
		MTime:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Blocks: []BlockChecksum{{
			Rsum:     Rsum{},
			Checksum: []byte{0, 0, 0},
		}},
	}
	if err := cf.Write(failingWriter{}); err == nil {
		t.Fatal("expected write error from huge URL")
	}
}

func TestControlFileWriteFinalFlushError(t *testing.T) {
	// Small CF: everything fits in bufio's buffer, so the only place an
	// error can surface is the final Flush().
	cf := &ControlFile{
		Blocksize:   1024,
		Length:      1024,
		HashLengths: HashLengths{1, 2, 3},
		URLs:        []string{"x.bin"},
		SHA1Hex:     "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		MinVersion:  "0.6.0",
		Filename:    "x.bin",
		HasMTime:    true,
		MTime:       time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Blocks: []BlockChecksum{{
			Rsum:     Rsum{A: 0, B: 0},
			Checksum: []byte{0, 0, 0},
		}},
	}
	if err := cf.Write(failingWriter{}); err == nil {
		t.Fatal("expected Flush error to surface")
	}
}
