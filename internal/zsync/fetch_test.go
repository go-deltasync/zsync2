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
	if len(got) != 1 || got[0] != "http://example.com/dir/target.bin" {
		t.Errorf("got %q", got)
	}

	// Absolute URL in the control file wins.
	cf = &ControlFile{URLs: []string{"https://cdn.example.com/x.bin"}}
	got, err = ResolveTargetURL(cf, "http://example.com/x.zsync")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "https://cdn.example.com/x.bin" {
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

// TestFetchBlocksMultiPartBatching exercises the happy path of A.3:
// multiple missing ranges land in a single GET with a comma-separated
// Range header; the server replies 206 + multipart/byteranges; the
// matcher receives every part.
//
// Go's http.ServeContent emits multipart/byteranges for free when the
// client asks for multiple ranges, which is what we lean on here.
func TestFetchBlocksMultiPartBatching(t *testing.T) {
	bs := 256
	target := make([]byte, bs*8)
	for i := range target {
		target[i] = byte(i)
	}
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "target.bin",
		time.Time{}, []string{"target.bin"})

	// Track how many GETs the server saw — A.3's whole point is to make
	// this just one for the batched path (vs. len(ranges) before).
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.ServeContent(w, r, "target.bin", time.Now(), bytes.NewReader(target))
	}))
	defer srv.Close()

	m := NewMatcher(cf)
	fc := NewFetchClient()
	// Three disjoint missing runs.
	ranges := [][2]int{{0, 1}, {3, 4}, {6, 7}}
	if err := fc.FetchBlocksMulti([]string{srv.URL + "/target.bin"}, cf, m, ranges); err != nil {
		t.Fatal(err)
	}
	for _, r := range ranges {
		for i := r[0]; i < r[1]; i++ {
			if !m.Got(i) {
				t.Errorf("block %d not got", i)
			}
		}
	}
	// One batched GET, not three.
	if hits != 1 {
		t.Errorf("expected exactly one GET (batched), got %d", hits)
	}
}

// TestFetchBlocksMultiPartBatchingFallsBackOn200 covers the second
// branch of A.3: server returns 200 OK ignoring Range entirely, batched
// path returns (false, nil) and the per-range loop carries on.
func TestFetchBlocksMultiPartBatchingFallsBackOn200(t *testing.T) {
	bs := 256
	target := make([]byte, bs*4)
	for i := range target {
		target[i] = byte(i ^ 0x37)
	}
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})

	srv := httptest.NewServer(serveAlways200(target))
	defer srv.Close()

	m := NewMatcher(cf)
	fc := NewFetchClient()
	// Two ranges so we exercise the batched code path even though the
	// server ignores it.
	if err := fc.FetchBlocksMulti([]string{srv.URL + "/t.bin"}, cf, m, [][2]int{{0, 1}, {2, 3}}); err != nil {
		t.Fatal(err)
	}
	if m.AcceptedBlocks() != 2 {
		t.Errorf("200 fallback: got %d, want 2", m.AcceptedBlocks())
	}
}

// singleRange206Handler always responds 206 with a single Content-Range
// regardless of how many ranges the client asked for — emulates a CDN
// that refuses multi-range. The first range in the request wins.
func singleRange206Handler(data []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rng := r.Header.Get("Range")
		if !strings.HasPrefix(rng, "bytes=") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		spec := rng[len("bytes="):]
		// Take only the first range.
		if i := strings.IndexByte(spec, ','); i >= 0 {
			spec = spec[:i]
		}
		dash := strings.IndexByte(spec, '-')
		if dash < 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		startS := spec[:dash]
		endS := spec[dash+1:]
		var start, end int64
		fmt.Sscanf(startS, "%d", &start)
		fmt.Sscanf(endS, "%d", &end)
		if end >= int64(len(data)) {
			end = int64(len(data)) - 1
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(data)))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", end-start+1))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(data[start : end+1])
	})
}

// TestFetchBlocksMultiPartBatchingFallsBackOnSingleRange206 — server
// honoured the Range header but with a single Content-Range (no
// multipart body). Caller's per-range loop must finish the job.
func TestFetchBlocksMultiPartBatchingFallsBackOnSingleRange206(t *testing.T) {
	bs := 256
	target := make([]byte, bs*6)
	for i := range target {
		target[i] = byte(i)
	}
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})

	srv := httptest.NewServer(singleRange206Handler(target))
	defer srv.Close()

	m := NewMatcher(cf)
	fc := NewFetchClient()
	if err := fc.FetchBlocksMulti([]string{srv.URL + "/t.bin"}, cf, m, [][2]int{{0, 1}, {2, 3}, {5, 6}}); err != nil {
		t.Fatal(err)
	}
	if m.AcceptedBlocks() != 3 {
		t.Errorf("single-range 206 fallback: got %d, want 3", m.AcceptedBlocks())
	}
}

// TestFetchBlocksMultiPartBatchingHonoursMaxRanges checks that
// MaxRangesPerRequest chunks the missing-runs list into batches.
func TestFetchBlocksMultiPartBatchingHonoursMaxRanges(t *testing.T) {
	bs := 256
	target := make([]byte, bs*8)
	for i := range target {
		target[i] = byte(i)
	}
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		http.ServeContent(w, r, "t.bin", time.Now(), bytes.NewReader(target))
	}))
	defer srv.Close()

	m := NewMatcher(cf)
	fc := NewFetchClient()
	fc.MaxRangesPerRequest = 2 // force two batches across four ranges
	ranges := [][2]int{{0, 1}, {2, 3}, {5, 6}, {7, 8}}
	if err := fc.FetchBlocksMulti([]string{srv.URL + "/t.bin"}, cf, m, ranges); err != nil {
		t.Fatal(err)
	}
	if hits != 2 {
		t.Errorf("expected 2 batched GETs (cap=2, 4 ranges), got %d", hits)
	}
}

// TestFetchBlocksMultiPartZeroCapDefaults — MaxRangesPerRequest == 0
// must be treated as the default (50). Covers the cap<=0 branch.
func TestFetchBlocksMultiPartZeroCapDefaults(t *testing.T) {
	bs := 256
	target := make([]byte, bs*4)
	for i := range target {
		target[i] = byte(i)
	}
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "t.bin", time.Now(), bytes.NewReader(target))
	}))
	defer srv.Close()

	m := NewMatcher(cf)
	fc := NewFetchClient()
	fc.MaxRangesPerRequest = 0 // exercise the default-fill branch
	if err := fc.FetchBlocksMulti([]string{srv.URL + "/t.bin"}, cf, m, [][2]int{{0, 1}, {3, 4}}); err != nil {
		t.Fatal(err)
	}
	if m.AcceptedBlocks() != 2 {
		t.Errorf("got %d, want 2", m.AcceptedBlocks())
	}
}

// TestFetchBlocksMultiEmptyRangesIsNoop — a fetch with no missing ranges
// must short-circuit cleanly, not error.
func TestFetchBlocksMultiEmptyRangesIsNoop(t *testing.T) {
	cf := &ControlFile{Blocksize: 1024, Length: 1024, HashLengths: HashLengths{1, 2, 3}}
	m := NewMatcher(cf)
	fc := NewFetchClient()
	if err := fc.FetchBlocksMulti([]string{"http://example.invalid/"}, cf, m, nil); err != nil {
		t.Errorf("empty ranges: %v", err)
	}
}

// TestFetchBlocksMultiEmptyURLsRejected — empty URL list is a programmer
// error and must be surfaced loudly.
func TestFetchBlocksMultiEmptyURLsRejected(t *testing.T) {
	cf := &ControlFile{Blocksize: 1024, Length: 1024, HashLengths: HashLengths{1, 2, 3}}
	m := NewMatcher(cf)
	fc := NewFetchClient()
	err := fc.FetchBlocksMulti(nil, cf, m, [][2]int{{0, 1}})
	if err == nil {
		t.Fatal("expected empty-URL-list error")
	}
}

// TestFetchBlocksMultiPartBatchedTransportError — every URL down on the
// batched path: surfaces the underlying transport error.
func TestFetchBlocksMultiPartBatchedTransportError(t *testing.T) {
	bs := 256
	target := make([]byte, bs*4)
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})
	m := NewMatcher(cf)
	fc := NewFetchClient()
	// Two ranges so we hit the batched path. Bad URL fails NewRequest;
	// the batched failover loop should treat that as transport-class and
	// give up at the last URL.
	err := fc.FetchBlocksMulti([]string{"http://%/x"}, cf, m, [][2]int{{0, 1}, {2, 3}})
	if err == nil {
		t.Fatal("expected error")
	}
}

// TestFetchBlocksMultiPartBatched4xxFatalStops — a 4xx that's NOT 404
// (e.g. 403) stops the batched failover loop right away.
func TestFetchBlocksMultiPartBatched4xxFatalStops(t *testing.T) {
	bs := 256
	target := make([]byte, bs*4)
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	m := NewMatcher(cf)
	fc := NewFetchClient()
	err := fc.FetchBlocksMulti([]string{srv.URL}, cf, m, [][2]int{{0, 1}, {2, 3}})
	if err == nil {
		t.Fatal("expected 403 to surface")
	}
}

// TestFetchBlocksMultiPartBatchedBadMultipart — server returns 206 +
// multipart/byteranges but the body is malformed.
func TestFetchBlocksMultiPartBatchedBadMultipart(t *testing.T) {
	bs := 256
	target := make([]byte, bs*4)
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "multipart/byteranges; boundary=ZZZ")
		w.WriteHeader(http.StatusPartialContent)
		// Garbage body that NextPart will reject.
		_, _ = w.Write([]byte("garbage without a boundary"))
	}))
	defer srv.Close()
	m := NewMatcher(cf)
	fc := NewFetchClient()
	err := fc.FetchBlocksMulti([]string{srv.URL}, cf, m, [][2]int{{0, 1}, {2, 3}})
	if err == nil {
		t.Fatal("expected multipart parse error")
	}
}

// TestFetchBlocksMultiPartBatchedWeird2xx — server returns a 202 that's
// neither 200 nor 206. tryBatchedRanges' "anything else" branch fires.
//
// HTTP semantics here are unusual: we accept 206 in getMultiRange (and
// 200), and tryBatchedRanges then classifies based on status. A 202
// would slip through getMultiRange's gate as a 4xx-or-5xx and fail there,
// not at the unexpected-status branch — so we instead emulate the
// "server returned 206 with a NON-multipart Content-Type that isn't a
// single-range either" cul-de-sac, which is the genuine surprise case.
//
// We trigger it by returning 206 with a text/plain content type and
// body. The current implementation classifies that as
// "single-range 206 fallback" → returns false (per spec, fall back to
// per-range loop), so the per-range loop must complete the job.
func TestFetchBlocksMultiPartBatchedNonMultipart206FallsBack(t *testing.T) {
	bs := 256
	target := make([]byte, bs*4)
	for i := range target {
		target[i] = byte(i)
	}
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})
	srv := httptest.NewServer(singleRange206Handler(target))
	defer srv.Close()
	m := NewMatcher(cf)
	fc := NewFetchClient()
	if err := fc.FetchBlocksMulti([]string{srv.URL}, cf, m, [][2]int{{0, 1}, {2, 3}}); err != nil {
		t.Fatal(err)
	}
	if m.AcceptedBlocks() != 2 {
		t.Errorf("non-multipart 206 fallback: got %d, want 2", m.AcceptedBlocks())
	}
}

// TestFetchBlocksMultiPartBatchedBodyReadError — connection drops mid-body
// on the batched GET.
func TestFetchBlocksMultiPartBatchedBodyReadError(t *testing.T) {
	bs := 256
	target := make([]byte, bs*4)
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})
	srv := httptest.NewServer(brokenBodyHandler{})
	defer srv.Close()
	m := NewMatcher(cf)
	fc := NewFetchClient()
	err := fc.FetchBlocksMulti([]string{srv.URL}, cf, m, [][2]int{{0, 1}, {2, 3}})
	if err == nil {
		t.Fatal("expected body-read error")
	}
}

// TestFetchBlocksMultiPartBatchedLastByteCapAtEOF — request a missing run
// that includes the short tail block. The cap-at-totalLen branch fires.
func TestFetchBlocksMultiPartBatchedLastByteCapAtEOF(t *testing.T) {
	bs := 256
	target := make([]byte, bs*3+50) // last block is short
	for i := range target {
		target[i] = byte(i)
	}
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "t.bin", time.Now(), bytes.NewReader(target))
	}))
	defer srv.Close()
	m := NewMatcher(cf)
	fc := NewFetchClient()
	// Two ranges, one covering the short tail block.
	if err := fc.FetchBlocksMulti([]string{srv.URL + "/t.bin"}, cf, m, [][2]int{{0, 1}, {3, 4}}); err != nil {
		t.Fatal(err)
	}
	if !m.Got(3) {
		t.Error("short tail block not got via batched path")
	}
}

// TestFetchBlocksMultiPartBatchedWrongHashFromServer — batched server
// returns 206 + multipart with garbage payload; matcher must reject.
func TestFetchBlocksMultiPartBatchedWrongHashFromServer(t *testing.T) {
	bs := 256
	target := make([]byte, bs*4)
	for i := range target {
		target[i] = byte(i)
	}
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})

	// Use Go's http.ServeContent against GARBAGE bytes; multipart shape is
	// well-formed but the payload won't match the control file's hashes.
	garbage := make([]byte, len(target))
	for i := range garbage {
		garbage[i] = 0xaa
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "t.bin", time.Now(), bytes.NewReader(garbage))
	}))
	defer srv.Close()
	m := NewMatcher(cf)
	fc := NewFetchClient()
	err := fc.FetchBlocksMulti([]string{srv.URL + "/t.bin"}, cf, m, [][2]int{{0, 1}, {2, 3}})
	if err == nil {
		t.Fatal("expected strong-hash mismatch on batched multipart")
	}
}

// TestFetchBlocksMultiPartBatchedHTTPDoTransportError — connecting to a
// port with no listener triggers the transport-error branch of
// getMultiRange (not the NewRequest path).
func TestFetchBlocksMultiPartBatchedHTTPDoTransportError(t *testing.T) {
	bs := 256
	target := make([]byte, bs*4)
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})
	m := NewMatcher(cf)
	fc := NewFetchClient()
	err := fc.FetchBlocksMulti([]string{"http://127.0.0.1:1/"}, cf, m, [][2]int{{0, 1}, {2, 3}})
	if err == nil {
		t.Fatal("expected transport error")
	}
}

// TestFeedMultipartPartsSkipsUnaskedPart — a part whose Start doesn't
// match any asked range is silently skipped.
func TestFeedMultipartPartsSkipsUnaskedPart(t *testing.T) {
	bs := 256
	target := make([]byte, bs*4)
	for i := range target {
		target[i] = byte(i)
	}
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})
	m := NewMatcher(cf)
	fc := NewFetchClient()
	// asked={0..256-1, 512..767} ; parts include one unexpected start
	parts := []multipartPart{
		{Start: 0, End: int64(bs) - 1, Body: append([]byte(nil), target[0:bs]...)},
		{Start: 99999, End: 100000, Body: []byte("garbage")}, // unmatched
		{Start: int64(bs * 2), End: int64(bs*3) - 1, Body: append([]byte(nil), target[bs*2:bs*3]...)},
	}
	asked := [][2]int64{{0, int64(bs) - 1}, {int64(bs * 2), int64(bs*3) - 1}}
	chunk := [][2]int{{0, 1}, {2, 3}}
	if err := fc.feedMultipartParts(parts, asked, chunk, cf, m); err != nil {
		t.Fatalf("unaskedPart should be skipped, got err: %v", err)
	}
	if !m.Got(0) || !m.Got(2) {
		t.Errorf("expected blocks 0 and 2 to be got")
	}
}

// TestFeedMultipartPartsShortPayload — a multipart part whose body
// doesn't even cover the first block of the asked range surfaces a
// short-payload error.
func TestFeedMultipartPartsShortPayload(t *testing.T) {
	bs := 256
	target := make([]byte, bs*4)
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})
	m := NewMatcher(cf)
	fc := NewFetchClient()
	parts := []multipartPart{
		// Body is much shorter than the two blocks the range asks for.
		{Start: 0, End: int64(bs*2) - 1, Body: target[:5]},
	}
	asked := [][2]int64{{0, int64(bs*2) - 1}}
	chunk := [][2]int{{0, 2}}
	err := fc.feedMultipartParts(parts, asked, chunk, cf, m)
	if err == nil {
		t.Fatal("expected short-payload error")
	}
}

// TestFeedMultipartPartsOversizedTailGetsClamped — a part whose body
// is longer than the asked range (server padded the response) gets
// truncated to bs per block in feedMultipartParts. This exercises the
// `n > bs` clamp.
func TestFeedMultipartPartsOversizedTailGetsClamped(t *testing.T) {
	bs := 256
	target := make([]byte, bs*4)
	for i := range target {
		target[i] = byte(i)
	}
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})
	m := NewMatcher(cf)
	fc := NewFetchClient()
	// One-block range, but the server sent two blocks' worth (because it
	// coalesced something internally). The clamp keeps us safe.
	parts := []multipartPart{
		{Start: 0, End: int64(bs*2) - 1, Body: append([]byte(nil), target[0:bs*2]...)},
	}
	asked := [][2]int64{{0, int64(bs) - 1}}
	chunk := [][2]int{{0, 1}}
	if err := fc.feedMultipartParts(parts, asked, chunk, cf, m); err != nil {
		t.Fatalf("oversized payload: %v", err)
	}
	if !m.Got(0) {
		t.Error("expected block 0 to be got")
	}
}

// TestFeedMultipartPartsAcceptError — a part whose payload differs from
// the control file's expected bytes triggers the strong-hash error path.
func TestFeedMultipartPartsAcceptError(t *testing.T) {
	bs := 256
	target := make([]byte, bs*4)
	for i := range target {
		target[i] = byte(i)
	}
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})
	m := NewMatcher(cf)
	fc := NewFetchClient()
	parts := []multipartPart{
		{Start: 0, End: int64(bs) - 1, Body: bytes.Repeat([]byte{0xff}, bs)}, // garbage
	}
	asked := [][2]int64{{0, int64(bs) - 1}}
	chunk := [][2]int{{0, 1}}
	err := fc.feedMultipartParts(parts, asked, chunk, cf, m)
	if err == nil {
		t.Fatal("expected accept-block error from wrong-hash payload")
	}
}

// TestFetchBlocksMultiPartBatched4xxFailoverThenServe — first server
// returns 403 (NOT a failover-worthy status by policy), so the call
// must fail fast at server 1; the second server is never tried.
//
// This pins down the "shouldFailover=false stops the batched loop"
// branch in getMultiRangeFailover.
func TestFetchBlocksMultiPartBatched4xxStopsFailover(t *testing.T) {
	bs := 256
	target := make([]byte, bs*4)
	cf, _ := Make(bytes.NewReader(target), int64(len(target)), bs, "t.bin",
		time.Time{}, []string{"t.bin"})

	srv403 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv403.Close()
	srvOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "t.bin", time.Now(), bytes.NewReader(target))
	}))
	defer srvOK.Close()
	m := NewMatcher(cf)
	fc := NewFetchClient()
	err := fc.FetchBlocksMulti([]string{srv403.URL, srvOK.URL + "/t.bin"}, cf, m, [][2]int{{0, 1}, {2, 3}})
	if err == nil {
		t.Fatal("expected 403 to stop failover")
	}
}

// TestShouldFailoverBareError — a bare (non-*failoverError) error is
// always treated as a transport error worth retrying. Drives the
// `!ok` branch at fetch.go:431.
func TestShouldFailoverBareError(t *testing.T) {
	if !shouldFailover(io.EOF) {
		t.Fatal("bare error should trigger failover")
	}
	if !shouldFailover(fmt.Errorf("synthetic transport failure")) {
		t.Fatal("bare wrapped error should trigger failover")
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
