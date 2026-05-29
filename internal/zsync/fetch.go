package zsync

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // wire format
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// FetchClient knows how to ask an HTTP server for byte ranges of the target
// file. It uses standard net/http and supports multipart/byteranges responses.
type FetchClient struct {
	HTTP *http.Client
	// MaxRangesPerRequest caps how many ranges are batched into a single
	// Range: header. RFC 7233 doesn't put a strict limit but many servers
	// reject very long Range headers; 50 is a common conservative cap.
	MaxRangesPerRequest int
	// UserAgent overrides the default Go HTTP UA.
	UserAgent string
}

// NewFetchClient returns a FetchClient with sensible defaults.
func NewFetchClient() *FetchClient {
	return &FetchClient{
		HTTP:                http.DefaultClient,
		MaxRangesPerRequest: 50,
		UserAgent:           "gozsync/0.1 (+https://github.com/go-deltasync/zsync2)",
	}
}

// ResolveTargetURL returns every `URL:` listed in the control file resolved
// against the .zsync's own URL (the base used for relative references — this
// mirrors the C reference's behaviour). The returned slice preserves order:
// callers should try entries in the order given and only fall back to the
// next on a network error or a 5xx/404 response.
//
// When the control file carries a Z-Map2 / Z-URL: header for the
// gzip-compressed-target path, callers should use ResolveCompressedURLs
// instead — this function deliberately returns only the uncompressed URLs.
func ResolveTargetURL(cf *ControlFile, zsyncURL string) ([]string, error) {
	return resolveURLs(cf.URLs, zsyncURL, "URL")
}

// ResolveCompressedURLs is the Z-Map2 counterpart of ResolveTargetURL: it
// returns the `Z-URL:` entries (URLs of the gzip-compressed target) resolved
// against the .zsync's own URL. The caller wires these into
// FetchClient.FetchCompressedBlocks together with the parsed Z-Map.
func ResolveCompressedURLs(cf *ControlFile, zsyncURL string) ([]string, error) {
	return resolveURLs(cf.ZURLs, zsyncURL, "Z-URL")
}

func resolveURLs(refs []string, base string, label string) ([]string, error) {
	if len(refs) == 0 {
		return nil, fmt.Errorf("zsync: no %s in .zsync", label)
	}
	b, err := url.Parse(base)
	if err != nil {
		return nil, fmt.Errorf("zsync: bad zsync URL %q: %w", base, err)
	}
	out := make([]string, 0, len(refs))
	for _, raw := range refs {
		ref, err := url.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("zsync: bad %s in .zsync %q: %w", label, raw, err)
		}
		out = append(out, b.ResolveReference(ref).String())
	}
	return out, nil
}

// FetchBlocks is the single-URL convenience wrapper around FetchBlocksMulti.
// It exists so callers that don't care about failover (every existing test
// and the historical exported API) don't have to wrap their URL in a slice.
// The retry semantics from FetchBlocksMulti still apply for the single URL.
func (fc *FetchClient) FetchBlocks(targetURL string, cf *ControlFile, m *Matcher, ranges [][2]int) error {
	return fc.FetchBlocksMulti([]string{targetURL}, cf, m, ranges)
}

// FetchBlocksMulti downloads the listed missing block ranges (each
// [start, end) in block indices) from the first URL that accepts the Range
// request, feeding the bytes into the matcher.
//
// The implementation first attempts a single batched GET listing every
// missing run in one `Range: bytes=a-b,c-d,…` header (RFC 7233 §3.1). A
// well-behaved origin replies 206 Partial Content with a
// `multipart/byteranges` body that we demultiplex and feed to the matcher.
// Two graceful fallbacks cover non-compliant servers:
//
//   - 206 with a single `Content-Range` (server refused multi-range, common
//     on some CDNs): we drop to the per-range loop and reissue one GET per
//     missing run.
//   - 200 OK (server ignored Range entirely, e.g. Python's http.server):
//     we slice the whole-file body for every missing run.
//
// Failover policy across the urls slice:
//
//   - On a network/transport error (DNS, TCP, TLS, timeout) we advance to
//     the next URL.
//   - On a 5xx or 404 response we advance to the next URL.
//   - On any other 4xx we fail fast: that's a request-side problem (bad
//     URL, auth, etc.) which retrying against the same network can only
//     reproduce.
//   - The last URL's error is returned verbatim so the caller gets a real
//     diagnostic.
//   - Once a URL accepts a Range request we "stick" to it for the remaining
//     ranges: we don't re-run the failover loop per range.
//
// An empty urls slice is a programmer error and returns a clear message.
func (fc *FetchClient) FetchBlocksMulti(urls []string, cf *ControlFile, m *Matcher, ranges [][2]int) error {
	if len(urls) == 0 {
		return fmt.Errorf("zsync: FetchBlocks: empty URL list")
	}
	if len(ranges) == 0 {
		return nil
	}
	// Try the batched path first when we have more than one missing run.
	// A single range is naturally handled by the per-range loop and there's
	// no win in dressing it up as a multi-range request.
	if len(ranges) > 1 {
		batched, err := fc.tryBatchedRanges(urls, cf, m, ranges)
		if err != nil {
			return err
		}
		if batched {
			return nil
		}
		// Fell through: server didn't honour multi-range. Drop to the
		// per-range loop, which knows how to deal with 200-fallback and
		// single-Content-Range 206.
	}
	bs := int64(cf.Blocksize)
	totalLen := cf.Length

	// stickyURL: once any URL has accepted a Range request we keep using
	// it for subsequent ranges. The empty string means "not chosen yet".
	stickyURL := ""

	for _, rg := range ranges {
		startBlk, endBlk := rg[0], rg[1] // [start, end)
		startByte := int64(startBlk) * bs
		// last byte is inclusive in HTTP Range
		lastByte := int64(endBlk)*bs - 1
		// Cap at end of file: we still want a full-blocksize payload per
		// block (zero-padded) so the strong-hash check works, so we pad below.
		serverLast := lastByte
		if serverLast >= totalLen {
			serverLast = totalLen - 1
		}

		// Choose the list of URLs to try for this range: just the sticky
		// one if we've already settled on it, otherwise the full failover
		// list.
		try := urls
		if stickyURL != "" {
			try = []string{stickyURL}
		}

		body, status, chosen, err := fc.getRangeFailover(try, startByte, serverLast)
		if err != nil {
			return err
		}
		stickyURL = chosen

		// If the server ignored Range (returned 200 OK with the whole file)
		// the body offset for block i is `i*bs`. If it honoured the range
		// (206) the body offset is `(i - startBlk) * bs`. Detect from the
		// declared/observed body length.
		bodyIsFullFile := status == http.StatusOK && int64(len(body)) == totalLen

		buf := make([]byte, bs)
		for i := startBlk; i < endBlk; i++ {
			var off int64
			if bodyIsFullFile {
				off = int64(i) * bs
			} else {
				off = int64(i-startBlk) * bs
			}
			n := int64(len(body)) - off
			if n <= 0 {
				return fmt.Errorf("zsync: short HTTP response for block %d (body=%d, off=%d, status=%d)",
					i, len(body), off, status)
			}
			if n > bs {
				n = bs
			}
			for j := range buf {
				buf[j] = 0
			}
			copy(buf, body[off:off+n])
			if err := m.AcceptDownloadedBlock(i, buf); err != nil {
				return fmt.Errorf("zsync: block %d: %w", i, err)
			}
		}
	}
	return nil
}

// tryBatchedRanges issues ONE HTTP GET listing every missing run in the
// `Range:` header as `bytes=a-b,c-d,…`. It returns (true, nil) when the
// server honoured the multi-range request and the matcher has been fed
// every requested run; (false, nil) when the server didn't honour
// multi-range (a 200 OK or a single-range 206) so the caller should drop
// to the per-range loop; (_, err) on any unrecoverable failure.
//
// The first URL whose response can be classified ((batched OK) | (fall
// back to per-range)) wins; failover only triggers on transport / 5xx /
// 404 errors (same policy as the single-range path).
//
// The MaxRangesPerRequest cap from FetchClient bounds how many ranges land
// in one Range: header. If the caller's missing-runs list exceeds the cap
// we chunk it (still cheaper than one-GET-per-run, but bounded so an
// adversarial server can't blow up on a 10k-range header).
func (fc *FetchClient) tryBatchedRanges(urls []string, cf *ControlFile, m *Matcher, ranges [][2]int) (bool, error) {
	bs := int64(cf.Blocksize)
	totalLen := cf.Length
	cap := fc.MaxRangesPerRequest
	if cap <= 0 {
		cap = 50
	}

	stickyURL := ""

	for start := 0; start < len(ranges); start += cap {
		end := start + cap
		if end > len(ranges) {
			end = len(ranges)
		}
		chunk := ranges[start:end]

		// Build the Range header. Each missing-block run [bs, be) becomes
		// a byte range [startByte, lastByte] (HTTP byte ranges are
		// inclusive on both ends).
		var rangeHdr strings.Builder
		rangeHdr.WriteString("bytes=")
		byteRanges := make([][2]int64, 0, len(chunk))
		for i, rg := range chunk {
			startByte := int64(rg[0]) * bs
			lastByte := int64(rg[1])*bs - 1
			if lastByte >= totalLen {
				lastByte = totalLen - 1
			}
			if i > 0 {
				rangeHdr.WriteByte(',')
			}
			fmt.Fprintf(&rangeHdr, "%d-%d", startByte, lastByte)
			byteRanges = append(byteRanges, [2]int64{startByte, lastByte})
		}

		try := urls
		if stickyURL != "" {
			try = []string{stickyURL}
		}
		body, status, contentType, chosen, err := fc.getMultiRangeFailover(try, rangeHdr.String())
		if err != nil {
			return false, err
		}
		stickyURL = chosen

		// Server ignored Range entirely: caller falls back to per-range
		// path. Caller's stickyURL machinery will re-discover this URL.
		if status == http.StatusOK && int64(len(body)) == totalLen {
			return false, nil
		}
		// Server honoured multi-range with a multipart/byteranges body.
		if status == http.StatusPartialContent && strings.HasPrefix(contentType, "multipart/byteranges") {
			parts, err := parseMultipartByteRanges(contentType, bytes.NewReader(body))
			if err != nil {
				return false, fmt.Errorf("zsync: parse multipart/byteranges: %w", err)
			}
			if err := fc.feedMultipartParts(parts, byteRanges, chunk, cf, m); err != nil {
				return false, err
			}
			continue
		}
		// Server honoured Range but with a single-range 206 (no
		// multipart body). Tell the caller to fall back to the
		// per-range loop, which knows how to slice this out.
		//
		// getMultiRange already rejected every status other than 200 and
		// 206 via failoverError, so this is the only remaining shape.
		return false, nil
	}
	return true, nil
}

// getMultiRangeFailover issues a Range: <hdr> GET against each URL in
// `urls` in order. Mirrors getRangeFailover but returns the Content-Type
// too (we need it to demux multipart/byteranges).
func (fc *FetchClient) getMultiRangeFailover(urls []string, rangeHdr string) (body []byte, status int, contentType, chosen string, err error) {
	var lastErr error
	for _, u := range urls {
		body, status, contentType, err = fc.getMultiRange(u, rangeHdr)
		if err == nil {
			return body, status, contentType, u, nil
		}
		lastErr = err
		if !shouldFailover(err) {
			return nil, 0, "", "", err
		}
	}
	return nil, 0, "", "", lastErr
}

// getMultiRange does the actual Range GET with a multi-range header.
func (fc *FetchClient) getMultiRange(targetURL, rangeHdr string) ([]byte, int, string, error) {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, 0, "", &failoverError{status: 0, err: err}
	}
	req.Header.Set("Range", rangeHdr)
	if fc.UserAgent != "" {
		req.Header.Set("User-Agent", fc.UserAgent)
	}
	resp, err := fc.HTTP.Do(req)
	if err != nil {
		return nil, 0, "", &failoverError{status: 0, err: fmt.Errorf("zsync: GET %s: %w", targetURL, err)}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, "", &failoverError{
			status: resp.StatusCode,
			err:    fmt.Errorf("zsync: unexpected status %s for multi-range from %s", resp.Status, targetURL),
		}
	}
	ct := resp.Header.Get("Content-Type")
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, ct, &failoverError{status: 0, err: fmt.Errorf("zsync: read body from %s: %w", targetURL, err)}
	}
	return b, resp.StatusCode, ct, nil
}

// feedMultipartParts walks the demultiplexed multipart parts and pushes
// each one through the matcher. We trust the Content-Range on each part
// for the inflated byte offset and decode the block index from that.
//
// Servers MAY reorder ranges; we re-associate each part with the original
// chunk entry by its start-byte rather than relying on iteration order.
// Some servers also coalesce adjacent ranges: a part whose Start doesn't
// appear in our request map is skipped (the missed blocks then surface as
// errors at the matcher's strong-hash check, which is the right place to
// report the protocol violation).
func (fc *FetchClient) feedMultipartParts(parts []multipartPart, asked [][2]int64, chunk [][2]int, cf *ControlFile, m *Matcher) error {
	bs := int64(cf.Blocksize)
	type want struct {
		startBlk, endBlk int
	}
	wantByStart := make(map[int64]want, len(chunk))
	for i, rg := range chunk {
		wantByStart[asked[i][0]] = want{startBlk: rg[0], endBlk: rg[1]}
	}
	buf := make([]byte, bs)
	for _, p := range parts {
		w, ok := wantByStart[p.Start]
		if !ok {
			continue
		}
		// Walk the blocks covered by this part. The server may have
		// returned a shorter body than we asked for (tail of file
		// capped at Content-Length-1); zero-pad the trailing short
		// block to a full blocksize so the strong-hash check works.
		for i := w.startBlk; i < w.endBlk; i++ {
			off := int64(i-w.startBlk) * bs
			n := int64(len(p.Body)) - off
			if n <= 0 {
				return fmt.Errorf("zsync: short multipart payload for block %d (body=%d off=%d)", i, len(p.Body), off)
			}
			if n > bs {
				n = bs
			}
			for j := range buf {
				buf[j] = 0
			}
			copy(buf, p.Body[off:off+n])
			if err := m.AcceptDownloadedBlock(i, buf); err != nil {
				return fmt.Errorf("zsync: block %d: %w", i, err)
			}
		}
	}
	return nil
}

// getRangeFailover issues an HTTP Range GET for [start, last] against each
// URL in `urls` in order, returning the first non-error 2xx response. The
// failover policy is documented on FetchBlocksMulti.
//
// On success it returns (body, status, urlThatAnswered, nil). On the last
// URL failing it surfaces the underlying error.
func (fc *FetchClient) getRangeFailover(urls []string, start, last int64) ([]byte, int, string, error) {
	var lastErr error
	for i, u := range urls {
		body, status, err := fc.getRange(u, start, last)
		if err == nil {
			return body, status, u, nil
		}
		lastErr = err
		// Retry on transient errors only: network/transport errors, 5xx,
		// and 404. Anything else (other 4xx) is fatal and stops the
		// failover loop at this URL.
		if !shouldFailover(err) {
			return nil, 0, "", err
		}
		// If we just exhausted the URL list, return the underlying error.
		_ = i
	}
	return nil, 0, "", lastErr
}

// failoverError is what getRange returns for a "try the next URL" error.
// It wraps the underlying error and carries the HTTP status code (or 0 for
// a transport error). shouldFailover unwraps it.
type failoverError struct {
	status int
	err    error
}

func (e *failoverError) Error() string { return e.err.Error() }
func (e *failoverError) Unwrap() error { return e.err }

// shouldFailover returns true if `err` is a "try the next URL" error per
// FetchBlocksMulti's failover policy.
func shouldFailover(err error) bool {
	fe, ok := err.(*failoverError)
	if !ok {
		// Transport error from http.Client.Do is bare (no failoverError
		// wrapper); we always retry those.
		return true
	}
	if fe.status == 0 {
		// Wrapped transport error.
		return true
	}
	if fe.status >= 500 || fe.status == http.StatusNotFound {
		return true
	}
	return false
}

// getRange does the actual Range GET. It returns (body, status, nil) on a
// 200 or 206; otherwise it returns an error wrapped in *failoverError with
// the status code so the caller's failover loop can decide whether to retry.
func (fc *FetchClient) getRange(targetURL string, start, last int64) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, targetURL, nil)
	if err != nil {
		// A malformed URL is a programmer/config error and cannot be
		// fixed by trying the next URL on the same conceptual list, BUT
		// the caller's failover loop may still have other URLs to try
		// that are well-formed. We treat it as transport-class (status==0)
		// so the failover loop moves on.
		return nil, 0, &failoverError{status: 0, err: err}
	}
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", start, last))
	if fc.UserAgent != "" {
		req.Header.Set("User-Agent", fc.UserAgent)
	}
	resp, err := fc.HTTP.Do(req)
	if err != nil {
		return nil, 0, &failoverError{status: 0, err: fmt.Errorf("zsync: GET %s: %w", targetURL, err)}
	}
	if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, resp.StatusCode, &failoverError{
			status: resp.StatusCode,
			err: fmt.Errorf("zsync: unexpected status %s for range %d-%d from %s",
				resp.Status, start, last, targetURL),
		}
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		// A read error mid-body could plausibly be the server's fault and
		// retrying might succeed; classify as transport.
		return nil, resp.StatusCode, &failoverError{
			status: 0,
			err:    fmt.Errorf("zsync: read body from %s: %w", targetURL, err),
		}
	}
	return body, resp.StatusCode, nil
}

// VerifySHA1 checks the reconstructed buffer against the SHA-1 from the
// control file, if one was provided. Returns nil if no checksum was set.
func VerifySHA1(cf *ControlFile, data []byte) error {
	if cf.SHA1Hex == "" {
		return nil
	}
	h := sha1.New() //nolint:gosec // wire format
	h.Write(data)
	got := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(got, cf.SHA1Hex) {
		return fmt.Errorf("zsync: SHA-1 mismatch: got %s, want %s", got, cf.SHA1Hex)
	}
	return nil
}

// VerifyFileHash checks the reconstructed buffer against the file-wide
// strong digest carried by the control file. For zsync2 files this is the
// FileHash field decoded from the `File-Hash: <algo>:<hex>` header; for
// classic zsync files it's the SHA-1 stored in SHA1Hex.
//
// Returns nil when the control file carries no file-wide digest at all
// (matching VerifySHA1's "no-op if empty" contract).
func VerifyFileHash(cf *ControlFile, data []byte) error {
	if len(cf.FileHash) == 0 {
		// No File-Hash header: fall back to the legacy SHA-1 path.
		return VerifySHA1(cf, data)
	}
	algo := cf.HashAlgorithm
	if algo == "" {
		algo = HashAlgoMD4
	}
	got := strongHash(algo, data)
	if !bytes.Equal(got, cf.FileHash) {
		return fmt.Errorf("zsync: %s file-hash mismatch: got %s, want %s",
			strongHashLabel(algo), hex.EncodeToString(got), hex.EncodeToString(cf.FileHash))
	}
	return nil
}

// parseMultipartByteRanges is a helper for a future batched-fetch path. It
// parses a multipart/byteranges response into a list of (Content-Range,
// payload) pairs. Unused by the MVP fetcher above; kept here so the unit
// tests can exercise it.
func parseMultipartByteRanges(contentType string, body io.Reader) (parts []multipartPart, err error) {
	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, err
	}
	boundary, ok := params["boundary"]
	if !ok {
		return nil, fmt.Errorf("zsync: multipart response missing boundary")
	}
	mr := multipart.NewReader(body, boundary)
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		buf, err := io.ReadAll(p)
		if err != nil {
			return nil, err
		}
		cr := p.Header.Get("Content-Range")
		start, end, err := parseContentRange(cr)
		if err != nil {
			return nil, err
		}
		parts = append(parts, multipartPart{Start: start, End: end, Body: buf})
	}
	return parts, nil
}

type multipartPart struct {
	Start, End int64
	Body       []byte
}

func parseContentRange(cr string) (start, end int64, err error) {
	// "bytes 0-499/1234"
	cr = strings.TrimSpace(cr)
	if !strings.HasPrefix(cr, "bytes ") {
		return 0, 0, fmt.Errorf("zsync: bad Content-Range %q", cr)
	}
	rest := cr[len("bytes "):]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return 0, 0, fmt.Errorf("zsync: bad Content-Range %q", cr)
	}
	rng := rest[:slash]
	dash := strings.IndexByte(rng, '-')
	if dash < 0 {
		return 0, 0, fmt.Errorf("zsync: bad Content-Range %q", cr)
	}
	start, err = strconv.ParseInt(rng[:dash], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	end, err = strconv.ParseInt(rng[dash+1:], 10, 64)
	if err != nil {
		return 0, 0, err
	}
	return start, end, nil
}

