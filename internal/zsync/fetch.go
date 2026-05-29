package zsync

import (
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

// ResolveTargetURL picks an absolute URL for the target file given the URLs
// listed in the .zsync and the .zsync's own URL (used as the base for relative
// references — matching the C client's behaviour).
func ResolveTargetURL(cf *ControlFile, zsyncURL string) (string, error) {
	if len(cf.URLs) == 0 {
		return "", fmt.Errorf("zsync: no URL in .zsync (Z-URL/zmap not supported in this build)")
	}
	base, err := url.Parse(zsyncURL)
	if err != nil {
		return "", fmt.Errorf("zsync: bad zsync URL %q: %w", zsyncURL, err)
	}
	ref, err := url.Parse(cf.URLs[0])
	if err != nil {
		return "", fmt.Errorf("zsync: bad URL in .zsync %q: %w", cf.URLs[0], err)
	}
	return base.ResolveReference(ref).String(), nil
}

// FetchBlocks downloads the listed missing block ranges (each [start, end)
// in block indices) and feeds them into the matcher.
//
// Each range becomes one HTTP GET with a Range: header. If the server
// honours the range it replies 206 Partial Content with just the requested
// bytes; if it doesn't (Python's http.server is a notable example) it
// replies 200 OK with the whole file and we slice out what we want. Both
// paths are exercised by the smoke test.
func (fc *FetchClient) FetchBlocks(targetURL string, cf *ControlFile, m *Matcher, ranges [][2]int) error {
	bs := int64(cf.Blocksize)
	totalLen := cf.Length
	for _, rg := range ranges {
		startBlk, endBlk := rg[0], rg[1] // [start, end)
		startByte := int64(startBlk) * bs
		// last byte is inclusive in HTTP Range
		lastByte := int64(endBlk)*bs - 1
		// Cap at end of file: we still want a full-blocksize payload per
		// block (zero-padded) so the MD4 check works, so we pad below.
		serverLast := lastByte
		if serverLast >= totalLen {
			serverLast = totalLen - 1
		}
		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", startByte, serverLast))
		if fc.UserAgent != "" {
			req.Header.Set("User-Agent", fc.UserAgent)
		}
		resp, err := fc.HTTP.Do(req)
		if err != nil {
			return fmt.Errorf("zsync: GET %s: %w", targetURL, err)
		}
		if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("zsync: unexpected status %s for range %d-%d",
				resp.Status, startByte, serverLast)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("zsync: read body: %w", err)
		}

		// If the server ignored Range (returned 200 OK with the whole file)
		// the body offset for block i is `i*bs`. If it honoured the range
		// (206) the body offset is `(i - startBlk) * bs`. Detect from the
		// declared/observed body length.
		bodyIsFullFile := resp.StatusCode == http.StatusOK && int64(len(body)) == totalLen

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
				return fmt.Errorf("zsync: short HTTP response for block %d (body=%d, off=%d, status=%s)",
					i, len(body), off, resp.Status)
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

