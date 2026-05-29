// gozsync is a pure-Go zsync client. Given a URL to a .zsync control file
// and a local seed file (an older version of the target), it reconstructs
// the target by reusing as many blocks from the seed as possible and
// fetching only the changed blocks over HTTP Range requests.
//
// This is the cross-platform counterpart of Colin Phipps' `zsync` (C) and
// of the AppImageCommunity/zsync2 (C++). MVP scope: no compressed targets
// (no Z-Map2), no multi-URL failover, no resumable on-disk staging.
package main

import (
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-deltasync/zsync2/internal/zsync"
)

func main() {
	var (
		seedPath = flag.String("i", "", "local seed file (older version of the target) — optional")
		outPath  = flag.String("o", "", "output path (default: Filename: from .zsync, then basename of URL)")
		quiet    = flag.Bool("q", false, "quiet: suppress progress output")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: gozsync [-i seed] [-o out] [-q] <zsync-url-or-file>\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	loc := flag.Arg(0)

	cf, baseURL, err := loadControlFile(loc)
	if err != nil {
		die("%v", err)
	}

	if !*quiet {
		fmt.Fprintf(os.Stderr, "zsync: target %q, %d blocks of %d bytes (%d bytes total)\n",
			cf.Filename, cf.NumBlocks(), cf.Blocksize, cf.Length)
	}

	m := zsync.NewMatcher(cf)

	if *seedPath != "" {
		sf, err := os.Open(*seedPath)
		if err != nil {
			die("open seed %s: %v", *seedPath, err)
		}
		t0 := time.Now()
		err = m.FeedSeed(sf)
		_ = sf.Close()
		if err != nil {
			die("feed seed: %v", err)
		}
		if !*quiet {
			fmt.Fprintf(os.Stderr, "seed scan: matched %d/%d blocks in %s\n",
				m.AcceptedBlocks(), m.TotalBlocks(), time.Since(t0).Round(time.Millisecond))
		}
	}

	missing := m.MissingRanges()
	if !*quiet {
		var missingBlocks int
		for _, r := range missing {
			missingBlocks += r[1] - r[0]
		}
		fmt.Fprintf(os.Stderr, "need to fetch %d blocks (%d bytes) in %d ranges\n",
			missingBlocks, missingBlocks*cf.Blocksize, len(missing))
	}

	if len(missing) > 0 {
		targetURL, err := zsync.ResolveTargetURL(cf, baseURL)
		if err != nil {
			die("%v", err)
		}
		if !*quiet {
			fmt.Fprintf(os.Stderr, "fetching from %s\n", targetURL)
		}
		fc := zsync.NewFetchClient()
		if err := fc.FetchBlocks(targetURL, cf, m, missing); err != nil {
			die("%v", err)
		}
	}

	if err := zsync.VerifySHA1(cf, m.Out()); err != nil {
		die("%v", err)
	}

	out := *outPath
	if out == "" {
		out = cf.Filename
		if out == "" {
			out = strings.TrimSuffix(filepath.Base(baseURL), ".zsync")
		}
		if out == "" || out == "." || out == "/" {
			die("could not derive output filename; pass -o")
		}
	}
	if err := os.WriteFile(out, m.Out(), 0o644); err != nil {
		die("write %s: %v", out, err)
	}
	if !*quiet {
		fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", out, cf.Length)
	}
}

func loadControlFile(loc string) (*zsync.ControlFile, string, error) {
	// If it parses as an absolute http(s) URL, fetch over HTTP. Otherwise
	// treat as a local path.
	if u, err := url.Parse(loc); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		req, err := http.NewRequest(http.MethodGet, loc, nil)
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("User-Agent", "gozsync/0.1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, "", fmt.Errorf("GET %s: %w", loc, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, "", fmt.Errorf("GET %s: %s", loc, resp.Status)
		}
		cf, err := zsync.Read(resp.Body)
		if err != nil {
			return nil, "", err
		}
		// Pin the final URL after redirects so relative URLs in the .zsync
		// resolve against where we actually got it from.
		final := resp.Request.URL.String()
		return cf, final, nil
	}
	f, err := os.Open(loc)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	cf, err := zsync.Read(f)
	if err != nil {
		return nil, "", err
	}
	// Synthesise a file:// base for relative URL resolution.
	abs, err := filepath.Abs(loc)
	if err != nil {
		return nil, "", err
	}
	return cf, "file://" + abs, nil
}

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "gozsync: "+f+"\n", a...)
	os.Exit(1)
}

