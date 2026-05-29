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
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-deltasync/zsync2/internal/zsync"
	"github.com/spf13/cobra"
)

func main() {
	var (
		seedPath string
		outPath  string
		quiet    bool
	)
	cmd := &cobra.Command{
		Use:   "gozsync [flags] <zsync-url-or-file>",
		Short: "Reconstruct a file from a .zsync control file + an optional seed",
		Long: `gozsync reads a .zsync control file (locally or over HTTP), reuses any
blocks it can find in the given seed file, fetches the rest via HTTP
Range requests against the URL embedded in the .zsync, and writes the
reconstructed file. The on-the-wire format is byte-compatible with the
original zsync (Colin Phipps) and AppImageCommunity/zsync2.`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, args []string) error {
			return run(args[0], seedPath, outPath, quiet)
		},
	}
	cmd.Flags().StringVarP(&seedPath, "input", "i", "", "local seed file (older version of the target) — optional")
	cmd.Flags().StringVarP(&outPath, "output", "o", "", "output path (default: Filename: from .zsync, then basename of URL)")
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "suppress progress output")

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "gozsync: %v\n", err)
		os.Exit(1)
	}
}

func run(loc, seedPath, outPath string, quiet bool) error {
	cf, baseURL, err := loadControlFile(loc)
	if err != nil {
		return err
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "zsync: target %q, %d blocks of %d bytes (%d bytes total)\n",
			cf.Filename, cf.NumBlocks(), cf.Blocksize, cf.Length)
	}

	m := zsync.NewMatcher(cf)

	if seedPath != "" {
		sf, err := os.Open(seedPath)
		if err != nil {
			return fmt.Errorf("open seed %s: %w", seedPath, err)
		}
		t0 := time.Now()
		err = m.FeedSeed(sf)
		_ = sf.Close()
		if err != nil {
			return fmt.Errorf("feed seed: %w", err)
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "seed scan: matched %d/%d blocks in %s\n",
				m.AcceptedBlocks(), m.TotalBlocks(), time.Since(t0).Round(time.Millisecond))
		}
	}

	missing := m.MissingRanges()
	if !quiet {
		var missingBlocks int
		for _, r := range missing {
			missingBlocks += r[1] - r[0]
		}
		fmt.Fprintf(os.Stderr, "need to fetch %d blocks (%d bytes) in %d ranges\n",
			missingBlocks, missingBlocks*cf.Blocksize, len(missing))
	}

	if len(missing) > 0 {
		targetURLs, err := zsync.ResolveTargetURL(cf, baseURL)
		if err != nil {
			return err
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "fetching from %s (with %d URL fallback(s))\n", targetURLs[0], len(targetURLs)-1)
		}
		fc := zsync.NewFetchClient()
		if err := fc.FetchBlocksMulti(targetURLs, cf, m, missing); err != nil {
			return err
		}
	}

	// VerifyFileHash covers both the classic SHA-1 path (when FileHash is
	// empty and SHA1Hex is set) and the zsync2 BLAKE3 path.
	if err := zsync.VerifyFileHash(cf, m.Out()); err != nil {
		return err
	}

	out := outPath
	if out == "" {
		out = cf.Filename
		if out == "" {
			base := filepath.Base(baseURL)
			base = strings.TrimSuffix(base, ".zsync2")
			base = strings.TrimSuffix(base, ".zsync")
			out = base
		}
		if out == "" || out == "." || out == "/" {
			return fmt.Errorf("could not derive output filename; pass --output")
		}
	}
	if err := os.WriteFile(out, m.Out(), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", out, err)
	}
	if !quiet {
		fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", out, cf.Length)
	}
	return nil
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
	abs, err := filepath.Abs(loc)
	if err != nil {
		return nil, "", err
	}
	return cf, "file://" + abs, nil
}
