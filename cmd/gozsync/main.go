// gozsync is a pure-Go zsync client. Given a URL to a .zsync control file
// and a local seed file (an older version of the target), it reconstructs
// the target by reusing as many blocks from the seed as possible and
// fetching only the changed blocks over HTTP Range requests.
//
// This is the cross-platform counterpart of Colin Phipps' `zsync` (C) and
// of the AppImageCommunity/zsync2 (C++).
package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-deltasync/zsync2/internal/zsync"
	"github.com/spf13/cobra"
)

// errUpToDate is returned by run when the server replies 304 Not Modified
// to a conditional GET of the .zsync. Main prints a message and exits 0.
var errUpToDate = errors.New("already up to date")

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
		if errors.Is(err, errUpToDate) {
			if !quiet {
				fmt.Fprintln(os.Stderr, "already up to date")
			}
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "gozsync: %v\n", err)
		os.Exit(1)
	}
}

func run(loc, seedPath, outPath string, quiet bool) error {
	// If we already have an existing output / seed file with an mtime, send
	// `If-Modified-Since:` on the .zsync GET. A 304 short-circuits the run.
	var ifModSince time.Time
	if outPath != "" {
		if st, err := os.Stat(outPath); err == nil {
			ifModSince = st.ModTime()
		}
	}
	if ifModSince.IsZero() && seedPath != "" {
		if st, err := os.Stat(seedPath); err == nil {
			ifModSince = st.ModTime()
		}
	}

	cf, baseURL, err := loadControlFile(loc, ifModSince)
	if err != nil {
		return err
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "zsync: target %q, %d blocks of %d bytes (%d bytes total)\n",
			cf.Filename, cf.NumBlocks(), cf.Blocksize, cf.Length)
	}

	m := zsync.NewMatcher(cf)

	// Resolve output path early — both the resume-from-.partial seed step
	// and the final write need it.
	out, err := deriveOutputName(outPath, cf.Filename, baseURL)
	if err != nil {
		return err
	}

	// Order of seeds: the explicit --input first, then any stale <out>.partial
	// left over from a previous interrupted run. Both can supply blocks; the
	// matcher's idempotent acceptance means we won't double-count.
	seedPaths := []string{}
	if seedPath != "" {
		seedPaths = append(seedPaths, seedPath)
	}
	partial := out + ".partial"
	if _, err := os.Stat(partial); err == nil {
		seedPaths = append(seedPaths, partial)
	}

	for _, sp := range seedPaths {
		sf, err := os.Open(sp)
		if err != nil {
			return fmt.Errorf("open seed %s: %w", sp, err)
		}
		t0 := time.Now()
		err = m.FeedSeed(sf)
		_ = sf.Close()
		if err != nil {
			return fmt.Errorf("feed seed: %w", err)
		}
		if !quiet {
			fmt.Fprintf(os.Stderr, "seed scan %s: matched %d/%d blocks in %s\n",
				sp, m.AcceptedBlocks(), m.TotalBlocks(), time.Since(t0).Round(time.Millisecond))
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

	// Resumable on-disk staging: write to `out.partial` first, then rename
	// into place. A crashed or interrupted run leaves a `.partial` behind
	// that we can pick up as a seed on the next invocation.
	partial = out + ".partial"
	if err := os.WriteFile(partial, m.Out(), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", partial, err)
	}
	if err := os.Rename(partial, out); err != nil {
		return fmt.Errorf("rename %s -> %s: %w", partial, out, err)
	}
	// MTime preservation: if the control file carried one, stamp the output
	// with it so the reconstructed file matches the upstream timestamp.
	if cf.HasMTime {
		if err := os.Chtimes(out, cf.MTime, cf.MTime); err != nil {
			// Non-fatal: timestamps can fail on read-only filesystems or
			// network mounts that don't honour utimes. Warn but continue.
			fmt.Fprintf(os.Stderr, "warning: could not preserve MTime on %s: %v\n", out, err)
		}
	}
	if !quiet {
		fmt.Fprintf(os.Stderr, "wrote %s (%d bytes)\n", out, cf.Length)
	}
	return nil
}

func loadControlFile(loc string, ifModSince time.Time) (*zsync.ControlFile, string, error) {
	// If it parses as an absolute http(s) URL, fetch over HTTP. Otherwise
	// treat as a local path.
	if u, err := url.Parse(loc); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		req, err := http.NewRequest(http.MethodGet, loc, nil)
		if err != nil {
			return nil, "", err
		}
		req.Header.Set("User-Agent", "gozsync/0.1")
		if !ifModSince.IsZero() {
			req.Header.Set("If-Modified-Since", ifModSince.UTC().Format(http.TimeFormat))
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, "", fmt.Errorf("GET %s: %w", loc, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotModified {
			// Drain body to allow connection reuse, then surface a sentinel
			// the caller turns into a clean exit-0.
			_, _ = io.Copy(io.Discard, resp.Body)
			return nil, "", errUpToDate
		}
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

// deriveOutputName resolves the download's output path. An explicit --output is
// honoured verbatim (the operator's own choice). Otherwise the name is taken
// from the UNTRUSTED .zsync control file's Filename header (falling back to the
// URL basename) and reduced to a single path component, so a malicious control
// file cannot set Filename to "../../etc/x" or "/abs/path" and have gozsync
// write (and create <name>.partial) outside the working directory.
func deriveOutputName(explicit, controlFilename, baseURL string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	out := controlFilename
	if out == "" {
		base := filepath.Base(baseURL)
		base = strings.TrimSuffix(base, ".zsync2")
		base = strings.TrimSuffix(base, ".zsync")
		out = base
	}
	// Strip any directory components from the untrusted name.
	out = filepath.Base(filepath.Clean(out))
	if out == "" || out == "." || out == ".." || out == string(filepath.Separator) {
		return "", fmt.Errorf("could not derive a safe output filename; pass --output")
	}
	return out, nil
}
