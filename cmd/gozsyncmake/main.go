// gozsyncmake builds a .zsync (or .zsync2) control file from a local
// file. It is the pure-Go counterpart of Colin Phipps' `zsyncmake` from
// the C reference implementation
// (https://github.com/probonopd/zsync-curl).
//
// MVP scope: emits the headers + block table needed to drive a vanilla
// gozsync client. The compressed-target path (Z-Map2 / Recompress) from the
// C reference is intentionally omitted.
//
// Two wire formats are supported, selectable with `--format`:
//
//   - `zsync` (default): the classic Phipps `zsync: 0.6` format using
//     MD4 + SHA-1. Byte-compatible with upstream `zsync`/`zsyncmake`.
//   - `zsync2`: the BLAKE3-capable upgrade proposed at
//     https://go-deltasync.github.io/zsync2/proposal-blake3/. The output
//     filename defaults to `<input>.zsync2`.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-deltasync/zsync2/internal/zsync"
	"github.com/spf13/cobra"
)

func main() {
	var (
		blocksize int
		outFile   string
		fname     string
		urls      []string
		zURLs     []string
		format    string
		zmap      bool
	)
	cmd := &cobra.Command{
		Use:   "gozsyncmake [flags] <input>",
		Short: "Build a .zsync (or .zsync2) control file from a local file",
		Long: `gozsyncmake hashes the input file block-by-block and writes a
control file that a zsync client can later use to reconstruct the input
on a target machine while re-using as many shared blocks as possible
from a seed file.

Two on-the-wire formats are supported:

  --format=zsync   (default) classic Phipps zsync: 0.6 with MD4 + SHA-1.
                   Compatible with upstream zsync / zsyncmake.
  --format=zsync2  BLAKE3-capable zsync2: 1.0; output defaults to
                   <input>.zsync2. See
                   https://go-deltasync.github.io/zsync2/proposal-blake3/

When the input is a .gz file you can pass --z-map (or let auto-detect
fire on the .gz extension) to additionally compute the Z-Map2
restart-point table. The resulting .zsync carries Z-URL: + Z-Map2:
headers so a client can fetch the gzipped target by HTTP byte range
and decompress on the fly.`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, args []string) error {
			return run(args[0], outFile, fname, blocksize, urls, zURLs, format, zmap)
		},
	}
	cmd.Flags().IntVarP(&blocksize, "blocksize", "b", 0, "block size in bytes; must be a power of two (default: auto)")
	cmd.Flags().StringVarP(&outFile, "output", "o", "", "output control filename (default: <input>.zsync or <input>.zsync2)")
	cmd.Flags().StringVarP(&fname, "filename", "f", "", "target filename to embed in the control file (default: basename of input)")
	cmd.Flags().StringArrayVarP(&urls, "url", "u", nil, "URL the client should fetch the uncompressed target from (may be repeated)")
	cmd.Flags().StringArrayVarP(&zURLs, "z-url", "Z", nil, "URL the client should fetch the gzipped target from (Z-Map2 path; may be repeated)")
	cmd.Flags().StringVar(&format, "format", "zsync", "wire format to emit: zsync (classic, MD4+SHA-1) or zsync2 (BLAKE3)")
	cmd.Flags().BoolVar(&zmap, "z-map", false, "compute a Z-Map2 restart table over the input (input must be a .gz file)")

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "gozsyncmake: %v\n", err)
		os.Exit(1)
	}
}

func run(in, outFile, fname string, blocksize int, urls []string, zURLs []string, format string, zmap bool) error {
	algo, ext, err := formatToAlgo(format)
	if err != nil {
		return err
	}

	// Auto-detect: a `.gz` input flips the Z-Map2 mode on by default. The
	// user can still opt out via `--z-map=false` if they really want a
	// plain checksum over the gz bytes (rare).
	if !zmap && strings.HasSuffix(strings.ToLower(in), ".gz") {
		zmap = true
	}
	if zmap && algo == zsync.HashAlgoBLAKE3 {
		return fmt.Errorf("--z-map with --format=zsync2 is not supported (BLAKE3 + Z-Map2 wire interaction is unspecified)")
	}

	f, err := os.Open(in)
	if err != nil {
		return fmt.Errorf("open %s: %w", in, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", in, err)
	}

	// In Z-Map2 mode the embedded target filename strips the .gz suffix
	// so the client knows the *uncompressed* target name.
	target := fname
	if target == "" {
		target = filepath.Base(in)
		if zmap {
			target = strings.TrimSuffix(target, ".gz")
		}
	}
	out := outFile
	if out == "" {
		out = target + ext
	}
	if len(urls) == 0 {
		// Per the C reference: assume the target file sits alongside the
		// control file, so the relative path is the basename.
		urls = []string{target}
		fmt.Fprintf(os.Stderr,
			"warning: no --url given; embedding relative URL %q. Serve the control file and the target from the same directory, or pass --url.\n",
			urls[0])
	}
	if zmap && len(zURLs) == 0 {
		// Match the URL fallback: assume the gz sits next to the
		// control file.
		zURLs = []string{filepath.Base(in)}
		fmt.Fprintf(os.Stderr,
			"warning: no --z-url given; embedding relative Z-URL %q.\n",
			zURLs[0])
	}

	mtime := st.ModTime().UTC().Truncate(time.Second)

	var cf *zsync.ControlFile
	if zmap {
		gzData, err := os.ReadFile(in)
		if err != nil {
			return fmt.Errorf("read %s: %w", in, err)
		}
		cf, err = zsync.MakeWithZMap2(gzData, blocksize, target, mtime, urls, zURLs, algo)
		if err != nil {
			return fmt.Errorf("zsync.MakeWithZMap2: %w", err)
		}
	} else {
		cf, err = zsync.MakeWithAlgo(f, st.Size(), blocksize, target, mtime, urls, algo)
		if err != nil {
			return fmt.Errorf("zsync.Make: %w", err)
		}
	}

	w, err := os.Create(out)
	if err != nil {
		return fmt.Errorf("create %s: %w", out, err)
	}
	if err := cf.Write(w); err != nil {
		_ = w.Close()
		return fmt.Errorf("write %s: %w", out, err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close %s: %w", out, err)
	}
	suffix := ""
	if zmap {
		suffix = fmt.Sprintf(", %d Z-Map2 entries", len(cf.ZMap))
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d blocks of %d bytes, total %d bytes, %s strong hash%s)\n",
		out, cf.NumBlocks(), cf.Blocksize, cf.Length, cf.HashAlgorithm, suffix)
	return nil
}

// formatToAlgo maps the user-facing --format value to the internal algo
// identifier and the conventional output-filename extension.
func formatToAlgo(format string) (algo, ext string, err error) {
	switch strings.ToLower(format) {
	case "", "zsync":
		return zsync.HashAlgoMD4, ".zsync", nil
	case "zsync2":
		return zsync.HashAlgoBLAKE3, ".zsync2", nil
	default:
		return "", "", fmt.Errorf("unknown --format %q (want \"zsync\" or \"zsync2\")", format)
	}
}
