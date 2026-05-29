// gozsyncmake builds a .zsync control file from a local file. It is the
// pure-Go counterpart of Colin Phipps' `zsyncmake` from the C reference
// implementation (https://github.com/probonopd/zsync-curl).
//
// MVP scope: emits the headers + block table needed to drive a vanilla
// gozsync client. The compressed-target path (Z-Map2 / Recompress) from the
// C reference is intentionally omitted.
package main

import (
	"fmt"
	"os"
	"path/filepath"
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
	)
	cmd := &cobra.Command{
		Use:   "gozsyncmake [flags] <input>",
		Short: "Build a .zsync control file from a local file",
		Long: `gozsyncmake hashes the input file block-by-block (rolling weak
checksum + MD4) and writes a .zsync control file that a zsync client
can later use to reconstruct the input on a target machine while
re-using as many shared blocks as possible from a seed file.`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(_ *cobra.Command, args []string) error {
			return run(args[0], outFile, fname, blocksize, urls)
		},
	}
	cmd.Flags().IntVarP(&blocksize, "blocksize", "b", 0, "block size in bytes; must be a power of two (default: auto)")
	cmd.Flags().StringVarP(&outFile, "output", "o", "", "output .zsync filename (default: <input>.zsync)")
	cmd.Flags().StringVarP(&fname, "filename", "f", "", "target filename to embed in the .zsync (default: basename of input)")
	cmd.Flags().StringArrayVarP(&urls, "url", "u", nil, "URL the client should fetch the target from (may be repeated)")

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "gozsyncmake: %v\n", err)
		os.Exit(1)
	}
}

func run(in, outFile, fname string, blocksize int, urls []string) error {
	f, err := os.Open(in)
	if err != nil {
		return fmt.Errorf("open %s: %w", in, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", in, err)
	}

	target := fname
	if target == "" {
		target = filepath.Base(in)
	}
	out := outFile
	if out == "" {
		out = target + ".zsync"
	}
	if len(urls) == 0 {
		// Per the C reference: assume the target file sits alongside the
		// .zsync, so the relative path is the basename.
		urls = []string{filepath.Base(in)}
		fmt.Fprintf(os.Stderr,
			"warning: no --url given; embedding relative URL %q. Serve the .zsync and the target from the same directory, or pass --url.\n",
			urls[0])
	}

	mtime := st.ModTime().UTC().Truncate(time.Second)
	cf, err := zsync.Make(f, st.Size(), blocksize, target, mtime, urls)
	if err != nil {
		return fmt.Errorf("zsync.Make: %w", err)
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
	fmt.Fprintf(os.Stderr, "wrote %s (%d blocks of %d bytes, total %d bytes)\n",
		out, cf.NumBlocks(), cf.Blocksize, cf.Length)
	return nil
}
