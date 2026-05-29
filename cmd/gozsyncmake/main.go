// gozsyncmake builds a .zsync control file from a local file. It is the
// pure-Go counterpart of Colin Phipps' `zsyncmake` from the C reference
// implementation (https://github.com/probonopd/zsync-curl).
//
// MVP scope: emits the headers + block table needed to drive a vanilla
// gozsync client. The compressed-target path (Z-Map2 / Recompress) from the
// C reference is intentionally omitted.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-deltasync/zsync2/internal/zsync"
)

func main() {
	var (
		blocksize = flag.Int("b", 0, "block size in bytes; must be a power of two (default: auto)")
		outFile   = flag.String("o", "", "output .zsync filename (default: <input>.zsync)")
		fname     = flag.String("f", "", "target filename to embed in the .zsync (default: basename of input)")
		urlOpt    multiFlag
	)
	flag.Var(&urlOpt, "u", "URL the client should fetch the target from (may be repeated)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: gozsyncmake [-b blocksize] [-o out.zsync] [-f name] [-u url ...] <input>\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	in := flag.Arg(0)
	f, err := os.Open(in)
	if err != nil {
		die("open %s: %v", in, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		die("stat %s: %v", in, err)
	}

	target := *fname
	if target == "" {
		target = filepath.Base(in)
	}
	out := *outFile
	if out == "" {
		out = target + ".zsync"
	}

	urls := []string(urlOpt)
	if len(urls) == 0 {
		// Per the C reference: assume the target file sits alongside the
		// .zsync, so the relative path is the basename.
		urls = []string{filepath.Base(in)}
		fmt.Fprintf(os.Stderr,
			"warning: no -u given; embedding relative URL %q. Serve the .zsync and the target from the same directory, or pass -u.\n",
			urls[0])
	}

	mtime := st.ModTime().UTC().Truncate(time.Second)
	cf, err := zsync.Make(f, st.Size(), *blocksize, target, mtime, urls)
	if err != nil {
		die("zsync.Make: %v", err)
	}

	w, err := os.Create(out)
	if err != nil {
		die("create %s: %v", out, err)
	}
	if err := cf.Write(w); err != nil {
		_ = w.Close()
		die("write %s: %v", out, err)
	}
	if err := w.Close(); err != nil {
		die("close %s: %v", out, err)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d blocks of %d bytes, total %d bytes)\n",
		out, cf.NumBlocks(), cf.Blocksize, cf.Length)
}

type multiFlag []string

func (m *multiFlag) String() string    { return fmt.Sprintf("%v", []string(*m)) }
func (m *multiFlag) Set(s string) error { *m = append(*m, s); return nil }

func die(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "gozsyncmake: "+f+"\n", a...)
	os.Exit(1)
}
