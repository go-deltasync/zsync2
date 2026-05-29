# go-zsync

A pure-Go reimplementation of [zsync][zsync-home] — HTTP range-based delta
file updates using rolling weak checksums plus MD4 per block. Single binary,
no cgo, builds and runs on Linux, macOS and Windows from the same source.

> zsync is an rsync-like protocol designed by Colin Phipps (2005). The server
> publishes a small `.zsync` control file listing checksums for every block of
> the target file. A client that already has an older version of the target
> uses the control file to figure out which blocks it can reuse and fetches
> only the changed blocks via HTTP `Range:` requests. It is the protocol
> behind AppImage's delta updates.

## Status

Phase 1 / MVP. Implemented:

- [x] `.zsync` parser (`internal/zsync.Read`)
- [x] `.zsync` writer (`internal/zsync.Make` + `ControlFile.Write`)
- [x] Rolling weak checksum (Phipps' Adler-style `a`/`b` pair) with the
      byte-wise incremental update rule, verified by a property test against
      a from-scratch recompute
- [x] MD4 per-block strong checksum (via `golang.org/x/crypto/md4`)
- [x] SHA-1 of the whole file
- [x] Per-file `Hash-Lengths` sizing matching the C reference's `make.c`
- [x] Seed-file matcher (find common blocks via rolling-checksum sliding
      window, MD4-verify, copy into output buffer)
- [x] HTTP fetcher for missing block ranges. Works against both
      `206 Partial Content` (e.g. nginx, Go's `http.ServeContent`) and
      `200 OK` (e.g. Python's `http.server`, which ignores Range).
- [x] `gozsync` client and `gozsyncmake` maker CLIs
- [x] End-to-end test: 256 KB file with mutated seed reconstructed byte-exact
      over an in-process HTTP server
- [x] 10 MB smoke test against `python3 -m http.server`: 3 mutated regions
      in the seed, exactly 3 blocks fetched, output byte-identical to the
      target.
- [x] Cross-compile verified for `linux/amd64`, `linux/arm64`,
      `windows/amd64`.

Intentionally out of scope for this MVP (documented gaps):

- [ ] `Z-Map2` / `Recompress`: the path where the target is gzip-compressed
      and the `.zsync` indexes the *uncompressed* stream so the client can
      reuse a previous compressed copy. The maker simply does not emit
      Z-Map2 and the client errors out if it encounters one.
- [ ] `seq_matches == 2` filtering. We *parse* control files that declare
      `seq_matches = 2` (they're the norm for files larger than one block)
      and *find* matches correctly — we just skip the "next block must also
      match" optimisation and rely on MD4 to weed out the extra weak-checksum
      hits. Throughput is fine on the smoke-test scale; for large files this
      is a TODO.
- [ ] Multi-range / `multipart/byteranges` batching. We issue one HTTP GET
      per contiguous missing-block run. A `parseMultipartByteRanges` helper
      is already wired up for when we want to start batching.
- [ ] Multi-URL failover, resumable on-disk staging, RFC 822 mtime
      preservation on the output file.
- [ ] Conditional GET / `If-Modified-Since`.

The bits we *do* implement are bit-compatible with the C reference's
`.zsync` files, modulo unimplemented headers — control files written by the
C `zsyncmake` are read fine, and our control files are accepted by clients
expecting the canonical layout.

## Relationship to upstream `zsync` and `zsync2`

- **C reference**: <https://github.com/probonopd/zsync-curl> (originally
  <http://zsync.moria.org.uk>). Colin Phipps, Artistic License v2. This is
  the canonical implementation that defines the wire format. `go-zsync`
  reads its `make.c`, `rsum.c` and `zsync.c` as ground truth.
- **C++ rewrite**: <https://github.com/AppImageCommunity/zsync2>. Modern C++
  rewrite with a library + standalone tools. Linux-only in practice.
- **Other Go**: <https://github.com/cph6/zsync> is an unrelated Go port by a
  different author. We did not consult it; this implementation is derived
  directly from the C source and the 2005 paper.

`go-zsync` is *not* a drop-in CLI replacement for either: the option flags
and exit codes don't match. It is meant as a clean, portable, embeddable
library (`internal/zsync`) plus thin CLIs.

## Install

```sh
go install github.com/tannevaled/go-zsync/cmd/gozsync@latest
go install github.com/tannevaled/go-zsync/cmd/gozsyncmake@latest
```

Or from a checkout:

```sh
go build ./...
```

## Usage

### Server side: make a `.zsync`

```sh
gozsyncmake -u https://example.com/dist/firmware-2.bin firmware-2.bin
# -> firmware-2.bin.zsync
```

Then serve `firmware-2.bin` and `firmware-2.bin.zsync` from any HTTP
server that supports byte ranges (nginx, caddy, S3, GitHub Releases...).

### Client side: fetch only the changed bytes

```sh
gozsync -i firmware-1.bin -o firmware-2.bin \
  https://example.com/dist/firmware-2.bin.zsync
```

`firmware-1.bin` is your existing older version; the client scans it for
blocks that also appear in the new target, fetches only the missing blocks,
and writes the reconstructed `firmware-2.bin`. Without `-i seed` the client
just downloads everything via Range requests (verifying each block's MD4).

### Smoke test (the one in the test suite, but with CLIs)

```sh
mkdir -p srv && dd if=/dev/urandom of=srv/big.bin bs=1m count=10
cp srv/big.bin seed.bin
printf 'MUTATED' | dd of=seed.bin bs=1 seek=5000000 count=7 conv=notrunc
gozsyncmake -u big.bin -o srv/big.bin.zsync srv/big.bin
(cd srv && python3 -m http.server 8765) &
gozsync -i seed.bin -o new.bin http://127.0.0.1:8765/big.bin.zsync
diff srv/big.bin new.bin   # empty -> reconstruction is byte-exact
```

## Why MD4 in 2026?

MD4 is broken for collision resistance and we know it. The zsync wire
format requires MD4 (because Colin Phipps designed it in 2005 and it's
fast). The threat model here is *integrity against accidental corruption
in the seed file*, not authentication — the authoritative integrity check
is the file-wide SHA-1 (also weak, but slightly less so). For a security
review:

- An attacker who controls the *content served at the URL in `URL:`* can
  obviously serve whatever they want; the `.zsync` is the trust anchor.
- An attacker who controls the `.zsync` can swap in their own URL.
- MD4 collisions can let an attacker craft a *seed file* that the matcher
  accepts as containing a block of the target; the file-wide SHA-1 at the
  end will catch it. Don't trust the seed otherwise.

For new protocols, use BLAKE3. For zsync, use MD4 because that's the
protocol.

## License

BSD 3-Clause. See [LICENSE](LICENSE).

The C reference at <https://github.com/probonopd/zsync-curl> is under the
Artistic License v2; this is a clean-room Go reimplementation that reads
the C source as a *specification*, not a code dependency.

[zsync-home]: http://zsync.moria.org.uk
