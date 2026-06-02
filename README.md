# zsync2

[![ci](https://github.com/go-deltasync/zsync2/actions/workflows/ci.yml/badge.svg)](https://github.com/go-deltasync/zsync2/actions/workflows/ci.yml)
[![compat](https://github.com/go-deltasync/zsync2/actions/workflows/compat.yml/badge.svg)](https://github.com/go-deltasync/zsync2/actions/workflows/compat.yml)
[![coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)](https://github.com/go-deltasync/zsync2/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/go-deltasync/zsync2.svg)](https://pkg.go.dev/github.com/go-deltasync/zsync2)
[![Go version](https://img.shields.io/github/go-mod/go-version/go-deltasync/zsync2)](go.mod)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-blue)](LICENSE)

`zsync2` is a pure-Go reimplementation of [zsync][zsync-home], the rsync-style
delta-update protocol designed by Colin Phipps in 2005. The library lets an
HTTP client download only the bytes that actually differ between a local
"seed" file and a newer "target" file published by a vanilla HTTP server.

It ships as a small, dependency-light library (`github.com/go-deltasync/zsync2/internal/zsync`)
plus two CLIs:

| binary           | role                                              |
| ---------------- | ------------------------------------------------- |
| `gozsyncmake`    | server side &mdash; emit a `.zsync` control file  |
| `gozsync`        | client side &mdash; reconstruct a target file     |

The on-the-wire `.zsync` format is bit-compatible with the C reference, so
files emitted by `gozsyncmake` are accepted by upstream `zsync`, and files
emitted by upstream `zsyncmake` are accepted by `gozsync`. A dedicated
integration test, gated by the `compat` build tag, pins that down.

## How it compares

| Implementation                                                    | Language | OS support       |
| ----------------------------------------------------------------- | -------- | ---------------- |
| [Colin Phipps' `zsync`][zsync-home]                               | C        | Linux, BSD       |
| [`zsync-curl`](https://github.com/probonopd/zsync-curl)           | C        | Linux            |
| [`AppImageCommunity/zsync2`](https://github.com/AppImageCommunity/zsync2) | C++      | Linux            |
| **this project**                                                  | Go       | Linux, macOS, Windows |

This is *not* a drop-in CLI replacement &mdash; option flags and exit codes
differ &mdash; but it speaks the same wire format. Library users get a clean
package surface (`Read`, `Write`, `Make`, `Matcher`, `FetchClient`) that
exposes the protocol without dragging in any C code.

There is no `cgo`. There is no `fopencookie` or other glibc-specific call.
The package builds and runs from the same source on Linux, macOS and
Windows, and cross-compiles cleanly to ARM via `GOOS`/`GOARCH`.

## Install

```sh
go install github.com/go-deltasync/zsync2/cmd/gozsync@latest
go install github.com/go-deltasync/zsync2/cmd/gozsyncmake@latest
```

Pre-built binaries for `linux/amd64`, `linux/arm64`, `darwin/amd64`,
`darwin/arm64`, `windows/amd64` and `windows/arm64` are attached to each
GitHub release.

From a checkout:

```sh
go build ./...
```

## Usage

### Server side: emit a `.zsync` control file

```sh
gozsyncmake -u https://example.com/dist/firmware-2.bin firmware-2.bin
# wrote firmware-2.bin.zsync (4096 blocks of 2048 bytes, total 8388608 bytes)
```

Then publish `firmware-2.bin` and `firmware-2.bin.zsync` from any HTTP
server that supports byte-range requests (`nginx`, `caddy`, Amazon S3,
GitHub Releases, the `python3 -m http.server` test server &mdash; all
work).

Flags:

```
-b int          block size in bytes; must be a power of two (default: auto)
-o string       output control filename (default: <input>.zsync or <input>.zsync2)
-f string       target filename to embed in the control file (default: basename of input)
-u string       URL the client should fetch the target from (may be repeated)
   --format     wire format: "zsync" (classic, MD4+SHA-1; default) or "zsync2" (BLAKE3)
```

### Client side: fetch only the bytes that changed

```sh
gozsync -i firmware-1.bin -o firmware-2.bin \
  https://example.com/dist/firmware-2.bin.zsync
# zsync: target "firmware-2.bin", 4096 blocks of 2048 bytes (8388608 bytes total)
# seed scan: matched 4093/4096 blocks in 12ms
# need to fetch 3 blocks (6144 bytes) in 1 ranges
# fetching from https://example.com/dist/firmware-2.bin
# wrote firmware-2.bin (8388608 bytes)
```

The client opens the local seed file (the older version of the target),
slides a rolling-checksum window over every byte position, MD4-verifies
each candidate match against the control-file's block table, and copies
matched blocks straight from the seed into the output buffer. Anything
the seed cannot supply is fetched from the server with HTTP `Range`
requests and MD4-verified again before acceptance. A final SHA-1 check
over the whole reconstructed file rejects partial-corruption.

Flags:

```
-i string       local seed file (older version of the target) — optional
-o string       output path (default: Filename: from .zsync, then basename of URL)
-q              quiet: suppress progress output
```

If `-i` is omitted the client downloads everything via Range requests
(verifying each block's MD4) &mdash; useful as a sanity check.

### End-to-end smoke test

```sh
mkdir -p srv && dd if=/dev/urandom of=srv/big.bin bs=1m count=10
cp srv/big.bin seed.bin
printf 'MUTATED' | dd of=seed.bin bs=1 seek=5000000 count=7 conv=notrunc
gozsyncmake -u big.bin -o srv/big.bin.zsync srv/big.bin
(cd srv && python3 -m http.server 8765) &
gozsync -i seed.bin -o new.bin http://127.0.0.1:8765/big.bin.zsync
diff srv/big.bin new.bin       # empty: reconstruction is byte-exact
```

## How it works

```
                       +-----------------------+
                       |  target.bin (server)  |
                       +----------+------------+
                                  |
                gozsyncmake / zsyncmake (server-side)
                                  |
                                  v
        +-------------------------+--------------------------+
        |              target.bin.zsync (.zsync)             |
        |                                                    |
        | header                                             |
        |   Filename / Blocksize / Length / Hash-Lengths     |
        |   URL: ...   SHA-1: <full-file digest>             |
        | block table                                        |
        |   per block: weak rolling rsum + leading MD4 bytes |
        +-------------------------+--------------------------+
                                  |
                          (published over HTTP)
                                  |
       +---------- client (gozsync / zsync) ----------+
       |                                              |
       v                                              v
   seed.bin                                target.bin.zsync (parsed)
       |                                              |
       v                                              |
  +---------+   slide rolling rsum window  +-------------------+
  | matcher | -----------------------------|   block table     |
  +----+----+         (one byte at a time) +---------+---------+
       |  hit on hashRsum ?                          |
       |  yes -> MD4-verify -> copy block to output  |
       |  no  -> mark block as missing               |
       v                                             v
  output buffer                              HTTP Range request
  (filled in-place)                                  |
       ^                                             v
       |                                       MD4 verify block
       +---------------------------------------------+
                                                     |
                                       SHA-1 the whole reconstructed file
                                                     |
                                                     v
                                              target.bin (client)
```

The block table associates every fixed-size block of the target with two
checksums:

- a weak **rolling rsum** (Phipps' Adler-style `a`/`b` pair) which the
  client can update in O(1) as it slides its window byte-by-byte across
  the seed file; and
- the leading bytes of an **MD4** digest of the block, which the client
  uses to confirm any candidate match the rolling rsum proposed.

The choice of (rsum-bytes, checksum-bytes, seq_matches) is sized per file
to keep both the on-disk control file small and the expected false-positive
rate well below 1 per block. The function `ComputeHashLengths` in
[`internal/zsync/rsum.go`](internal/zsync/rsum.go) reproduces the C
reference's sizing formula exactly.

## Cross-platform / portability

The codebase intentionally avoids any system-specific dependency:

- **No cgo.** `CGO_ENABLED=0 go build ./...` produces fully static binaries
  on every supported OS. The release workflow builds and ships them.
- **No `fopencookie`, `funopen`, mmap or sendfile.** The matcher uses an
  ordinary `io.Reader` and an in-memory output buffer.
- **No platform-conditional files.** Every `.go` source in this repo
  compiles on every supported `GOOS`/`GOARCH` combination.

Tested matrix in CI: `linux`, `macos`, `windows` × `go 1.22`, `go 1.23`.

## Compatibility with upstream zsync / zsync2

The on-the-wire `.zsync` format implemented here is exercised against
Colin Phipps' canonical C `zsync` (the one packaged as `zsync` in Debian,
Ubuntu and Homebrew) by a dedicated integration test suite:
[`internal/zsync/compat_test.go`](internal/zsync/compat_test.go). It is
gated by the `compat` build tag, so a plain `go test ./...` doesn't depend
on an external binary; CI runs it through the
[`compat.yml`](.github/workflows/compat.yml) workflow which installs
`zsync` from `apt` before invoking:

```sh
go test -tags=compat ./internal/zsync/...
```

The compat suite covers four directions:

1. **upstream make &rarr; our read.** A `.zsync` produced by C `zsyncmake`
   is parsed by our `Read` and the resulting block table is asserted equal
   to the one our `Make` computes from the same input.
2. **our make &rarr; upstream apply.** Our `Make` writes a `.zsync` that
   is then handed to the upstream C `zsync` client, which reconstructs the
   target file byte-identically.
3. **upstream make &rarr; our apply.** The mirror image: upstream's
   `.zsync` is handed to our matcher + fetcher, which reconstructs the
   target byte-identically.
4. **round-trip parse.** Parse upstream's `.zsync`, re-serialise it with
   our `Write`, parse it again, and assert no drift in headers, block
   table or SHA-1.

The [AppImageCommunity C++ zsync2](https://github.com/AppImageCommunity/zsync2)
reads and writes the same wire format as Phipps' C; testing against the C
binary therefore implicitly covers it. If you want to test against the C++
implementation specifically, build it from source in the
[`compat.yml`](.github/workflows/compat.yml) workflow's apt step.

## Security note

The classic `zsync: 0.6` wire format requires **MD4** and **SHA-1**, both
of which are broken for collision resistance. The threat model there is
integrity against accidental corruption of the seed file, not
authentication: the real trust anchor is whoever serves the `.zsync`
control file. Concretely:

- An attacker who controls the content served at the `URL:` in the
  `.zsync` can obviously serve whatever they want. The `.zsync` is the
  trust anchor.
- An attacker who controls the `.zsync` can swap in their own `URL:`.
- MD4 collisions could let an attacker craft a *seed* file whose blocks
  the matcher accepts as matching the target. The file-wide SHA-1 at the
  end will catch that &mdash; *unless* the attacker also crafts a SHA-1
  collision for the whole reconstructed file (more expensive, but no
  longer rocket science).

For deployments that want a modern security margin, pass
`--format=zsync2` to `gozsyncmake`. The
[`zsync2: 1.0` wire format][proposal-blake3] uses **BLAKE3** for both the
per-block strong hash and the file-wide digest, replaces the `SHA-1:`
header with a self-describing `File-Hash: BLAKE3:<hex>` line, and bumps
the magic line so old `zsync: 0.6` parsers reject it cleanly. The
default stays `--format=zsync` for the year-one transition window; the
in-tree `gozsync` client reads both formats transparently.

[proposal-blake3]: https://go-deltasync.github.io/zsync2/proposal-blake3/

## Project scope and known gaps

The current release covers the uncompressed path of the zsync protocol in
full and the Z-Map2 maker (gzip-compressed-target path) at least
server-side. What's still missing:

- **Client-side Z-Map2 fetch.** The maker emits `Z-URL:` + `Z-Map2:`
  headers via `gozsyncmake --z-map` (or auto on `.gz` input); the client
  parses them and exposes a parsed `cf.ZMap` table; but the actual
  "fetch the gz by HTTP byte range, reset the decompressor at a Z-Map2
  restart point, decompress just enough bytes to cover the missing
  range" plumbing is not wired into `gozsync` yet. A client running
  against a Z-Map2 `.zsync` whose `URL:` points at a gz endpoint will
  download the gz whole-file via the URL fallback.
- **`Recompress`.** The header round-trips through `Write` but the
  client never acts on it.
- **BLAKE3 + Z-Map2.** The proposal intentionally leaves the wire
  interaction unspecified; the parser rejects the combination loudly
  and the maker refuses `--z-map --format=zsync2`.

Everything else from the original "known gaps" list has landed in this
release: `seq_matches == 2` filtering (a ~2x throughput win on noisy
seeds), multipart/byteranges batching, multi-URL failover, RFC 822
MTime preservation, conditional GET (`If-Modified-Since:` on the
`.zsync` GET), and resumable on-disk staging (`<output>.partial` is
reused as a seed on the next invocation).

## Contributing

Patches, bug reports and compat-test cases are very welcome. Before
sending a PR:

```sh
go vet ./...
go test -race ./...
go test -tags=compat ./...   # requires `zsync` from apt / brew / pkgsrc
```

The `internal/zsync` package is held to **&ge;99% line coverage** by CI;
new code should keep it there. Any change to header parsing or block-table
serialisation must keep all four compat-test scenarios green.

## Library

Importable for use in other Go programs (pure Go, no cgo):

```go
import "github.com/go-deltasync/zsync2"

cf, _ := zsync2.Make(target, size, blocksize, "file", mtime, urls) // build .zsync
m := zsync2.NewMatcher(cf)
_ = m.FeedSeed(localSeed) // reuse local blocks; fetch m.MissingRanges() over HTTP
```

## License

BSD 3-Clause. See [LICENSE](LICENSE).

The C reference at <https://github.com/probonopd/zsync-curl> is under the
Artistic License v2; this is a clean-room Go reimplementation that reads
the C source as a *specification*, not a code dependency.

[zsync-home]: http://zsync.moria.org.uk
