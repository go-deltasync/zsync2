// Package zsync is a pure-Go implementation of the zsync delta-transfer
// protocol designed by Colin Phipps in 2005, with the BLAKE3-capable
// "zsync2" wire-format upgrade described at
// https://go-deltasync.github.io/zsync2/proposal-blake3/ layered on top.
//
// # Overview
//
// zsync lets an HTTP client download only the bytes that differ between a
// local "seed" file and a newer "target" file published by the server. The
// server publishes a small control file that lists, for every fixed-size
// block of the target, two checksums:
//
//   - A rsync-style weak rolling checksum (Phipps' Adler-style a/b pair)
//     that supports O(1) byte-wise slide updates.
//   - The leading prefix of a strong digest (MD4 in the classic format,
//     BLAKE3 in zsync2: 1.0), used to verify candidate matches and to
//     authenticate blocks fetched over HTTP.
//
// The client scans every byte offset of its seed file with the rolling
// checksum, looks each window up in a hash table built from the control
// file, strong-hash-verifies any hits, and copies the matching block
// straight from the seed into the output buffer. Any block that the seed
// cannot supply is fetched from the server with an HTTP Range request and
// strong-hash-verified again before being accepted. The fully reconstructed
// file is finally validated against the file-wide digest stored in the
// control file (SHA-1 in the classic format, BLAKE3 in zsync2).
//
// # Wire formats
//
// Two on-the-wire formats are supported by the same Read/Write/Matcher
// surface; the choice is per-file and round-trips transparently:
//
//   - FormatZsync ("zsync") -- Colin Phipps' classic 2005 wire format.
//     The first header line is `zsync: <version>`. The per-block strong
//     hash is MD4 (16-byte digest, truncated to checksum_bytes); the
//     file-wide hash is the `SHA-1: <hex>` header.
//
//   - FormatZsync2 ("zsync2") -- the BLAKE3-capable upgrade. The first
//     header line is `zsync2: <version>`. Two optional headers are added:
//     `Hash-Algorithm: <algo>` selects MD4 or BLAKE3 for the block-strong
//     hash, and `File-Hash: <algo>:<hex>` carries the file-wide digest.
//     The binary block-table layout is unchanged; only the meaning of
//     the strong-hash prefix bytes changes (MD4 -> BLAKE3).
//
// Read accepts both formats and exposes the parsed Format/HashAlgorithm
// on the returned ControlFile. Write emits the matching layout based on
// ControlFile.Format. Make defaults to the classic format for
// back-compat; MakeWithAlgo lets the caller pick.
//
// # What this package implements
//
// The exported surface of this package covers the building blocks needed
// to read, write and apply zsync / zsync2 files:
//
//   - Read parses a control-file stream into a ControlFile, accepting
//     both `zsync: 0.6` and `zsync2: 1.0` magic lines.
//   - ControlFile.Write serialises a ControlFile back to the wire format
//     matching its Format field.
//   - Make scans a source io.Reader and produces a classic-format
//     ControlFile; MakeWithAlgo is the algo-aware variant.
//   - Rsum is the rolling weak checksum; CalcRsum computes one over a
//     full block.
//   - HashLengths captures the (seq_matches, rsum_bytes, checksum_bytes)
//     triple from the Hash-Lengths header. ComputeHashLengths reproduces
//     the C reference's per-file sizing; ComputeHashLengthsAlgo extends
//     it with the BLAKE3-only 16-byte floor from the proposal.
//   - Matcher applies a parsed ControlFile against a seed reader, tracks
//     which target blocks were satisfied locally (under the control
//     file's declared strong-hash algorithm) and reports the byte ranges
//     that still need to come from the server.
//   - FetchClient downloads the missing block ranges over HTTP and feeds
//     them into the Matcher with strong-hash verification.
//   - VerifySHA1 checks the reconstructed buffer against the SHA-1 from
//     a classic control file; VerifyFileHash is the format-agnostic
//     version that handles both legacy SHA-1 and the zsync2 File-Hash.
//
// # Compatibility
//
// The classic on-the-wire .zsync format produced and consumed by this
// package is compatible with Colin Phipps' C reference
// (https://zsync.moria.org.uk and the fork at
// https://github.com/probonopd/zsync-curl) and with the AppImageCommunity
// C++ rewrite (https://github.com/AppImageCommunity/zsync2). An
// integration test gated by the "compat" build tag exercises a round-trip
// against the C zsync binary when it is installed on PATH; see
// compat_test.go for details.
//
// The zsync2: 1.0 format is currently only spoken by this package; the
// proposal calls for the AppImageCommunity C++ rewrite to gain a
// `--format=zsync2` mode in a follow-up. Old `zsync: 0.6` clients reject
// zsync2 files with a "not a zsync file" error -- the magic-line change
// is deliberate and one-way.
//
// # Known limitations of this implementation
//
// The current MVP intentionally omits a few features of the C reference
// that are unrelated to base correctness on uncompressed targets:
//
//   - No Z-Map2 / Recompress support (the transparently-decompressed-gzip
//     path). The parser reads Z-Map2 headers but does not interpret them
//     and Make never emits them. A client that encounters a Z-Map2 control
//     file will fail loudly rather than silently produce a wrong file.
//   - seq_matches == 2 is parsed and matched correctly but the "next block
//     must also match" optimisation is not applied; the strong hash is
//     relied on to reject the additional false positives.
//   - The HTTP fetcher issues one GET per contiguous run of missing
//     blocks; multipart/byteranges batching is parsed (the helper is
//     exposed for tests) but not yet driven from FetchClient.
//
// # Security
//
// The classic zsync wire format requires MD4 and SHA-1, both of which are
// broken for collision resistance. The threat model is integrity against
// accidental corruption in the seed file, not authentication: the trust
// anchor is whoever serves the control file. The zsync2 format lifts
// this constraint by switching both hashes to BLAKE3; see the README
// security section and proposal-blake3 for the longer discussion.
package zsync
