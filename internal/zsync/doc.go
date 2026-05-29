// Package zsync is a pure-Go implementation of the zsync delta-transfer
// protocol designed by Colin Phipps in 2005.
//
// Overview
//
// zsync lets an HTTP client download only the bytes that differ between a
// local "seed" file and a newer "target" file published by the server. The
// server publishes a small .zsync control file that lists, for every fixed
// size block of the target, two checksums:
//
//   - A rsync-style weak rolling checksum (Phipps' Adler-style a/b pair)
//     that supports O(1) byte-wise slide updates.
//   - The leading prefix of an MD4 digest, used to verify candidate
//     matches and to authenticate blocks fetched over HTTP.
//
// The client scans every byte offset of its seed file with the rolling
// checksum, looks each window up in a hash table built from the control
// file, MD4-verifies any hits, and copies the matching block straight from
// the seed into the output buffer. Any block that the seed cannot supply is
// fetched from the server with an HTTP Range request and MD4-verified
// again before being accepted. The fully reconstructed file is finally
// validated against the SHA-1 digest stored in the control file.
//
// What this package implements
//
// The exported surface of this package covers the building blocks needed
// to read, write and apply .zsync files:
//
//   - Read parses a .zsync stream into a ControlFile.
//   - ControlFile.Write serialises a ControlFile back to the wire format.
//   - Make scans a source io.Reader and produces a ControlFile.
//   - Rsum is the rolling weak checksum; CalcRsum computes one over a
//     full block.
//   - HashLengths captures the (seq_matches, rsum_bytes, checksum_bytes)
//     triple from the .zsync Hash-Lengths header. ComputeHashLengths
//     reproduces the C reference's per-file sizing.
//   - Matcher applies a parsed ControlFile against a seed reader, tracks
//     which target blocks were satisfied locally and reports the byte
//     ranges that still need to come from the server.
//   - FetchClient downloads the missing block ranges over HTTP and feeds
//     them into the Matcher with MD4 verification.
//   - VerifySHA1 checks the reconstructed buffer against the SHA-1 stored
//     in the control file.
//
// Compatibility
//
// The on-the-wire .zsync format produced and consumed by this package is
// compatible with Colin Phipps' C reference (https://zsync.moria.org.uk
// and the fork at https://github.com/probonopd/zsync-curl) and with the
// AppImageCommunity C++ rewrite (https://github.com/AppImageCommunity/zsync2).
// An integration test gated by the "compat" build tag exercises a
// round-trip against the C zsync binary when it is installed on PATH; see
// compat_test.go for details.
//
// Known limitations of this implementation
//
// The current MVP intentionally omits a few features of the C reference
// that are unrelated to base correctness on uncompressed targets:
//
//   - No Z-Map2 / Recompress support (the transparently-decompressed-gzip
//     path). The parser reads Z-Map2 headers but does not interpret them
//     and Make never emits them. A client that encounters a Z-Map2 control
//     file will fail loudly rather than silently produce a wrong file.
//   - seq_matches == 2 is parsed and matched correctly but the "next block
//     must also match" optimisation is not applied; MD4 is relied on to
//     reject the additional false positives.
//   - The HTTP fetcher issues one GET per contiguous run of missing
//     blocks; multipart/byteranges batching is parsed (the helper is
//     exposed for tests) but not yet driven from FetchClient.
//
// Security
//
// The zsync wire format requires MD4 and SHA-1, both of which are broken
// for collision resistance. The threat model is integrity against accidental
// corruption in the seed file, not authentication: the trust anchor is
// whoever serves the .zsync control file. See the README for a longer
// discussion.
package zsync
