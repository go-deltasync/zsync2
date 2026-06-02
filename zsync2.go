// Package zsync2 is a pure-Go, cgo-free reimplementation of zsync, the
// rsync-style HTTP delta-update protocol: build a .zsync control file for a
// target, then let a client download only the blocks that differ from a local
// seed using ordinary HTTP range requests.
//
//	cf, _ := zsync2.Make(target, size, blocksize, "file", mtime, urls)
//	m := zsync2.NewMatcher(cf)
//	_ = m.FeedSeed(localSeed)          // reuse what we already have
//	// fetch m.MissingRanges() over HTTP, m.AcceptDownloadedBlock(...)
package zsync2

import (
	impl "github.com/go-deltasync/zsync2/internal/zsync"
)

// Default emitted client-version strings.
const (
	DefaultVersionZsync  = impl.DefaultVersionZsync
	DefaultVersionZsync2 = impl.DefaultVersionZsync2
)

// Core types.
type (
	ControlFile   = impl.ControlFile
	Matcher       = impl.Matcher
	FetchClient   = impl.FetchClient
	HashLengths   = impl.HashLengths
	BlockChecksum = impl.BlockChecksum
	Rsum          = impl.Rsum
	ZMapEntry     = impl.ZMapEntry
	DeflateWalker = impl.DeflateWalker
)

// Re-exported functions (the internal package is the single source of truth).
var (
	Make                   = impl.Make
	MakeWithAlgo           = impl.MakeWithAlgo
	MakeWithZMap2          = impl.MakeWithZMap2
	Read                   = impl.Read
	NewMatcher             = impl.NewMatcher
	NewFetchClient         = impl.NewFetchClient
	ComputeHashLengths     = impl.ComputeHashLengths
	ComputeHashLengthsAlgo = impl.ComputeHashLengthsAlgo
	ResolveTargetURL       = impl.ResolveTargetURL
	ResolveCompressedURLs  = impl.ResolveCompressedURLs
	VerifyFileHash         = impl.VerifyFileHash
	VerifySHA1             = impl.VerifySHA1
	Walk                   = impl.Walk
	EncodeZMap2            = impl.EncodeZMap2
	CalcRsum               = impl.CalcRsum
)
