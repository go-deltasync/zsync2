// Copyright (c) 2026, the go-deltasync/zsync2 authors
// SPDX-License-Identifier: BSD-3-Clause

package main

import "testing"

func TestDeriveOutputName(t *testing.T) {
	cases := []struct {
		name     string
		explicit string
		filename string
		baseURL  string
		want     string
		wantErr  bool
	}{
		{"explicit honoured verbatim", "/tmp/whatever", "ignored", "http://x/y.zsync", "/tmp/whatever", false},
		{"explicit may be any path", "../out.bin", "x", "u", "../out.bin", false},
		{"plain control filename", "", "image.iso", "http://x/image.iso.zsync", "image.iso", false},
		{"traversal in control file is stripped", "", "../../etc/passwd", "http://x/a.zsync", "passwd", false},
		{"absolute control file is stripped", "", "/etc/shadow", "http://x/a.zsync", "shadow", false},
		{"nested traversal collapses to base", "", "foo/../../bar", "http://x/a.zsync", "bar", false},
		{"dotdot-only rejected", "", "..", "http://x/a.zsync", "", true},
		{"dot-only rejected", "", ".", "http://x/a.zsync", "", true},
		{"empty filename falls back to URL basename", "", "", "http://host/dist/ubuntu.iso.zsync2", "ubuntu.iso", false},
		{"url basename also sanitized", "", "", "http://host/../../../evil.zsync", "evil", false},
		{"nothing derivable is an error", "", "", "", "", true},
		{"bare separator filename rejected", "", "/", "http://x/a.zsync", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := deriveOutputName(c.explicit, c.filename, c.baseURL)
			if (err != nil) != c.wantErr {
				t.Fatalf("err=%v, wantErr=%v", err, c.wantErr)
			}
			if !c.wantErr && got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}
