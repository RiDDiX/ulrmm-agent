package agent

import (
	"archive/tar"
	"bytes"
	"io"
	"maps"
	"sort"
	"strings"
)

// tarCounter counts the archive bytes written so far.
type tarCounter struct {
	w io.Writer
	n int64
}

func (c *tarCounter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// tarPadStep keeps every padding record below the 1 MiB PAX limit of Go's tar.
const tarPadStep = 512 << 10

// writeAlignedHeader starts the data of a file of at least one block on the
// server's block grid. Otherwise a small file before it that changes size moves
// all later content against the grid, and no block is reused. The padding is PAX
// comments, which extractors skip: global headers for a gap above tarPadStep,
// then the file's own header.
func writeAlignedHeader(archive *tar.Writer, written *tarCounter, header *tar.Header) error {
	if header.Size < imagingBlock {
		return archive.WriteHeader(header)
	}
	padded := func(pad int) *tar.Header {
		h := *header
		h.PAXRecords = maps.Clone(header.PAXRecords)
		if h.PAXRecords == nil {
			h.PAXRecords = map[string]string{}
		}
		// Not digits: unpatched Python tarfile (CVE-2024-6232) scans digit runs in quadratic time.
		h.PAXRecords["comment"] = strings.Repeat("x", pad)
		return &h
	}
	size := func(pad int) int64 {
		var buf bytes.Buffer
		if tar.NewWriter(&buf).WriteHeader(padded(pad)) != nil {
			return -1
		}
		return int64(buf.Len())
	}
	gap := &tar.Header{Typeflag: tar.TypeXGlobalHeader, PAXRecords: map[string]string{"comment": strings.Repeat("x", tarPadStep)}}
	var wire bytes.Buffer
	if err := tar.NewWriter(&wire).WriteHeader(gap); err != nil {
		return err
	}
	for {
		if err := archive.Flush(); err != nil {
			return err
		}
		need := (written.n+size(1)+imagingBlock-1)/imagingBlock*imagingBlock - written.n
		if need-size(1) >= int64(wire.Len()) {
			if err := archive.WriteHeader(gap); err != nil {
				return err
			}
			continue
		}
		// Header sizes grow in 512-byte steps with the pad, and the offset is a
		// multiple of 512, so one pad length meets the block boundary exactly.
		pad := 1 + sort.Search(int(need), func(n int) bool { return size(n+1) >= need })
		if size(pad) == need {
			header = padded(pad)
		}
		return archive.WriteHeader(header)
	}
}
