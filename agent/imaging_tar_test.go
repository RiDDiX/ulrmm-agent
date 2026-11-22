package agent

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"
)

func TestWriteAlignedHeaderStartsLargeFilesOnTheBlockGrid(t *testing.T) {
	// 519680 leaves exactly one gap header's payload to fill, which once cost a block.
	for _, lead := range []int{0, 1, 511, 776, 519680, 2833186, imagingBlock - 700} {
		var out bytes.Buffer
		written := &tarCounter{w: &out}
		archive := tar.NewWriter(written)
		files := []struct {
			name string
			data []byte
		}{
			{"WindowsImageBackup/a.xml", bytes.Repeat([]byte{'a'}, lead)},
			{"WindowsImageBackup/disk.vhdx", bytes.Repeat([]byte{'V'}, imagingBlock+3)},
			{"WindowsImageBackup/esp.vhdx", bytes.Repeat([]byte{'E'}, imagingBlock)},
		}
		for _, f := range files {
			header := &tar.Header{Name: f.name, Mode: 0o600, Size: int64(len(f.data)), Typeflag: tar.TypeReg}
			if err := writeAlignedHeader(archive, written, header); err != nil {
				t.Fatal(err)
			}
			if _, err := archive.Write(f.data); err != nil {
				t.Fatal(err)
			}
		}
		if err := archive.Close(); err != nil {
			t.Fatal(err)
		}
		for _, marker := range []byte{'V', 'E'} {
			at := bytes.Index(out.Bytes(), bytes.Repeat([]byte{marker}, 512))
			if at < 0 || at%imagingBlock != 0 {
				t.Errorf("lead %d: %c data starts at %d, not on the %d grid", lead, marker, at, imagingBlock)
			}
		}
		// Header plus lead data, then a PAX header, then the first boundary after it.
		if at := bytes.Index(out.Bytes(), bytes.Repeat([]byte{'V'}, 512)); lead < imagingBlock && at >= 512+(lead+511)/512*512+1536+imagingBlock {
			t.Errorf("lead %d: V data starts at %d, a block later than needed", lead, at)
		}
		reader := tar.NewReader(&out)
		for _, f := range files {
			header, err := reader.Next()
			for err == nil && header.Typeflag == tar.TypeXGlobalHeader {
				header, err = reader.Next()
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(reader)
			if err != nil || header.Name != f.name || !bytes.Equal(data, f.data) {
				t.Fatalf("lead %d: read back %s (%v), want %s intact", lead, header.Name, err, f.name)
			}
		}
	}
}
