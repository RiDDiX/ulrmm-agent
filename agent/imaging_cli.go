// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

func ImagingCommand(command string, args []string) error {
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	addr := f.String("url", "", "Scoped HTTPS transfer URL")
	img := f.String("image", "", "Selected image UUID")
	target := f.String("target", "", "Selected ULRMM agent ID")
	disk := f.String("disk", "", "Approved disk identity")
	mode := f.String("network-mode", "internal", "internal or internet")
	iface := f.String("interface", "", "Managed tunnel interface")
	ca := f.String("ca", "", "Additional trusted CA bundle")
	output := f.String("output", "", "New recovery artifact file")
	if err := f.Parse(args); err != nil {
		return err
	}
	if *img == "" || *target == "" || *disk == "" || (*output == "" && command == "imaging-fetch") {
		return errors.New("provide image, target, disk and a new output path for recovery")
	}
	token, err := bufio.NewReader(io.LimitReader(os.Stdin, 256)).ReadString('\n')
	if err != nil && err != io.EOF {
		return err
	}
	ctx := context.Background()
	t, err := openImaging(imagingGrant{URL: *addr, Token: strings.TrimSpace(token), Image: *img, Mode: *mode}, *iface, &Agent{Logger: logrus.New(), Cert: *ca})
	if err != nil {
		return err
	}
	if command == "imaging-fetch" {
		m, e := t.manifest(ctx, *target, *disk, "restore")
		if e != nil {
			return e
		}
		if e := t.fetch(ctx, m, *output); e != nil {
			return e
		}
		fmt.Printf("Verified %d bytes, SHA-256 %s\n", m.Size, m.Hash)
		return nil
	}
	m, e := t.manifest(ctx, *target, *disk, "capture")
	if e != nil {
		return e
	}
	local, e := imagingRecoveryCapability(ctx, *disk)
	if e != nil {
		return e
	}
	if !strings.EqualFold(m.UUID, local.DeviceUUID) || local.SourceID != *disk || local.Method != m.Native.Method || local.Size != m.Native.Size || local.SectorSize != m.Native.SectorSize || local.BootMode != m.Native.BootMode {
		return errors.New("local recovery source differs from the approved source")
	}
	stream, e := nativeImagingCapture(ctx, local)
	if e != nil {
		return e
	}
	return errors.Join(t.upload(ctx, m, stream), stream.Close())
}
