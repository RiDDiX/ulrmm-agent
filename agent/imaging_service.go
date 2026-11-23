// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"time"
)

func (a *Agent) imagingPoll(ctx context.Context, capability ImagingCapability) error {
	origin, err := url.Parse(a.BaseURL)
	if err != nil || origin.Scheme != "https" || origin.Host == "" {
		return errors.New("native imaging requires an HTTPS agent control channel")
	}
	path := fmt.Sprintf("/api/v3/%s/imaging/", a.AgentID)
	report := map[string]any{"capability": capability}
	r, e := a.rClient.R().SetContext(ctx).SetBody(report).Post(path)
	if e != nil {
		return e
	}
	if r.StatusCode() == 204 || r.StatusCode() == 404 {
		return nil
	}
	if r.StatusCode() != 200 {
		return fmt.Errorf("imaging poll status %d", r.StatusCode())
	}
	var grant imagingGrant
	if e = json.Unmarshal(r.Body(), &grant); e != nil {
		return e
	}
	phase := "network"
	e = func() error {
		imagingBusy.Store(true)
		defer imagingBusy.Store(false)
		if updateRunning.Load() {
			return errors.New("native imaging waits for the running agent update")
		}
		t, err := openImaging(grant, os.Getenv("ULRMM_IMAGING_INTERFACE"), a.Cert)
		if err != nil {
			return err
		}
		defer t.client.CloseIdleConnections()
		m, err := t.manifest(ctx, a.AgentID, capability.SourceID, "capture")
		if err != nil {
			return err
		}
		if !capability.Ready || m.Native.Method != capability.Method || m.Native.DeviceUUID != capability.DeviceUUID || m.Native.SourceID != capability.SourceID {
			return errors.New("capture source is no longer ready")
		}
		phase = "capture"
		m.Native.JobID = m.Image
		m.Native.PriorCaptureFinished = func(ctx context.Context, id string) (bool, error) {
			var status struct {
				Status string `json:"status"`
			}
			r, err := a.rClient.R().SetContext(ctx).SetQueryParam("point", id).SetResult(&status).Get(path)
			if err != nil {
				return false, err
			}
			return imagingPriorFinished(r.StatusCode(), status.Status)
		}
		stream, err := nativeImagingCapture(ctx, m.Native)
		if err != nil {
			return err
		}
		defer func() {
			if err := stream.Close(); err != nil {
				a.Logger.Warnln("Imaging source close:", err)
			}
		}()
		phase = "upload"
		if err := t.upload(ctx, m, stream); err != nil {
			var failed *imagingStreamError
			if errors.As(err, &failed) {
				phase = "capture"
			}
			return err
		}
		if staged, ok := stream.(interface{ Finish() error }); ok {
			if cleanup := staged.Finish(); cleanup != nil {
				a.Logger.Warnln("Imaging staging cleanup:", cleanup)
			}
		}
		return nil
	}()
	if e != nil {
		report["image_id"] = grant.Image
		report["failure"] = phase
		report["claim"] = grant.Claim
		a.rClient.R().SetContext(ctx).SetBody(report).Post(path)
	}
	return e
}

// imagingPriorFinished tells whether the server is done with a previous
// point, so its local staging set may be cleared. A discarded point is gone.
func imagingPriorFinished(code int, status string) (bool, error) {
	if code == 404 {
		return true, nil
	}
	if code != 200 {
		return false, fmt.Errorf("previous point status %d", code)
	}
	return status == "verified" || status == "failed", nil
}

// imagingBusy holds off a self-update that would stop the service during a
// granted capture; updateRunning holds off a new capture during an update.
var imagingBusy atomic.Bool

// RunImaging performs one normal capability report and processes a pending job.
// Each request has its own timeout and the server grant ends an idle transfer,
// so a long upload has no overall time limit.
func (a *Agent) RunImaging() error {
	ctx := context.Background()
	return a.imagingPoll(ctx, nativeImagingCapability(ctx))
}

var imagingWake = make(chan struct{}, 1)

// imagingBackoff is the wait before the next poll after failures runs in a row.
func imagingBackoff(failures int) time.Duration {
	if failures >= 7 {
		return 6 * time.Hour
	}
	return 5 * time.Minute << failures
}

func (a *Agent) imagingLoop() {
	failures := 0
	for {
		a.guard("NativeImaging", func() {
			if err := a.RunImaging(); err != nil {
				failures++
				a.Logger.Debugln("Native imaging:", err)
			} else {
				failures = 0
			}
		})
		select {
		case <-time.After(imagingBackoff(failures)):
		case <-imagingWake:
			failures = 0
		}
	}
}
