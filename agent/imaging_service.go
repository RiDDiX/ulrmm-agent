// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sync/atomic"
	"time"

	"github.com/go-resty/resty/v2"
)

// imagingClaim is a protocol-2 claim. Only an answer the transport opened
// from a seal fills more than the grant.
type imagingClaim struct {
	imagingGrant
	Run       string `json:"run"`
	Trigger   string `json:"trigger"`
	StopAt    *int64 `json:"stop_at"`
	RunConfig struct {
		Throttle        imagingThrottle `json:"throttle"`
		PauseOnBattery  bool            `json:"pause_on_battery"`
		PauseMaxMinutes int             `json:"pause_max_minutes"`
		KeepAwake       bool            `json:"keep_awake"`
		Priority        string          `json:"priority"`
		Smart           string          `json:"smart"`
	} `json:"run_config"`
	Hooks                  []imagingHook `json:"hooks"`
	NushellEnableConfig    bool          `json:"nushell_enable_config"`
	DenoDefaultPermissions string        `json:"deno_default_permissions"`
}

func decodeImagingClaim(body []byte, opened bool) (imagingClaim, error) {
	var c imagingClaim
	if !opened {
		err := json.Unmarshal(body, &c.imagingGrant)
		return c, err
	}
	err := json.Unmarshal(body, &c)
	return c, err
}

// imagingSend posts a poll body; an answered poll has delivered what it carried.
func (a *Agent) imagingSend(ctx context.Context, path string, report map[string]any, sent imagingSent) (*resty.Response, error) {
	r, err := a.rClient.R().SetContext(ctx).SetBody(report).Post(path)
	if err == nil {
		err = a.imagingAnswerError(r)
	}
	if err != nil {
		return nil, err
	}
	if r.StatusCode() == 200 || r.StatusCode() == 204 {
		a.imagingAnswered(sent)
	}
	return r, nil
}

func (a *Agent) imagingPoll(ctx context.Context, capability ImagingCapability) error {
	origin, err := url.Parse(a.BaseURL)
	if err != nil || origin.Scheme != "https" || origin.Host == "" {
		return errors.New("native imaging requires an HTTPS agent control channel")
	}
	path := fmt.Sprintf("/api/v3/%s/imaging/", a.AgentID)
	a.imagingRevalidate()
	report, sent := a.imagingReport(capability)
	r, e := a.imagingSend(ctx, path, report, sent)
	if e != nil {
		return e
	}
	// a refused seal fails a poll without a claim, so the loop backs off
	refused := a.imagingSyncConfig(ctx, r.Header().Get(imagingConfigHeader))
	if r.StatusCode() == 204 || r.StatusCode() == 404 {
		return refused
	}
	if r.StatusCode() != 200 {
		return fmt.Errorf("imaging poll status %d", r.StatusCode())
	}
	// a claim that fails before its run or capture starts is reported with
	// its id; once a run starts, its failures go by PATCH
	claim, e := decodeImagingClaim(r.Body(), r.Header().Get(imagingOpened) == "1")
	grant := claim.imagingGrant
	phase, early := "network", true
	if e == nil {
		e = func() error {
			imagingBusy.Store(true)
			defer imagingBusy.Store(false)
			updating := errors.New("native imaging waits for the running agent update")
			if updateRunning.Load() && claim.Run == "" {
				return updating
			}
			t, err := openImaging(grant, os.Getenv("ULRMM_IMAGING_INTERFACE"), a)
			if err != nil {
				return err
			}
			defer t.client.CloseIdleConnections()
			early = false
			// run is read only from an answer the transport opened from a seal
			if claim.Run == "" {
				return a.imagingCapture(ctx, t, nil, &capability, &phase)
			}
			if updateRunning.Load() {
				r := &imagingRun{a: a, claim: claim, t: t, step: "snapshot"}
				r.reportRest(false)
				r.send(&imagingFinal{"interrupted", "The agent is being updated; the backup runs again after the update."}, false)
				return updating
			}
			return a.imagingRunClaim(ctx, claim, t, capability)
		}()
	}
	if e != nil && (early || claim.Run == "" && !a.imagingHeaderSeen()) {
		report, sent := a.imagingReport(capability)
		report["image_id"] = grant.Image
		report["failure"] = phase
		report["claim"] = grant.Claim
		a.imagingSend(ctx, path, report, sent)
	}
	return e
}

// imagingStartCapture starts the capture of the approved source; tests replace it.
var imagingStartCapture = nativeImagingCapture

// imagingCapture runs a granted capture; run is nil for a legacy grant. The
// hook phases sit around nativeImagingCapture, which starts the Linux child,
// stages wbadmin or runs Time Machine before it returns.
func (a *Agent) imagingCapture(ctx context.Context, t *imagingTransfer, run *imagingRun, capability *ImagingCapability, phase *string) error {
	path := fmt.Sprintf("/api/v3/%s/imaging/", a.AgentID)
	if err := run.runHooks("pre-backup"); err != nil {
		return err
	}
	m, err := t.manifest(ctx, a.AgentID, capability.SourceID, "capture")
	if err != nil {
		return err
	}
	*capability = a.imagingProbe(ctx)
	if c := *capability; !c.Ready || m.Native.Method != c.Method || m.Native.DeviceUUID != c.DeviceUUID || m.Native.SourceID != c.SourceID {
		if run != nil {
			return &imagingFinal{"failed", "The backup source is no longer ready: " + cmp.Or(c.Reason, "The backup source changed.")}
		}
		return errors.New("capture source is no longer ready")
	}
	if err := run.smart(); err != nil {
		return err
	}
	*phase = "capture"
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
	var stream io.ReadCloser
	// once the pre-snapshot phase began, the post-snapshot hooks run exactly
	// once, also when the capture start panics
	posted := false
	post := func() error {
		if posted {
			return nil
		}
		posted = true
		return run.runHooks("post-snapshot")
	}
	defer post()
	err = run.runHooks("pre-snapshot")
	if err == nil {
		if run != nil {
			m.Native.Priority = run.claim.RunConfig.Priority
		}
		run.logf("Snapshot started.")
		// the Linux start gives a typed nil with its error
		if stream, err = imagingStartCapture(ctx, m.Native); err != nil {
			stream = nil
		}
	}
	if stream != nil {
		defer func() {
			if err := stream.Close(); err != nil {
				a.Logger.Warnln("Imaging source close:", err)
			}
		}()
	}
	if perr := post(); err == nil {
		err = perr
	}
	if err != nil {
		return err
	}
	*phase = "upload"
	run.setStep("transfer")
	run.logf("Transfer started.")
	if err := t.upload(ctx, m, stream); err != nil {
		var failed *imagingStreamError
		if errors.As(err, &failed) {
			*phase = "capture"
		}
		return err
	}
	if staged, ok := stream.(interface{ Finish() error }); ok {
		if cleanup := staged.Finish(); cleanup != nil {
			a.Logger.Warnln("Imaging staging cleanup:", cleanup)
		}
	}
	return nil
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
	err := a.imagingPoll(ctx, a.imagingCached(ctx))
	if due, wake := a.imagingRecheck(); due {
		a.imagingProbe(ctx)
		if wake {
			imagingWakeUp()
		}
	}
	return err
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
	a.imagingStarted()
	go func() {
		battery := false
		for range time.Tick(time.Minute) {
			battery = a.imagingACStep(battery)
		}
	}()
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
