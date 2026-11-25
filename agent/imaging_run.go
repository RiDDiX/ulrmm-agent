// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	imagingLogMax     = 64
	imagingLogKept    = 2000
	imagingHookTail   = 4096
	imagingReasonMax  = 255
	imagingWindowWarn = 10 * time.Minute
)

var (
	imagingProgressEvery = 5 * time.Second
	imagingBatteryEvery  = 30 * time.Second
	imagingPauseEvery    = 30 * time.Second
	imagingGateEvery     = time.Second
	// a service stop waits imagingStopWait for the post hooks and the final
	// of the run, then sends the final itself within imagingStopFinal; the
	// script of a hook still running then is left running, as the agent holds
	// no handle to stop it. Both fit TimeoutStopSec=15 after the power probes
	// and their notice.
	imagingStopWait  = 6 * time.Second
	imagingStopFinal = 3 * time.Second
)

// imagingFinal ends a run on the server: status failed, interrupted or cancelled.
type imagingFinal struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}

func (f *imagingFinal) Error() string { return f.Reason }

// errImagingEnded: the server answered 409, the run is over on its side.
var errImagingEnded = errors.New("the server ended this backup run")

var imagingCancelled = &imagingFinal{"cancelled", "Cancelled from the dashboard."}

type imagingWarning struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

type imagingHookResult struct {
	Phase      string `json:"phase"`
	ScriptID   int    `json:"script_id"`
	SHA256     string `json:"sha256"`
	Status     string `json:"status"`
	ExitCode   int    `json:"exit_code"`
	DurationMs int64  `json:"duration_ms"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
}

// imagingRunScript runs a hook body with the script runner; tests replace it.
var imagingRunScript = func(a *Agent, h imagingHook, nushell bool, deno string) (string, string, int, error) {
	return a.RunScript(h.Code, h.Shell, h.Args, h.Timeout, h.RunAsUser, h.EnvVars, nushell, deno)
}

// imagingDisks are the disks of the SMART precheck; tests replace it.
var imagingDisks = func(a *Agent) []HDisk { return a.Health().Disks }

type imagingSample struct {
	at    time.Time
	bytes int64
}

// imagingRun is one protocol-2 run of a sealed claim. Its context ends with
// the first cause that stops it.
type imagingRun struct {
	a       *Agent
	claim   imagingClaim
	t       *imagingTransfer
	ctx     context.Context
	cancel  context.CancelCauseFunc
	done    chan struct{}
	metered chan struct{}
	// closed when finish has reported the end
	ended   chan struct{}
	release func()
	bucket  imagingBucket

	mu                    sync.Mutex
	step                  string
	bytesRead, blocksRead int64
	blocksNew, bytesSent  int64
	rawNew, payloadNew    int64
	samples               []imagingSample
	log                   []string
	warnings              []imagingWarning
	hooks                 []imagingHookResult
	// per claim hook: 1 started, 2 done
	hookState                []int8
	sealed, warned, finished bool
	netSince, batterySince   time.Time
}

func (a *Agent) imagingRunStart(ctx context.Context, claim imagingClaim, t *imagingTransfer) *imagingRun {
	r := &imagingRun{a: a, claim: claim, t: t, done: make(chan struct{}), metered: make(chan struct{}), ended: make(chan struct{}), step: "snapshot"}
	r.ctx, r.cancel = context.WithCancelCause(ctx)
	t.run = r
	if claim.RunConfig.KeepAwake {
		if release, err := holdAwake(24 * time.Hour); err != nil {
			a.Logger.Debugln("Imaging keep-awake:", err)
		} else {
			r.release = release
		}
	}
	s := &a.imaging
	s.mu.Lock()
	s.run = r
	s.mu.Unlock()
	r.logf("Backup run started (%s).", claim.Trigger)
	tick := time.NewTicker(imagingProgressEvery)
	go func() {
		defer tick.Stop()
		r.meter(tick.C)
	}()
	return r
}

// imagingRunClaim runs a sealed claim to its end on the server.
func (a *Agent) imagingRunClaim(ctx context.Context, claim imagingClaim, t *imagingTransfer, capability ImagingCapability) error {
	r := a.imagingRunStart(ctx, claim, t)
	phase := "network"
	err := func() (err error) {
		// a panic must still run the post hooks and end the run on the server
		defer func() {
			if v := recover(); v != nil {
				a.Logger.Errorf("imaging run: recovered from panic: %v\n%s", v, debug.Stack())
				err = &imagingFinal{"failed", fmt.Sprintf("Agent error during the backup: %v", v)}
			}
		}()
		return a.imagingCapture(r.ctx, t, r, &capability, &phase)
	}()
	return r.finish(err, phase)
}

func (r *imagingRun) logf(format string, v ...any) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.logLocked(fmt.Sprintf(format, v...))
}

func (r *imagingRun) logLocked(line string) {
	at := time.UnixMilli(r.a.serverNowMs()).UTC().Format("2006-01-02T15:04:05Z")
	r.log = append(r.log, clip(at+" "+line, imagingTextMax))
	if len(r.log) > imagingLogKept {
		r.log = r.log[len(r.log)-imagingLogKept:]
	}
}

func (r *imagingRun) warn(code, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.warnLocked(code, detail)
}

func (r *imagingRun) warnLocked(code, detail string) {
	r.warnings = append(r.warnings, imagingWarning{code, clip(detail, imagingTextMax)})
	r.logLocked("Warning: " + detail)
}

func (r *imagingRun) setStep(step string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.step = step
	r.mu.Unlock()
}

// read, uploaded and sealedNow feed the counters from the upload loop.
func (r *imagingRun) read(n int) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.bytesRead += int64(n)
	r.blocksRead++
	r.mu.Unlock()
}

func (r *imagingRun) uploaded(raw, sent int) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.bytesSent += int64(sent)
	if raw > 0 {
		r.blocksNew++
		r.rawNew, r.payloadNew = r.rawNew+int64(raw), r.payloadNew+int64(sent)
	}
	r.mu.Unlock()
}

func (r *imagingRun) sealedNow() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.sealed = true
	r.logLocked("The backup is sealed; the server verifies it.")
	r.mu.Unlock()
}

// imagingTaken counts what a PATCH carried, dropped once the server took it.
type imagingTaken struct{ log, warnings, hooks int }

// body is a progress PATCH. onlyLogHooks is the resend after a 409.
func (r *imagingRun) body(final *imagingFinal, onlyLogHooks bool) (map[string]any, imagingTaken) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := imagingTaken{min(len(r.log), imagingLogMax), len(r.warnings), len(r.hooks)}
	b := map[string]any{"run": r.claim.Run, "log": append([]string{}, r.log[:n.log]...), "hooks": append([]imagingHookResult{}, r.hooks...)}
	if onlyLogHooks {
		n.warnings = 0
		return b, n
	}
	b["warnings"] = append([]imagingWarning{}, r.warnings...)
	state, reason := "running", ""
	if !r.netSince.IsZero() {
		state, reason = "paused", "network"
	} else if !r.batterySince.IsZero() {
		state, reason = "paused", "battery"
	}
	now := time.Now()
	r.samples = append(r.samples, imagingSample{now, r.bytesRead})
	for len(r.samples) > 1 && now.Sub(r.samples[1].at) >= 30*time.Second {
		r.samples = r.samples[1:]
	}
	var rate int64
	if first := r.samples[0]; now.Sub(first.at) > 0 {
		rate = int64(float64(r.bytesRead-first.bytes) / now.Sub(first.at).Seconds())
	}
	var dedup, compression int64
	if r.blocksRead > 0 {
		dedup = (r.blocksRead - r.blocksNew) * 1000 / r.blocksRead
	}
	if r.rawNew > 0 {
		compression = r.payloadNew * 1000 / r.rawNew
	}
	b["state"], b["step"], b["pause_reason"] = state, r.step, reason
	b["counters"] = map[string]any{"bytes_read": r.bytesRead, "blocks_read": r.blocksRead, "blocks_new": r.blocksNew, "bytes_sent": r.bytesSent,
		"rate": rate, "eta": nil, "expected_bytes": nil, "dedup_permille": dedup, "compression_permille": compression}
	if final != nil {
		b["final"] = imagingFinal{final.Status, sdioCut(strings.TrimSpace(final.Reason), imagingReasonMax)}
	}
	return b, n
}

func (r *imagingRun) drop(n imagingTaken) {
	r.mu.Lock()
	r.log, r.warnings, r.hooks = r.log[n.log:], r.warnings[n.warnings:], r.hooks[n.hooks:]
	r.mu.Unlock()
}

// answered applies a progress answer: the cancel flag, and a stop on 404,
// 403 (grant revoked, run replaced) or 409 (run ended).
func (r *imagingRun) answered(data []byte, status int, err error, n imagingTaken) {
	switch {
	case err == nil:
		r.drop(n)
		var answer struct {
			Cancel bool `json:"cancel"`
		}
		if json.Unmarshal(data, &answer) == nil && answer.Cancel {
			r.cancel(imagingCancelled)
		}
	case status == http.StatusNotFound || status == http.StatusForbidden:
		r.cancel(err)
	case status == http.StatusConflict:
		r.cancel(errImagingEnded)
	}
}

// meter sends the progress on every tick; ticks that come while a PATCH is
// out are dropped by the ticker, so a slow server never holds up the run.
func (r *imagingRun) meter(tick <-chan time.Time) {
	defer close(r.metered)
	var sampled time.Time
	for {
		if now := time.Now().Round(0); sampled.IsZero() || now.Sub(sampled) >= imagingBatteryEvery {
			sampled = now
			r.battery()
		}
		r.window()
		body, taken := r.body(nil, false)
		// post-backup results travel with the final
		if body["step"] == "cleanup" {
			delete(body, "hooks")
			taken.hooks = 0
		}
		raw, _ := json.Marshal(body)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		data, status, err := r.t.request(ctx, http.MethodPatch, "progress/", raw, "application/json")
		cancel()
		r.answered(data, status, err, taken)
		select {
		case <-r.done:
			return
		case <-tick:
		}
	}
}

// send is a PATCH with the retry of a final result; it gives the status.
func (r *imagingRun) send(final *imagingFinal, onlyLogHooks bool) int {
	body, taken := r.body(final, onlyLogHooks)
	raw, _ := json.Marshal(body)
	code, err := r.a.retrySend("imaging progress", pkgRetryWait, 0, func() (int, error) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, status, err := r.t.request(ctx, http.MethodPatch, "progress/", raw, "application/json")
		return status, err
	})
	if err == nil {
		r.drop(taken)
	} else {
		r.a.Logger.Debugln("Imaging progress:", err)
	}
	return code
}

// finish runs the post-backup hooks and reports the end: a final for a run
// that did not seal, only the hook results and log after the seal.
func (r *imagingRun) finish(err error, phase string) error {
	defer close(r.ended)
	// registered until the report went out: a service stop then waits for it
	defer func() {
		s := &r.a.imaging
		s.mu.Lock()
		if s.run == r {
			s.run = nil
		}
		s.mu.Unlock()
	}()
	cause := context.Cause(r.ctx)
	// the meter keeps the run from going stale while the post hooks run
	r.setStep("cleanup")
	var panicked error
	func() {
		// a panic here must still stop the meter, free keep-awake and end the run
		defer func() {
			if v := recover(); v != nil {
				r.a.Logger.Errorf("imaging run: recovered from panic: %v\n%s", v, debug.Stack())
				panicked = &imagingFinal{"failed", fmt.Sprintf("Agent error during the backup: %v", v)}
			}
		}()
		r.runHooks("post-backup")
	}()
	close(r.done)
	<-r.metered
	if r.release != nil {
		r.release()
	}
	r.cancel(nil)
	r.mu.Lock()
	sealed, sent := r.sealed, r.finished
	r.finished = true
	r.mu.Unlock()
	if cause != nil && !sealed {
		err = cause
	}
	if panicked != nil && !sealed {
		err = panicked
	}
	// the final of the service stop carried the rest already
	if !sent {
		r.reportRest(false)
	}
	switch {
	case sent:
		return err
	case sealed:
		r.send(nil, false)
		return nil
	case errors.Is(err, errImagingEnded):
		r.send(nil, true)
		return err
	}
	final := imagingFinalFor(err, phase)
	if final == nil {
		return err
	}
	r.logf("Backup run ended %s: %s", final.Status, final.Reason)
	if r.send(final, false) == http.StatusConflict {
		r.send(nil, true)
	}
	return err
}

// imagingFinalFor maps the error that ended a run to its final; nil sends
// none (403 or 404: the grant is gone).
func imagingFinalFor(err error, phase string) *imagingFinal {
	var final *imagingFinal
	var refused *imagingStatusError
	switch {
	case errors.As(err, &final):
		return final
	case errors.As(err, &refused) && (refused.status == http.StatusNotFound || refused.status == http.StatusForbidden):
		return nil
	case errors.As(err, &refused):
		what := "upload"
		if refused.path == "seal/" {
			what = "seal"
		}
		return &imagingFinal{"failed", fmt.Sprintf("The server refused the %s: %d %s", what, refused.status, refused.detail)}
	case phase == "capture":
		return &imagingFinal{"failed", "Capture failed: " + sdioCut(err.Error(), 200)}
	}
	return &imagingFinal{"failed", err.Error()}
}

// runHooks runs the hooks of phase in claim order. A failing abort hook
// ends a pre phase and fails the run; every post-snapshot hook runs, and a
// post-backup hook only warns.
func (r *imagingRun) runHooks(phase string) error {
	if r == nil {
		return nil
	}
	pre := phase == "pre-backup" || phase == "pre-snapshot"
	var abort error
	for i, h := range r.claim.Hooks {
		if h.Phase != phase {
			continue
		}
		// a stopped run starts no more pre hooks
		if err := context.Cause(r.ctx); pre && err != nil {
			return err
		}
		res := r.hook(i, h)
		if res.Status == "ok" {
			continue
		}
		if h.OnFail == "abort" && phase != "post-backup" {
			if abort == nil {
				abort = &imagingFinal{"failed", fmt.Sprintf("Hook %s failed in %s.", h.Name, phase)}
			}
			if phase != "post-snapshot" {
				return abort
			}
			continue
		}
		r.warn("hook", fmt.Sprintf("Hook %s %s in %s.", h.Name, res.Status, phase))
	}
	return abort
}

func (r *imagingRun) hook(i int, h imagingHook) imagingHookResult {
	r.markHook(i, 1)
	res := imagingHookResult{Phase: h.Phase, ScriptID: h.ScriptID, SHA256: h.SHA256, Status: "suspended"}
	// the server pins sha256(shell NUL code) of the approved body
	sum := sha256.Sum256([]byte(h.Shell + "\x00" + h.Code))
	if !h.Suspended && hex.EncodeToString(sum[:]) != h.SHA256 {
		res.Status, res.Stderr = "failed", "The script does not match its approved hash; it was not run."
	} else if !h.Suspended {
		start := time.Now()
		stdout, stderr, code, err := imagingRunScript(r.a, h, r.claim.NushellEnableConfig, r.claim.DenoDefaultPermissions)
		took := time.Since(start)
		res.ExitCode, res.DurationMs = code, took.Milliseconds()
		res.Stdout, res.Stderr = outputTail(stdout, imagingHookTail), outputTail(stderr, imagingHookTail)
		switch {
		case err == nil && code == cmdTimeoutExit && took >= time.Duration(h.Timeout)*time.Second:
			res.Status = "timeout"
		case err == nil && code == 0:
			res.Status = "ok"
		default:
			res.Status = "failed"
		}
	}
	r.markHook(i, 2)
	r.mu.Lock()
	r.hooks = append(r.hooks, res)
	r.logLocked(fmt.Sprintf("Hook %s %s in %s.", h.Name, res.Status, h.Phase))
	r.mu.Unlock()
	return res
}

func (r *imagingRun) markHook(i int, state int8) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hookState == nil {
		r.hookState = make([]int8, len(r.claim.Hooks))
	}
	r.hookState[i] = state
}

// reportRest reports the hooks without a result: skipped when they never
// started, failed when one still runs as the run ends. stopped: the service
// stops and leaves the script of such a hook running.
func (r *imagingRun) reportRest(stopped bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, h := range r.claim.Hooks {
		var state int8
		if i < len(r.hookState) {
			state = r.hookState[i]
		}
		res := imagingHookResult{Phase: h.Phase, ScriptID: h.ScriptID, SHA256: h.SHA256, Status: "skipped"}
		switch state {
		case 2:
			continue
		case 1:
			res.Status, res.Stderr = "failed", "The run ended while this hook ran."
			if stopped {
				res.Stderr = "The agent service stopped while this hook ran; the script was left running."
			}
		}
		r.hooks = append(r.hooks, res)
	}
}

// smart is the SMART precheck before the pre-snapshot hooks.
func (r *imagingRun) smart() error {
	if r == nil || r.claim.RunConfig.Smart == "off" {
		return nil
	}
	for _, detail := range imagingBadDisks(imagingDisks(r.a)) {
		if r.claim.RunConfig.Smart == "abort" {
			return &imagingFinal{"failed", "SMART warning on " + detail}
		}
		r.warn("smart", detail)
	}
	return nil
}

// netLost is one step of the network pause after the retries: the run
// waits and tries again, or ends once the pause passed its limit.
func (r *imagingRun) netLost(ctx context.Context) error {
	limit := r.claim.RunConfig.PauseMaxMinutes
	r.mu.Lock()
	if r.netSince.IsZero() {
		r.netSince = time.Now().Round(0)
		r.logLocked("The network was lost; the upload pauses.")
	}
	since := r.netSince
	r.mu.Unlock()
	if limit == 0 {
		return &imagingFinal{"interrupted", "The network was lost."}
	}
	// wall time: a suspend counts toward the limit
	if time.Now().Round(0).Sub(since) > time.Duration(limit)*time.Minute {
		return &imagingFinal{"interrupted", fmt.Sprintf("Paused longer than %d minutes.", limit)}
	}
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-time.After(imagingPauseEvery):
	}
	return nil
}

func (r *imagingRun) netBack() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.netSince.IsZero() {
		r.netSince = time.Time{}
		r.logLocked("The network is back; the upload continues.")
	}
}

// battery samples the power during a run with pause_on_battery.
func (r *imagingRun) battery() {
	rc := r.claim.RunConfig
	if !rc.PauseOnBattery {
		return
	}
	onAC, known := imagingOnAC()
	r.mu.Lock()
	defer r.mu.Unlock()
	if !known || onAC {
		if !r.batterySince.IsZero() {
			r.batterySince = time.Time{}
			r.logLocked("On AC power again; the upload continues.")
		}
		return
	}
	if r.batterySince.IsZero() {
		r.batterySince = time.Now().Round(0)
		r.logLocked("On battery; the upload pauses.")
	}
	if rc.PauseMaxMinutes == 0 || time.Now().Round(0).Sub(r.batterySince) > time.Duration(rc.PauseMaxMinutes)*time.Minute {
		r.cancel(&imagingFinal{"interrupted", fmt.Sprintf("On battery longer than %d minutes.", rc.PauseMaxMinutes)})
	}
}

// gate holds the upload while the run pauses on battery.
func (r *imagingRun) gate() error {
	if r == nil {
		return nil
	}
	for {
		r.mu.Lock()
		paused := !r.batterySince.IsZero()
		r.mu.Unlock()
		if !paused {
			return context.Cause(r.ctx)
		}
		select {
		case <-r.ctx.Done():
			return context.Cause(r.ctx)
		case <-time.After(imagingGateEvery):
		}
	}
}

// window ends a run that did not seal at stop_at, on the server clock, and
// warns once 10 minutes before.
func (r *imagingRun) window() {
	at := r.claim.StopAt
	if at == nil {
		return
	}
	now := r.a.serverNowMs()
	r.mu.Lock()
	defer r.mu.Unlock()
	switch {
	case r.sealed:
	case now >= *at:
		r.cancel(&imagingFinal{"interrupted", "The backup window ended."})
	case *at-now <= imagingWindowWarn.Milliseconds() && !r.warned:
		r.warned = true
		r.warnLocked("window", "The backup window ends at "+time.UnixMilli(*at).UTC().Format("15:04")+" UTC.")
	}
}

// charge takes n bytes from the bandwidth limit and waits for the deficit.
func (r *imagingRun) charge(ctx context.Context, n int) error {
	if r == nil {
		return nil
	}
	now := time.Now()
	wait := r.bucket.take(now, n, int64(imagingThrottleKbps(r.claim.RunConfig.Throttle, now))*125)
	if wait <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-time.After(wait):
	}
	return nil
}

// imagingBucket is a token bucket in bytes that holds one second of rate.
type imagingBucket struct {
	tokens float64
	at     time.Time
}

// take charges n bytes at rate bytes per second and gives the wait that
// pays the deficit; rate 0 is unlimited.
func (b *imagingBucket) take(now time.Time, n int, rate int64) time.Duration {
	if rate <= 0 {
		b.at = time.Time{}
		return 0
	}
	if b.at.IsZero() {
		b.tokens = float64(rate)
	} else {
		b.tokens += now.Sub(b.at).Seconds() * float64(rate)
		if b.tokens > float64(rate) {
			b.tokens = float64(rate)
		}
	}
	b.at = now
	b.tokens -= float64(n)
	if b.tokens >= 0 {
		return 0
	}
	return time.Duration(-b.tokens / float64(rate) * float64(time.Second))
}

// imagingThrottleKbps is the limit at now on the agent's clock: the first
// rule whose range holds now, else the default. A range that ends before
// it starts runs past midnight and belongs to its start day.
func imagingThrottleKbps(t imagingThrottle, now time.Time) int {
	day := (int(now.Weekday())+6)%7 + 1
	prev := (day+5)%7 + 1
	minute := now.Hour()*60 + now.Minute()
	hhmm := func(s string) int {
		var h, m int
		fmt.Sscanf(s, "%d:%d", &h, &m)
		return h*60 + m
	}
	for _, rule := range t.Rules {
		start, end := hhmm(rule.Start), hhmm(rule.End)
		on := func(d int) bool { return slices.Contains(rule.Days, d) }
		if start == end && on(day) || start < end && on(day) && minute >= start && minute < end ||
			start > end && (on(day) && minute >= start || on(prev) && minute < end) {
			return rule.Kbps
		}
	}
	return t.DefaultKbps
}

// imagingCancel stops the active run with that id.
func (a *Agent) imagingCancel(run string) bool {
	s := &a.imaging
	s.mu.Lock()
	r := s.run
	s.mu.Unlock()
	if r == nil || run == "" || r.claim.Run != run {
		return false
	}
	r.cancel(imagingCancelled)
	return true
}

// imagingServiceStop interrupts the active run before the service ends. The
// run gets imagingStopWait for its post hooks and its final; after that the
// final goes out from here.
func (a *Agent) imagingServiceStop() {
	s := &a.imaging
	s.mu.Lock()
	r := s.run
	s.mu.Unlock()
	if r == nil {
		return
	}
	final := &imagingFinal{"interrupted", "The agent service stopped."}
	deadline := time.Now().Add(imagingStopWait + imagingStopFinal)
	r.cancel(final)
	select {
	case <-r.ended:
		return
	case <-time.After(imagingStopWait):
	}
	r.mu.Lock()
	skip := r.sealed || r.finished
	if !skip {
		r.finished = true
	}
	r.mu.Unlock()
	if skip {
		// finish sends the report itself; the process must not exit under it
		select {
		case <-r.ended:
		case <-time.After(time.Until(deadline)):
		}
		return
	}
	r.reportRest(true)
	body, _ := r.body(final, false)
	raw, _ := json.Marshal(body)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	if _, _, err := r.t.request(ctx, http.MethodPatch, "progress/", raw, "application/json"); err != nil {
		a.Logger.Debugln("Imaging progress at service stop:", err)
	}
}

// imagingACStep samples the power while the document asks for the
// ac_connected event and queues it on a change from battery to AC. It
// gives the state for the next sample.
func (a *Agent) imagingACStep(wasBattery bool) bool {
	s := &a.imaging
	s.mu.Lock()
	want := s.config.raw != nil && slices.Contains(s.config.doc.ScheduleEvents, "ac_connected")
	s.mu.Unlock()
	if !want {
		return false
	}
	onAC, known := imagingOnAC()
	battery := known && !onAC
	if wasBattery && !battery {
		s.mu.Lock()
		if !slices.Contains(s.events, "ac_connected") {
			s.events = append(s.events, "ac_connected")
		}
		s.mu.Unlock()
		imagingWakeUp()
	}
	return battery
}

// imagingPmsetAC reads pmset -g batt; a failed or timed-out run is unknown.
func imagingPmsetAC(out string, err error) (onAC, known bool) {
	return err == nil && parseOnAC(out), err == nil
}

// imagingACLine maps ACLineStatus of GetSystemPowerStatus: 1 on, 0 off,
// anything else unknown.
func imagingACLine(status byte) (onAC, known bool) {
	return status == 1, status == 0 || status == 1
}

// imagingSysfsOnAC reads /sys/class/power_supply: a Mains or USB supply
// that is online means AC, offline ones mean battery. A system without a
// battery of its own (type Battery, scope not Device) runs on AC.
func imagingSysfsOnAC(root string) (onAC, known bool) {
	entries, _ := os.ReadDir(root)
	supply, battery := false, false
	read := func(dir, name string) string {
		b, _ := os.ReadFile(filepath.Join(root, dir, name))
		return strings.TrimSpace(string(b))
	}
	for _, e := range entries {
		t := read(e.Name(), "type")
		battery = battery || t == "Battery" && read(e.Name(), "scope") != "Device"
		if t == "Mains" || strings.HasPrefix(t, "USB") {
			supply = true
			if read(e.Name(), "online") == "1" {
				return true, true
			}
		}
	}
	if !battery {
		return true, true
	}
	return false, supply
}
