// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-resty/resty/v2"
)

const (
	imagingProtocol     = 2
	imagingConfigHeader = "X-ULRMM-Imaging-Config"
	// set by sealTransport on an imaging answer it opened from a seal
	imagingOpened     = "X-Ulrmm-Opened"
	imagingSchema     = 1
	imagingTextMax    = 512
	imagingHooksMax   = 8
	imagingRulesMax   = 16
	imagingKbpsMax    = 10_000_000
	imagingProbeEvery = 6 * time.Hour
	// after a server rollback the agent takes unsealed grants again
	imagingHeaderTTL = 24 * time.Hour
)

// imagingDoc is the backup settings document of the server. The agent keeps
// it in memory only.
type imagingDoc struct {
	NetworkMode    string   `json:"network_mode"`
	AutoSetup      string   `json:"auto_setup"`
	Smart          string   `json:"smart"`
	OnBattery      string   `json:"on_battery"`
	ScheduleEvents []string `json:"schedule_events"`
}

type imagingThrottle struct {
	DefaultKbps int `json:"default_kbps"`
	Rules       []struct {
		Days  []int  `json:"days"`
		Start string `json:"start"`
		End   string `json:"end"`
		Kbps  int    `json:"kbps"`
	} `json:"rules"`
}

// imagingHook is a hook of a claim, which carries its body.
type imagingHook struct {
	Phase     string   `json:"phase"`
	ScriptID  int      `json:"script_id"`
	Name      string   `json:"name"`
	SHA256    string   `json:"sha256"`
	Shell     string   `json:"shell"`
	Code      string   `json:"code"`
	Args      []string `json:"args"`
	EnvVars   []string `json:"env_vars"`
	Timeout   int      `json:"timeout"`
	OnFail    string   `json:"on_fail"`
	RunAsUser bool     `json:"run_as_user"`
	Suspended bool     `json:"suspended"`
}

type imagingConfigError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// imagingConfig: version, hash, fetched, status and errors describe the
// last fetched document; raw and doc the last applied one, which stays in
// force after an error, without its fixes.
type imagingConfig struct {
	version int
	hash    string
	fetched []byte
	raw     []byte
	doc     imagingDoc
	status  string
	errors  []imagingConfigError
}

func (c *imagingConfig) autoSetup() string {
	if c.raw == nil || c.status == "error" {
		return "off"
	}
	return c.doc.AutoSetup
}

func (c *imagingConfig) smart() string {
	if c.raw == nil {
		return "warn"
	}
	return c.doc.Smart
}

type imagingState struct {
	mu     sync.Mutex
	config imagingConfig
	// gen counts changes of the config state; reportedGen is the one the
	// last answered poll carried, probeGen the one the stored probe ran under
	gen, reportedGen, probeGen int
	capability                 ImagingCapability
	checks                     []imagingCheck
	// wall time, a suspend must not stretch the 6 h
	checksAt      time.Time
	checksAtMs    int64
	checksVersion int
	// probeSeq numbers stored probes; fixesSent: an answered poll carried
	// the fixed checks of the stored one
	probeSeq  int
	fixesSent bool
	wakeProbe bool
	upSince   time.Time
	events    []string
	refetch   bool
	// one probe at a time; mu stays free meanwhile
	probe sync.Mutex
	// ms of the last answer that named a settings version
	headerAt atomic.Int64
	// the protocol-2 run in progress
	run *imagingRun
}

func (a *Agent) imagingHeaderSeen() bool {
	at := a.imaging.headerAt.Load()
	return at != 0 && time.Now().UnixMilli()-at < imagingHeaderTTL.Milliseconds()
}

// imagingAnswerError refuses an answer that a redirect took off the asked
// URL, past the path rules of the transport, and an unmarked 200 once the
// config header was seen.
func (a *Agent) imagingAnswerError(r *resty.Response) error {
	if r.RawResponse == nil || r.RawResponse.Request == nil || r.Request.RawRequest == nil {
		return errors.New("imaging answer without its request")
	}
	asked, final := r.Request.RawRequest.URL, r.RawResponse.Request.URL
	if final.String() != asked.String() {
		return errors.New("refusing an imaging answer redirected to " + final.Path)
	}
	if r.StatusCode() == 200 && r.Header().Get(imagingOpened) != "1" && a.imagingHeaderSeen() {
		return &sealError{"unsealed", "refusing an unsealed imaging answer from " + asked.Path}
	}
	return nil
}

var imagingHHMM = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

func imagingNull(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || string(t) == "null"
}

func imagingInt(raw json.RawMessage) (int, bool) {
	var n int
	return n, !imagingNull(raw) && json.Unmarshal(raw, &n) == nil
}

func imagingEnum(raw json.RawMessage, values ...string) bool {
	var s string
	return !imagingNull(raw) && json.Unmarshal(raw, &s) == nil && slices.Contains(values, s)
}

// imagingText shows a value in a message: a string without quotes, else
// its JSON text.
func imagingText(raw json.RawMessage) string {
	var s string
	if imagingNull(raw) {
		return "null"
	}
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(bytes.TrimSpace(raw))
}

// parseImagingDoc checks the document as this agent uses it: one error per
// failed key, unknown keys ignored.
func parseImagingDoc(raw []byte, agentID string) (imagingDoc, []imagingConfigError) {
	var doc imagingDoc
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) != nil || keys == nil {
		return doc, []imagingConfigError{{"document", "The document is not a JSON object."}}
	}
	// a value of the wrong type stays zero here and fails its check below
	_ = json.Unmarshal(raw, &doc)
	var errs []imagingConfigError
	fail := func(field, format string, v ...any) {
		errs = append(errs, imagingConfigError{field, clip(fmt.Sprintf(format, v...), imagingTextMax)})
	}
	if n, ok := imagingInt(keys["schema"]); !ok || n > imagingSchema {
		fail("schema", "Unsupported document schema %s.", imagingText(keys["schema"]))
	}
	if !imagingEnum(keys["agent_id"], agentID) {
		fail("agent_id", "The document belongs to another agent.")
	}
	var target struct {
		Kind json.RawMessage `json:"kind"`
	}
	_ = json.Unmarshal(keys["target"], &target)
	if !imagingEnum(target.Kind, "server") {
		fail("target.kind", "Target kind %s is not supported by this agent.", imagingText(target.Kind))
	}
	if !imagingEnum(keys["network_mode"], "internal", "internet") {
		fail("network_mode", "Unknown network mode %s.", imagingText(keys["network_mode"]))
	} else if doc.NetworkMode == "internal" {
		if _, err := imagingDialContext(os.Getenv("ULRMM_IMAGING_INTERFACE")); err != nil {
			fail("network_mode", "Internal-only mode is not usable here: %s", err)
		}
	}
	if !imagingEnum(keys["compression"], "none", "gzip") {
		fail("compression", "Unknown compression %s.", imagingText(keys["compression"]))
	}
	if n, ok := imagingInt(keys["compression_level"]); !ok || n < 0 || n > 9 {
		fail("compression_level", "Compression level must be 0-9.")
	}
	for _, e := range []struct {
		key    string
		values []string
	}{
		{"auto_setup", []string{"safe", "all", "off"}},
		{"smart", []string{"warn", "abort", "off"}},
		{"priority", []string{"background", "normal"}},
		{"on_battery", []string{"defer", "run"}},
	} {
		if !imagingEnum(keys[e.key], e.values...) {
			fail(e.key, "Unknown value %s.", imagingText(keys[e.key]))
		}
	}
	if n, ok := imagingInt(keys["pause_max_minutes"]); !ok || n < 0 || n > 240 {
		fail("pause_max_minutes", "Pause limit must be 0-240 minutes.")
	}
	if reason := imagingThrottleError(keys["throttle"]); reason != "" {
		fail("throttle", "Invalid bandwidth rule %s.", reason)
	}
	var events []json.RawMessage
	if json.Unmarshal(keys["schedule_events"], &events) != nil && !imagingNull(keys["schedule_events"]) {
		fail("schedule_events", "Unknown event %s.", imagingText(keys["schedule_events"]))
	}
	for _, e := range events {
		if !imagingEnum(e, "agent_start", "ac_connected") {
			fail("schedule_events", "Unknown event %s.", imagingText(e))
			break
		}
	}
	if reason := imagingHooksError(keys["hooks"]); reason != "" {
		fail("hooks", "Invalid hook %s.", reason)
	}
	return doc, errs
}

// imagingThrottleError is "<rule>: <reason>" for the first broken part of
// the bandwidth table; rule 0 is the table itself and its default.
func imagingThrottleError(raw json.RawMessage) string {
	var t map[string]json.RawMessage
	if json.Unmarshal(raw, &t) != nil || t == nil {
		return "0: not an object"
	}
	if n, ok := imagingInt(t["default_kbps"]); !ok || n < 0 || n > imagingKbpsMax {
		return "0: default_kbps must be 0-10000000"
	}
	var rules []json.RawMessage
	if json.Unmarshal(t["rules"], &rules) != nil && !imagingNull(t["rules"]) {
		return "0: rules must be a list"
	}
	if len(rules) > imagingRulesMax {
		return fmt.Sprintf("%d: at most %d rules", imagingRulesMax+1, imagingRulesMax)
	}
	for i, r := range rules {
		var rule struct {
			Days       []int
			Start, End string
			Kbps       json.RawMessage
		}
		if imagingNull(r) || json.Unmarshal(r, &rule) != nil {
			return fmt.Sprintf("%d: not a rule", i+1)
		}
		for _, d := range rule.Days {
			if d < 1 || d > 7 {
				return fmt.Sprintf("%d: days must be 1-7", i+1)
			}
		}
		if !imagingHHMM.MatchString(rule.Start) || !imagingHHMM.MatchString(rule.End) {
			return fmt.Sprintf("%d: start and end must be HH:MM", i+1)
		}
		if n, ok := imagingInt(rule.Kbps); !ok || n < 0 || n > imagingKbpsMax {
			return fmt.Sprintf("%d: kbps must be 0-10000000", i+1)
		}
	}
	return ""
}

// imagingHooksError is "<hook>: <reason>" for the first broken hook, counted from 1.
func imagingHooksError(raw json.RawMessage) string {
	var hooks []json.RawMessage
	if json.Unmarshal(raw, &hooks) != nil && !imagingNull(raw) {
		return "0: not a list"
	}
	if len(hooks) > imagingHooksMax {
		return fmt.Sprintf("%d: at most %d hooks", imagingHooksMax+1, imagingHooksMax)
	}
	for i, r := range hooks {
		var h struct {
			Phase, SHA256 string
			OnFail        string `json:"on_fail"`
			Timeout       json.RawMessage
		}
		if imagingNull(r) || json.Unmarshal(r, &h) != nil {
			return fmt.Sprintf("%d: not a hook", i+1)
		}
		if !slices.Contains([]string{"pre-backup", "pre-snapshot", "post-snapshot", "post-backup"}, h.Phase) {
			return fmt.Sprintf("%d: unknown phase %s", i+1, h.Phase)
		}
		if h.OnFail != "abort" && h.OnFail != "warn" {
			return fmt.Sprintf("%d: unknown on_fail %s", i+1, h.OnFail)
		}
		if n, ok := imagingInt(h.Timeout); !ok || n < 1 || n > 3600 {
			return fmt.Sprintf("%d: timeout must be 1-3600 seconds", i+1)
		}
		if !sha256Hex.MatchString(h.SHA256) {
			return fmt.Sprintf("%d: sha256 must be 64 hex digits", i+1)
		}
	}
	return ""
}

func imagingWakeUp() {
	select {
	case imagingWake <- struct{}{}:
	default:
	}
}

// imagingSyncConfig fetches the settings document when a poll answer names
// another version than the one this agent holds, or a fetch is due after a
// start or a NATS reconnect. No version named: a server before delivery 1,
// nothing is fetched. A failed fetch changes nothing and is retried; a
// refused seal is also given back.
func (a *Agent) imagingSyncConfig(ctx context.Context, header string) error {
	version, err := strconv.Atoi(header)
	if err != nil || version < 0 {
		return nil
	}
	s := &a.imaging
	s.mu.Lock()
	due := version != s.config.version || s.refetch
	s.mu.Unlock()
	if !due {
		return nil
	}
	var answer struct {
		Version  int    `json:"version"`
		Document string `json:"document"`
	}
	r, err := a.rClient.R().SetContext(ctx).Get(fmt.Sprintf("/api/v3/%s/imaging/config/", a.AgentID))
	if err == nil {
		err = a.imagingAnswerError(r)
	}
	if err == nil && (r.StatusCode() != 200 || r.Header().Get(imagingOpened) != "1") {
		err = fmt.Errorf("imaging config status %d", r.StatusCode())
	}
	if err == nil {
		err = json.Unmarshal(r.Body(), &answer)
	}
	if err != nil {
		a.Logger.Debugln("Imaging config:", err)
		var refused *sealError
		if errors.As(err, &refused) {
			a.imagingSealRefused(version, refused.reason)
			return refused
		}
		return nil
	}
	// the hash covers the received bytes, never a re-encoding
	raw := []byte(answer.Document)
	sum := sha256.Sum256(raw)
	doc, errs := parseImagingDoc(raw, a.AgentID)
	s.mu.Lock()
	old := s.config
	c := &s.config
	c.version, c.hash, c.fetched, c.errors, c.status = answer.Version, hex.EncodeToString(sum[:]), raw, errs, "error"
	if len(errs) == 0 {
		c.status, c.raw, c.doc = "applied", raw, doc
	}
	s.refetch = false
	changed := old.version != c.version || old.hash != c.hash || old.status != c.status
	if changed {
		s.gen++
	}
	s.mu.Unlock()
	if changed {
		imagingWakeUp()
	}
	return nil
}

// imagingSealRefused reports a version whose answer did not pass the seal
// like a refused document, so the dashboard shows why; network errors and
// 5xx stay silent. The fetch is tried again on every poll.
func (a *Agent) imagingSealRefused(version int, reason string) {
	msg := "The agent cannot verify the server's sealed answer (" + reason + ")."
	switch reason {
	case "signature", "key", "decrypt":
		msg += " Its enrolment key does not match this server."
	case "clock":
		msg += " Check the clock of the device."
	case "unsealed":
		msg = "The server sent the backup settings without a seal; the agent takes them only sealed."
	}
	s := &a.imaging
	s.mu.Lock()
	old := s.config
	c := &s.config
	// no fetched bytes: imagingRevalidate cannot apply this version from old ones
	c.version, c.hash, c.fetched, c.status = version, "", nil, "error"
	c.errors = []imagingConfigError{{"sealing", clip(msg, imagingTextMax)}}
	s.refetch = true
	changed := old.version != c.version || old.hash != c.hash || old.status != c.status
	if changed {
		s.gen++
	}
	s.mu.Unlock()
	if changed {
		imagingWakeUp()
	}
}

// imagingRevalidate checks a refused document again: its reason can lie in
// the environment, such as the tunnel of internal mode.
func (a *Agent) imagingRevalidate() {
	s := &a.imaging
	s.mu.Lock()
	c := s.config
	s.mu.Unlock()
	if c.status != "error" {
		return
	}
	doc, errs := parseImagingDoc(c.fetched, a.AgentID)
	if len(errs) != 0 {
		return
	}
	s.mu.Lock()
	if s.config.status == "error" && s.config.hash == c.hash {
		s.config.status, s.config.raw, s.config.doc, s.config.errors = "applied", c.fetched, doc, nil
		s.gen++
	}
	s.mu.Unlock()
}

// imagingSent is what a poll body carried, taken as delivered once answered.
type imagingSent struct{ events, gen, seq int }

// imagingReport is the protocol-2 poll body; a server before delivery 1
// ignores the new keys.
func (a *Agent) imagingReport(capability ImagingCapability) (map[string]any, imagingSent) {
	onAC, known := imagingOnAC()
	var ac any
	if known {
		ac = onAC
	}
	s := &a.imaging
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.config
	deferred := ""
	if c.raw != nil && c.doc.OnBattery == "defer" && known && !onAC {
		deferred = "on_battery"
	}
	status := c.status
	if status == "" {
		status = "none"
	}
	var upSince int64
	if !s.upSince.IsZero() {
		upSince = s.upSince.UnixMilli() + a.sec2.offset.Load()
	}
	return map[string]any{
		"protocol":     imagingProtocol,
		"capability":   capability,
		"capabilities": []ImagingCapability{capability},
		"config": map[string]any{"version": c.version, "hash": c.hash, "status": status, "errors": append([]imagingConfigError{}, c.errors...),
			"checks_version": s.checksVersion},
		"checks":     append([]imagingCheck{}, s.checks...),
		"checks_at":  s.checksAtMs,
		"conditions": map[string]any{"on_ac": ac, "up_since": upSince, "events": append([]string{}, s.events...)},
		"deferred":   deferred,
	}, imagingSent{len(s.events), s.gen, s.probeSeq}
}

// imagingAnswered drops the events an answered poll carried.
func (a *Agent) imagingAnswered(sent imagingSent) {
	s := &a.imaging
	s.mu.Lock()
	s.events = s.events[min(sent.events, len(s.events)):]
	s.reportedGen = sent.gen
	if sent.seq == s.probeSeq {
		s.fixesSent = true
	}
	s.mu.Unlock()
}

// imagingWoken: the server asks for a poll, the probe follows it.
func (a *Agent) imagingWoken() {
	s := &a.imaging
	s.mu.Lock()
	s.wakeProbe = true
	s.mu.Unlock()
	imagingWakeUp()
}

func (a *Agent) imagingStarted() {
	s := &a.imaging
	s.mu.Lock()
	s.upSince, s.events, s.refetch = time.Now(), []string{"agent_start"}, true
	s.mu.Unlock()
}

func (a *Agent) imagingReconnected() {
	s := &a.imaging
	s.mu.Lock()
	s.upSince, s.refetch = time.Now(), true
	s.mu.Unlock()
	imagingWakeUp()
}
