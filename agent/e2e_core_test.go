// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

//go:build e2e && !windows

package agent

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	nats "github.com/nats-io/nats.go"
	"github.com/sirupsen/logrus"
	"github.com/ugorji/go/codec"
)

func e2eDecode(t *testing.T, b []byte) interface{} {
	var v interface{}
	var mh codec.MsgpackHandle
	mh.RawToString = true
	if err := codec.NewDecoderBytes(b, &mh).Decode(&v); err != nil {
		t.Fatalf("decode %q: %v", b, err)
	}
	return v
}

func TestE2ECore(t *testing.T) {
	url := os.Getenv("NATS_URL")
	agentNC, err := nats.Connect(url, nats.NoEcho())
	if err != nil {
		t.Fatal(err)
	}
	defer agentNC.Close()
	a := &Agent{Logger: logrus.New(), AgentID: "e2eagent", Version: "9.11.10.2026"}
	a.Logger.SetLevel(logrus.DebugLevel)
	if _, err := agentNC.Subscribe(a.AgentID, func(m *nats.Msg) { a.dispatch(agentNC, m) }); err != nil {
		t.Fatal(err)
	}
	agentNC.Flush()

	srv, err := nats.Connect(url)
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	request := func(v map[string]interface{}, timeout time.Duration) interface{} {
		b, _ := encodeMsgpack(v)
		m, err := srv.Request(a.AgentID, b, timeout)
		if err != nil {
			t.Fatalf("%v: %v", v["func"], err)
		}
		return e2eDecode(t, m.Data)
	}

	if r := request(map[string]interface{}{"func": "ping"}, 2*time.Second); r != "pong" {
		t.Fatalf("ping: %v", r)
	}
	if r := request(map[string]interface{}{"func": "nosuchfunc"}, 2*time.Second); r != "unknown request: nosuchfunc" {
		t.Fatalf("unknown func: %v", r)
	}
	if r := request(map[string]interface{}{"func": "needsreboot"}, 5*time.Second); r != false && r != true {
		t.Fatalf("needsreboot: %#v", r)
	}

	// sysinfo answers before the slow check-ins it starts
	start := time.Now()
	if r := request(map[string]interface{}{"func": "sysinfo"}, 5*time.Second); r != "ok" || time.Since(start) > time.Second {
		t.Fatalf("sysinfo: %v after %v", r, time.Since(start))
	}

	// streamed rawcmd: lines, one done with the real exit code, full reply
	var mu sync.Mutex
	var lines []string
	var dones []interface{}
	sub, _ := srv.Subscribe(a.AgentID+".cmdoutput.c1", func(m *nats.Msg) {
		mu.Lock()
		defer mu.Unlock()
		switch v := e2eDecode(t, m.Data).(type) {
		case string:
			lines = append(lines, v)
		default:
			dones = append(dones, v)
		}
	})
	defer sub.Unsubscribe()
	srv.Flush()
	r := request(map[string]interface{}{
		"func": "rawcmd", "timeout": 10, "stream": true,
		"payload": map[string]string{"shell": "/bin/sh", "command": "echo a; echo b 1>&2; exit 3", "cmd_id": "c1"},
	}, 15*time.Second)
	if r != "a\n\nb\n" {
		t.Fatalf("rawcmd reply %q", r)
	}
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	if len(dones) != 1 || strings.Join(lines, ",") != "a,b" && strings.Join(lines, ",") != "b,a" {
		t.Fatalf("stream lines %q dones %v", lines, dones)
	}
	if d, ok := dones[0].(map[interface{}]interface{}); !ok || d["done"] != true || fmt.Sprint(d["exit_code"]) != "3" {
		t.Fatalf("done %#v", dones[0])
	}
	mu.Unlock()

	// check-in framing: reply subject is the mode
	got := make(chan *nats.Msg, 1)
	ci, _ := srv.Subscribe(a.AgentID, func(m *nats.Msg) {
		if m.Reply == "agent-hello" {
			got <- m
		}
	})
	srv.Flush()
	a.NatsMessage(agentNC, "agent-hello")
	select {
	case m := <-got:
		hello := e2eDecode(t, m.Data).(map[interface{}]interface{})
		if hello["agent_id"] != a.AgentID || hello["version"] != a.Version || len(hello) != 2 {
			t.Fatalf("hello %v", hello)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no agent-hello")
	}
	ci.Unsubscribe()

	// terminal: early resize, ordered input, UTF-8 safe chunks, done
	var out strings.Builder
	termDone := make(chan map[interface{}]interface{}, 2)
	var chunksValid = true
	ts, _ := srv.Subscribe(a.AgentID+".terminal.s1", func(m *nats.Msg) {
		switch v := e2eDecode(t, m.Data).(type) {
		case string:
			mu.Lock()
			out.WriteString(v)
			if !utf8.ValidString(v) {
				chunksValid = false
			}
			mu.Unlock()
		case map[interface{}]interface{}:
			termDone <- v
		}
	})
	defer ts.Unsubscribe()
	srv.Flush()
	pub := func(fn string, p map[string]string) {
		b, _ := encodeMsgpack(map[string]interface{}{"func": fn, "payload": p})
		srv.Publish(a.AgentID, b)
	}
	pub("terminal_resize", map[string]string{"session_id": "s1", "rows": "33", "cols": "101"})
	pub("terminal_start", map[string]string{"session_id": "s1", "shell": "/bin/sh"})
	for i := 0; i < 50; i++ {
		pub("terminal_input", map[string]string{"session_id": "s1", "data": "x" + string(rune('A'+i%26))})
	}
	pub("terminal_input", map[string]string{"session_id": "s1", "data": "\n"})
	pub("terminal_input", map[string]string{"session_id": "s1", "data": "stty size; i=0; while [ $i -lt 3000 ]; do printf 'é'; i=$((i+1)); done; echo; exit 0\n"})
	select {
	case d := <-termDone:
		if d["done"] != true || fmt.Sprint(d["exit_code"]) != "0" {
			t.Fatalf("terminal done %v", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("no terminal done, output %q", out.String())
	}
	mu.Lock()
	o := out.String()
	mu.Unlock()
	var typed strings.Builder
	for i := 0; i < 50; i++ {
		typed.WriteString("x" + string(rune('A'+i%26)))
	}
	if !strings.Contains(o, typed.String()) || !strings.Contains(o, "33 101") || !strings.Contains(o, strings.Repeat("é", 3000)) || !chunksValid {
		t.Fatalf("terminal output (valid chunks %v): %q", chunksValid, o)
	}

	// duplicate session and kill
	pub("terminal_start", map[string]string{"session_id": "s2", "shell": "/bin/sh"})
	time.Sleep(300 * time.Millisecond)
	errs := make(chan map[interface{}]interface{}, 2)
	s2, _ := srv.Subscribe(a.AgentID+".terminal.s2", func(m *nats.Msg) {
		if v, ok := e2eDecode(t, m.Data).(map[interface{}]interface{}); ok {
			errs <- v
		}
	})
	defer s2.Unsubscribe()
	srv.Flush()
	pub("terminal_start", map[string]string{"session_id": "s2", "shell": "/bin/sh"})
	select {
	case e := <-errs:
		if e["output"] != "[ERROR] session already exists: s2\r\n" || fmt.Sprint(e["exit_code"]) != "1" || e["done"] != true {
			t.Fatalf("duplicate: %v", e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no duplicate error")
	}
	pub("terminal_kill", map[string]string{"session_id": "s2"})
	select {
	case e := <-errs:
		if e["done"] != true || fmt.Sprint(e["exit_code"]) != "-1" {
			t.Fatalf("kill done: %v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no done after kill")
	}
}
