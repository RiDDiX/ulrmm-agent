// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"bytes"
	"encoding/xml"
	"io"
	"testing"
	"unicode/utf16"
)

func TestHealTaskXML(t *testing.T) {
	bin := `C:\Program Files\R&D <x>\agent.exe`
	b := healTaskXML(bin)
	if len(b) < 2 || b[0] != 0xff || b[1] != 0xfe || len(b)%2 != 0 {
		t.Fatal("not UTF-16 LE with BOM")
	}
	u := make([]uint16, 0, len(b)/2-1)
	for i := 2; i < len(b); i += 2 {
		u = append(u, uint16(b[i])|uint16(b[i+1])<<8)
	}
	var task struct {
		Interval  string `xml:"Triggers>TimeTrigger>Repetition>Interval"`
		Start     string `xml:"Triggers>TimeTrigger>StartBoundary"`
		User      string `xml:"Principals>Principal>UserId"`
		RunLevel  string `xml:"Principals>Principal>RunLevel"`
		Instances string `xml:"Settings>MultipleInstancesPolicy"`
		NoBattery string `xml:"Settings>DisallowStartIfOnBatteries"`
		StopBatt  string `xml:"Settings>StopIfGoingOnBatteries"`
		Limit     string `xml:"Settings>ExecutionTimeLimit"`
		Command   string `xml:"Actions>Exec>Command"`
		Args      string `xml:"Actions>Exec>Arguments"`
	}
	d := xml.NewDecoder(bytes.NewReader([]byte(string(utf16.Decode(u)))))
	d.CharsetReader = func(_ string, r io.Reader) (io.Reader, error) { return r, nil }
	if err := d.Decode(&task); err != nil {
		t.Fatal(err)
	}
	if task.Interval != "PT15M" || task.Start == "" || task.User != "S-1-5-18" || task.RunLevel != "HighestAvailable" ||
		task.Instances != "IgnoreNew" || task.NoBattery != "false" || task.StopBatt != "false" || task.Limit != "PT30M" ||
		task.Command != bin || task.Args != "-m selfheal" {
		t.Fatalf("%+v", task)
	}
}
