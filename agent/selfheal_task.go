// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import (
	"encoding/xml"
	"strings"
	"unicode/utf16"
)

// healTaskXML is the Windows task of the self-healing job, in the UTF-16 with
// BOM schtasks /XML reads. schtasks /SC cannot turn off the battery stops, so
// on a laptop off power the job would never run.
func healTaskXML(healBin string) []byte {
	var cmd strings.Builder
	_ = xml.EscapeText(&cmd, []byte(healBin))
	s := `<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>PT15M</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2026-01-01T00:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <Enabled>true</Enabled>
    <ExecutionTimeLimit>PT30M</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>` + cmd.String() + `</Command>
      <Arguments>-m selfheal</Arguments>
    </Exec>
  </Actions>
</Task>
`
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, 2+2*len(u))
	b = append(b, 0xff, 0xfe)
	for _, c := range u {
		b = append(b, byte(c), byte(c>>8))
	}
	return b
}
