// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import "time"

// Home editions ignore the WindowsUpdate policies; the consumer pause switch
// holds at most 35 days, so the service re-arms it once a day.
const (
	pauseDays       = 35
	patchRearmEvery = 24 * time.Hour
)

// homeEdition is true for the EditionID of a Home edition.
func homeEdition(editionID string) bool {
	switch editionID {
	case "Core", "CoreN", "CoreSingleLanguage", "CoreCountrySpecific":
		return true
	}
	return false
}

// pauseWindow is the start and end of the pause, as the Settings app writes it.
func pauseWindow(now time.Time) (start, end string) {
	const layout = "2006-01-02T15:04:05Z"
	now = now.UTC()
	return now.Format(layout), now.AddDate(0, 0, pauseDays).Format(layout)
}
