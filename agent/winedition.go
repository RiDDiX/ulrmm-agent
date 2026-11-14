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

const pauseLayout = "2006-01-02T15:04:05Z"

// pauseWindow is the start and end of the pause, as the Settings app writes it.
func pauseWindow(now time.Time) (start, end string) {
	now = now.UTC()
	return now.Format(pauseLayout), now.AddDate(0, 0, pauseDays).Format(pauseLayout)
}

// The pause values pauseConsumerUpdates writes, all starts with one time and
// all ends with another.
var (
	pauseStartValues = []string{"PauseUpdatesStartTime", "PauseFeatureUpdatesStartTime", "PauseQualityUpdatesStartTime"}
	pauseEndValues   = []string{"PauseUpdatesExpiryTime", "PauseFeatureUpdatesEndTime", "PauseQualityUpdatesEndTime"}
)

// agentAUOption is true for the AUOptions values the agent writes: 1, and 0
// in older versions. Any other value comes from a policy and stays.
func agentAUOption(v uint64) bool { return v <= 1 }

// agentPause is true when the pause values found (name to value, missing
// ones left out) are a window pauseWindow wrote. A pause the user set or
// changed in the Settings app since then stays.
func agentPause(found map[string]string) bool {
	t, err := time.Parse(pauseLayout, found[pauseStartValues[0]])
	if err != nil {
		return false
	}
	start, end := pauseWindow(t)
	for _, n := range pauseStartValues {
		if v, ok := found[n]; ok && v != start {
			return false
		}
	}
	for _, n := range pauseEndValues {
		if v, ok := found[n]; ok && v != end {
			return false
		}
	}
	return true
}
