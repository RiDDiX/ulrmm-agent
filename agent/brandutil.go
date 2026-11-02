// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import "strings"

// brandPlistSafe escapes a branding value for the launchd plist. A company
// name containing & or <> would otherwise produce malformed XML, launchctl
// would refuse to load the daemon and a fresh mac install would never start.
// Lives outside brand.go because the build pipeline rewrites that file.
func brandPlistSafe(s string) string {
	return strings.NewReplacer(
		"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;",
	).Replace(s)
}

// pubIPURLs returns where to ask for this machine's public address. With
// BrandPubIPURL set the rmm server answers it, so the fleet stops announcing
// itself to a third party on every checkin.
func pubIPURLs() []string {
	if BrandPubIPURL != "" {
		return []string{BrandPubIPURL}
	}
	return []string{"https://icanhazip.com", "https://ifconfig.co/ip"}
}

// pubIPFallbackURL is used when the first answer was not IPv4.
func pubIPFallbackURL() string {
	if BrandPubIPURL != "" {
		return BrandPubIPURL
	}
	return "https://ifconfig.me/ip"
}
