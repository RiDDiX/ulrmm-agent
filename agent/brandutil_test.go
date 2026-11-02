// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

import "testing"

func TestPubIPURLsFollowBranding(t *testing.T) {
	old := BrandPubIPURL
	defer func() { BrandPubIPURL = old }()

	BrandPubIPURL = ""
	if got := pubIPURLs(); len(got) != 2 || got[0] != "https://icanhazip.com" {
		t.Fatalf("default changed: %v", got)
	}
	if pubIPFallbackURL() != "https://ifconfig.me/ip" {
		t.Fatalf("default fallback changed: %s", pubIPFallbackURL())
	}

	BrandPubIPURL = "https://api.example.com/pubip"
	got := pubIPURLs()
	if len(got) != 1 || got[0] != BrandPubIPURL {
		t.Fatalf("branded build must ask only our own host, got %v", got)
	}
	if pubIPFallbackURL() != BrandPubIPURL {
		t.Fatalf("ipv4 fallback still leaves the deployment: %s", pubIPFallbackURL())
	}
}

func TestBrandPlistSafe(t *testing.T) {
	if got := brandPlistSafe(`A&B <"x">`); got != "A&amp;B &lt;&quot;x&quot;&gt;" {
		t.Fatalf("plist escaping: %s", got)
	}
}
