// SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
// SPDX-License-Identifier: FSL-1.1-ALv2

package agent

// The build (riddix/agents/write_brand.py on the server) rewrites this file
// from the server settings. The committed values are the defaults.
var (
	BrandProductName    = "UniversalLocal RMM"
	BrandAgentName      = "UniversalLocal RMM Agent"
	BrandServiceDisplay = "UniversalLocal RMM Agent Service"
	BrandPublisher      = "UniversalLocal RMM"

	// Endpoints the agent would otherwise fetch from a third party.
	BrandPubIPURL = ""
	BrandPyURL    = ""

	// Ed25519 public key (base64 of the raw 32 bytes) the server signs
	// enrollment data with. Empty: the build cannot enroll from a deployment.
	BrandEnrollPubKey = ""

	// Identity: how the agent is installed and found again. The defaults are
	// ulrmm's. The build overwrites them from AGENT_* on the server.
	IdentWinSvcName    = "ulrmm-agent"
	IdentWinExe        = "ulrmm-agent.exe"
	IdentWinProgDir    = "ULRMM Agent"
	IdentWinRegKey     = "UniversalLocalRMM"
	IdentNixBin        = "ulrmm-agent"
	IdentNixDir        = "/opt/ulrmm-agent"
	IdentNixConf       = "/etc/ulrmm-agent"
	IdentNixSvc        = "ulrmm-agent.service"
	IdentMacPlistLabel = "ulrmm-agent"
	IdentTaskPrefix    = "ULRMM_"
	IdentArtifact      = "ulrmm-agent"
)
