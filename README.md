# UniversalLocal RMM Agent

[![Run tests](https://github.com/RiDDiX/ulrmm-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/RiDDiX/ulrmm-agent/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-FSL--1.1--ALv2-blue)](LICENSE.md)
[![Security policy](https://img.shields.io/badge/security-policy-informational)](SECURITY.md)

The endpoint agent of UniversalLocal RMM for Windows, Linux, macOS and FreeBSD
including TrueNAS. Written in Go, one self-contained binary per target.

Release agents are built and signed only by the UniversalLocal RMM server
(`riddix/agents/build_agents.sh`), which writes branding and the agent identity
into `agent/brand.go` before compiling and builds the Windows installer from
`build/setup.iss`. Installing the server and adding agents is described in the
[server README](https://github.com/RiDDiX/ulrmm) (`../README.md` when this
repository is checked out inside the server repository). A feature tour with
screenshots is in the server repository under
[docs/SHOWCASE.md](https://github.com/RiDDiX/ulrmm/blob/main/docs/SHOWCASE.md).

## What the agent does

- Holds three keys per device: an Ed25519 identity key, an X25519 sealing key
  and a NATS nkey (`agent/identity.go`, `agent/seal.go`).
- Talks to the server over TLS 1.3 only, with mutual TLS (client certificate)
  and a signed pin set of SubjectPublicKeyInfo hashes instead of the system
  trust store. X25519MLKEM768 is the preferred key exchange (`agent/trust.go`).
  When no pin matches, the agent fetches the signed pin document, re-checks and
  reports `pin_mismatch` or `tls_failure`.
- Every command arrives in an envelope signed with the server's Ed25519 command
  key and encrypted with ChaCha20-Poly1305; session keys come from an ephemeral
  X25519 exchange and HKDF; the agent re-keys after 64 MiB or 100,000 messages
  and the server additionally ratchets the epoch by time (`agent/session.go`,
  `agent/envelope.go`). Unsigned commands are refused.
- Uses each refresh token once (`agent/credential.go`); the server treats a
  second use of a rotated token as a clone and can quarantine the identity.
- Recovers after an offline period within the server's grace: a signed CSR plus
  identity signature gets a new certificate and token family; retried every
  30 minutes (`agent/credential.go`).
- Renews its client certificate automatically at a configurable share of its
  lifetime (`agent/svc.go`).
- Takes updates only over https, with a valid sha256 and the server's signature
  for this agent; downgrades are refused (`agent/security.go`). On Linux, macOS
  and FreeBSD the downloaded binary runs `-selftest` (TLS 1.3 handshake with
  the pinned trust, `/core/health/` answers) before it replaces the running
  build, and the service reverts to the previous binary when the server is not
  reached within ten minutes of service start (`update_reverted` event). On
  Windows the signed installer replaces the files; there is no rollback copy.
- Checks its own executable at start and every six hours against a signed
  manifest from the server and reports `integrity_mismatch`; repair is
  attempted at most daily (`agent/integrity.go`). Self-heal on Unix runs from a
  second copy under the agent directory (`agent/agent_unix.go`).
- Agent protection: an uninstall code the server keeps per agent, a marker for
  service stops the agent did not cause, `config_tampered` when the
  configuration is changed outside the agent and `clock_skew` reports
  (`agent/protect.go`, `agent/agent.go`).
- Keep-awake for maintenance windows, at most six hours per request, with lid
  handling: a logind inhibitor on Linux, `powercfg` lid actions on Windows; the
  state survives a restart via `keepawake.json` (`agent/power.go`).
- Hardware health: disks, temperatures with warning and critical thresholds,
  battery cycles and condition, Wake-on-LAN capability, collected per OS with a
  30-second deadline (`agent/health.go`).
- Process list with CPU and memory, service control, journald and macOS unified
  log queries (`agent/process.go`, `agent/svc.go`, `agent/nixlogs.go`) and the
  Windows event log (`agent/eventlog_windows.go`).
- FreeBSD support with TrueNAS SCALE detection (`agent/freebsd.go`,
  `agent/agent.go`).

These points describe how the agent works; they are not a promise that it has
no flaws.

## Network contacts

The agent talks to the RMM server, MeshCentral and, when used, the RustDesk
server. On its own it also contacts:

- icanhazip.com and ifconfig.co, with ifconfig.me as fallback, for its public
  IP address at check-in, but only when it was built without
  `ULRMM_AGENT_PUBIP_URL`. `install.sh` and the Docker setup set it to
  `https://<api host>/pubip`, so these agents ask the RMM server instead.
- github.com, to download Nushell or Deno the first time a script needs that
  runtime and the server offers no download of its own.
- chocolatey.org, for the Chocolatey install script when the server has no
  copy of it.
- the web seed of Snappy Driver Installer Origin, for the driver packs the
  driver feature installs.

## Supported systems

What the Go 1.27 toolchain supports: Windows 10 and Windows Server 2016 or newer
(amd64, 386), macOS 13 or newer (Intel and Apple Silicon), Linux with systemd
(amd64, arm64, 386, arm), FreeBSD (amd64, arm64) including TrueNAS.

## Version

The agent has its own version in the format `X.DD.MM.YYYY` (release date, `X` =
release number of that day, stored without `v`). It changes only when the agent
changes. `version` in `main.go` and `MyAppVersion` in `build/setup.iss` must
equal `LATEST_AGENT_VER` in the server's `api/ulrmm/ulrmm/settings.py`.

## Local build

Go 1.27.3, the version the server pins (`GO_VER` in
`riddix/scripts/go_toolchain.sh`):

```bash
for t in linux/amd64 linux/386 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/386 freebsd/amd64 freebsd/arm64; do
  env CGO_ENABLED=0 GOOS=${t%/*} GOARCH=${t#*/} go build -trimpath -buildvcs=false -ldflags "-s -w" -o /dev/null .
done
```

## Gates

Before every commit:

```bash
gofmt -l .                                  # must print nothing
for os in linux darwin windows freebsd; do GOOS=$os go vet ./...; done
CGO_ENABLED=0 go test ./...
CGO_ENABLED=1 go test -race -run "Heal|Setup|Restore|Reinstall|Refuses|Accepts|Uninstalled|Service|Hung|Rate|Disabled|SafeJoin" ./agent/
```

plus the ten-target build above, and `-version` of the linux/amd64 build must
print the version from `main.go`. On the server side:
`python3 riddix/agents/write_brand.py --selftest` and
`python3 riddix/scripts/check_versions.py --agent <path to this checkout>`.

## License and third-party software

Licensed under the Functional Source License, Version 1.1, ALv2 Future License
([LICENSE.md](LICENSE.md)); two years after a version is made available it is
also licensed under Apache-2.0. If you redistribute copies, modifications or
derivatives, include LICENSE.md or a link to it and keep the copyright notices,
[NOTICE.md](NOTICE.md) included.

Third-party parts keep their own licenses: `agent/wua_windows.go` (Google
osconfig, Apache-2.0), `internal/taskmaster` and `internal/winapi` (MIT), the
winpty binaries in `agent/winpty_bins` (MIT), the Go modules compiled into the
agent and the Inno Setup runtime in the Windows installer.
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) lists them with their license
texts. Every agent carries these notices: `-m licenses` prints them together
with LICENSE.md and NOTICE.md, and the Windows installer puts the three files
into the program folder. Whoever passes agent binaries or installers on to
others has to pass these notices on with them.

The agent runs as SYSTEM or root and executes what the server sends it. It is
provided as is, without warranty, see LICENSE.md, and the notes in the
[server README](https://github.com/RiDDiX/ulrmm#use-at-your-own-risk) apply.
Product names such as Windows, macOS, FreeBSD and TrueNAS are trademarks of
their owners; the project is not affiliated with or endorsed by them.
