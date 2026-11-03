# Agent changelog

## 1.03.11.2026 (2026-11-03)

- a keep awake hold on macOS ends with the disablesleep value from before the hold, not always with 0

## 1.02.11.2026 (2026-11-02)

- built with Go 1.27.3, which fixes GO-2026-6809 in crypto/x509 certificate verification

## 2.01.11.2026 (2026-11-01)

- FreeBSD and TrueNAS CORE announce a shutdown or restart when rc.shutdown stops the agent, with the kind and user from the shutdown(8) line
- the cancel after a wake waits for the reconnect, a long sleep dropped it before
- macOS announces at once when the kernel says the system goes down and reads the log only otherwise; a loginwindow notice anyone could post no longer holds back a sleep notice

## 1.01.11.2026 (2026-11-01)

- the agent announces an orderly shutdown, restart or sleep to the server before the machine goes away (check-in mode agent-power) and takes it back with a cancel when it is cancelled or the machine is back
- Windows runs its service through its own handler with PRESHUTDOWN, tells restart from shutdown by System event 1074 (user, process, reason) and reports sleep and the Fast Startup shutdown through the suspend notification
- Linux follows logind PrepareForShutdown and PrepareForSleep from the real logind sender with a delay inhibitor and checks the systemd jobs at the stop signal; existing units get the stop order after the network and a 15 s stop timeout
- macOS follows the root-only loginwindow and power state notifications and reads launchd and shutdown(8) log lines at the stop signal; notices any user could post count only when the kernel confirms the shutdown
- reboot, shutdown and sleep sent from the server are announced before they run
- an announced shutdown or restart no longer counts as a manual service stop

## 1.31.10.2026 (2026-10-31)

- new mode -m licenses prints LICENSE.md NOTICE.md and THIRD_PARTY_NOTICES.md which are built into the agent
- the Windows installer puts these three files into the program folder
- the wire types in the shared package have new names and a new grouping while the json and msgpack format is unchanged across all 56 types with every encoder
- check results share one header type for id and agent_id
- the Windows Update code that reads severity installed and downloaded state is rewritten with the same behaviour
- .gitignore is rewritten with the same rules

## 2.29.10.2026 (2026-10-29)

- Windows agents repair a binary that does not match the server build by having the self-heal response name the sha256 of the agent exe inside the setup so the agent compares against that instead of the setup sha256, which fixes the issue where the integrity check reported a mismatch and never reinstalled, and the same comparison is now used when the service starts and in the scheduled self-heal check

## 1.29.10.2026 (2026-10-29)

- switch license to FSL-1.1-ALv2 with NOTICE.md and SPDX headers in all source files
- retain Apache-2.0 notice in agent/wua_windows.go from Google osconfig
- restructure code without changing behavior including service config, launchd plist builder, lookup tables, and helper functions
- write macOS LaunchDaemon plists with one key per line and have the self-healing job reload once after update
- rewrite README
- set Windows version resource to 1.29.10.2026

## 1.26.10.2026 (2026-10-26)

- Key store: the token pair, client key, uninstall code and identity seed are encrypted with one key per host (`kek1`). The key is sealed by the TPM through the Microsoft Platform Crypto Provider on Windows, with a DPAPI copy, or by DPAPI alone; on Linux by `systemd-creds` (TPM2 without PCR binding plus a host-key copy, or the host key), in the System keychain on macOS, otherwise in a root-only file. Existing values are converted at the first start; nothing is written in the clear once a key store exists. The key store is reported to the server and shown in the trust matrix
- When the key store cannot be opened, the agent opens the copy, reports it and seals the key again; without any copy it stops with the real reason instead of "not installed"
- Uninstall removes the key store (files, keychain item, TPM key and registry values); the Windows setup checks the uninstall code against a stored hash
- Self-check: at start and every 6 hours the agent compares its own binary with the server's signed build manifest and, on a mismatch, reports it and reinstalls the listed build once a day; it never installs an older build
- The API address, CA, pins, proxy and NATS settings are protected by a MAC kept by the service: a change made outside the agent is reported and the agent keeps the last values it verified
- Client certificates are renewed at the share of their lifetime the server's policy sets (renew_pct)

## 3.25.10.2026 (2026-10-25)

- Agent identity: the service makes one random seed at its first start (Windows: DPAPI of the service account, elsewhere the 0600 config), derives a signing key, an X25519 key and a NATS nkey from it and registers the public keys with the server. From then on NATS logs in with the nkey on `/natsws/<agent id>` instead of the token; a server without the endpoint keeps the token login
- The install token is exchanged for a token pair: a short-lived access token for REST and a single-use refresh token, both bound to the identity by signatures. The agent refreshes after 70 % of the access lifetime and on an expired-token answer; after a long offline time (expired certificate or tokens) it recovers with the identity signature, at most every 30 minutes
- Commands come signed with a command key from the server's pin document and encrypted in a session the server opens with a signed X25519 handshake; answers and stream and terminal output go back encrypted, answers also signed. Each command is checked for signature, clock (30 s), session, sequence window and nonce before anything runs; once the pin document turns signed commands on, plaintext commands are refused and reported
- Package job plans, the self-heal download and certificate answers come sealed to the agent's key and are opened only with a valid command key signature
- The agent follows the dashboard's rotate requests (certificate, token, identity) and an identity reset by an admin
- Patch management on Windows Home editions: the AU policy is ignored there, so the agent also sets the 35-day update pause of the Settings app and renews it once a day while patch management is on; turning it off removes the pause

## 2.25.10.2026 (2026-10-25)

- Connections to the RMM (REST, NATS, downloads from the RMM host) need TLS 1.3 and check the server certificate against the pins of the enrollment token and of the server's signed pin document (`/api/v3/pins/`), which the agent stores and refreshes at start; a self-signed server is accepted when its certificate is pinned. When the pins no longer match, the agent fetches a newer signed pin document at most every 5 minutes. Other hosts keep the system roots and TLS 1.2
- `-insecure` was removed: the flag ends the agent with a pointer to `-cert`, a stored insecure setting is dropped at service start. RMM and update URLs over plain http are refused. An agent that used the insecure mode against an IP address or a name its certificate does not cover cannot connect after this update and has to be reinstalled with the certificate's host name
- Agent updates need the server's signature over URL, version and sha256 for this agent, a valid sha256 and a version newer than the running one; the same version does nothing. Windows updates stop when the work directory cannot be locked down
- Refused certificates, pin rescues, refused updates and a dropped insecure setting are reported to the server as security events
- Check-ins go to `<agent id>.checkin`
- `-auth-file <file>` reads the installer token from a root-only file (0600, no link) and deletes it
- Script environment variables the server refuses (interpreter hooks such as `LD_PRELOAD`, `PERL5OPT`, `JAVA_TOOL_OPTIONS`, `GCONV_PATH`) are dropped by the agent too

## 1.25.10.2026 (2026-10-25)

- `-m install -enroll <file>` enrolls with a signed deployment token, read from the block at the end of a deployment setup exe or from a token file; the token is checked against the Ed25519 key built into the agent, and the server certificate against the token's SPKI pins. The Windows setup runs it by itself when it carries a token
- Client certificates: the agent creates a P-256 key, gets its certificate at enrollment (or on its first run after the update) and renews it after two thirds of its lifetime; every connection to the RMM presents it. A certificate the server or nginx refuses is dropped and replaced
- Package jobs: large and archive packages are downloaded by the agent with resume and sha256 check, unpacked (.zip, .7z, .tar.gz, nothing outside the work folder) and installed as SYSTEM or root, with progress to the server

## 2.21.10.2026 (2026-10-21)

- FreeBSD builds (amd64, arm64): rc.d service run through daemon(8), cron self-healing, mesh install and uninstall, services and service checks through rc.d, processes, boot time, disks, sysctl sensors, ZFS/gmirror/graid state, pf/ipfw state, idle time, suspend with Wake-on-LAN, `/bin/sh` as default shell; keep awake answers "keep awake is not available on FreeBSD"
- TrueNAS SCALE: files under `/root/ulrmm-agent` and `/root/ulrmm-mesh`, scripts in `/var/tmp/ulrmm-agent`, OS reported as TrueNAS with its version; the agent keeps a POSTINIT init script registered and `-m selfheal` restores the units after a TrueNAS update
- Self-healing right after a restore no longer takes the restarted agent for hung
- Terminals fall back to `/bin/sh` when `/bin/bash` is missing; an update refuses a binary built for another OS

## 1.21.10.2026 (2026-10-21)

- Windows: command output that is not UTF-8 is decoded line by line with the OEM or the ANSI code page, whichever reads as text (pnputil output showed "÷" for "ö" in cmd)

## 7.20.10.2026 (2026-10-20)

- Windows: SDIO driver jobs report download progress to the server (bytes so far and pack size), at most every 5 seconds; a slow server does not slow the download

## 5.20.10.2026 (2026-10-20)

- Windows: installs driver updates approved on the server from SDIO driver packs. The agent downloads the pack from the SDIO mirror over https into a folder in its work directory, checks its pieces against the torrent's SHA1 hashes (the first or last piece only when the mirror also has the neighboring file; a broken download resumes at the last good piece), unpacks only the approved driver folders, installs them with the server's install script as SYSTEM and deletes the files. One job at a time; Linux and macOS answer "not supported on this OS"

## 4.20.10.2026 (2026-10-20)

- Windows: winget runs as SYSTEM without a signed-in user; its VC++ runtime package is put on PATH, which Windows does not resolve for SYSTEM (exit 0xC0000135 before). Installs and app updates both benefit

## 3.20.10.2026 (2026-10-20)

- Windows: installs packages from winget on request (exact id, machine scope, silent), as SYSTEM first and with the signed-in user's token where Windows needs it; shares the lock with app updates
- App update ids with characters such as & ! @ + are accepted

## 2.20.10.2026 (2026-10-20)

- Windows: command, script and package output in the system's OEM code page keeps umlauts and other non-ASCII letters instead of dropping them
- Windows: a driver package deleted with pnputil no longer shows in the driver list until the next reboot

## 1.20.10.2026 (2026-10-20)

- Windows: reports installed drivers and devices with problems once a day and on request from the dashboard
- Windows: driver updates from Windows Update are found and installed when the server asks for them; older servers keep the software-only search
- Windows: installing an approved update tries the driver search before reporting it as superseded

## 1.19.10.2026 (2026-10-19)

- Reports system state every five minutes: failed or starting systemd units, mounts with read-only and stale flags and inode usage, time sync source and offset, RAID state (md, ZFS, vendor controllers via their CLI), temperature, fan and voltage sensors (hwmon, IPMI)
- Reports network interfaces with link state, speed and duplex, addresses, bond and bridge membership, and per-second rates for bytes, packets, errors and drops
- Reports containers and virtual machines: Docker and Podman with CPU, memory and network per container, LXD and Incus, plain LXC, Proxmox guests and cluster quorum, Hyper-V on Windows
- Reports CPU, memory, swap and load with the same push, so the server keeps a metric history without polling
- New checks: systemd unit (with optional restart) and container state; metric threshold checks are judged by the server from the pushed values
- Windows reports performance, mounts, interfaces and Hyper-V; macOS reports performance, mounts and interfaces

## 1.14.10.2026 (2026-10-14)

- Process list on macOS shows names and memory again; one ps call replaces the per-process lookups that need cgo
- Process CPU is the current share of the whole machine since the last refresh (all systems), so the total no longer goes past 100 %
- Refreshes closer than half a second reuse the last answer instead of queueing on the agent
- Ending a process on macOS no longer starts lsof and ps for every process to find its children

## 3.11.10.2026 (2026-10-11)

- Updated github.com/klauspost/compress; no known vulnerabilities reachable from the agent

## 2.11.10.2026 (2026-10-11)

- Updated golang.org/x/net and golang.org/x/text and built with Go 1.27.2; clears the known net/http, HTTP/2, TLS and text vulnerabilities (govulncheck: none reachable)

## 1.11.10.2026 (2026-10-11)

- Agent re-implemented from its behaviour specification; wire protocol, install paths, service names and config keys are unchanged, installed agents update in place
- Downloads of agent updates, nushell, deno and the chocolatey install script are checked against the sha256 the server sends; agent updates are fetched over https only, except on agents installed with -insecure
- Registry editor: the default value of a key can be read, created, changed and deleted; SAM, SECURITY and the agent's own configuration and service keys are refused; bad page values, oversized values and symlink keys give an error instead of a crash
- Streamed commands and terminals send one done event with the real exit code; a terminal kill ends the whole process tree; UTF-8 output is split on character boundaries; script output is capped at 4 MiB per stream with a marker
- Unknown shells, malformed scheduled-task payloads and malformed requests get an error reply instead of a crash; PowerShell scripts run with -File so their exit codes reach the dashboard; event log parameter references no longer fall back to the system message table
- Linux and macOS: run as user runs as the console user, agent updates check the new binary and keep a rollback copy, uninstall no longer executes server-supplied script text
- Check-in intervals are clamped to at least 5 seconds; WinTmpDir and natsproxy config keys are honoured; a command timeout of 0 means 60 seconds

## 2.09.10.2026 (2026-10-09)

- Run winget as the signed-in user when the service cannot

## 1.09.10.2026 (2026-10-09)

- App updates over winget, brew and mas, uninstall code and service protection

## 1.08.10.2026 (2026-10-08)

- Verify updates, lock down the Windows work dir and logs

## 2.07.10.2026 (2026-10-07)

- Hold the lid open for keepawake and survive restarts

## 1.07.10.2026 (2026-10-07)

- List, control and read logs of POSIX services

## 1.06.10.2026 (2026-10-06)

- Take the Deno permission list after the first equals sign

## 2.25.09.2026 (2026-09-25)

- Ask SATA disks as sat, count SSH without a pty as active

## 1.25.09.2026 (2026-09-25)

- Report endpoint health and wake support, add keepawake and idle

## 1.24.09.2026 (2026-09-24)

- First release under the UniversalLocal RMM name

