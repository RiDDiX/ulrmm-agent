#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

# macOS 13+: MeshAgent LaunchAgent doesn't start at login. Same label
# ("meshagent") as the LaunchDaemon, and users can't enter the mesh dir.
# https://github.com/Ylianst/MeshAgent/issues/161

mesh_dir="${1:?usage: $0 <mesh dir>}"
agent_plist_old=/Library/LaunchAgents/meshagent.plist
agent_plist=/Library/LaunchAgents/meshagent-agent.plist

if [ ! -f /Library/LaunchDaemons/meshagent.plist ]; then
    echo "No meshagent LaunchDaemon, nothing to fix."
    exit 0
fi

if [ -d "${mesh_dir}" ] && /usr/bin/stat -f "%Sp" "${mesh_dir}" | grep -qv 'x$'; then
    echo "Allowing users to enter ${mesh_dir}"
    chmod o+X "${mesh_dir}"
fi

if [ -f "${agent_plist_old}" ]; then
    echo "Renaming ${agent_plist_old} to ${agent_plist}"
    mv "${agent_plist_old}" "${agent_plist}"
fi

# defaults rewrites the plist in binary format.
if [ -f "${agent_plist}" ] && [ "$(defaults read "${agent_plist}" Label)" != "meshagent-agent" ]; then
    echo "Setting Label meshagent-agent in ${agent_plist}"
    defaults write "${agent_plist}" Label "meshagent-agent"
fi
