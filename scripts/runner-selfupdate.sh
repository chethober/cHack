#!/usr/bin/env bash
# Keep the cHack runner in sync with origin/master, safely.
#
# Fast-forwards the local checkout to origin/master and restarts the runner
# service only when the code actually changed. It never discards local commits
# or uncommitted work: if the branch has diverged or a fast-forward is not
# possible, it logs and leaves everything untouched.
#
# Invoked by the chack-update.timer systemd user unit (see docs), or by hand.
set -euo pipefail

REPO="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
BRANCH="master"
RUNNER_UNIT="chack-runner.service"
cd "$REPO"

# Never block on an interactive SSH/credential prompt when run from a timer.
export GIT_SSH_COMMAND="${GIT_SSH_COMMAND:-ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new}"
export GIT_TERMINAL_PROMPT=0

log(){ printf '[selfupdate %(%Y-%m-%dT%H:%M:%S)T] %s\n' -1 "$*"; }

# Only operate on the tracking branch; stay out of the way on feature branches.
cur="$(git rev-parse --abbrev-ref HEAD)"
if [ "$cur" != "$BRANCH" ]; then
  log "on '$cur', not '$BRANCH' — skipping auto-update."; exit 0
fi

git fetch --quiet origin "$BRANCH" || { log "git fetch failed — skipping."; exit 0; }

local_rev="$(git rev-parse HEAD)"
remote_rev="$(git rev-parse "origin/$BRANCH")"
if [ "$local_rev" = "$remote_rev" ]; then
  log "already up to date ($(git rev-parse --short HEAD))."; exit 0
fi

# Fast-forward only when HEAD is an ancestor of origin/master (purely behind).
# Anything else (local commits, divergence) is left alone.
if ! git merge-base --is-ancestor HEAD "origin/$BRANCH"; then
  log "local branch has diverged from origin/$BRANCH (local commits?) — skipping, nothing changed."; exit 0
fi

if git merge --ff-only --quiet "origin/$BRANCH"; then
  log "updated $(git rev-parse --short "$local_rev") -> $(git rev-parse --short HEAD); restarting runner."
  systemctl --user restart "$RUNNER_UNIT" && log "runner restarted."
else
  log "fast-forward blocked (local changes to incoming files) — skipping, nothing changed."
fi
