# Runner host scripts

## `runner-selfupdate.sh`
Fast-forwards this checkout to `origin/master` and restarts the runner service
**only when `HEAD` actually moves**. It fetches headlessly (SSH `BatchMode`, no
credential prompt) and is non-destructive: it only advances a branch that is
purely behind `origin/master`, and skips (changing nothing) if the branch has
diverged, carries local commits, or is on a non-`master` branch.

## 24/7 runner (systemd user units, on the runner laptop)
These live in `~/.config/systemd/user/` (machine-local, not in the repo):

- `chack-runner.service` — supervises `./cHack.sh -D`; `Restart=always`;
  wrapped in `systemd-inhibit --what=sleep:idle` so the machine stays awake
  while the runner is up. Starts at boot (user lingering enabled).
- `chack-update.service` + `chack-update.timer` — runs `runner-selfupdate.sh`
  ~3 min after boot and hourly (`Persistent=true` catches missed runs on wake).

### Managing
```bash
systemctl --user status  chack-runner          # runner health
journalctl --user -u chack-runner -f           # live runner logs
journalctl --user -u chack-update -n 20        # last update checks
systemctl --user start   chack-update          # force an update check now
systemctl --user stop    chack-runner          # pause (releases the sleep lock)
systemctl --user disable --now chack-update.timer chack-runner   # remove
```

### Power
A laptop runner should stay on AC. Lid-close only suspends on battery by
default (`HandleLidSwitchExternalPower=ignore`); to keep it running on battery
with the lid shut, set `HandleLidSwitch=ignore` in a
`/etc/systemd/logind.conf.d/*.conf` drop-in (root).
