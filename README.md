# atomic-lockfile-supply-chain-attack

[English](README.md) | [Español](README.es.md)

Detector for indicators associated with the `atomic-lockfile` AUR supply-chain
attack.

- Author: [l0rdmalware](https://l0rdmalware.cc)
- Repository: <https://github.com/l0rdmalware/atomic-lockfile-supply-chain-attack>
- Reference project: <https://github.com/lenucksi/aur-malware-check>

## Versions

All versions accept the same options and use the
`aur_infected_packages.md` list.

```bash
# Bash
./check_supply-chain-attack.sh --full

# zsh
./check_supply-chain-attack.zsh --full

# fish
./check_supply-chain-attack.fish --full

# Python 3.9+
./check_supply-chain-attack.py --full
```

The zsh and fish launchers use the Python implementation to maintain identical
behavior. The Bash version is independent.

## Main Options

```text
--update             Update the affected package list
--list FILE          Use a different Markdown list
--skip-logs          Skip the pacman history scan
--check-systemd      Check systemd units for persistence
--check-ebpf         Check for known eBPF map names
--check-npm-cache    Check npm artifacts
--check-bun-cache    Check bun artifacts
--full               Enable all optional checks
--all-time           Scan the complete pacman history
-v, --verbose        Show the files being inspected
```

## Requirements

- Arch Linux or a system with `pacman`.
- Bash for the `.sh` version.
- Python 3.9 or newer for the `.py`, `.zsh`, and `.fish` versions.
- zsh or fish for the corresponding launcher.
- `zstdcat` to inspect pacman logs compressed with Zstandard.

## Exit Codes

- `0`: no indicators were found.
- `1`: the scan was incomplete or an error occurred.
- `2`: one or more indicators were found.

A match is an indicator requiring investigation, not automatic confirmation
of compromise.
