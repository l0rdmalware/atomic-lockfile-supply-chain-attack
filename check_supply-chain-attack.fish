#!/usr/bin/env fish

# Native fish entry point for the shared Python implementation.
set -l script_path (status --current-filename)
set -l script_dir (cd (dirname "$script_path"); and pwd -P)
set -l python_script "$script_dir/check_supply-chain-attack.py"

if not type -q python3
    echo "ERROR: python3 is required" >&2
    exit 1
end

if not test -r "$python_script"
    echo "ERROR: Python implementation not found: $python_script" >&2
    exit 1
end

set -lx SUPPLY_CHAIN_ENTRYPOINT (basename "$script_path")
exec python3 "$python_script" $argv
