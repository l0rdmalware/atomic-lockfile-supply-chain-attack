#!/usr/bin/env zsh

# Native zsh entry point for the shared Python implementation.
set -u

readonly SCRIPT_DIR=${0:A:h}
readonly PYTHON_SCRIPT="$SCRIPT_DIR/check_supply-chain-attack.py"

if ! command -v python3 >/dev/null 2>&1; then
    print -u2 -- "ERROR: python3 is required"
    exit 1
fi

if [[ ! -r $PYTHON_SCRIPT ]]; then
    print -u2 -- "ERROR: Python implementation not found: $PYTHON_SCRIPT"
    exit 1
fi

export SUPPLY_CHAIN_ENTRYPOINT=${0:t}
exec python3 "$PYTHON_SCRIPT" "$@"
