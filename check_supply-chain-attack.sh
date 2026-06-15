#!/usr/bin/env bash

# Project: atomic-lockfile-supply-chain-attack
# Author: l0rdmalware
# Website: https://l0rdmalware.cc
# Repository: https://github.com/l0rdmalware/atomic-lockfile-supply-chain-attack
#
# Detection features were adapted with reference to the original community
# project maintained at:
# https://github.com/lenucksi/aur-malware-check

set -euo pipefail

readonly SCRIPT_NAME="check_supply-chain-attack.sh"
readonly SCRIPT_VERSION="1.1.1"
readonly PROJECT_NAME="atomic-lockfile-supply-chain-attack"
readonly AUTHOR="l0rdmalware"
readonly WEBSITE="https://l0rdmalware.cc"
readonly REPOSITORY="https://github.com/l0rdmalware/atomic-lockfile-supply-chain-attack"
readonly SOURCE_REPOSITORY="https://github.com/lenucksi/aur-malware-check"
readonly LIST_URL="https://md.archlinux.org/s/SxbqukK6IA/download"
readonly CAMPAIGN_START="2026-06-09"
readonly CAMPAIGN_END="2026-06-12"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
LIST_FILE="$SCRIPT_DIR/aur_infected_packages.md"
PACMAN_LOG_GLOB=${PACMAN_LOG_GLOB:-/var/log/pacman.log*}
MIN_EXPECTED_PACKAGES=1000
UPDATE=0
CHECK_LOGS=1
CHECK_SYSTEMD=0
CHECK_EBPF=0
CHECK_NPM_CACHE=0
CHECK_BUN_CACHE=0
ALL_TIME=0
VERBOSE=0
RESULT=0

readonly MALICIOUS_JS_PACKAGES="atomic-lockfile
js-digest
lockfile-js
nextfile-js"

banner() {
    cat <<'EOF'
 _  ___          _                 _                          ___ ___
| |/ _ \ _ __ __| |_ __ ___   __ _| |_      ____ _ _ __ ___ / __/ __|
| | | | | '__/ _` | '_ ` _ \ / _` | \ \ /\ / / _` | '__/ _ \ (_| (__
|_|\___/|_|  \__,_|_| |_| |_|\__,_|_|\ V  V /\__,_|_|  \___/\___\___|
                                   \_/\_/
EOF
    printf '  Project:    %s v%s\n' "$PROJECT_NAME" "$SCRIPT_VERSION"
    printf '  Author:     %s (%s)\n' "$AUTHOR" "$WEBSITE"
    printf '  Repository: %s\n' "$REPOSITORY"
    printf '  Reference:  %s\n\n' "$SOURCE_REPOSITORY"
}

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [OPTIONS]

Detects indicators associated with the June 2026 atomic-lockfile AUR
supply-chain attack.

Project:    $REPOSITORY
Reference:  $SOURCE_REPOSITORY

  --update             Refresh the affected AUR package list
  --list FILE          Use a different Markdown package list
  --skip-logs          Do not scan current and compressed pacman logs
  --check-systemd      Scan systemd units for known persistence settings
  --check-ebpf         Check for known eBPF rootkit map names
  --check-npm-cache    Search npm cache/global modules for malicious packages
  --check-bun-cache    Search bun cache for malicious packages
  --full               Enable all optional checks
  --all-time           Scan all pacman history, not only ${CAMPAIGN_START}..${CAMPAIGN_END}
  -v, --verbose        Show files being scanned
  -h, --help           Show this help
  --version            Show version and repository information

Environment:
  PACMAN_LOG_GLOB      Log glob (default: /var/log/pacman.log*)

Exit status:
  0  No indicators found
  1  One or more checks could not be completed
  2  One or more indicators found
EOF
}

die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

warn() {
    printf 'WARNING: %s\n' "$*" >&2
    ((RESULT < 1)) && RESULT=1
}

note() {
    printf 'Notice: %s\n' "$*" >&2
}

mark_detected() {
    RESULT=2
}

verbose() {
    ((VERBOSE)) && printf '  [info] %s\n' "$*"
    return 0
}

section() {
    printf '\n--- %s ---\n' "$1"
}

while (($#)); do
    case "$1" in
        --update)
            UPDATE=1
            shift
            ;;
        --list)
            (($# >= 2)) || die "--list requires a file path"
            LIST_FILE=$2
            shift 2
            ;;
        --skip-logs)
            CHECK_LOGS=0
            shift
            ;;
        --check-systemd)
            CHECK_SYSTEMD=1
            shift
            ;;
        --check-ebpf)
            CHECK_EBPF=1
            shift
            ;;
        --check-npm-cache)
            CHECK_NPM_CACHE=1
            shift
            ;;
        --check-bun-cache)
            CHECK_BUN_CACHE=1
            shift
            ;;
        --full)
            CHECK_SYSTEMD=1
            CHECK_EBPF=1
            CHECK_NPM_CACHE=1
            CHECK_BUN_CACHE=1
            shift
            ;;
        --all-time)
            ALL_TIME=1
            shift
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        --version)
            printf '%s %s\n' "$SCRIPT_NAME" "$SCRIPT_VERSION"
            printf 'Project: %s\n' "$REPOSITORY"
            printf 'Reference: %s\n' "$SOURCE_REPOSITORY"
            exit 0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1"
            ;;
    esac
done

banner

command -v pacman >/dev/null 2>&1 || die "pacman is not installed"
command -v comm >/dev/null 2>&1 || die "comm is not installed"

tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM

parse_list() {
    local source=$1
    local output=$2
    local unsorted="$tmp_dir/packages.unsorted"
    local metadata="$tmp_dir/list.metadata"
    local fences invalid count

    awk -v metadata="$metadata" '
        /^```[[:space:]]*$/ {
            fences++
            in_block = !in_block
            next
        }
        in_block {
            sub(/\r$/, "")
            if ($0 ~ /^[a-z0-9][a-z0-9@._+-]*$/)
                print
            else if ($0 !~ /^[[:space:]]*$/)
                invalid++
        }
        END {
            printf "%d %d\n", fences, invalid > metadata
            if (fences != 2 || in_block)
                exit 2
        }
    ' "$source" > "$unsorted" ||
        die "the package list is not a single complete Markdown code block"

    read -r fences invalid < "$metadata"
    LC_ALL=C sort -u "$unsorted" > "$output"
    count=$(wc -l < "$output")
    count=${count//[[:space:]]/}

    ((count >= MIN_EXPECTED_PACKAGES)) ||
        die "parsed only $count packages; expected at least $MIN_EXPECTED_PACKAGES"

    if ((invalid > 0)); then
        note "ignored $invalid malformed package-list entries"
    fi
}

update_list() {
    local downloaded="$tmp_dir/downloaded.md"

    command -v curl >/dev/null 2>&1 || die "curl is required for --update"
    printf 'Downloading affected package list from %s...\n' "$LIST_URL"
    curl -fsSL --proto '=https' --tlsv1.2 "$LIST_URL" -o "$downloaded" ||
        die "failed to download the package list"
    parse_list "$downloaded" "$tmp_dir/affected.sorted"
    mv -- "$downloaded" "$LIST_FILE"
    printf 'Updated %s.\n' "$LIST_FILE"
}

date_in_scope() {
    local value=$1
    ((ALL_TIME)) && return 0
    [[ $value < $CAMPAIGN_START || $value > $CAMPAIGN_END ]] && return 1
    return 0
}

read_log() {
    local file=$1

    case "$file" in
        *.gz)
            command -v gzip >/dev/null 2>&1 || return 3
            gzip -cd -- "$file"
            ;;
        *.xz)
            command -v xz >/dev/null 2>&1 || return 3
            xz -cd -- "$file"
            ;;
        *.zst)
            command -v zstdcat >/dev/null 2>&1 || return 3
            zstdcat -- "$file"
            ;;
        *.bz2)
            command -v bzip2 >/dev/null 2>&1 || return 3
            bzip2 -cd -- "$file"
            ;;
        *)
            cat -- "$file"
            ;;
    esac
}

log_reader_available() {
    case "$1" in
        *.gz) command -v gzip >/dev/null 2>&1 ;;
        *.xz) command -v xz >/dev/null 2>&1 ;;
        *.zst) command -v zstdcat >/dev/null 2>&1 ;;
        *.bz2) command -v bzip2 >/dev/null 2>&1 ;;
        *) return 0 ;;
    esac
}

check_installed_packages() {
    local found_count package_count installed_count

    section "Currently installed foreign packages"
    LC_ALL=C pacman -Qmq | LC_ALL=C sort -u > "$tmp_dir/installed.sorted" ||
        die "failed to query installed foreign packages"
    LC_ALL=C comm -12 "$tmp_dir/installed.sorted" "$tmp_dir/affected.sorted" \
        > "$tmp_dir/installed.matches"

    package_count=$(wc -l < "$tmp_dir/affected.sorted")
    package_count=${package_count//[[:space:]]/}
    installed_count=$(wc -l < "$tmp_dir/installed.sorted")
    installed_count=${installed_count//[[:space:]]/}
    found_count=$(wc -l < "$tmp_dir/installed.matches")
    found_count=${found_count//[[:space:]]/}

    printf 'Checked %d affected names against %d foreign packages.\n' \
        "$package_count" "$installed_count"
    if ((found_count == 0)); then
        printf 'Clean: no listed packages are currently installed.\n'
        return
    fi

    printf 'DETECTED: %d listed package(s) currently installed:\n' "$found_count"
    sed 's/^/  - /' "$tmp_dir/installed.matches"
    mark_detected
}

check_pacman_logs() {
    local file
    local log_count=0
    local skipped=0

    section "Pacman installation history"
    : > "$tmp_dir/log.matches"

    # Intentional word splitting expands the user-configurable log glob.
    # shellcheck disable=SC2086
    for file in $PACMAN_LOG_GLOB; do
        [[ -e $file ]] || continue
        log_count=$((log_count + 1))
        verbose "Scanning $file"

        if [[ ! -r $file ]]; then
            warn "cannot read pacman log: $file"
            skipped=$((skipped + 1))
            continue
        fi
        if ! log_reader_available "$file"; then
            warn "required decompressor is unavailable for: $file"
            skipped=$((skipped + 1))
            continue
        fi

        if ! read_log "$file" 2>/dev/null |
            LC_ALL=C awk \
                -v list="$tmp_dir/affected.sorted" \
                -v source="$file" \
                -v start="$CAMPAIGN_START" \
                -v end="$CAMPAIGN_END" \
                -v all_time="$ALL_TIME" '
                    BEGIN {
                        while ((getline package < list) > 0)
                            affected[package] = 1
                        close(list)
                    }
                    {
                        date = substr($0, 2, 10)
                        if (date !~ /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/)
                            next
                        if (!all_time && (date < start || date > end))
                            next
                        marker = "[ALPM] "
                        position = index($0, marker)
                        if (!position)
                            next
                        event = substr($0, position + length(marker))
                        split(event, fields, /[[:space:]]+/)
                        action = fields[1]
                        package = fields[2]
                        if (action != "installed" &&
                            action != "upgraded" &&
                            action != "reinstalled")
                            next
                        if (package in affected)
                            printf "%s\t%s\t%s\t%s\n", date, action, package, source
                    }
                ' >> "$tmp_dir/log.matches"; then
            warn "could not decompress or scan: $file"
            skipped=$((skipped + 1))
        fi
    done

    if ((log_count == 0)); then
        warn "no pacman logs matched: $PACMAN_LOG_GLOB"
        return
    fi

    LC_ALL=C sort -u "$tmp_dir/log.matches" -o "$tmp_dir/log.matches"
    if [[ -s $tmp_dir/log.matches ]]; then
        printf 'DETECTED: affected package activity in pacman history:\n'
        awk -F '\t' '{ printf "  - %s: %s (%s) [%s]\n", $1, $3, $2, $4 }' \
            "$tmp_dir/log.matches"
        mark_detected
    else
        printf 'Clean: no affected package activity found in %d log(s).\n' "$log_count"
    fi

    ((skipped == 0)) || printf 'Review warning(s): %d log(s) were skipped.\n' "$skipped"
}

check_systemd() {
    local dir service

    section "Systemd persistence"
    : > "$tmp_dir/systemd.matches"

    for dir in /etc/systemd/system "$HOME/.config/systemd/user"; do
        [[ -d $dir ]] || continue
        while IFS= read -r service; do
            if grep -q '^[[:space:]]*Restart=always[[:space:]]*$' "$service" 2>/dev/null &&
                grep -q '^[[:space:]]*RestartSec=30s\{0,1\}[[:space:]]*$' "$service" 2>/dev/null; then
                printf '%s\n' "$service" >> "$tmp_dir/systemd.matches"
            fi
        done < <(find "$dir" -type f -name '*.service' 2>/dev/null)
    done

    if [[ -s $tmp_dir/systemd.matches ]]; then
        printf 'DETECTED: service units matching known persistence settings:\n'
        sed 's/^/  - /' "$tmp_dir/systemd.matches"
        mark_detected
    else
        printf 'Clean: no service units matched known persistence settings.\n'
    fi
}

check_ebpf() {
    local map

    section "eBPF rootkit artifacts"
    if [[ ! -d /sys/fs/bpf ]]; then
        warn "/sys/fs/bpf is unavailable; eBPF artifacts could not be checked"
        return
    fi

    : > "$tmp_dir/ebpf.matches"
    for map in hidden_pids hidden_names hidden_inodes; do
        [[ -e /sys/fs/bpf/$map ]] && printf '/sys/fs/bpf/%s\n' "$map" \
            >> "$tmp_dir/ebpf.matches"
    done

    if [[ -s $tmp_dir/ebpf.matches ]]; then
        printf 'DETECTED: known malicious eBPF map name(s):\n'
        sed 's/^/  - /' "$tmp_dir/ebpf.matches"
        mark_detected
    else
        printf 'Clean: no known malicious eBPF map names found.\n'
    fi
}

check_npm_cache() {
    local package cache_dir global_dir

    section "npm artifacts"
    if ! command -v npm >/dev/null 2>&1; then
        printf 'Skipped: npm is not installed.\n'
        return
    fi

    : > "$tmp_dir/npm.matches"
    npm cache ls > "$tmp_dir/npm.cache" 2>/dev/null || warn "npm cache index could not be read"
    cache_dir=$(npm config get cache 2>/dev/null || true)
    global_dir=$(npm root -g 2>/dev/null || true)

    while IFS= read -r package; do
        [[ -n $package ]] || continue
        grep -F -- "$package" "$tmp_dir/npm.cache" 2>/dev/null |
            sed "s#^#cache:$package:#" >> "$tmp_dir/npm.matches" || true
        [[ -n $global_dir && -d $global_dir/$package ]] &&
            printf 'global:%s:%s\n' "$package" "$global_dir/$package" >> "$tmp_dir/npm.matches"
        if [[ -n $cache_dir && -d $cache_dir ]]; then
            find "$cache_dir" -type d -name "*${package}*" -print 2>/dev/null |
                sed "s#^#path:$package:#" >> "$tmp_dir/npm.matches" || true
        fi
    done <<< "$MALICIOUS_JS_PACKAGES"

    if [[ -s $tmp_dir/npm.matches ]]; then
        printf 'DETECTED: malicious package name(s) in npm artifacts:\n'
        sed 's/^/  - /' "$tmp_dir/npm.matches"
        mark_detected
    else
        printf 'Clean: no malicious package names found in npm artifacts.\n'
    fi
}

check_bun_cache() {
    local package cache_dir

    section "bun artifacts"
    if ! command -v bun >/dev/null 2>&1; then
        printf 'Skipped: bun is not installed.\n'
        return
    fi

    : > "$tmp_dir/bun.matches"
    bun pm cache ls > "$tmp_dir/bun.cache" 2>/dev/null || warn "bun cache index could not be read"
    cache_dir=$(bun pm cache 2>/dev/null || printf '%s/.bun/install/cache' "$HOME")

    while IFS= read -r package; do
        [[ -n $package ]] || continue
        grep -F -- "$package" "$tmp_dir/bun.cache" 2>/dev/null |
            sed "s#^#cache:$package:#" >> "$tmp_dir/bun.matches" || true
        if [[ -d $cache_dir ]]; then
            find "$cache_dir" -type d -name "*${package}*" -print 2>/dev/null |
                sed "s#^#path:$package:#" >> "$tmp_dir/bun.matches" || true
        fi
    done <<< "$MALICIOUS_JS_PACKAGES"

    if [[ -s $tmp_dir/bun.matches ]]; then
        printf 'DETECTED: malicious package name(s) in bun artifacts:\n'
        sed 's/^/  - /' "$tmp_dir/bun.matches"
        mark_detected
    else
        printf 'Clean: no malicious package names found in bun artifacts.\n'
    fi
}

if ((UPDATE)); then
    update_list
else
    [[ -r $LIST_FILE ]] || die "package list not found: $LIST_FILE (run with --update)"
    parse_list "$LIST_FILE" "$tmp_dir/affected.sorted"
fi

if ((UPDATE)); then
    # update_list already validated the downloaded list.
    [[ -s $tmp_dir/affected.sorted ]] || parse_list "$LIST_FILE" "$tmp_dir/affected.sorted"
fi

printf 'Campaign window: %s through %s%s\n' \
    "$CAMPAIGN_START" "$CAMPAIGN_END" "$([[ $ALL_TIME -eq 1 ]] && printf ' (all-time mode enabled)' || true)"

check_installed_packages
((CHECK_LOGS)) && check_pacman_logs
((CHECK_SYSTEMD)) && check_systemd
((CHECK_EBPF)) && check_ebpf
((CHECK_NPM_CACHE)) && check_npm_cache
((CHECK_BUN_CACHE)) && check_bun_cache

printf '\n============================================================\n'
case "$RESULT" in
    0) printf 'RESULT: CLEAN - no checked indicators were found.\n' ;;
    1) printf 'RESULT: INCOMPLETE - review warnings and rerun failed checks.\n' ;;
    2)
        printf 'RESULT: INDICATORS FOUND - isolate and investigate this host.\n'
        printf 'Rotate credentials from a trusted system; consider reinstallation.\n'
        ;;
esac
printf '============================================================\n'
exit "$RESULT"
