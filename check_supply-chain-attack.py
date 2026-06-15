#!/usr/bin/env python3

"""Detect indicators from the atomic-lockfile AUR supply-chain attack."""

from __future__ import annotations

import argparse
import bz2
import glob
import gzip
import lzma
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable, Iterator, Sequence

VERSION = "1.2.0"
PROJECT_NAME = "atomic-lockfile-supply-chain-attack"
AUTHOR = "l0rdmalware"
WEBSITE = "https://l0rdmalware.cc"
REPOSITORY = "https://github.com/l0rdmalware/atomic-lockfile-supply-chain-attack"
SOURCE_REPOSITORY = "https://github.com/lenucksi/aur-malware-check"
LIST_URL = "https://md.archlinux.org/s/SxbqukK6IA/download"
CAMPAIGN_START = "2026-06-09"
CAMPAIGN_END = "2026-06-12"
MIN_EXPECTED_PACKAGES = 1000
DEFAULT_LOG_GLOB = "/var/log/pacman.log*"
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_LIST_FILE = SCRIPT_DIR / "aur_infected_packages.md"
SCRIPT_NAME = os.environ.get("SUPPLY_CHAIN_ENTRYPOINT", Path(sys.argv[0]).name)

MALICIOUS_JS_PACKAGES = (
    "atomic-lockfile",
    "js-digest",
    "lockfile-js",
    "nextfile-js",
)
EBPF_MAP_NAMES = ("hidden_pids", "hidden_names", "hidden_inodes")
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9@._+-]*$")
LOG_RE = re.compile(
    r"^\[(?P<date>\d{4}-\d{2}-\d{2})[^\]]*\].*?"
    r"\[ALPM\] (?P<action>installed|upgraded|reinstalled) "
    r"(?P<package>\S+)"
)

BANNER = r""" _  ___          _                 _                          ___ ___
| |/ _ \ _ __ __| |_ __ ___   __ _| |_      ____ _ _ __ ___ / __/ __|
| | | | | '__/ _` | '_ ` _ \ / _` | \ \ /\ / / _` | '__/ _ \ (_| (__
|_|\___/|_|  \__,_|_| |_| |_|\__,_|_|\ V  V /\__,_|_|  \___/\___\___|
                                   \_/\_/"""


class Scanner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.result = 0
        self.affected: set[str] = set()

    def warn(self, message: str) -> None:
        print(f"WARNING: {message}", file=sys.stderr)
        if self.result < 1:
            self.result = 1

    @staticmethod
    def notice(message: str) -> None:
        print(f"Notice: {message}", file=sys.stderr)

    def detected(self) -> None:
        self.result = 2

    def verbose(self, message: str) -> None:
        if self.args.verbose:
            print(f"  [info] {message}")

    @staticmethod
    def section(title: str) -> None:
        print(f"\n--- {title} ---")

    def parse_list(self, source: Path) -> set[str]:
        try:
            lines = source.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeError) as error:
            fail(f"cannot read package list {source}: {error}")

        fences = 0
        in_block = False
        malformed = 0
        packages: set[str] = set()

        for raw_line in lines:
            line = raw_line.rstrip("\r")
            if re.fullmatch(r"```[ \t]*", line):
                fences += 1
                in_block = not in_block
                continue
            if not in_block or not line.strip():
                continue
            if PACKAGE_RE.fullmatch(line):
                packages.add(line)
            else:
                malformed += 1

        if fences != 2 or in_block:
            fail("the package list is not a single complete Markdown code block")
        if len(packages) < MIN_EXPECTED_PACKAGES:
            fail(
                f"parsed only {len(packages)} packages; "
                f"expected at least {MIN_EXPECTED_PACKAGES}"
            )
        if malformed:
            self.notice(f"ignored {malformed} malformed package-list entries")
        return packages

    def update_list(self) -> None:
        target = self.args.list_file
        target.parent.mkdir(parents=True, exist_ok=True)
        print(f"Downloading affected package list from {LIST_URL}...")
        request = urllib.request.Request(
            LIST_URL,
            headers={"User-Agent": f"{PROJECT_NAME}/{VERSION}"},
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                data = response.read()
        except (OSError, urllib.error.URLError) as error:
            fail(f"failed to download the package list: {error}")

        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=target.parent, delete=False
            ) as temporary:
                temporary.write(data)
                temporary_path = Path(temporary.name)
            self.affected = self.parse_list(temporary_path)
            temporary_path.replace(target)
        except BaseException:
            if "temporary_path" in locals():
                temporary_path.unlink(missing_ok=True)
            raise
        print(f"Updated {target}.")

    def check_installed_packages(self) -> None:
        self.section("Currently installed foreign packages")
        try:
            process = subprocess.run(
                ["pacman", "-Qmq"],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as error:
            fail(f"failed to run pacman: {error}")
        if process.returncode != 0:
            fail(f"failed to query installed foreign packages: {process.stderr.strip()}")

        installed = {line.strip() for line in process.stdout.splitlines() if line.strip()}
        matches = sorted(installed & self.affected)
        print(
            f"Checked {len(self.affected)} affected names against "
            f"{len(installed)} foreign packages."
        )
        if not matches:
            print("Clean: no listed packages are currently installed.")
            return

        print(f"DETECTED: {len(matches)} listed package(s) currently installed:")
        print_items(matches)
        self.detected()

    def open_log(self, path: Path) -> Iterable[str]:
        suffix = path.suffix.lower()
        if suffix == ".gz":
            return gzip.open(path, mode="rt", encoding="utf-8", errors="replace")
        if suffix == ".xz":
            return lzma.open(path, mode="rt", encoding="utf-8", errors="replace")
        if suffix == ".bz2":
            return bz2.open(path, mode="rt", encoding="utf-8", errors="replace")
        if suffix == ".zst":
            if not shutil.which("zstdcat"):
                raise OSError("zstdcat is required to read .zst logs")
            process = subprocess.run(
                ["zstdcat", "--", str(path)],
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if process.returncode != 0:
                raise OSError(process.stderr.strip() or "zstdcat failed")
            return process.stdout.splitlines()
        return path.open(mode="rt", encoding="utf-8", errors="replace")

    def check_pacman_logs(self) -> None:
        self.section("Pacman installation history")
        paths = sorted(Path(item) for item in glob.glob(self.args.log_glob))
        if not paths:
            self.warn(f"no pacman logs matched: {self.args.log_glob}")
            return

        matches: set[tuple[str, str, str, str]] = set()
        skipped = 0
        for path in paths:
            self.verbose(f"Scanning {path}")
            try:
                lines = self.open_log(path)
                try:
                    for line in lines:
                        match = LOG_RE.search(line)
                        if not match:
                            continue
                        date = match.group("date")
                        if not self.args.all_time and not (
                            CAMPAIGN_START <= date <= CAMPAIGN_END
                        ):
                            continue
                        package = match.group("package")
                        if package in self.affected:
                            matches.add(
                                (date, match.group("action"), package, str(path))
                            )
                finally:
                    close = getattr(lines, "close", None)
                    if close:
                        close()
            except OSError as error:
                self.warn(f"could not scan {path}: {error}")
                skipped += 1

        if matches:
            print("DETECTED: affected package activity in pacman history:")
            for date, action, package, source in sorted(matches):
                print(f"  - {date}: {package} ({action}) [{source}]")
            self.detected()
        else:
            print(f"Clean: no affected package activity found in {len(paths)} log(s).")
        if skipped:
            print(f"Review warning(s): {skipped} log(s) were skipped.")

    def check_systemd(self) -> None:
        self.section("Systemd persistence")
        roots = (
            Path("/etc/systemd/system"),
            Path.home() / ".config/systemd/user",
        )
        matches: list[str] = []
        restart_re = re.compile(r"^\s*Restart=always\s*$", re.MULTILINE)
        delay_re = re.compile(r"^\s*RestartSec=30s?\s*$", re.MULTILINE)

        for root in roots:
            if not root.is_dir():
                continue
            for service in root.rglob("*.service"):
                try:
                    content = service.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if restart_re.search(content) and delay_re.search(content):
                    matches.append(str(service))

        if matches:
            print("DETECTED: service units matching known persistence settings:")
            print_items(sorted(set(matches)))
            self.detected()
        else:
            print("Clean: no service units matched known persistence settings.")

    def check_ebpf(self) -> None:
        self.section("eBPF rootkit artifacts")
        root = Path("/sys/fs/bpf")
        if not root.is_dir():
            self.warn("/sys/fs/bpf is unavailable; eBPF artifacts could not be checked")
            return
        matches = [str(root / name) for name in EBPF_MAP_NAMES if (root / name).exists()]
        if matches:
            print("DETECTED: known malicious eBPF map name(s):")
            print_items(matches)
            self.detected()
        else:
            print("Clean: no known malicious eBPF map names found.")

    def check_npm_cache(self) -> None:
        self.section("npm artifacts")
        if not shutil.which("npm"):
            print("Skipped: npm is not installed.")
            return

        cache_output = self.run_optional(["npm", "cache", "ls"], "npm cache index")
        cache_dir = self.command_value(["npm", "config", "get", "cache"])
        global_dir = self.command_value(["npm", "root", "-g"])
        matches = self.js_artifact_matches(cache_output, cache_dir, "cache")

        if global_dir:
            for package in MALICIOUS_JS_PACKAGES:
                candidate = Path(global_dir) / package
                if candidate.is_dir():
                    matches.add(f"global:{package}:{candidate}")
        self.report_js_matches("npm", matches)

    def check_bun_cache(self) -> None:
        self.section("bun artifacts")
        if not shutil.which("bun"):
            print("Skipped: bun is not installed.")
            return

        cache_output = self.run_optional(["bun", "pm", "cache", "ls"], "bun cache index")
        cache_dir = self.command_value(["bun", "pm", "cache"])
        if not cache_dir:
            cache_dir = str(Path.home() / ".bun/install/cache")
        matches = self.js_artifact_matches(cache_output, cache_dir, "cache")
        self.report_js_matches("bun", matches)

    def run_optional(self, command: Sequence[str], label: str) -> str:
        try:
            process = subprocess.run(
                command,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as error:
            self.warn(f"{label} could not be read: {error}")
            return ""
        if process.returncode != 0:
            self.warn(f"{label} could not be read")
            return ""
        return process.stdout

    @staticmethod
    def command_value(command: Sequence[str]) -> str:
        try:
            process = subprocess.run(
                command,
                check=False,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            return ""
        return process.stdout.strip() if process.returncode == 0 else ""

    @staticmethod
    def walk_matching_paths(root: Path, package: str) -> Iterator[Path]:
        if not root.is_dir():
            return
        try:
            for current_root, directories, _files in os.walk(root):
                for directory in directories:
                    if package in directory:
                        yield Path(current_root) / directory
        except OSError:
            return

    def js_artifact_matches(
        self, cache_output: str, cache_dir: str, prefix: str
    ) -> set[str]:
        matches: set[str] = set()
        lines = cache_output.splitlines()
        for package in MALICIOUS_JS_PACKAGES:
            for line in lines:
                if package in line:
                    matches.add(f"{prefix}:{package}:{line}")
            if cache_dir:
                for path in self.walk_matching_paths(Path(cache_dir), package):
                    matches.add(f"path:{package}:{path}")
        return matches

    def report_js_matches(self, tool: str, matches: set[str]) -> None:
        if matches:
            print(f"DETECTED: malicious package name(s) in {tool} artifacts:")
            print_items(sorted(matches))
            self.detected()
        else:
            print(f"Clean: no malicious package names found in {tool} artifacts.")

    def run(self) -> int:
        print_banner()
        if not shutil.which("pacman"):
            fail("pacman is not installed")

        if self.args.update:
            self.update_list()
        else:
            if not self.args.list_file.is_file():
                fail(
                    f"package list not found: {self.args.list_file} "
                    "(run with --update)"
                )
            self.affected = self.parse_list(self.args.list_file)

        suffix = " (all-time mode enabled)" if self.args.all_time else ""
        print(f"Campaign window: {CAMPAIGN_START} through {CAMPAIGN_END}{suffix}")

        self.check_installed_packages()
        if not self.args.skip_logs:
            self.check_pacman_logs()
        if self.args.check_systemd:
            self.check_systemd()
        if self.args.check_ebpf:
            self.check_ebpf()
        if self.args.check_npm_cache:
            self.check_npm_cache()
        if self.args.check_bun_cache:
            self.check_bun_cache()

        print("\n============================================================")
        if self.result == 0:
            print("RESULT: CLEAN - no checked indicators were found.")
        elif self.result == 1:
            print("RESULT: INCOMPLETE - review warnings and rerun failed checks.")
        else:
            print("RESULT: INDICATORS FOUND - isolate and investigate this host.")
            print("Rotate credentials from a trusted system; consider reinstallation.")
        print("============================================================")
        return self.result


def print_items(items: Iterable[str]) -> None:
    for item in items:
        print(f"  - {item}")


def print_banner() -> None:
    print(BANNER)
    print(f"  Project:    {PROJECT_NAME} v{VERSION}")
    print(f"  Author:     {AUTHOR} ({WEBSITE})")
    print(f"  Repository: {REPOSITORY}")
    print(f"  Reference:  {SOURCE_REPOSITORY}\n")


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=SCRIPT_NAME,
        description=(
            "Detect indicators associated with the June 2026 "
            "atomic-lockfile AUR supply-chain attack."
        ),
        epilog=(
            f"Project: {REPOSITORY}\n"
            f"Reference: {SOURCE_REPOSITORY}\n\n"
            "Exit status: 0 clean, 1 incomplete/error, 2 indicators found."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--update", action="store_true", help="refresh the affected AUR package list"
    )
    parser.add_argument(
        "--list",
        dest="list_file",
        type=Path,
        default=DEFAULT_LIST_FILE,
        metavar="FILE",
        help="use a different Markdown package list",
    )
    parser.add_argument(
        "--skip-logs",
        action="store_true",
        help="do not scan current and compressed pacman logs",
    )
    parser.add_argument(
        "--check-systemd",
        action="store_true",
        help="scan systemd units for known persistence settings",
    )
    parser.add_argument(
        "--check-ebpf",
        action="store_true",
        help="check for known eBPF rootkit map names",
    )
    parser.add_argument(
        "--check-npm-cache",
        action="store_true",
        help="search npm cache/global modules for malicious packages",
    )
    parser.add_argument(
        "--check-bun-cache",
        action="store_true",
        help="search bun cache for malicious packages",
    )
    parser.add_argument("--full", action="store_true", help="enable all optional checks")
    parser.add_argument(
        "--all-time",
        action="store_true",
        help="scan all pacman history, not only the campaign window",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument(
        "--version",
        action="version",
        version=(
            f"{SCRIPT_NAME} {VERSION}\n"
            f"Project: {REPOSITORY}\n"
            f"Reference: {SOURCE_REPOSITORY}"
        ),
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.full:
        args.check_systemd = True
        args.check_ebpf = True
        args.check_npm_cache = True
        args.check_bun_cache = True
    args.log_glob = os.environ.get("PACMAN_LOG_GLOB", DEFAULT_LOG_GLOB)
    return Scanner(args).run()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nERROR: interrupted", file=sys.stderr)
        raise SystemExit(1)
