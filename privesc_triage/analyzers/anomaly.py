from __future__ import annotations

from shlex import quote

UNUSUAL_PREFIXES = ("/usr/local/", "/opt/", "/home/", "/tmp/", "/var/tmp/")


def unusual_location(path: str) -> bool:
    return path.startswith(UNUSUAL_PREFIXES)


def suggested_binary_checks(path: str) -> list[str]:
    target = quote(path)
    checks = [
        f"file {target}",
        f"ls -la {target}",
        f"strings {target}",
        f"ldd {target}",
        f"stat {target}",
    ]
    if path.endswith((".sh", ".py", ".pl", ".rb")):
        checks.append(f"head {target}")
    return checks


def suggested_sudo_checks(path: str) -> list[str]:
    """Checks that expose ownership, writable parents, symlinks, and scripts."""
    target = quote(path)
    return [
        f"file {target}",
        f"ls -la {target}",
        f"namei -l {target}",
        f"readlink -f {target}",
        f"stat {target}",
        f"strings {target}",
        f"sed -n '1,240p' {target}",
    ]
