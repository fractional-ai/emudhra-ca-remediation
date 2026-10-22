#!/usr/bin/env python3
"""Part of the emudhra-ca-remediation skill.

Find Go binaries and report the toolchain each was built with. That covers
your own services and the third-party CLIs built in Go (terraform, helm,
kubectl, gh, the docker CLI, cloud CLIs, providers). Go compiles
crypto/x509 into every binary, so one built before Go 1.26.10 / 1.27.3
keeps trusting the compromised eMudhra intermediates until its vendor
ships a rebuild, whatever the OS trust store says.

No Go toolchain is needed: the version is read from the build info that
Go 1.18+ embeds in every binary. Older binaries carry no build info and
are reported as VULNERABLE (built before 1.18).

    go_binaries.py [DIR_OR_FILE ...]     # default: every directory on $PATH
    go_binaries.py --json /usr/local/bin
    go_binaries.py --root fs fs          # an image filesystem exported to ./fs

With --root, symlinks are resolved inside that directory, as they would be in
the image: an absolute link such as usr/local/bin/helm -> /opt/helm/helm is
read from fs/opt/helm/helm, never from the host.

A file named on the command line that is not a Go binary (often a version
manager's shim: asdf, tfenv, mise) is reported as REVIEW, since the real
binary was not read. So is an executable packed with UPX, whose contents
cannot be read until it is unpacked (upx -d). A target that does not exist,
or a file or directory that cannot be read, is an ERROR.

Exit status: 1 if any binary is VULNERABLE, else 2 on any ERROR, else 3 on any
REVIEW, else 0. Only 0 is a pass.
"""

from collections import deque

import json
import mmap
import os
import re
import sys

MAGIC = b"\xff Go buildinf:"
FIXED = {(1, 26): (1, 26, 10), (1, 27): (1, 27, 3)}
MIN_SIZE = 512 * 1024


def uvarint(buf, pos):
    value = shift = 0
    while pos < len(buf):
        b = buf[pos]
        pos += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, pos
        shift += 7
    return None, pos


class Packed(Exception):
    pass


def go_version(path):
    """The 'go1.x.y' a binary was built with, '' for a Go binary whose
    version cannot be read (pre-1.18, or an unexpected header), or None when
    it is not a Go binary. Raises OSError if unreadable, Packed if UPX-packed."""
    if os.path.getsize(path) < MIN_SIZE:
        return None
    with open(path, "rb") as f:
        head = f.read(4)
        if head not in (b"\x7fELF", b"MZ\x90\x00") and head[:2] != b"MZ" and \
                head not in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
            return None
        # The whole file, mapped: Terraform providers run to 800 MB and more.
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as data:
            return _go_version(data)


def _go_version(data):
    i = data.find(MAGIC)
    if i < 0:
        if data.find(b"runtime.goexit") >= 0 or data.find(b"Go build ID:") >= 0:
            return ""
        if b"UPX!" in data[:4096]:
            raise Packed()
        return None
    flags = data[i + 15] if i + 15 < len(data) else 0
    if flags & 0x2:  # Go 1.18+: inline varint-prefixed strings after a 32-byte header
        n, pos = uvarint(data, i + 32)
        if n:
            return data[pos:pos + n].decode("ascii", "replace")
    # A pre-1.18 header (pointer-based) or something unexpected. Searching the
    # binary for a "go1.x" string could find any text, so report it unknown:
    # every pre-1.18 toolchain is affected.
    return ""


def verdict(version):
    m = re.match(r"go(\d+)\.(\d+)(?:\.(\d+))?", version or "")
    if not m:
        return "VULNERABLE", ("no readable Go version (older than Go 1.18, or stripped by the build): "
                              "treat it as affected until its vendor confirms the toolchain")
    v = tuple(int(x or 0) for x in m.groups())
    line = v[:2]
    if line in FIXED:
        return ("FIXED", "") if v >= FIXED[line] else ("VULNERABLE", "needs >= go%d.%d.%d" % FIXED[line])
    if line < (1, 26):
        return "VULNERABLE", "Go %d.%d has no patched release; needs a build on 1.26.10+ or 1.27.3+" % line
    return "REVIEW", "newer than the advisory; confirm it includes CVE-2026-111943"


def realpath_in(root, path):
    """realpath() as seen from inside root: absolute links restart at root, and
    '..' never climbs above it. None for a loop or a dangling link."""
    parts = deque(os.path.relpath(path, root).split(os.sep))
    resolved = []
    hops = 0
    while parts:
        c = parts.popleft()
        if c in ("", "."):
            continue
        if c == "..":
            if resolved:
                resolved.pop()
            continue
        cand = os.path.join(root, *resolved, c)
        if os.path.islink(cand):
            hops += 1
            if hops > 40:
                return None
            target = os.readlink(cand)
            if target.startswith("/"):
                resolved = []
            parts.extendleft(reversed(target.split("/")))
        else:
            resolved.append(c)
    real = os.path.join(root, *resolved)
    return real if os.path.exists(real) else None


def walk(target, root, seen, errors):
    """Yield (shown path, file to read) for every regular file under target."""
    def resolve(p):
        return realpath_in(root, p) if root else os.path.realpath(p)
    if not os.path.isdir(target) or (root and os.path.islink(target)):
        real = resolve(target)
        if real and os.path.isfile(real):
            yield target, real
        return
    def onerror(e):
        errors.append("%s: %s" % (getattr(e, "filename", None) or target, e))

    for dirpath, dirnames, filenames in os.walk(target, onerror=onerror):
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules", "proc", "sys", "dev")]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            real = resolve(p)
            if not real or real in seen or not os.path.isfile(real):
                continue
            seen.add(real)
            yield p, real


def main():
    argv = sys.argv[1:]
    as_json = "--json" in argv
    root = None
    if "--root" in argv:
        i = argv.index("--root")
        if i + 1 >= len(argv) or not os.path.isdir(argv[i + 1]):
            print("--root needs an existing directory", file=sys.stderr)
            return 2
        root = os.path.abspath(argv[i + 1])
        del argv[i:i + 2]
    args = [a for a in argv if a != "--json"]
    named = bool(args)
    targets = args or [d for d in os.environ.get("PATH", "").split(os.pathsep) if os.path.isdir(d)]
    rows = []
    missing = False
    seen = set()
    files = total = 0
    for t in targets:
        if not os.path.lexists(t):
            print("ERROR      %s does not exist" % t, file=sys.stderr)
            missing = True
            continue
        found = 0
        errors = []
        for shown, real in walk(os.path.abspath(t) if root else t, root, seen, errors):
            files += 1
            try:
                v = go_version(real)
            except OSError as e:
                rows.append({"status": "ERROR", "path": shown, "go": "?", "detail": "could not be read: %s" % e})
                continue
            except Packed:
                rows.append({"status": "REVIEW", "path": shown, "go": "?",
                             "detail": "packed with UPX, so its build info cannot be read; unpack a copy (upx -d) and rerun"})
                continue
            if v is None:
                continue
            found += 1
            total += 1
            status, note = verdict(v)
            if real != os.path.abspath(shown):
                note = ("%s (reads %s)" % (note, real)).strip()
            rows.append({"status": status, "path": shown, "go": v or "unknown", "detail": note})
        rows += [{"status": "ERROR", "path": e, "go": "?", "detail": "directory could not be listed"} for e in errors]
        if named and not found:
            rows.append({"status": "REVIEW", "path": t, "go": "none",
                         "detail": "no Go binary here; if this is a version-manager shim, run this on the binary it launches"
                         if not os.path.isdir(t) else "no Go binaries under this directory"})
    if not total and not named:
        # An empty result proves nothing about the hosts that matter: this
        # PATH may not be the one the services run with.
        rows.append({"status": "REVIEW", "path": "$PATH", "go": "none",
                     "detail": "no Go binaries on this PATH; name the directories the services and CLIs live in"})
    order = {"VULNERABLE": 0, "ERROR": 1, "REVIEW": 2, "FIXED": 3}
    rows.sort(key=lambda r: (order[r["status"]], r["path"]))
    if as_json:
        json.dump(rows, sys.stdout, indent=2)
        print()
    else:
        for r in rows:
            print("%-10s %-10s %s %s" % (r["status"], r["go"], r["path"], r["detail"]))
        print("%d files read in %s; %d Go binaries, %d vulnerable, %d errors, %d to review" % (
            files, ", ".join(targets) or "nothing", sum(r["go"] not in ("none", "?") for r in rows), sum(r["status"] == "VULNERABLE" for r in rows),
            sum(r["status"] == "ERROR" for r in rows), sum(r["status"] == "REVIEW" for r in rows)))
    statuses = {r["status"] for r in rows}
    if "VULNERABLE" in statuses:
        return 1
    if missing or "ERROR" in statuses:
        return 2
    return 3 if "REVIEW" in statuses else 0


if __name__ == "__main__":
    sys.exit(main())
