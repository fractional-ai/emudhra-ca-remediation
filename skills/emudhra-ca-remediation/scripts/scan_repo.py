#!/usr/bin/env python3
# /// script
# requires-python = ">=3.8"
# dependencies = ["pyyaml", "tomli; python_version < '3.11'"]
# ///
"""Part of the emudhra-ca-remediation skill.

Scan a source tree for components affected by the October 2026 eMudhra
intermediate CA compromise.

Every file is read with a parser for its format (JSON, TOML, YAML, PEP 508
requirement lines, Dockerfile instructions, lockfile grammars), and every file
of any kind is searched for the affected certificates and public keys by their
bytes, so a vendored bundle, keystore, Kubernetes Secret or compiled binary is
caught whatever it is called. Zip-family archives (jar, war, whl, apk, nupkg)
and tarballs, compressed or not, are opened in memory, nested ones too, and
every member is searched the same way; nothing is extracted to disk or run.
UTF-16 and UTF-32 text is decoded, not skipped as binary. Each finding has a
status:

  VULNERABLE  the pinned version predates the fix, or its release line has none,
              or the file carries an affected certificate or key
  ERROR       a file that matters could not be read or parsed. Not clean
  REVIEW      the repo cannot settle it (floating tag, a range, unpinned, a fix
              still pending, or a setting a person has to read)
  FIXED       the pinned version is at or past the fix
  INFO        context: where a version comes from, a bundle that was read and
              holds none of the affected certificates

Exit status: 1 if anything is VULNERABLE, else 2 on any ERROR, else 3 on any
REVIEW, else 0. Only 0 means the repo pins nothing affected, and even then it
says nothing about what is deployed: SKILL.md covers checking the running
artifact. A tree in which nothing was recognised is an ERROR, not a pass.

The tables are a snapshot; check_advisory.py reports what changed since.

Standard library, plus PyYAML for YAML and tomli on Pythons before 3.11. When
one is missing, the files it would parse are ERROR rows.

    python3 scan_repo.py PATH [PATH ...] [--json] [--all] [--no-info]
"""

import argparse
import ast
import bz2
import codecs
import configparser
import gzip
import io
import json
import lzma
import os
import re
import shlex
import sys
import tarfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import emudhra_certs as E  # noqa: E402
import trust_store  # noqa: E402

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None
try:
    import yaml
except ImportError:
    yaml = None

# Fixed releases per release line, from https://emudhra.we-have-a-problem.com/
# (snapshot 2026-10-22). A line missing from a table has no fix: upgrade it.
NODE_FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
GO_FIXED = {(1, 26): (1, 26, 10), (1, 27): (1, 27, 3)}
ELECTRON_FIXED = {42: (42, 11, 16), 43: (43, 8, 1), 44: (44, 9, 1)}
# The OpenJDK advisory lists these builds as the last affected ones, and the
# tracker lists the next ".0.2" vendor build as fixed. These builds and anything
# below are VULNERABLE (8u511 is on both lists, so it fails closed); past them,
# confirm the vendor's build notes.
JAVA_LAST_AFFECTED = {
    27: (27, 0, 1), 25: (25, 0, 5), 21: (21, 0, 13),
    17: (17, 0, 21), 11: (11, 0, 33), 8: (8, 0, 511),
}
DENO_FIXED = (2, 9, 8)
BUN_FIXED = (1, 4, 4)
BUN_COMPILED = ("the binary embeds Bun's root store, so it stays exposed until rebuilt on Bun 1.4.4+ "
                "and reshipped; check which Bun the build uses")
EMBEDS_RUNTIME = ("bundles a runtime and its root store into the artifact: rebuild it on a fixed runtime and "
                  "reship, then check the artifact (scan_repo.py on the binary, go_binaries.py, or a probe)")
SNAPSHOT_DATE = "2026-10-22"
NEWER = ("a release line newer than the %s snapshot: almost certainly fixed. Confirm with check_advisory.py, "
         "then with a probe of the running artifact" % SNAPSHOT_DATE)

# Single-threshold packages: name -> (fixed version, ecosystem note)
PY_PACKAGES = {
    "certifi": ((2026, 10, 19), "CA bundle used by requests, httpx, botocore, aiohttp and most Python HTTP clients"),
    "pip": ((26, 2, 2), "pip loads its vendored certifi even when system certs are on"),
    "uv": ((0, 13, 4), "uv ships webpki-roots unless UV_SYSTEM_CERTS / --native-tls is set"),
    "sigstore": ((4, 5, 1), ""),
}
CARGO_PACKAGES = {
    "webpki-roots": ((1, 0, 10), "rustls root bundle; 0.26.x is a shim over 1.x, check the 1.x entry"),
    "webpki-root-certs": ((1, 0, 10), "rustls root bundle"),
    "rustls-webpki": ((0, 103, 16), "rustls verifier; only the 0.103 line has the block"),
}
RUSTLS_DEPS = {"webpki-roots", "webpki-root-certs", "rustls-webpki", "rustls", "reqwest", "ureq", "hyper-rustls",
               "tokio-rustls", "rustls-native-certs", "rustls-platform-verifier"}
HEX_PACKAGES = {
    "castore": ((1, 0, 22), "Elixir CA bundle"),
    "certifi": (None, "Erlang certifi: fix pending upstream (certifi/erlang-certifi#56)"),
}
TOOL_FIXED = {
    "uv": (0, 13, 4), "pixi": (0, 82, 1), "mise": (2026, 10, 17), "deno": DENO_FIXED, "claude-code": (2, 1, 303),
}
GO_CLIS = {"terraform", "opentofu", "tofu", "packer", "vault", "consul", "nomad", "kubectl", "helm", "gh",
           "trivy", "goreleaser", "pulumi", "k9s", "kustomize", "argocd", "flux", "golangci-lint", "hugo"}
GO_CLI_NOTE = ("a Go-built tool: it carries its own crypto/x509, so it stays exposed until its vendor ships a build "
               "on Go >= 1.26.10 / 1.27.3. Check the installed binary with go_binaries.py")
GO_CLI_ACTIONS = {"hashicorp/setup-terraform", "azure/setup-helm", "azure/setup-kubectl", "opentofu/setup-opentofu",
                  "hashicorp/setup-packer", "pulumi/actions", "aquasecurity/trivy-action",
                  "goreleaser/goreleaser-action", "golangci/golangci-lint-action", "cli/gh-extension-precompile",
                  "docker/setup-buildx-action"}  # BuildKit's default buildx-stable-1 image was on go1.26.8
CONDA_CA_FIXED = (2026, 10, 19)  # a conda ca-certificates build older than the fix cannot contain it

# Pruned unless --all. Virtualenvs are pruned by their pyvenv.cfg, whatever
# they are called. Every pruned directory is listed in the coverage summary.
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
    "target", ".next", ".terraform", "site-packages", ".gradle", ".idea",
}
RANGE = re.compile(r"^\s*(?:[\^~<>*]|latest\b)|[|\s]|\.[xX*]|^\d+(?:\.\d+)?$")
MAX_BYTES = 64 * 1024 * 1024
CHUNK = 16 * 1024 * 1024
# This skill names the CA everywhere; never report it against itself.
SKILL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Copies of the skill's own scripts dropped into a repo are skipped too, by
# name and marker together, so the marker alone hides nothing.
SKILL_MARKER = b"Part of the emudhra-ca-remediation skill"
SKILL_FILES = {"scan_repo.py", "trust_store.py", "emudhra_certs.py", "go_binaries.py", "check_advisory.py",
               "probe_runtime.sh", "test_scripts.py"}
STORE_EXT = {".jks", ".jceks", ".keystore", ".truststore", ".p12", ".pfx", ".bks", ".der", ".cer", ".crt", ".pem"}
KEYSTORE_EXT = {".jks", ".jceks", ".keystore", ".truststore", ".p12", ".pfx", ".bks"}

# Text hints. They can only add findings; nothing is ever cleared by them.
TRUST_KNOBS = re.compile(
    r"REQUESTS_CA_BUNDLE|SSL_CERT_FILE|SSL_CERT_DIR|CURL_CA_BUNDLE|NODE_EXTRA_CA_CERTS|AWS_CA_BUNDLE"
    r"|PIP_CERT|UV_NATIVE_TLS|UV_SYSTEM_CERTS|--use-system-ca|--use-openssl-ca|NODE_USE_SYSTEM_CA"
    r"|DENO_TLS_CA_STORE|DENO_CERT|GIT_SSL_CAINFO|javax\.net\.ssl\.trustStore|truststore\.inject_into_ssl"
)
TLS_DISABLED = re.compile(
    r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|insecure_skip_verify"
    r"|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['\"]?0|danger_accept_invalid_certs\s*\(\s*true"
    r"|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|--insecure\b|\bcurl\b[^\n|;&]*\s-\w*k\w*\b|--no-check-certificate"
    r"|strict-ssl\s*[=:]?\s*false|ssl_verify\s*[=:]\s*false|sslVerify\s*=?\s*false|CERT_NONE"
)
# Encrypts but accepts any server certificate, so a certificate from the
# compromised intermediates is accepted too (libpq, postgres.js, node-postgres).
TLS_UNVERIFIED = re.compile(
    r"sslmode\s*[=:]\s*['\"]?(?:require|prefer|allow)\b|\bssl\s*:\s*['\"](?:require|prefer|allow)['\"]"
    r"|ssl\s*:\s*\{[^}]*rejectUnauthorized\s*:\s*false"
)
# Names of the affected certificates as they appear in pin lists, truststore
# aliases and config. The certificates themselves are found by their bytes.
EMUDHRA_MENTION = re.compile(r"emSign (?:ECC )?Root|EM (?:DV|OV|EV) (?:TLS|CS) CA|emsign[a-z]*root", re.I)
CODE_EXT = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".rs", ".java", ".kt", ".kts", ".scala",
    ".rb", ".php", ".cs", ".ex", ".exs", ".sh", ".bash", ".zsh", ".ps1", ".yml", ".yaml", ".toml", ".env",
    ".json", ".cfg", ".ini", ".conf", ".tf", ".hcl", ".properties", ".gradle", ".xml", ".nix", ".j2", ".tpl",
}

findings = []
coverage = {"files": 0, "parsed": {}, "pruned": [], "symlinked_dirs": [], "unreadable": [], "large": [],
            "missing_parsers": {}}
recognised = [0]
electron_declared = {}     # dir -> (path, spec) from package.json
electron_resolved = set()  # dirs whose lockfile resolved electron
cargo_manifests = []       # (dir, path, deps) of Cargo.toml files that use rustls
cargo_locks = set()
py_consumers = {}          # dir -> (path, names) of manifests using certifi's consumers
certifi_pinned = set()     # dirs whose manifest or lockfile names certifi
package_jsons = []         # paths of package.json files
node_seen = [False]        # whether anything in the tree names the Node version


PRERELEASE = re.compile(r"\d[-.~_+]?(?:alpha|beta|rc|pre|preview|dev|canary|nightly|next|snapshot|a|b)\.?\d*(?![a-z])", re.I)


def add(status, path, component, version, detail):
    # A pre-release of the fixed version comes before it: never FIXED.
    if status == "FIXED" and PRERELEASE.search(str(version or "")):
        status, detail = "REVIEW", "a pre-release; it sorts before the release that carries the fix. " + detail
    row = {"status": status, "path": path, "component": component, "version": str(version or ""), "detail": detail}
    if row not in findings:
        findings.append(row)


def parsed(kind):
    coverage["parsed"][kind] = coverage["parsed"].get(kind, 0) + 1
    recognised[0] += 1


def vtuple(text):
    """'v22.11.0-alpine' -> (22, 11, 0); None when no leading number."""
    m = re.match(r"\s*[v=^~]*\s*(\d+(?:\.\d+)*)", str(text or ""))
    return tuple(int(p) for p in m.group(1).split(".")) if m else None


def pad(t, n):
    return tuple(t) + (0,) * (n - len(t))


def dotted(t):
    return ".".join(map(str, t))


def split_words(s):
    try:
        return shlex.split(s)
    except ValueError:
        return s.split()


# ---------------------------------------------------------------- judges

def judge_threshold(path, component, version, fixed, note=""):
    v = vtuple(version)
    if fixed is None:
        add("REVIEW", path, component, version, note or "no fixed release yet")
    elif v is None:
        add("REVIEW", path, component, version, "unpinned or unparsable; check the resolved/deployed version. " + note)
    elif pad(v, 3) < fixed:
        add("VULNERABLE", path, component, version, "fixed in %s. %s" % (dotted(fixed), note))
    else:
        add("FIXED", path, component, version, note)


def judge_node(path, version, source):
    node_seen[0] = True
    v = vtuple(version)
    comp = "node (%s)" % source
    if v is None:
        add("REVIEW", path, comp, version, "floating version; check the deployed runtime")
    elif v[0] > max(NODE_FIXED):
        add("REVIEW", path, comp, version, NEWER)
    elif v[0] not in NODE_FIXED:
        add("VULNERABLE", path, comp, version, "no patched release on Node %d; move to 22.23.4, 24.22.1 or 26.12.1" % v[0])
    elif len(v) < 3:
        add("REVIEW", path, comp, version, "floating minor; rebuild/redeploy and confirm >= %s" % dotted(NODE_FIXED[v[0]]))
    elif v < NODE_FIXED[v[0]]:
        add("VULNERABLE", path, comp, version, "fixed in %s" % dotted(NODE_FIXED[v[0]]))
    else:
        add("FIXED", path, comp, version, "")


def judge_go(path, version, source):
    version = str(version)
    v = vtuple(version[2:] if version.startswith("go") else version)
    comp = "go toolchain (%s)" % source
    note = "Go programs carry crypto/x509 statically: every binary must be rebuilt with the fixed toolchain"
    if v is None or len(v) < 2:
        add("REVIEW", path, comp, version, "floating version. " + note)
        return
    line = v[:2]
    if line not in GO_FIXED:
        if line < (1, 26):
            add("VULNERABLE", path, comp, version, "no patched release on Go %d.%d; move to 1.26.10 or 1.27.3. %s" % (line + (note,)))
        else:
            add("REVIEW", path, comp, version, NEWER)
    elif len(v) < 3:
        add("REVIEW", path, comp, version, "floating patch; confirm >= %s. %s" % (dotted(GO_FIXED[line]), note))
    elif v < GO_FIXED[line]:
        add("VULNERABLE", path, comp, version, "fixed in %s. %s" % (dotted(GO_FIXED[line]), note))
    else:
        add("FIXED", path, comp, version, "binaries built before the bump still need a rebuild")


def java_tuple(version):
    """'8u432-b06' / '1.8.0_432' -> (8, 0, 432); '21.0.4_7' -> (21, 0, 4)."""
    s = str(version).strip()
    m = re.match(r"(?:8u|1\.8\.0_)(\d+)", s)
    if m:
        return (8, 0, int(m.group(1)))
    return vtuple(s)


def java_image_tag(tag, build_tool=False):
    """Pull the JDK version out of an image tag: 'maven:3.9.6-eclipse-temurin-21' -> '21',
    'gradle:8.5-jdk21' -> '21', 'eclipse-temurin:21.0.4_7-jre' -> '21.0.4_7-jre'. A
    maven/gradle tag that names no JDK gives '', which is reported as REVIEW rather than
    reading the build tool's version as Java's."""
    m = re.search(r"(?:eclipse-temurin|amazoncorretto|corretto|zulu|semeru|sapmachine|jdk|jre)-?(\d[\w.]*)", tag)
    if m:
        return m.group(1)
    return "" if build_tool else tag


def judge_java(path, version, source):
    v = java_tuple(version)
    comp = "java runtime (%s)" % source
    if v is None:
        add("REVIEW", path, comp, version, "no JDK version in the tag or unparsable; check the deployed JDK")
        return
    major = v[0]
    if major not in JAVA_LAST_AFFECTED:
        add("VULNERABLE" if major < 27 else "REVIEW", path, comp, version,
            "no patched release listed for Java %d" % major)
    elif len(v) < 3:
        add("REVIEW", path, comp, version, "floating tag; rebuild with --pull and check the deployed JDK build")
    elif pad(v, 3) <= JAVA_LAST_AFFECTED[major]:
        add("VULNERABLE", path, comp, version,
            "at or before %s, the last affected build; update the JDK" % dotted(JAVA_LAST_AFFECTED[major]))
    else:
        add("REVIEW", path, comp, version,
            "past %s: confirm the vendor build carries the 2026-10-21 fix (OpenJDK CVE-2026-91403). "
            "Distro JDKs use the OS cacerts, so updating ca-certificates covers them" % dotted(JAVA_LAST_AFFECTED[major]))


def judge_electron(path, version):
    version = str(version)
    v = vtuple(version)
    if v is not None and RANGE.search(version):
        add("REVIEW", path, "electron", version, "a range, not a version; check the resolved version in the lockfile")
    elif v is None:
        add("REVIEW", path, "electron", version, "unpinned")
    elif v[0] > max(ELECTRON_FIXED):
        add("REVIEW", path, "electron", version, NEWER)
    elif v[0] not in ELECTRON_FIXED:
        add("VULNERABLE", path, "electron", version, "no patched release on Electron %d; move to 42.11.16, 43.8.1 or 44.9.1" % v[0])
    elif pad(v, 3) < ELECTRON_FIXED[v[0]]:
        add("VULNERABLE", path, "electron", version, "fixed in %s; ship a new app build" % dotted(ELECTRON_FIXED[v[0]]))
    else:
        add("FIXED", path, "electron", version, "")


def judge_bun(path, version, source):
    bare = re.sub(r"^bun@|^bun-v", "", str(version or ""))
    v = vtuple(bare)
    comp = "bun (%s)" % source
    if v is None or len(v) < 3:
        add("REVIEW", path, comp, version, "floating or unparsable; check the Bun that actually runs (fixed in 1.4.4)")
    else:
        judge_threshold(path, comp, bare, BUN_FIXED, "rebuild and reship any `bun build --compile` binary too")


def judge_deno(path, version, source):
    judge_threshold(path, "deno (%s)" % source, version, DENO_FIXED, "rebuild and reship any `deno compile` binary too")


def judge_uv(path, version, source):
    judge_threshold(path, "uv (%s)" % source, version, TOOL_FIXED["uv"])


def judge_composer_ca_bundle(path, version):
    v = vtuple(version)
    if v is None:
        add("REVIEW", path, "composer/ca-bundle", version, "unparsable")
    elif pad(v, 3) < (1, 4, 16) or (1, 5, 0) <= pad(v, 3) < (1, 6, 0):
        add("VULNERABLE", path, "composer/ca-bundle", version, "fixed in 1.4.16 and 1.6.0")
    else:
        add("FIXED", path, "composer/ca-bundle", version, "")


def judge_conda(path, name, ver):
    if name == "certifi":
        judge_threshold(path, "certifi (conda)", ver, PY_PACKAGES["certifi"][0], "conda env's certifi")
    elif name == "ca-certificates":
        v = vtuple(ver)
        if v is None:
            add("REVIEW", path, "ca-certificates (conda)", ver, "unparsable; check $CONDA_PREFIX/ssl/cacert.pem with trust_store.py")
        elif pad(v, 3) < CONDA_CA_FIXED:
            add("VULNERABLE", path, "ca-certificates (conda)", ver,
                "conda envs use their own bundle at $CONDA_PREFIX/ssl/cacert.pem, not the OS store; update it")
        else:
            add("REVIEW", path, "ca-certificates (conda)", ver,
                "dated after the fix; confirm with trust_store.py on $CONDA_PREFIX/ssl/cacert.pem")


# URL shapes that pin a runtime or tool version in a download.
URL_RULES = [
    (re.compile(r"astral\.sh/uv/(\d[\w.]*)/install"), lambda p, v: judge_uv(p, v, "install script")),
    (re.compile(r"github\.com/astral-sh/uv/releases/download/(\d[\w.]*)/"), lambda p, v: judge_uv(p, v, "download")),
    (re.compile(r"nodejs\.org/dist/v(\d[\w.]*)/"), lambda p, v: judge_node(p, v, "download")),
    (re.compile(r"(?:go\.dev/dl|dl\.google\.com/go)/go(\d[\d.]*\d)\."), lambda p, v: judge_go(p, v, "download")),
    (re.compile(r"github\.com/oven-sh/bun/releases/download/bun-v(\d[\w.]*)/"), lambda p, v: judge_bun(p, v, "download")),
    (re.compile(r"github\.com/denoland/deno/releases/download/v(\d[\w.]*)/"), lambda p, v: judge_deno(p, v, "download")),
    (re.compile(r"releases\.hashicorp\.com/(\w+)/(\d[\w.]*)"), lambda p, t, v: add("REVIEW", p, "%s download" % t, v, GO_CLI_NOTE)),
    (re.compile(r"get\.helm\.sh/helm-v(\d[\w.]*)"), lambda p, v: add("REVIEW", p, "helm download", v, GO_CLI_NOTE)),
    (re.compile(r"dl\.k8s\.io/release/v(\d[\w.]*)"), lambda p, v: add("REVIEW", p, "kubectl download", v, GO_CLI_NOTE)),
    (re.compile(r"github\.com/cli/cli/releases/download/v(\d[\w.]*)"), lambda p, v: add("REVIEW", p, "gh download", v, GO_CLI_NOTE)),
    (re.compile(r"/(certifi|ca-certificates)-(\d[\w.]*)-[^/\s\"']+\.(?:conda|tar\.bz2)\b"), lambda p, n, v: judge_conda(p, n, v)),
]


def scan_urls(path, text):
    for rx, judge in URL_RULES:
        for m in rx.finditer(text):
            judge(path, *m.groups())


# ---------------------------------------------------------------- requirement specs

REQ_NAME = re.compile(r"\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)\s*(\[[^\]]*\])?\s*(.*)$", re.S)
CLAUSE = re.compile(r"\s*(===|==|~=|!=|<=|>=|<|>)\s*([^\s,]+)\s*$")


def norm(name):
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def judge_clauses(path, name, clauses, fixed, note, raw):
    """clauses: [(op, version)] from a PEP 440 specifier. Fail closed: only an
    exact pin can be FIXED, and a bound that provably excludes the fix is
    VULNERABLE; everything else is REVIEW."""
    if fixed is None:
        add("REVIEW", path, name, raw, note or "no fixed release yet")
        return
    exact = [v for op, v in clauses if op in ("==", "===") and "*" not in v]
    if exact:
        judge_threshold(path, name, exact[0], fixed, note)
        return
    floor = [vtuple(v) for op, v in clauses if op in (">=", ">", "~=") and vtuple(v)]
    if any(pad(t, 3) >= fixed for t in floor) and not any(PRERELEASE.search(v) for _, v in clauses):
        add("FIXED", path, name, raw, "every version the specifier allows is at or past the fix. " + note)
        return
    for op, v in clauses:
        t = vtuple(v.replace(".*", ""))
        if t is None:
            continue
        if (op == "<" and pad(t, 3) <= fixed) or (op == "<=" and pad(t, 3) < fixed) \
                or (op == "==" and "*" in v and t < fixed[:len(t)]) \
                or (op == "~=" and len(t) > 1 and t[:-1] < fixed[:len(t) - 1]):
            add("VULNERABLE", path, name, raw, "the specifier excludes the fix %s. %s" % (dotted(fixed), note))
            return
    add("REVIEW", path, name, raw or "(unpinned)",
        "not pinned; the version is whatever resolved at build time. Check the lockfile or deployed environment")


# Python packages that load certifi's bundle: a manifest that uses one without
# pinning certifi gets whatever certifi resolved at install time.
CERTIFI_CONSUMERS = {"requests", "httpx", "boto3", "botocore", "aiohttp", "google-auth", "openai", "anthropic",
                     "urllib3", "grpcio", "pip-system-certs", "httplib2", "elasticsearch", "snowflake-connector-python"}


def note_python_name(path, name):
    d = os.path.dirname(path)
    if name == "certifi":
        certifi_pinned.add(d)
    elif name in CERTIFI_CONSUMERS:
        py_consumers.setdefault(d, (path, set()))[1].add(name)


WHEEL = re.compile(r"(?:^|/)([A-Za-z0-9][A-Za-z0-9._]*?)-(\d[\w.!+]*?)(?:-py\d|-cp\d|-\d+-|\.tar\.gz|\.zip|\.tar\.bz2)", re.I)


def judge_url_requirement(path, url):
    """A requirement given as a wheel or sdist URL: judged by its file name."""
    m = WHEEL.search(url.split("#", 1)[0].split("?", 1)[0])
    if not m or norm(m.group(1)) not in PY_PACKAGES:
        return False
    name = norm(m.group(1))
    note_python_name(path, name)
    fixed, note = PY_PACKAGES[name]
    judge_threshold(path, name, m.group(2), fixed, note)
    return True


def judge_requirement(path, req):
    """One PEP 508 requirement string. Returns True if it named a tracked package."""
    if re.match(r"\s*(?:https?|file)://", req):
        return judge_url_requirement(path, req.strip())
    m = REQ_NAME.match(req)
    if not m:
        return False
    name = norm(m.group(1))
    note_python_name(path, name)
    if name not in PY_PACKAGES:
        return False
    fixed, note = PY_PACKAGES[name]
    rest = m.group(3).split(";", 1)[0].strip()
    if rest.startswith("@"):
        if not judge_url_requirement(path, rest[1:].strip()):
            add("REVIEW", path, name, rest, "installed from a URL or path; check what it resolves to")
        return True
    rest = rest.strip("()").strip()
    clauses = []
    for part in [p for p in rest.split(",") if p.strip()]:
        c = CLAUSE.match(part)
        if not c:
            add("REVIEW", path, name, rest, "a specifier this scanner cannot read; check the resolved version")
            return True
        clauses.append((c.group(1), c.group(2)))
    judge_clauses(path, name, clauses, fixed, note, rest)
    return True


def poetry_clauses(spec):
    """Poetry's constraint syntax as PEP 440 clauses, or None if unreadable."""
    out = []
    for part in [p.strip() for p in re.split(r",|\s+(?=[<>=!~^])", spec) if p.strip()]:
        if part == "*":
            continue
        if part.startswith("^") or (part.startswith("~") and not part.startswith("~=")):
            t = vtuple(part.lstrip("^~"))
            if t is None:
                return None
            if part.startswith("^"):
                i = next((k for k, x in enumerate(t) if x), len(t) - 1)
            else:
                i = 1 if len(t) > 1 else 0
            out += [(">=", dotted(t)), ("<", dotted(t[:i] + (t[i] + 1,)))]
        elif re.match(r"\d", part):
            out.append(("==", part))
        else:
            c = CLAUSE.match(part)
            if not c:
                return None
            out.append((c.group(1), c.group(2)))
    return out


def judge_poetry(path, name, spec):
    name = norm(name)
    note_python_name(path, name)
    if name not in PY_PACKAGES:
        return
    if isinstance(spec, list):
        for s in spec:
            judge_poetry(path, name, s)
        return
    if isinstance(spec, dict):
        if "version" not in spec:
            add("REVIEW", path, name, json.dumps(spec)[:60], "installed from a git/path/url source; check what it resolves to")
            return
        spec = spec["version"]
    fixed, note = PY_PACKAGES[name]
    clauses = poetry_clauses(str(spec))
    if clauses is None:
        add("REVIEW", path, name, spec, "a constraint this scanner cannot read; check the lockfile")
    else:
        judge_clauses(path, name, clauses, fixed, note, spec)


# ---------------------------------------------------------------- shell commands

def commands(text):
    """Simple commands in a shell snippet, as token lists, split on ; && || |
    and newlines. Leading VAR=value assignments and sudo/exec/env are dropped."""
    out = []
    for chunk in re.sub(r"\\\r?\n", " ", text).splitlines():
        try:
            lex = shlex.shlex(chunk, posix=True, punctuation_chars=True)
            lex.whitespace_split = True
            lex.commenters = "#"
            toks = list(lex)
        except ValueError:
            toks = chunk.split()  # unbalanced quotes; still worth reading
        cur = []
        for t in toks + [";"]:
            if t and set(t) <= set(";&|()"):
                while cur and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", cur[0]) or cur[0] in ("sudo", "exec", "time", "env")):
                    cur = cur[1:]
                if cur:
                    out.append(cur)
                cur = []
            else:
                cur.append(t)
    return out


PIP_VALUE_OPTS = {"-r", "-c", "--requirement", "--constraint", "-i", "--index-url", "--extra-index-url", "--cert",
                  "--trusted-host", "-f", "--find-links", "--target", "-t", "--prefix", "--root", "--python", "-p"}


def scan_shell(path, text, where="script"):
    """Commands that pin or embed something. Returns facts the caller may use."""
    facts = set()
    for cmd in commands(text):
        prog, args = os.path.basename(cmd[0]), cmd[1:]
        runner = prog in ("npx", "pnpm", "yarn", "bunx", "npm") and args[:1] and args[0] != "exec"
        if prog == "bun" and args[:1] == ["build"] and "--compile" in args:
            add("REVIEW", path, "bun-compiled binary", where, BUN_COMPILED)
        elif prog == "deno" and args[:1] == ["compile"]:
            add("REVIEW", path, "deno-compiled binary", where, EMBEDS_RUNTIME)
        elif prog in ("pkg", "nexe", "postject") or (runner and args[0] in ("pkg", "nexe", "@yao-pkg/pkg", "postject")):
            add("REVIEW", path, "node single-executable (%s)" % (args[0] if runner else prog), where, EMBEDS_RUNTIME)
        elif prog == "node" and any(a.startswith("--experimental-sea-config") for a in args):
            add("REVIEW", path, "node single-executable", where, EMBEDS_RUNTIME)
        scan_version_managers(path, prog, args)
        pip_args = None
        if re.match(r"pip(?:3(?:\.\d+)?)?$", prog):
            pip_args = args
        elif re.match(r"python(?:\d(?:\.\d+)?)?$", prog) and args[:2] == ["-m", "pip"]:
            pip_args = args[2:]
        elif prog == "uv" and args[:1] in (["pip"], ["tool"]):
            pip_args = args[1:]
        elif prog == "pipx":
            pip_args = args
        if not pip_args or pip_args[0] not in ("install", "add", "inject"):
            continue
        rest = pip_args[1:]
        upgrade = any(a in ("-U", "--upgrade") or re.match(r"^-[a-zA-Z]*U[a-zA-Z]*$", a) for a in rest)
        skip = False
        for a in rest:
            if skip:
                skip = False
                continue
            if a in PIP_VALUE_OPTS:
                skip = True
                facts |= {"pip_cert"} if a == "--cert" else set()
                continue
            if a.startswith("-"):
                continue
            req = REQ_NAME.match(a)
            if req and norm(req.group(1)) == "pip" and (upgrade or "=" in a):
                facts.add("pip_upgraded")
            judge_requirement(path, a)
    return facts


def positional(args):
    return [a for a in args if not a.startswith("-")]


def judge_spec(path, spec, source):
    """'node@22.1.0', 'nodejs 22', 'bun@1.4.4': route to the right judge."""
    tool, _, ver = spec.partition("@")
    judge_tool_any(path, tool, ver or "", source)


def judge_tool_any(path, tool, ver, source):
    tool = tool.lower()
    if tool in ("node", "nodejs"):
        judge_node(path, ver, source)
    elif tool == "bun":
        judge_bun(path, ver, source)
    elif tool == "deno":
        judge_deno(path, ver, source)
    elif tool in ("go", "golang"):
        judge_go(path, ver, source)


def scan_version_managers(path, prog, args):
    """Runtimes installed by a version manager or a global package install."""
    pos = positional(args)
    if prog in ("nvm", "fnm", "n", "nodenv") and pos[:1] in (["install"], ["use"]):
        judge_node(path, pos[1] if len(pos) > 1 else "", prog)
    elif prog == "n" and pos and re.match(r"v?\d|lts|latest|current", pos[0]):
        judge_node(path, pos[0], "n")
    elif prog == "volta" and pos[:1] in (["install"], ["pin"]):
        for spec in pos[1:]:
            judge_spec(path, spec, "volta")
    elif prog in ("asdf", "mise", "rtx") and pos[:1] in (["install"], ["use"], ["global"], ["local"], ["set"]):
        rest = pos[1:]
        if rest and "@" in rest[0]:
            for spec in rest:
                judge_spec(path, spec, prog)
        elif len(rest) >= 2:
            judge_tool_any(path, rest[0], rest[1], prog)
    elif prog in ("npm", "pnpm", "yarn", "bun") and pos[:1] in (["install"], ["i"], ["add"]) \
            and ("-g" in args or "--global" in args or prog == "yarn" and "global" in args):
        for spec in pos[1:]:
            name, _, ver = spec.rpartition("@") if spec.count("@") > (1 if spec.startswith("@") else 0) else (spec, "", "")
            if name == "bun":
                judge_bun(path, ver, "global install")
            elif name in ("pnpm", "@pnpm/exe"):
                add("REVIEW", path, "pnpm (global install)", ver, PNPM_NOTE)


PNPM_NOTE = ("the standalone pnpm (@pnpm/exe, get.pnpm.io) embeds its own Node, which ignores the system one; "
             "check `pnpm --version` against a build on a fixed Node, or install pnpm from npm on a fixed Node")

def on_line(rx, line):
    m = re.search(rx, line)
    return m.group(1) if m else ""


# Installers that fetch whatever is current, or a version given on the line.
INSTALLERS = [
    (re.compile(r"(?:deb|rpm)\.nodesource\.com/setup_(\d+)\.x"), lambda p, m, line: judge_node(p, m.group(1), "nodesource")),
    (re.compile(r"(?:deb|rpm)\.nodesource\.com/setup_(lts|current)\.x"), lambda p, m, line: judge_node(p, m.group(1), "nodesource")),
    (re.compile(r"bun\.sh/install"), lambda p, m, line: judge_bun(p, on_line(r"bun-v(\d[\w.]*)", line), "bun.sh/install")),
    (re.compile(r"astral\.sh/uv/install\.(?:sh|ps1)"), lambda p, m, line: judge_uv(p, "", "unversioned install script")),
    (re.compile(r"deno\.land/(?:x/)?install"), lambda p, m, line: judge_deno(p, on_line(r"\bv(\d+\.\d+\.\d+)\b", line),
                                                                            "install script")),
    (re.compile(r"get\.pnpm\.io/install"), lambda p, m, line: add("REVIEW", p, "pnpm (standalone installer)", "", PNPM_NOTE)),
    (re.compile(r"\b(?:curl|wget)\b[^|]*://[^|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"),
     lambda p, m, line: add("REVIEW", p, "script piped to a shell", line.strip()[:120],
                            "fetched and run at build time: check which runtimes and binaries it installs, at which versions")),
    (re.compile(r"releases\.hashicorp\.com/|github\.com/[^/\s]+/[^/\s]+/releases/download/"),
     lambda p, m, line: add("REVIEW", p, "binary downloaded at build time", line.strip()[:120],
                            "if it is Go-built (most CLIs are), it carries its own crypto/x509: check the version "
                            "against a build on Go >= 1.26.10 / 1.27.3, or run go_binaries.py on the image")),
    (re.compile(r"raw\.githubusercontent\.com/nvm-sh/nvm/|fnm\.vercel\.app/install|get\.volta\.sh"),
     lambda p, m, line: add("REVIEW", p, "node version manager", "",
                            "installs Node versions on demand and keeps old ones: probe and remove every installed Node")),
]


def scan_installers(path, text):
    for line in text.splitlines():
        if "://" not in line and "nodesource" not in line:
            continue
        for rx, judge in INSTALLERS:
            m = rx.search(line)
            if m:
                judge(path, m, line)


# ---------------------------------------------------------------- images

IMAGE_RULES = [
    (re.compile(r"(?:^|/)node:(.+)$"), lambda p, t: judge_node(p, t, "image tag")),
    (re.compile(r"(?:^|/)golang:(.+)$"), lambda p, t: judge_go(p, t, "image tag")),
    (re.compile(r"(?:^|/)(?:eclipse-temurin|openjdk|amazoncorretto|ibm-semeru-runtimes|sapmachine|azul/zulu-openjdk[^:]*):(.+)$"),
     lambda p, t: judge_java(p, java_image_tag(t), "image tag")),
    (re.compile(r"(?:^|/)(?:maven|gradle):(.+)$"),
     lambda p, t: judge_java(p, java_image_tag(t, build_tool=True), "image tag") if java_image_tag(t, build_tool=True)
     else add("REVIEW", p, "java runtime (image tag)", t, "the tag names no JDK; check the JDK in the deployed image")),
    (re.compile(r"(?:^|/)denoland/deno:(?:[a-z]+-)?(.+)$"), lambda p, t: judge_deno(p, t, "image tag")),
    (re.compile(r"(?:^|/)astral-sh/uv:(.+)$"), lambda p, t: judge_uv(p, t, "image tag")),
    (re.compile(r"(?:^|/)dotnet/(?:sdk|aspnet|runtime|runtime-deps):(.+)$"), lambda p, t: add("REVIEW", p, ".NET (image tag)", t,
        ".NET trusts the image's OS store; rebuild on a base published after 2026-10-20")),
    (re.compile(r"(?:^|/)(?:continuumio/(?:mini|ana)conda3?|condaforge/(?:miniforge3|mambaforge)|mambaorg/micromamba):(.+)$"),
     lambda p, t: add("REVIEW", p, "conda (image tag)", t,
        "conda envs use their own ca-certificates and certifi, not the OS store; update both in the image")),
    (re.compile(r"(?:^|/)oven/bun:(.+)$"), lambda p, t: judge_bun(p, re.sub(r"^(?:canary|latest)\b.*", "", t) or t, "image tag")),
]


GO_TOOL_IMAGE = re.compile(
    r"(?:^|/)(?:docker|hashicorp/[\w-]+|otel/[\w-]+|datadog/agent|datadoghq/agent|traefik|caddy|prom/[\w-]+"
    r"|grafana/(?:agent|alloy|loki|tempo|mimir)|bitnami/kubectl|alpine/helm|amazon/aws-otel-collector)$")


def judge_image(path, image, where, base=True):
    image = str(image).strip().strip("\"'")
    if not image or image.lower() == "scratch":
        return
    if "$" in image or "{{" in image:
        add("REVIEW", path, "image (%s)" % where, image,
            "the image comes from a variable or template; check what the build or deploy actually uses")
        return
    ref = image.split("@", 1)[0]
    name = ref.split(":")[0].lower()
    if GO_TOOL_IMAGE.search(name):  # also when a binary is copied out with COPY --from
        add("REVIEW", path, "Go-built image (%s)" % where, image,
            "the program in this image carries its own crypto/x509, so --pull does not help: bump to a release "
            "built on Go >= 1.26.10 / 1.27.3 (Datadog Agent 7.84.5+) and check it with go_binaries.py --root")
    elif base:
        add("REVIEW", path, "base image (%s)" % where, image,
            "pinned by digest: it will not pick up a patched ca-certificates until the digest is bumped" if "@sha256:" in image
            else "rebuild with --pull --no-cache so the ca-certificates layer is refreshed, then verify the deployed image")
    if ":" in ref.split("/")[-1]:
        for rx, judge in IMAGE_RULES:
            m = rx.search(ref)
            if m:
                judge(path, m.group(1))
                break


# ---------------------------------------------------------------- Dockerfile

HEREDOC = re.compile(r"(?<!<)<<(?!<)-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?")


def dockerfile_instructions(text, problems=None):
    """(KEYWORD, arguments) for each instruction, with line continuations
    joined, comments dropped and heredoc bodies appended to their instruction.
    Only RUN, COPY and ADD take heredocs, and <<< is a shell here-string, not
    one. A heredoc with no terminator is reported in problems: everything after
    it would otherwise vanish into its body."""
    lines = text.splitlines()
    escape = "\\"
    for line in lines[:5]:
        m = re.match(r"\s*#\s*escape\s*=\s*(\S)", line, re.I)
        if m:
            escape = m.group(1)
    out, cur, i = [], "", 0
    while i < len(lines):
        s = lines[i].strip()
        i += 1
        if s.startswith("#") or (not s and not cur):
            continue
        if s.endswith(escape):
            cur += s[:-1] + " "
            continue
        cur += s
        tags = HEREDOC.findall(cur) if cur.split(None, 1)[0].upper() in ("RUN", "COPY", "ADD") else []
        for tag in tags:
            body, start = [], i
            while i < len(lines) and lines[i].strip() != tag:
                body.append(lines[i])
                i += 1
            if i >= len(lines):
                if problems is not None:
                    problems.append("heredoc <<%s from line %d is never closed" % (tag, start))
                i = start  # read what follows as instructions rather than lose it
                break
            i += 1
            cur += "\n" + "\n".join(body)
        parts = cur.split(None, 1)
        out.append((parts[0].upper(), parts[1] if len(parts) > 1 else ""))
        cur = ""
    if cur.strip():
        parts = cur.split(None, 1)
        out.append((parts[0].upper(), parts[1] if len(parts) > 1 else ""))
    return out


def substitute(value, env):
    def one(m):
        name, default = m.group(1) or m.group(3), m.group(2)
        if env.get(name):
            return env[name]
        return default if default is not None else m.group(0)
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)", one, value)


def exec_or_shell(args):
    s = args.strip()
    if s.startswith("["):
        try:
            return " ".join(shlex.quote(str(x)) for x in json.loads(s))
        except ValueError:
            pass
    return s


VERSION_VAR = re.compile(r"^([A-Za-z][A-Za-z0-9_]*?)_(?:VERSION|VER)$")
VERSION_VAR_TOOLS = {"node": "node", "nodejs": "node", "go": "go", "golang": "go", "bun": "bun", "deno": "deno",
                     "java": "java", "jdk": "java", "uv": "uv", "pixi": "pixi", "mise": "mise",
                     "claude_code": "claude-code", "claude": "claude-code"}


def scan_version_vars(path, pairs, source):
    """NODE_VERSION=22.1.0, CLAUDE_CODE_VERSION=2.1.239 and the like, in ARG,
    ENV and env files: a pin that an install command reads later."""
    for k, v in pairs:
        m = VERSION_VAR.match(k.strip())
        v = str(v).strip().strip("\"'")
        if not m or not v or "$" in v:
            continue
        name = m.group(1).lower()
        tool = VERSION_VAR_TOOLS.get(name) or (name.replace("_", "-") if name.replace("_", "-") in GO_CLIS else None)
        if tool:
            judge_tool(path, tool, v.lstrip("v"))


def scan_env_file(path, text):
    parsed("env file")
    pairs = []
    for line in text.splitlines():
        m = re.match(r"\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$", line)
        if m:
            pairs.append((m.group(1), m.group(2).split(" #")[0]))
    scan_version_vars(path, pairs, "env file")


def scan_dockerfile(path, text):
    parsed("Dockerfile")
    env, stages, python_image, facts, problems = {}, set(), False, set(), []
    instructions = dockerfile_instructions(text, problems)
    for problem in problems:
        add("ERROR", path, "Dockerfile", "", problem)
    for kw, args in instructions:
        if kw == "ARG":
            for tok in split_words(args):
                k, _, v = tok.partition("=")
                env.setdefault(k, v)
                scan_version_vars(path, [(k, v)], "ARG")
        elif kw == "ENV":
            words = split_words(args)
            pairs = [w.partition("=") for w in words] if words and "=" in words[0] else \
                [(words[0], "=", " ".join(words[1:]))] if words else []
            for k, _, v in pairs:
                env[k] = substitute(v, env)
                scan_version_vars(path, [(k, env[k])], "ENV")
                if k == "PIP_CERT":
                    facts.add("pip_cert")
        elif kw == "FROM":
            toks = [t for t in substitute(args, env).split() if not t.startswith("--")]
            if not toks:
                add("ERROR", path, "FROM", args, "a FROM with no image")
                continue
            image = toks[0]
            if len(toks) >= 3 and toks[1].lower() == "as":
                stages.add(toks[2].lower())
            if image.lower() in stages:
                continue
            judge_image(path, image, "FROM")
            if image.split("@")[0].split("/")[-1].split(":")[0].lower() in ("python", "pypy"):
                python_image = True
        elif kw in ("COPY", "ADD"):
            for tok in args.split():
                if tok.startswith("--from="):
                    src = substitute(tok[7:], env)
                    if src.lower() not in stages and not src.isdigit():
                        judge_image(path, src, "COPY --from", base=False)
        elif kw == "RUN":
            facts |= scan_shell(path, substitute(exec_or_shell(re.sub(r"^(?:--\S+\s+)*", "", args)), env), "RUN")
    if python_image and "pip_upgraded" not in facts:
        add("REVIEW", path, "pip in image", "",
            "official python images shipped an old pip as of 2026-10-21 (python:3.12-slim: pip 25.0.1, certifi "
            "2024.08.30); upgrade pip>=26.2.2 and certifi early in the build. PIP_CERT alone does not fix an old pip")


# ---------------------------------------------------------------- YAML

if yaml is not None:
    class AnyTagLoader(yaml.SafeLoader):
        """SafeLoader that reads unknown tags (!Ref, !reference) as plain data."""

    def _any_tag(loader, suffix, node):
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        return loader.construct_scalar(node)

    AnyTagLoader.add_multi_constructor("!", _any_tag)
    AnyTagLoader.add_multi_constructor("tag:", _any_tag)


def judge_setup_node_cached(path, version):
    """setup-node without check-latest: a floating version takes the runner's
    cached Node, which was 24.21.0 on the hosted images."""
    v = vtuple(version)
    if v is not None and len(v) < 3 and v[0] in NODE_FIXED:
        add("VULNERABLE", path, "node (setup-node)", version,
            "a floating version without check-latest: true takes the runner's cached Node (24.21.0 on the hosted "
            "images); pin %s or set check-latest" % dotted(NODE_FIXED[v[0]]))
    elif v is None and re.match(r"\s*(?:lts|node|latest|current)", str(version), re.I):
        add("VULNERABLE", path, "node (setup-node)", version,
            "an alias without check-latest: true takes the runner's cached Node; pin an exact fixed version")
    else:
        judge_node(path, version, "setup-node")


SETUP_ACTIONS = {
    "actions/setup-node": ("node-version", lambda p, v: judge_node(p, v, "setup-node")),
    "actions/setup-go": ("go-version", lambda p, v: judge_go(p, v, "setup-go")),
    "actions/setup-java": ("java-version", lambda p, v: judge_java(p, v, "setup-java")),
    "oven-sh/setup-bun": ("bun-version", lambda p, v: judge_bun(p, v, "setup-bun")),
    "denoland/setup-deno": ("deno-version", lambda p, v: judge_deno(p, v, "setup-deno")),
    "astral-sh/setup-uv": ("version", lambda p, v: judge_uv(p, v, "setup-uv")),
}
VERSION_KEYS = {key: judge for key, judge in SETUP_ACTIONS.values() if key != "version"}
SHELL_KEYS = {"run", "script", "before_script", "after_script", "command", "cmd", "entrypoint", "args"}


def scalars(v):
    if isinstance(v, list):
        for x in v:
            yield from scalars(x)
    elif v is not None and not isinstance(v, dict):
        yield str(v)


def resolve_expr(value, matrix):
    """Values of '${{ matrix.X }}' from the job's matrix, or None."""
    m = re.fullmatch(r"\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}", value.strip())
    if not m or not isinstance(matrix, dict):
        return None
    key = m.group(1)
    vals = list(scalars(matrix.get(key)))
    for inc in matrix.get("include") or []:
        if isinstance(inc, dict) and key in inc:
            vals += list(scalars(inc[key]))
    return vals or None


def judge_version_values(path, key, judge, value, matrix):
    for v in scalars(value):
        if "${{" in v:
            got = resolve_expr(v, matrix)
            if got is None:
                add("REVIEW", path, key, v, "an expression this scanner cannot resolve; check each value it takes")
            for x in got or []:
                judge(path, x)
        elif v.strip():
            judge(path, v.strip())


def walk_yaml(path, node, workflow, matrix=None):
    if isinstance(node, list):
        for x in node:
            walk_yaml(path, x, workflow, matrix)
        return
    if not isinstance(node, dict):
        return
    base = os.path.basename(path).lower()
    cloudbuild = base.startswith("cloudbuild")
    travis = base == ".travis.yml"
    if workflow and isinstance(node.get("strategy"), dict) and "matrix" in node["strategy"]:
        matrix = node["strategy"]["matrix"]
        if isinstance(matrix, str):
            add("REVIEW", path, "matrix", matrix, "a computed matrix; check each value it takes")
    uses = node.get("uses")
    if workflow and isinstance(uses, str):
        action = uses.split("@", 1)[0].lower()
        with_ = node.get("with") if isinstance(node.get("with"), dict) else {}
        if action in SETUP_ACTIONS:
            key, judge = SETUP_ACTIONS[action]
            if action == "actions/setup-node" and str(with_.get("check-latest", "")).lower() != "true":
                judge = judge_setup_node_cached
            files = [k for k in with_ if str(k).endswith("-file")]
            if key in with_:
                judge_version_values(path, key, judge, with_[key], matrix)
            elif files:
                add("INFO", path, files[0], with_[files[0]], "version comes from that file, scanned separately")
            else:
                add("REVIEW", path, action, "(no version)",
                    "no version given: the action uses the runner's copy or the latest; check what ran")
        elif action in GO_CLI_ACTIONS:
            add("REVIEW", path, action, with_.get("version", ""), GO_CLI_NOTE)
        elif uses.startswith("docker://"):
            judge_image(path, uses[9:], "uses docker://")
    for k, v in node.items():
        k = str(k)
        if k == "image" or (workflow and k == "container" and isinstance(v, str)):
            if isinstance(v, dict):
                v = v.get("name")
            if isinstance(v, str):
                judge_image(path, v, "yaml %s" % k)
        elif k == "services" and isinstance(v, list):
            for s in v:
                if isinstance(s, dict):
                    s = s.get("name") or s.get("image")
                if isinstance(s, str):
                    judge_image(path, s, "yaml services")
        elif k == "steps" and isinstance(v, list) and cloudbuild:
            for step in v:
                if isinstance(step, dict) and isinstance(step.get("name"), str):
                    judge_image(path, step["name"], "cloudbuild step")
        elif k == "task" and isinstance(v, str) and isinstance(node.get("inputs"), dict):
            inputs = node["inputs"]
            task = v.split("@", 1)[0].lower()
            if task in ("nodetool", "usenode"):
                judge_version_values(path, "NodeTool", lambda p, x: judge_node(p, x, "azure NodeTool"),
                                     inputs.get("versionSpec") or inputs.get("version") or "", matrix)
            elif task == "gotool":
                judge_version_values(path, "GoTool", lambda p, x: judge_go(p, x, "azure GoTool"),
                                     inputs.get("version") or "", matrix)
            elif task == "javatoolinstaller":
                judge_version_values(path, "JavaToolInstaller", lambda p, x: judge_java(p, x, "azure JavaToolInstaller"),
                                     inputs.get("versionSpec") or "", matrix)
        elif k == "runtime-versions" and isinstance(v, dict):
            for tool, ver in v.items():
                judge_tool_any(path, {"nodejs": "node", "golang": "go"}.get(str(tool), str(tool)), str(ver), "codebuild")
                if str(tool) in ("java", "corretto"):
                    judge_java(path, re.sub(r"^\D+", "", str(ver)), "codebuild")
        elif k == "node_js" and travis:
            for x in scalars(v):
                judge_node(path, x, "travis")
        elif k in ("go",) and travis:
            for x in scalars(v):
                judge_go(path, x, "travis")
        elif k in VERSION_KEYS and not isinstance(v, dict):
            judge_version_values(path, k, VERSION_KEYS[k], v, matrix)
        elif k == "runs-on" and "self-hosted" in json.dumps(v, default=str):
            add("REVIEW", path, "self-hosted runner", "",
                "the runner host's OS trust store, Node, JDK, pip and uv all need patching, not just the workflow")
        if k in SHELL_KEYS:
            for s in scalars(v):
                scan_shell(path, s, "script")
        walk_yaml(path, v, workflow, matrix)


def iter_dicts(node):
    if isinstance(node, dict):
        yield node
        for v in node.values():
            yield from iter_dicts(v)
    elif isinstance(node, list):
        for v in node:
            yield from iter_dicts(v)


def is_conda_env(doc):
    deps = doc.get("dependencies") if isinstance(doc, dict) else None
    return isinstance(deps, list) and bool(deps) and all(
        isinstance(d, str) or (isinstance(d, dict) and set(d) <= {"pip"}) for d in deps)


def scan_conda_env(path, doc):
    parsed("conda env")
    pinned_ca = False
    for d in doc["dependencies"]:
        if isinstance(d, dict):
            for req in d.get("pip") or []:
                if isinstance(req, str):
                    judge_requirement(path, req)
            continue
        m = re.match(r"\s*(?:[\w.-]+::)?([A-Za-z0-9_.-]+)\s*(.*)$", d)
        if not m or m.group(1).lower() not in ("certifi", "ca-certificates"):
            continue
        name, spec = m.group(1).lower(), m.group(2).strip()
        pinned_ca |= name == "ca-certificates"
        exact = re.match(r"^(?:==?)?\s*(\d[\w.]*)(?:[\s=]\S*)?$", spec)
        if spec and exact and not re.search(r"[*<>!~,|]", spec):
            judge_conda(path, name, exact.group(1))
        else:
            add("REVIEW", path, "%s (conda)" % name, spec or "(unpinned)",
                "not an exact pin; the env built from it decides. Check $CONDA_PREFIX/ssl/cacert.pem with trust_store.py")
    if not pinned_ca:
        add("REVIEW", path, "conda env", "",
            "conda installs its own ca-certificates and OpenSSL; rebuild the env (conda update ca-certificates certifi openssl) "
            "and check $CONDA_PREFIX/ssl/cacert.pem with trust_store.py")


def scan_conda_lock(path, doc):
    parsed("conda lock")
    for node in iter_dicts(doc):
        name = str(node.get("name", "")).lower()
        if name in ("certifi", "ca-certificates") and "version" in node:
            judge_conda(path, name, str(node["version"]))


def pnpm_key(k):
    k = str(k).lstrip("/").split("(", 1)[0]
    i = k.find("@", 1)
    if i > 0:
        return k[:i], k[i + 1:]
    if "/" in k:
        name, _, ver = k.rpartition("/")
        return name, ver
    return k, ""


def scan_pnpm_lock(full, path, doc):
    parsed("pnpm-lock.yaml")
    found = False
    for section in ("packages", "snapshots"):
        for key in (doc.get(section) or {}):
            name, ver = pnpm_key(key)
            if name == "electron" or name.endswith("/electron"):
                judge_electron(path, ver)
                found = True
    importers = doc.get("importers") or {".": doc}
    for imp in importers.values():
        for sec in ("dependencies", "devDependencies", "optionalDependencies"):
            v = ((imp or {}).get(sec) or {}).get("electron")
            if v is not None:
                judge_electron(path, str(v.get("version") if isinstance(v, dict) else v).split("(", 1)[0])
                found = True
    if found:
        electron_resolved.add(os.path.dirname(full))


def lock_descriptor_name(d):
    d = d.strip().strip('"')
    i = d.find("@", 1)
    return d[:i] if i > 0 else d


def scan_yarn_berry(full, path, doc):
    parsed("yarn.lock")
    for key, info in doc.items():
        if key != "__metadata" and isinstance(info, dict) and \
                any(lock_descriptor_name(d) == "electron" for d in str(key).split(",")):
            judge_electron(path, info.get("version", ""))
            electron_resolved.add(os.path.dirname(full))


def scan_yaml_file(full, path, text, low):
    unix = "/" + path.replace(os.sep, "/")
    workflow = bool(re.search(r"/\.(?:github|gitea|forgejo)/workflows/|/\.circleci/", unix)) or low in (
        ".gitlab-ci.yml", "action.yml", "action.yaml", "bitbucket-pipelines.yml", "azure-pipelines.yml",
        ".travis.yml", "buildspec.yml", "cloudbuild.yaml", "cloudbuild.yml")
    if yaml is None:
        coverage["missing_parsers"].setdefault("PyYAML", []).append(path)
        fallback_yaml(path, text)
        return
    try:
        docs = list(yaml.load_all(text, Loader=AnyTagLoader))
    except yaml.YAMLError as e:
        if "{{" in text or "{%" in text:
            add("REVIEW", path, "templated YAML", "",
                "a template, so it cannot be parsed as YAML: render it (helm template, kustomize build) and scan the output")
        else:
            add("ERROR", path, "YAML", "", "does not parse: %s" % str(e).splitlines()[0])
        fallback_yaml(path, text)
        return
    parsed("YAML")
    for doc in docs:
        if low == "pnpm-lock.yaml" and isinstance(doc, dict):
            scan_pnpm_lock(full, path, doc)
            continue
        if low == "yarn.lock" and isinstance(doc, dict):
            scan_yarn_berry(full, path, doc)
            continue
        if low in ("conda-lock.yml", "conda-lock.yaml", "pixi.lock") or low.endswith(".conda-lock.yml"):
            scan_conda_lock(path, doc)
        elif is_conda_env(doc):
            scan_conda_env(path, doc)
        walk_yaml(path, doc, workflow)
        if re.search(r"/\.github/workflows/", unix) and isinstance(doc, dict):
            check_hosted_runner(path, doc)


# An upgrade counts only after a fresh package index: the hosted image's apt lists
# predate the fixed package, so without `apt-get update` nothing changes.
UPGRADE_CA = re.compile(r"\bapt(?:-get)?\s+(?:-\S+\s+)*update\b.*?\bapt(?:-get)?\s+(?:-\S+\s+)*(?:install|upgrade)\b"
                        r"(?![^\n;&|]*--no-upgrade)[^\n;&|]*\bca-certificates(?![\w.+-])", re.S)


def runner_labels(job):
    """A job's runs-on labels, with ${{ matrix.X }} resolved from its own
    matrix. None stands for a label that could not be resolved."""
    ro = job.get("runs-on")
    if isinstance(ro, dict):
        ro = ro.get("labels", ro.get("group"))
    strategy = job.get("strategy")
    matrix = strategy.get("matrix") if isinstance(strategy, dict) else None
    out = []
    for v in ro if isinstance(ro, list) else [ro]:
        if v is None:
            continue
        v = str(v).strip()
        m = re.fullmatch(r"\$\{\{\s*matrix\.([\w-]+)\s*\}\}", v)
        if m and isinstance(matrix, dict):
            k = m.group(1)
            vals = matrix.get(k)
            vals = list(vals) if isinstance(vals, list) else ([] if vals is None else [vals])
            vals += [i[k] for i in matrix.get("include") or [] if isinstance(i, dict) and k in i]
            for x in vals or [None]:
                if isinstance(x, list):
                    out += [str(y) for y in x]
                else:
                    out.append(None if x is None or isinstance(x, dict) or "${{" in str(x) else str(x))
        else:
            out.append(None if "${{" in v else v)
    return out


def check_hosted_runner(path, doc):
    """Hosted ubuntu runners shipped ca-certificates 20260601, which trusts the
    emSign chains, until GitHub rebuilt them. Judged per job: only an upgrade
    that is the job's own first step, on the host, counts."""
    jobs = doc.get("jobs")
    if not isinstance(jobs, dict):
        return
    for name, job in jobs.items():
        if not isinstance(job, dict) or "uses" in job:  # a reusable workflow is judged where it is defined
            continue
        labels = runner_labels(job)
        if None not in labels and not any(l.startswith("ubuntu-") for l in labels):
            continue
        what = "hosted runner (job %s)" % name
        shown = ", ".join(l or "?" for l in labels) or "?"
        steps = [st for st in job.get("steps") or [] if isinstance(st, dict)]
        first = str(steps[0].get("run", "")) if steps else ""
        if "container" in job:
            add("REVIEW", path, what, shown,
                "a container job: its steps run in the container and cannot upgrade the host's ca-certificates, "
                "which the runner uses to pull images and run JavaScript actions. Fix the container image, and "
                "check the host side with probe_runtime.sh in a host step")
        elif UPGRADE_CA.search(first):
            add("INFO", path, what, shown, "the first step upgrades ca-certificates")
        else:
            add("REVIEW", path, what, shown,
                ("runs-on could not be resolved to a label; if it can be a hosted ubuntu runner: " if None in labels
                 else "") +
                "hosted ubuntu images shipped ca-certificates 20260601 (accepts the 6 emSign chains) and "
                "actions/checkout sends GITHUB_TOKEN over it: add `sudo apt-get update && sudo apt-get install -y "
                "--only-upgrade ca-certificates` as the first step of this job. The runner's own Node, which runs "
                "JavaScript actions, was 24.21.0 before runner v2.338.1: until every job runs on 2.338.1 or later, set "
                "NODE_OPTIONS=--use-openssl-ca and SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt in the job's env "
                "where it exchanges credentials (reference/deployed-verification.md, CI/CD runners). Once no job "
                "lands on an image older than ubuntu24 20261021, this row is answered and the step can go")


def fallback_yaml(path, text):
    """Additive only, for YAML that could not be parsed: image lines, version keys, commands."""
    for m in re.finditer(r"^\s*-?\s*(?:image|container):\s*['\"]?([^\s'\"#]+)", text, re.M):
        judge_image(path, m.group(1), "yaml image (unparsed file)")
    for m in re.finditer(r"\b(node|go|java|bun|deno)-version:\s*['\"]?([^\s'\"#,\]]+)", text):
        VERSION_KEYS[m.group(1) + "-version"](path, m.group(2))
    scan_shell(path, text, "script")


# ---------------------------------------------------------------- other formats

def loads_jsonc(text):
    """JSON with // and /* */ comments and trailing commas (bun.lock, global.json)."""
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
            out.append(c)
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j >= n or text[j] not in "}]":
                out.append(c)
        else:
            out.append(c)
        i += 1
    return json.loads("".join(out))


def load_toml(path, text, kind):
    if tomllib is None:
        coverage["missing_parsers"].setdefault("tomli (Python < 3.11)", []).append(path)
        return None
    try:
        data = tomllib.loads(text)
    except Exception as e:  # tomllib.TOMLDecodeError, or tomli's
        add("ERROR", path, kind, "", "does not parse as TOML: %s" % e)
        recognised[0] += 1
        return None
    parsed(kind)
    return data


def load_json(path, text, kind, jsonc=False):
    try:
        data = loads_jsonc(text) if jsonc else json.loads(text)
    except ValueError as e:
        add("ERROR", path, kind, "", "does not parse as JSON: %s" % e)
        recognised[0] += 1
        return None
    parsed(kind)
    return data


def scan_toml_lock(path, text, kind, table):
    data = load_toml(path, text, kind)
    if data is None:
        return
    for p in (data.get("package") or []) + (data.get("packages") or []):  # packages: pylock.toml
        if not isinstance(p, dict) or "name" not in p:
            continue
        name, ver = norm(p["name"]), str(p.get("version", ""))
        v = vtuple(ver)
        if table is PY_PACKAGES:
            note_python_name(path, name)
        if table is PY_PACKAGES and name in PY_PACKAGES and not ver:
            add("REVIEW", path, name, "", "locked without a version (a URL, path or VCS source); check what it resolves to")
        elif table is CARGO_PACKAGES and name == "webpki-roots" and v and v[:2] == (0, 26) and pad(v, 3) >= (0, 26, 8):
            add("INFO", path, name, ver, "0.26.8+ re-exports webpki-roots 1.x; the 1.x entry decides")
        elif table is CARGO_PACKAGES and name == "rustls-webpki" and v and v[:2] > (0, 103):
            add("REVIEW", path, name, ver, NEWER)
        elif name in table:
            fixed, note = table[name]
            judge_threshold(path, name, ver, fixed, note)


def scan_requirements(path, text):
    parsed("requirements")
    for line in re.sub(r"\\\r?\n", " ", text).splitlines():
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        line = re.split(r"\s+--?[A-Za-z]", line, maxsplit=1)[0]  # per-requirement options (--hash=...)
        if line and not line.startswith("-"):
            judge_requirement(path, line)


def scan_pyproject(path, text):
    data = load_toml(path, text, "pyproject.toml")
    if data is None:
        return
    tool = data.get("tool") or {}
    uv = tool.get("uv") or {}
    if "required-version" in uv:
        spec = str(uv["required-version"]).strip()
        # uv reads a bare version as ==.
        judge_requirement(path, "uv" + ("==" if re.match(r"\d", spec) else "") + spec)
    project = data.get("project") or {}
    reqs = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        reqs += group or []
    for group in (data.get("dependency-groups") or {}).values():
        reqs += group or []
    reqs += (data.get("build-system") or {}).get("requires") or []
    for group in ((tool.get("pdm") or {}).get("dev-dependencies") or {}).values():
        reqs += group or []
    reqs += uv.get("dev-dependencies") or []
    reqs += uv.get("override-dependencies") or []
    reqs += uv.get("constraint-dependencies") or []
    for r in reqs:
        if isinstance(r, str):
            judge_requirement(path, r)
    poetry = tool.get("poetry") or {}
    tables = [poetry.get("dependencies"), poetry.get("dev-dependencies")]
    tables += [g.get("dependencies") for g in (poetry.get("group") or {}).values() if isinstance(g, dict)]
    for t in tables:
        for name, spec in (t or {}).items():
            judge_poetry(path, name, spec)


def scan_pipfile(path, text):
    data = load_toml(path, text, "Pipfile")
    if data is None:
        return
    for sec in ("packages", "dev-packages"):
        for name, spec in (data.get(sec) or {}).items():
            if norm(name) in PY_PACKAGES:
                if isinstance(spec, dict):
                    spec = spec.get("version", "@ (git/path source)")
                judge_requirement(path, name + ("" if spec == "*" else str(spec)))


def scan_pipfile_lock(path, text):
    data = load_json(path, text, "Pipfile.lock")
    if not isinstance(data, dict):
        return
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            if isinstance(info, dict) and norm(name) in PY_PACKAGES:
                judge_requirement(path, name + str(info.get("version", "")))


def scan_setup_cfg(path, text):
    cp = configparser.ConfigParser(interpolation=None)
    try:
        cp.read_string(text)
    except configparser.Error as e:
        add("ERROR", path, "setup.cfg", "", "does not parse: %s" % str(e).splitlines()[0])
        return
    parsed("setup.cfg")
    values = []
    if cp.has_section("options"):
        values += [cp.get("options", k) for k in ("install_requires", "setup_requires") if cp.has_option("options", k)]
    if cp.has_section("options.extras_require"):
        values += [v for _, v in cp.items("options.extras_require")]
    for v in values:
        for line in v.splitlines():
            if line.strip():
                judge_requirement(path, line.strip())


def scan_setup_py(path, text):
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        add("ERROR", path, "setup.py", "", "does not parse: %s" % e)
        return
    parsed("setup.py")
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            judge_requirement(path, node.value)


def scan_package_json(full, path, text):
    data = load_json(path, text, "package.json")
    if not isinstance(data, dict):
        return
    package_jsons.append(path)
    engines = data.get("engines") or {}
    if engines.get("node"):
        node_seen[0] = True
        add("REVIEW", path, "node (engines)", engines["node"],
            "a range, not the runtime; check what CI and production actually run. Hosting platforms read it to pick "
            "a major only (Vercel, Netlify) and run whatever patch they have, so probe the deployed runtime")
    if engines.get("bun"):
        add("REVIEW", path, "bun (engines)", engines["bun"], "a range, not the runtime; check what CI and production run (fixed in 1.4.4)")
    volta = data.get("volta") or {}
    if volta.get("node"):
        judge_node(path, volta["node"], "volta")
    if volta.get("bun"):
        judge_bun(path, volta["bun"], "volta")
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        ver = (data.get(section) or {}).get("electron")
        if ver:
            electron_declared[os.path.dirname(full)] = (path, ver)
    for name, cmd in (data.get("scripts") or {}).items():
        if isinstance(cmd, str):
            scan_shell(path, cmd, "scripts.%s" % name)
    pm = data.get("packageManager")
    if isinstance(pm, str) and pm.startswith("bun@"):
        judge_bun(path, pm, "packageManager")
    if isinstance(data.get("pkg"), dict):
        add("REVIEW", path, "node single-executable (pkg config)", "", EMBEDS_RUNTIME)


def scan_package_lock(full, path, text):
    data = load_json(path, text, "package-lock")
    if not isinstance(data, dict):
        return
    found = []
    for key, info in (data.get("packages") or {}).items():
        if (key == "node_modules/electron" or key.endswith("/node_modules/electron")) and isinstance(info, dict):
            found.append(info.get("version", ""))

    def v1(deps):
        for name, info in (deps or {}).items():
            if isinstance(info, dict):
                if name == "electron":
                    found.append(info.get("version", ""))
                v1(info.get("dependencies"))
    v1(data.get("dependencies"))
    for ver in found:
        judge_electron(path, ver)
    if found:
        electron_resolved.add(os.path.dirname(full))


def scan_bun_lock(full, path, text):
    data = load_json(path, text, "bun.lock", jsonc=True)
    if not isinstance(data, dict):
        return
    for key, info in (data.get("packages") or {}).items():
        if key == "electron" or key.endswith("/electron"):
            spec = info[0] if isinstance(info, list) and info else ""
            judge_electron(path, str(spec).rpartition("@")[2])
            electron_resolved.add(os.path.dirname(full))


def scan_yarn_v1(full, path, text):
    parsed("yarn.lock")
    names = None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            names = [lock_descriptor_name(d) for d in line.rstrip().rstrip(":").split(",")]
        elif names and "electron" in names and re.match(r"^\s{2}version:?\s", line):
            judge_electron(path, line.split(None, 1)[1].strip().strip('"'))
            electron_resolved.add(os.path.dirname(full))


def scan_cargo_toml(full, path, text):
    data = load_toml(path, text, "Cargo.toml")
    if data is None:
        return
    names = set()
    for node in iter_dicts(data):
        for k in ("dependencies", "dev-dependencies", "build-dependencies"):
            if isinstance(node.get(k), dict):
                names |= {norm(n) for n in node[k]}
    used = sorted(names & RUSTLS_DEPS)
    if used:
        cargo_manifests.append((os.path.dirname(full), path, used))


def scan_go_mod(path, text):
    parsed("go.mod")
    go = toolchain = None
    for line in text.splitlines():
        toks = line.split("//", 1)[0].split()
        if len(toks) == 2 and toks[0] == "go":
            go = toks[1]
        elif len(toks) == 2 and toks[0] == "toolchain":
            toolchain = toks[1]
    if toolchain and toolchain != "default":
        judge_go(path, toolchain, "go.mod toolchain")
    if go:
        add("REVIEW", path, "go (go.mod go directive)", go,
            "a minimum, not the build toolchain; check the toolchain in CI/Dockerfile and `go version <binary>` on deployed binaries")


def scan_composer_lock(path, text):
    data = load_json(path, text, "composer.lock")
    if not isinstance(data, dict):
        return
    for section in ("packages", "packages-dev"):
        for p in data.get(section) or []:
            if isinstance(p, dict) and p.get("name") == "composer/ca-bundle":
                judge_composer_ca_bundle(path, str(p.get("version", "")).lstrip("v"))


def scan_erlang_lock(path, text):
    parsed("mix/rebar lock")
    for name, (fixed, note) in HEX_PACKAGES.items():
        hits = re.findall(r'"%s"\s*:\s*\{\s*:hex\s*,\s*:%s\s*,\s*"([^"]+)"' % (name, name), text)
        hits += re.findall(r'\{<<"%s">>\s*,\s*\{pkg\s*,\s*<<"%s">>\s*,\s*<<"([^"]+)">>' % (name, name), text)
        for ver in hits:
            judge_threshold(path, name, ver, fixed, note)
        if not hits and re.search(r'["<]%s[">]' % name, text):
            add("REVIEW", path, name, "", "named in the lockfile in a form this scanner cannot read; check its version. " + note)


def scan_cpan(path, text):
    parsed("cpanfile")
    hits = re.findall(r"Mozilla-CA-(\d{8})", text)
    for ver in hits:
        judge_threshold(path, "Mozilla::CA", ver, (20261020,), "")
    if not hits and "Mozilla::CA" in text:
        add("REVIEW", path, "Mozilla::CA", "", "required without a resolved version; check the installed one")


def judge_tool(path, tool, ver):
    tool, ver = tool.lower().split(":")[-1], str(ver)
    if tool in ("node", "nodejs"):
        judge_node(path, ver, tool)
    elif tool in ("go", "golang"):
        judge_go(path, ver, tool)
    elif tool == "java":
        judge_java(path, re.sub(r"^[a-z]+-", "", ver), tool)
    elif tool == "bun":
        judge_bun(path, ver, tool)
    elif tool == "deno":
        judge_deno(path, ver, tool)
    elif tool in TOOL_FIXED:
        judge_threshold(path, tool, ver, TOOL_FIXED[tool])
    elif tool in GO_CLIS:
        add("REVIEW", path, tool, ver, GO_CLI_NOTE)


VERSION_FILES = {".nvmrc": "node", ".node-version": "node", ".java-version": "java", ".go-version": "go",
                 ".bun-version": "bun", ".dvmrc": "deno", ".terraform-version": "terraform"}


def scan_version_file(path, text, base):
    parsed("version file")
    value = text.strip().splitlines()[0].strip() if text.strip() else ""
    judge_tool(path, VERSION_FILES[base], value)
    if not value:
        add("REVIEW", path, VERSION_FILES[base], "", "an empty version file; check what runs")


def scan_tool_versions(path, text):
    parsed("tool versions")
    for line in text.splitlines():
        toks = line.split("#", 1)[0].replace("=", " ").split()
        for ver in toks[1:]:
            judge_tool(path, toks[0], ver)


def scan_mise_toml(path, text):
    data = load_toml(path, text, "mise.toml")
    if data is None:
        return
    for tool, spec in (data.get("tools") or {}).items():
        for s in spec if isinstance(spec, list) else [spec]:
            judge_tool(path, tool, s.get("version", "") if isinstance(s, dict) else s)


def scan_netlify(path, text):
    data = load_toml(path, text, "netlify.toml")
    if data is None:
        return
    for node in iter_dicts(data):
        env = node.get("environment") if isinstance(node.get("environment"), dict) else {}
        if env.get("NODE_VERSION"):
            judge_node(path, str(env["NODE_VERSION"]), "netlify NODE_VERSION")
        if env.get("GO_VERSION"):
            judge_go(path, str(env["GO_VERSION"]), "netlify GO_VERSION")
        if isinstance(node.get("command"), str):
            scan_shell(path, node["command"], "netlify build")


def scan_pep723(path, text):
    """PEP 723 inline script metadata: `# /// script` ... `# ///`."""
    m = re.search(r"^# /// script\s*$(.*?)^# ///\s*$", text, re.M | re.S)
    if not m:
        return
    body = "\n".join(line[2:] if line.startswith("# ") else line[1:] for line in m.group(1).strip("\n").splitlines())
    data = load_toml(path, body, "PEP 723 script")
    for r in (data or {}).get("dependencies") or []:
        if isinstance(r, str):
            judge_requirement(path, r)


def scan_global_json(path, text):
    data = load_json(path, text, "global.json", jsonc=True)
    ver = ((data or {}).get("sdk") or {}).get("version") if isinstance(data, dict) else None
    if ver:
        add("REVIEW", path, ".NET SDK (global.json)", ver,
            ".NET trusts the OS store (OpenSSL on Linux, CTL updates on Windows): patch the base image or host")


# ---------------------------------------------------------------- certificates and keys

def scan_certificates(full, path, data, ext, base):
    """Find the affected certificates and keys in a file of any kind, by bytes.
    full is None for an archive member."""
    found, counted = {}, [0]

    def take(ders, where):
        for der in ders:
            counted[0] += 1
            try:
                kind, name = E.classify(der)
                aki = E.authority_key_id(der)
            except (E.DERError, IndexError) as e:
                add("ERROR", path, "certificate", where, "a certificate that does not parse: %s" % e)
                continue
            if kind:
                found.setdefault(name, "%s certificate%s" % (kind, where))
            elif aki in E.BAD_INTERMEDIATE_SKIS:
                found.setdefault("certificate for %s" % E.subject_cn(der),
                                 "issued by %s%s: replace it" % (E.BAD_INTERMEDIATE_SKIS[aki], where))

    store_like = ext in STORE_EXT or base in ("cacerts", "jssecacerts") or \
        data[:4] in (trust_store.JKS_MAGIC, trust_store.JCEKS_MAGIC)
    if store_like:
        try:
            entries, _ = trust_store.read_data(data, full)
            take([der for der, _, _ in entries], "")
        except trust_store.NotAStore:
            if ext in KEYSTORE_EXT or base in ("cacerts", "jssecacerts"):
                add("ERROR", path, "keystore", "", "not in a keystore format this scanner can read; check it with keytool")
        except (trust_store.StoreError, E.DERError, IndexError, OSError) as e:
            add("ERROR", path, "certificate store", "", "could not be read: %s. Check it with trust_store.py" % e)
    elif b"-----BEGIN" in data:
        take_pem(take, path, data, "")
    for payload in E.base64_payloads(data):  # binaries too: a program can carry a base64 bundle
        if b"-----BEGIN" in payload:
            take_pem(take, path, payload, " (base64-encoded)")
        elif payload[:1] == b"\x30":
            try:
                E.spki_sha256(payload)
                take([payload[:E.cert_length(payload)]], " (base64 DER)")
            except (E.DERError, IndexError):
                pass
        for name in E.public_keys_in(payload):
            found.setdefault(name, "public key, base64-encoded")
    for name in E.public_keys_in(data):
        found.setdefault(name, "public key in the file's bytes")
    for name, what in sorted(found.items()):
        add("VULNERABLE", path, name, what,
            "this file carries it. A trust store, bundle, pin list or binary that embeds it trusts the affected chain; "
            "remove it or replace the file (a block list that names it is the one exception)")
    if counted[0] and not found:
        add("INFO", path, "certificates", "%d read" % counted[0], "none of them is an affected root or intermediate")
    if counted[0] or found:
        parsed("certificates")


def take_pem(take, path, data, where):
    ders = []
    for der, err in E.pem_blocks(data):
        if err:
            add("ERROR", path, "PEM certificate", where.strip(" ()"), err)
        else:
            ders.append(der)
    take(ders, where)


def search_large(full, path):
    """Search a file too large to read whole (a runtime binary such as node
    embeds its root store as PEM text) in overlapping chunks: PEM blocks and raw
    keys. Base64 runs are not decoded here."""
    overlap = 1 << 16
    found, counted, tail = {}, 0, b""
    try:
        with open(full, "rb") as f:
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                window = tail + chunk
                for name in E.public_keys_in(window):
                    found.setdefault(name, "public key in the file's bytes")
                if b"-----BEGIN" in window:
                    for der, err in E.pem_blocks(window):
                        if err:
                            continue  # a block cut by the chunk edge is read whole from the next window
                        counted += 1
                        try:
                            kind, name = E.classify(der)
                        except (E.DERError, IndexError):
                            continue
                        if kind:
                            found.setdefault(name, "%s certificate (PEM)" % kind)
                tail = window[-overlap:]
    except OSError as e:
        add("ERROR", path, "file", "", "could not be read: %s" % e)
        return
    for name, what in sorted(found.items()):
        add("VULNERABLE", path, name, what,
            "this file carries it; a trust store or binary that embeds it trusts the affected chain. A runtime "
            "(node, bun, a compiled CLI) that embeds its roots stays exposed until replaced with a fixed build")
    if counted:
        parsed("certificates")


# ---------------------------------------------------------------- dispatch

def is_requirements(low, path):
    parent = os.path.basename(os.path.dirname(path)).lower()
    return bool(re.match(r"(requirements|constraints)[\w.-]*\.(txt|in|lock)$", low)) or low.endswith("requirements.txt") \
        or (parent in ("requirements", "reqs") and low.endswith((".txt", ".in", ".lock")))


def is_dockerfile(low):
    return low.startswith(("dockerfile", "containerfile")) or low.endswith((".dockerfile", ".containerfile"))


def dispatch(full, path, text, low, ext):
    if low in ("poetry.lock", "uv.lock", "pdm.lock") or re.match(r"pylock(?:\.[\w-]+)?\.toml$", low):
        scan_toml_lock(path, text, low, PY_PACKAGES)
    elif low == "cargo.lock":
        cargo_locks.add(os.path.dirname(full))
        scan_toml_lock(path, text, low, CARGO_PACKAGES)
    elif low == "cargo.toml":
        scan_cargo_toml(full, path, text)
    elif is_requirements(low, path):
        scan_requirements(path, text)
    elif low == "pipfile":
        scan_pipfile(path, text)
    elif low == "pipfile.lock":
        scan_pipfile_lock(path, text)
    elif low == "pyproject.toml":
        scan_pyproject(path, text)
    elif low == "setup.cfg":
        scan_setup_cfg(path, text)
    elif low == "setup.py":
        scan_setup_py(path, text)
    elif low == "package.json":
        scan_package_json(full, path, text)
    elif low in ("package-lock.json", "npm-shrinkwrap.json"):
        scan_package_lock(full, path, text)
    elif low == "bun.lock":
        scan_bun_lock(full, path, text)
    elif low == "yarn.lock" and "__metadata:" not in text:
        scan_yarn_v1(full, path, text)
    elif low in ("go.mod", "go.work"):
        scan_go_mod(path, text)
    elif low == "composer.lock":
        scan_composer_lock(path, text)
    elif low in ("mix.lock", "rebar.lock"):
        scan_erlang_lock(path, text)
    elif low in ("cpanfile.snapshot", "cpanfile"):
        scan_cpan(path, text)
    elif low in VERSION_FILES:
        scan_version_file(path, text, low)
    elif low in (".tool-versions", ".sdkmanrc"):
        scan_tool_versions(path, text)
    elif low in ("mise.toml", ".mise.toml", "mise.local.toml", ".rtx.toml") or path.replace(os.sep, "/").endswith("mise/config.toml"):
        scan_mise_toml(path, text)
    elif is_dockerfile(low):
        scan_dockerfile(path, text)
    elif low == "global.json":
        scan_global_json(path, text)
    elif low.startswith(".env") or low.endswith(".env"):
        scan_env_file(path, text)
    elif low == "netlify.toml":
        scan_netlify(path, text)
    elif low in ("devcontainer.json", ".devcontainer.json"):
        data = load_json(path, text, "devcontainer.json", jsonc=True)
        if isinstance(data, dict) and isinstance(data.get("image"), str):
            judge_image(path, data["image"], "devcontainer")
    elif ext in (".tf", ".hcl") and low != ".terraform.lock.hcl":
        parsed("terraform")
        for m in re.finditer(r"""["']?\bimage["']?\s*[=:]\s*(?:"([^"\n]*)"|'([^'\n]*)'|([A-Za-z_][\w.\[\]"()-]*))""", text):
            value = m.group(1) if m.group(1) is not None else m.group(2)
            if value is None:  # var.image, local.x, module.y.image: a reference, not a literal
                add("REVIEW", path, "image (terraform image)", m.group(3),
                    "the image comes from a variable or template; check what the build or deploy actually uses")
            else:
                judge_image(path, value, "terraform image")
        for m in re.finditer(r"""\b(user_data(?:_base64)?)\s*=\s*<<-?\s*(\w+)\n(.*?)\n\s*\2\b""", text, re.S):
            scan_shell(path, m.group(3), m.group(1))
    elif low == "jenkinsfile" or low.endswith(".jenkinsfile"):
        parsed("Jenkinsfile")
        for m in re.finditer(r"""(?:image|docker\.image)\s*[(:]?\s*['"]([^'"]+)['"]""", text):
            judge_image(path, m.group(1), "Jenkinsfile")
        for m in re.finditer(r"\bsh\s*\(?\s*(['\"]{1,3})(.*?)\1", text, re.S):
            scan_shell(path, m.group(2), "Jenkinsfile sh")
        for m in re.finditer(r"""\b(nodejs|jdk|go)\s+['"]([^'"]+)['"]""", text):
            add("REVIEW", path, "Jenkins tool %s" % m.group(1), m.group(2),
                "a Jenkins tool installation: check the version installed on the agents")
    elif low.endswith((".gradle", ".gradle.kts")):
        parsed("gradle")
        for m in re.finditer(r"JavaLanguageVersion\.of\(\s*(\d+)\s*\)", text):
            add("REVIEW", path, "gradle java toolchain", m.group(1),
                "Gradle may auto-provision this JDK; its cacerts carries both roots until patched. "
                "Check the toolchain JDK on CI runners with trust_store.py java")
    elif low == ".terraform.lock.hcl":
        parsed("terraform lock")
        add("REVIEW", path, "terraform providers", "", "providers are Go binaries; " + GO_CLI_NOTE)
    if ext in (".yml", ".yaml") or (low == "yarn.lock" and "__metadata:" in text):
        scan_yaml_file(full, path, text, low)
    if low.endswith("-explicit.txt") or text.startswith("@EXPLICIT") or "\n@EXPLICIT" in text[:4096]:
        parsed("conda explicit")
    if ext == ".py" and "# /// script" in text:
        scan_pep723(path, text)
    if ext in (".sh", ".bash", ".zsh") or low in ("makefile", "justfile", "procfile"):
        scan_shell(path, text, "script")
    scan_urls(path, text)
    scan_installers(path, text)


def scan_text_hints(path, text, ext):
    for rx, status, label, detail in (
        (EMUDHRA_MENTION, "REVIEW", "emSign/eMudhra reference", "pinning or trust config naming the affected CA"),
        (TRUST_KNOBS, "INFO", "custom trust setting", "decides which bundle this code trusts; make sure that bundle is patched"),
        (TLS_DISABLED, "REVIEW", "TLS verification disabled", "not this incident, but it trusts every certificate; flag it to the owner"),
        (TLS_UNVERIFIED, "REVIEW", "TLS without certificate verification",
         "encrypts but accepts any server certificate, including one issued by the compromised intermediates: "
         "use sslmode=verify-full (or ssl: { rejectUnauthorized: true, ca: ... }) with a patched CA file"),
    ):
        seen = set()
        for m in rx.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            if line not in seen:
                seen.add(line)
                add(status, "%s:%d" % (path, line), label, m.group(0)[:60], detail)
    if ext == ".go" and "golang.org/x/crypto/x509roots/fallback" in text:
        add("REVIEW", path, "x509roots/fallback", "",
            "embeds its own root bundle for hosts without one; bump golang.org/x/crypto to a release that drops the "
            "emSign roots, rebuild, and check the binary with go_binaries.py")


def decode_text(data):
    """The file as text, or None for a binary. UTF-8, UTF-16 and UTF-32 with a
    BOM, and UTF-16 without one (ASCII text with every other byte NUL), are
    text: Windows tools write them, and skipping them as binary hides them."""
    for bom, enc in ((codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"), (codecs.BOM_UTF8, "utf-8-sig"),
                     (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16")):
        if data.startswith(bom):
            return data.decode(enc, "replace")
    head = data[:8192]
    if b"\x00" not in head:
        return data.decode("utf-8", "replace")
    if len(head) >= 16:
        even, odd = head[0::2], head[1::2]
        if odd.count(0) > 0.95 * len(odd) and even.count(0) < 0.05 * len(even):
            return data.decode("utf-16-le", "replace")
        if even.count(0) > 0.95 * len(even) and odd.count(0) < 0.05 * len(odd):
            return data.decode("utf-16-be", "replace")
    return None


# ---------------------------------------------------------------- archives

ARCHIVE_DEPTH = 4
ARCHIVE_BUDGET = 1 << 30  # bytes decompressed per top-level archive before giving up as REVIEW
UNOPENED = {".7z": "7-Zip", ".rar": "RAR", ".zst": "zstd", ".tzst": "zstd", ".lz4": "lz4", ".cab": "CAB",
            ".msi": "MSI", ".dmg": "disk image", ".iso": "disk image", ".pkg": "macOS package", ".rpm": "RPM",
            ".deb": "Debian package", ".squashfs": "squashfs", ".sif": "Singularity image", ".asar": "Electron asar"}
UNOPENED_MAGIC = ((b"7z\xbc\xaf\x27\x1c", "7-Zip"), (b"Rar!", "RAR"), (b"\x28\xb5\x2f\xfd", "zstd"),
                  (b"\xed\xab\xee\xdb", "RPM"), (b"!<arch>\ndebian", "Debian package"), (b"hsqs", "squashfs"))


def archive_kind(head, name):
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if head[:2] == b"\x1f\x8b" or head[:3] == b"BZh" or head[:6] == b"\xfd7zXZ\x00" or head[257:262] == b"ustar":
        return "tar-or-stream"
    for magic, kind in UNOPENED_MAGIC:
        if head.startswith(magic):
            return kind
    return UNOPENED.get(os.path.splitext(name.lower())[1])


def open_archive(fileobj, kind):
    """(member name, reader) pairs. reader(limit) returns at most limit bytes."""
    if kind == "zip":
        zf = zipfile.ZipFile(fileobj)
        for info in zf.infolist():
            if not info.is_dir():
                yield info.filename, info.file_size, (lambda n, i=info: zf.open(i).read(n))
        return
    try:
        tf = tarfile.open(fileobj=fileobj, mode="r:*")
    except tarfile.ReadError:
        # A single compressed file (cacert.pem.gz), not a tarball.
        fileobj.seek(0)
        head = fileobj.read(6)
        fileobj.seek(0)
        opener = gzip.GzipFile if head[:2] == b"\x1f\x8b" else bz2.BZ2File if head[:3] == b"BZh" else lzma.LZMAFile
        stream = opener(fileobj=fileobj) if opener is gzip.GzipFile else opener(fileobj)
        yield "(decompressed)", -1, stream.read
        return
    for m in tf:
        if m.isfile():
            yield m.name, m.size, (lambda n, m=m: tf.extractfile(m).read(n))


def scan_archive(fileobj, path, kind, depth=0, budget=None):
    """Search every member of an archive in memory, recursing into nested
    archives. Members are never written to disk, and nothing is run."""
    budget = budget if budget is not None else [ARCHIVE_BUDGET]
    if kind not in ("zip", "tar-or-stream"):
        add("REVIEW", path, "archive (%s)" % kind, "",
            "a format this scanner cannot open, so its contents were not searched: unpack it and scan the files")
        return
    if depth >= ARCHIVE_DEPTH:
        add("REVIEW", path, "nested archive", "", "nested deeper than %d levels; unpack it and scan the files" % ARCHIVE_DEPTH)
        return
    members = 0
    try:
        for name, size, read in open_archive(fileobj, kind):
            mpath = "%s!%s" % (path, name)
            if budget[0] <= 0:
                add("REVIEW", path, "archive", "", "more than %d MB uncompressed; the rest was not searched. Unpack it and "
                    "scan the files" % (ARCHIVE_BUDGET >> 20))
                return
            try:
                data = read(MAX_BYTES + 1)
            except (RuntimeError, zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, lzma.LZMAError) as e:
                add("ERROR", mpath, "archive member", "", "could not be read (%s): %s" % (e.__class__.__name__, e))
                continue
            members += 1
            budget[0] -= len(data)
            if len(data) > MAX_BYTES:
                add("REVIEW", mpath, "archive member", "", "larger than %d MB uncompressed; unpack it and scan it"
                    % (MAX_BYTES >> 20))
                data = data[:MAX_BYTES]
            scan_member(mpath, name, data, depth + 1, budget)
    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, lzma.LZMAError, ValueError) as e:
        add("ERROR", path, "archive", "", "could not be opened (%s): %s" % (e.__class__.__name__, e))
        return
    coverage["archive_members"] = coverage.get("archive_members", 0) + members
    parsed("archive")


def scan_member(mpath, name, data, depth, budget):
    low = os.path.basename(name).lower()
    kind = archive_kind(data[:512], name)
    if kind:
        scan_archive(io.BytesIO(data), mpath, kind, depth, budget)
        return
    try:
        scan_certificates(None, mpath, data, os.path.splitext(low)[1], low)
        text = decode_text(data)
        if text is not None and b"\x00" in data[:8192]:
            scan_certificates(None, mpath, text.encode("utf-8"), os.path.splitext(low)[1], low)
    except Exception as e:
        add("ERROR", mpath, "scanner", "", "%s while searching this member: %s" % (e.__class__.__name__, e))


def scan_file(full, path):
    coverage["files"] += 1
    low = os.path.basename(full).lower()
    ext = os.path.splitext(low)[1]
    try:
        size = os.path.getsize(full)
        with open(full, "rb") as f:
            head = f.read(512)
        kind = archive_kind(head, low)
        if kind:
            with open(full, "rb") as f:
                scan_archive(f, path, kind)
            if size > MAX_BYTES:
                return
        if size > MAX_BYTES:
            coverage["large"].append(path)
            search_large(full, path)
            return
        with open(full, "rb") as f:
            data = f.read()
    except OSError as e:
        add("ERROR", path, "file", "", "could not be read: %s" % e)
        coverage["unreadable"].append(path)
        return
    if low in SKILL_FILES and SKILL_MARKER in data[:2048]:
        return
    # A parser bug must never turn into silence: any exception is an ERROR row.
    try:
        scan_certificates(full, path, data, ext, low)
    except Exception as e:
        add("ERROR", path, "scanner", "", "%s while searching this file for certificates: %s" % (e.__class__.__name__, e))
    text = decode_text(data)
    if text is None:
        return  # binary: searched for certificates and keys above, nothing else to parse
    if b"\x00" in data[:8192]:
        # UTF-16/32: search the decoded text too, where PEM and base64 are readable.
        try:
            scan_certificates(None, path, text.encode("utf-8"), ext, low)
        except Exception as e:
            add("ERROR", path, "scanner", "", "%s while searching this file for certificates: %s" % (e.__class__.__name__, e))
    try:
        dispatch(full, path, text, low, ext)
    except Exception as e:
        add("ERROR", path, "scanner", "", "%s while reading this file: %s" % (e.__class__.__name__, e))
    if ext in CODE_EXT or is_dockerfile(low) or low.startswith(".env") or low in ("makefile", "justfile", "procfile"):
        scan_text_hints(path, text, ext)


def walk(root, include_all):
    if os.path.isfile(root):
        yield root, os.path.basename(root)
        return
    if not os.path.isdir(root):
        add("ERROR", root, "path", "", "does not exist or is not a file or directory")
        return

    def onerror(e):
        add("ERROR", getattr(e, "filename", None) or root, "directory", "", "could not be listed: %s" % e)
        coverage["unreadable"].append(getattr(e, "filename", None) or root)

    for dirpath, dirnames, filenames in os.walk(root, onerror=onerror):
        keep = []
        for d in sorted(dirnames):
            full = os.path.join(dirpath, d)
            if os.path.abspath(full) == SKILL_ROOT:
                continue
            if os.path.islink(full):
                coverage["symlinked_dirs"].append(os.path.relpath(full, root))
            elif not include_all and (d in SKIP_DIRS or os.path.isfile(os.path.join(full, "pyvenv.cfg"))):
                coverage["pruned"].append(os.path.relpath(full, root))
            else:
                keep.append(d)
        dirnames[:] = keep
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            if os.path.isfile(full):
                yield full, os.path.relpath(full, root)


def resolved_above(d, done):
    while True:
        if d in done:
            return True
        parent = os.path.dirname(d)
        if parent == d:
            return False
        d = parent


def post_pass():
    """Checks that need the whole tree: a declared dependency no lockfile resolved."""
    for d, (path, spec) in sorted(electron_declared.items()):
        if resolved_above(d, electron_resolved):
            continue
        if RANGE.search(str(spec)) or vtuple(spec) is None:
            add("REVIEW", path, "electron", spec, "no lockfile in the tree resolved electron; the installed version decides")
        else:
            judge_electron(path, spec)
    for d, (path, names) in sorted(py_consumers.items()):
        if not resolved_above(d, certifi_pinned):
            add("REVIEW", path, "certifi (not pinned)", ", ".join(sorted(names)),
                "these load certifi's bundle, and nothing here pins certifi, so the one resolved at install time "
                "decides: pin certifi>=2026.10.19 or check the deployed environment with trust_store.py python. "
                "botocore and grpcio can also ship bundles of their own")
    if package_jsons and not node_seen[0]:
        add("REVIEW", package_jsons[0], "node (no version source)", "",
            "nothing in the tree names the Node version (.nvmrc, engines, volta, an image tag, setup-node), so the "
            "platform's default runs it. Probe the deployed runtime (SKILL.md, managed runtimes)")
    for d, path, used in cargo_manifests:
        if not resolved_above(d, cargo_locks):
            add("REVIEW", path, "rustls dependencies", ", ".join(used),
                "no Cargo.lock in the tree: the webpki-roots / rustls-webpki that resolves at build time decides")


ORDER = {"VULNERABLE": 0, "ERROR": 1, "REVIEW": 2, "FIXED": 3, "INFO": 4}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a Markdown table")
    ap.add_argument("--no-info", action="store_true", help="drop INFO rows from the output")
    ap.add_argument("--all", action="store_true", help="also scan node_modules, virtualenvs and the other pruned directories")
    args = ap.parse_args()
    for root in args.paths:
        label = os.path.basename(os.path.abspath(root))
        for full, rel in walk(root, args.all):
            scan_file(full, os.path.join(label, rel) if len(args.paths) > 1 else rel)
    post_pass()
    for parser, files in sorted(coverage["missing_parsers"].items()):
        add("ERROR", "%d files" % len(files), parser, "not installed",
            "these files were not parsed, only searched for certificates and hints: %s%s. Install it and run again"
            % (", ".join(files[:5]), " ..." if len(files) > 5 else ""))
    if not recognised[0]:
        add("ERROR", ", ".join(args.paths), "scanner", "",
            "nothing in this tree was recognised (no manifest, lockfile, Dockerfile, CI config or certificate), "
            "so it cannot say what the code runs on; inspect it by hand")
    rows = sorted(findings, key=lambda f: (ORDER[f["status"]], f["path"], f["component"]))
    status = 1 if any(f["status"] == "VULNERABLE" for f in rows) else \
        2 if any(f["status"] == "ERROR" for f in rows) else \
        3 if any(f["status"] == "REVIEW" for f in rows) else 0
    shown = [f for f in rows if not (args.no_info and f["status"] == "INFO")]
    if args.json:
        json.dump({"exit": status, "findings": shown, "coverage": coverage}, sys.stdout, indent=2)
        print()
        return status
    print("| Status | Path | Component | Version | Detail |")
    print("|---|---|---|---|---|")
    for f in shown:
        cells = [f["status"], f["path"], f["component"], f["version"], f["detail"]]
        print("| " + " | ".join(c.replace("|", "\\|").replace("\n", " ") for c in cells) + " |")
    counts = {s: sum(1 for f in rows if f["status"] == s) for s in ORDER}
    print("\n%(VULNERABLE)d vulnerable, %(ERROR)d errors, %(REVIEW)d to review, %(FIXED)d fixed, %(INFO)d info" % counts)
    print("Coverage: %d files read; parsed %s." % (coverage["files"], ", ".join(
        "%s x%d" % kv for kv in sorted(coverage["parsed"].items())) or "nothing"))
    for key, label in (("pruned", "Pruned (rerun with --all to include)"), ("symlinked_dirs", "Symlinked directories not followed"),
                       ("large", "Over %d MB, searched for keys only" % (MAX_BYTES >> 20)), ("unreadable", "Unreadable")):
        items = coverage[key]
        if items:
            print("%s: %s%s" % (label, ", ".join(items[:10]), " and %d more" % (len(items) - 10) if len(items) > 10 else ""))
    print("Thresholds are the advisory's table as of %s; run check_advisory.py for anything newer. "
          "Exit %d (0 only when nothing is vulnerable, unreadable or left to review)." % (SNAPSHOT_DATE, status))
    return status


if __name__ == "__main__":
    sys.exit(main())
