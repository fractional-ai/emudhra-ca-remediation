# Remediation by stack

For each stack: **where its trust decision comes from**, the **fixed version**, the
**fix**, and **how to confirm it in the deployed artifact**. Fixed versions are from
https://emudhra.we-have-a-problem.com/ as of 2026-10-23, and they are minimums:
any later release on the same line is fine. Run `scripts/check_advisory.py`
before relying on them. Versions are floors: where the live table and this file
differ, the later version wins, and the live table wins for anything marked
pending here.

Patch every trust source a process uses. A Python service on Debian can use three
at once: the OS store through `ssl`, certifi through `requests`, and pip's vendored
certifi at build time.

## OS trust stores (used by curl, wget, git, OpenSSL, Python `ssl`, Ruby, PHP, Go on Linux, .NET on Linux, distro JDKs)

| Platform | Fixed package |
|---|---|
| Ubuntu `ca-certificates` | 20260816ubuntu0.22.04.1, 20260816ubuntu0.24.04.1, 20260816ubuntu0.26.04.1, 20260816ubuntu0.26.10.1 |
| Debian `ca-certificates` | 20250419~deb12u2 (bookworm), 20250419+deb13u1 (trixie), 20260816+nmu1 (sid) |
| Alpine `ca-certificates` | 20261020-r0 |
| Fedora `ca-certificates` | 2026.2.92_v9.0.319 |
| Arch `ca-certificates-mozilla` | 3.131.1-1 |
| Gentoo | 20260816.3.125 |
| Chainguard / Wolfi | 20260909-r3 |
| FreeBSD | caroot 15.1-RELEASE-p6, 14.5-RELEASE-p3, 14.4-RELEASE-p12; ca_root_nss 1.131.1 |
| OpenBSD | -current (`cert.pem` rev 1.37), and the 8.0 and 7.9 errata |
| NSS | 3.131.1 |
| curl's `cacert.pem` | 2026-10-20 |
| Homebrew `ca-certificates` | 2026-09-25_1 |
| Bottlerocket | pending |
| RHEL / Rocky / Alma / Amazon Linux | not listed. Apply the blocklist below, then check with `trust_store.py system` |
| Windows | blocked through automatic CTL updates since 2026-10-20. For offline hosts, use the advisory's `Block-EmudhraCompromisedCA.ps1` |

Fix in a Dockerfile: install the package **in the final stage**, and rebuild without
cache:

```dockerfile
RUN apt-get update && apt-get install -y --only-upgrade ca-certificates && rm -rf /var/lib/apt/lists/*
# Alpine: RUN apk upgrade --no-cache ca-certificates ca-certificates-bundle
#   (images such as node:*-alpine ship only ca-certificates-bundle, and
#   `apk upgrade ca-certificates` alone exits 0 having changed nothing)
```

```bash
docker build --pull --no-cache -t IMAGE .
```

Where the distro has no fixed package yet, distrust the two roots. These commands
come from the advisory:

```bash
# Debian/Ubuntu
sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' \
  /etc/ca-certificates.conf && update-ca-certificates
# Alpine
sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' /etc/ca-certificates.conf && update-ca-certificates
# Fedora/RHEL/Rocky/Alma/Amazon Linux 2023
d=/etc/pki/ca-trust/source/blocklist; [ -d $d ] || d=/etc/pki/ca-trust/source/blacklist
trust extract --overwrite --format=pem-bundle --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' $d/Comodo_AAA_Services_root.pem &&
trust extract --overwrite --format=pem-bundle --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' $d/emSign_ECC_Root_CA_-_G3.pem &&
update-ca-trust
# NixOS: security.pki.caCertificateBlacklist = [ "Comodo AAA Services root" "emSign ECC Root CA - G3" ];
```

Distroless and scratch images have no package manager. Rebuild them on a
refreshed base (`gcr.io/distroless/*` and `cgr.dev/chainguard/*` republish), or
`COPY` a fixed `/etc/ssl/certs/ca-certificates.crt` from a patched builder stage.

## macOS developer machines

macOS has three trust paths, and each needs its own fix:

1. **Apple's own tools** (`/usr/bin/curl`, `git`, `perl`, `ruby`, `openssl`) read
   `/etc/ssl/cert.pem`, which Apple has not updated, and fall back to
   `Security.framework`, which soft-fails open on the G3B chains.
2. **Apple's `/usr/bin/python3`** (LibreSSL) ignores `SSL_CERT_FILE` entirely and
   always loads `/etc/ssl/cert.pem`, even when the variable points at an empty
   file. Keychain settings don't reach it either. The only fix is to filter
   `/etc/ssl/cert.pem` itself, which needs sudo, and a macOS update can put the
   old file back. Prefer a python.org, Homebrew or uv Python with a fixed certifi,
   and re-check after every OS update.
3. **Safari, Chrome and every app on Apple's trust** read the Keychain.

For the shell, write a filtered bundle and point the env-honouring clients at it.
Filter by key, not by name, so a renamed copy can't slip through:

```bash
python3 trust_store.py --filter ~/.ca-cert.pem /etc/ssl/cert.pem
cat >> ~/.zshrc <<'EOF'
export SSL_CERT_FILE="$HOME/.ca-cert.pem"
export CURL_CA_BUNDLE="$HOME/.ca-cert.pem"
export GIT_SSL_CAINFO="$HOME/.ca-cert.pem"
export PIP_CERT="$HOME/.ca-cert.pem"
EOF
```

`OPENSSL_X509_TEA_DISABLE=1` made no measurable difference when tested, so don't
count it as a fix. The filter also drops AAA Certificate Services, so a legacy site
whose chain reaches only AAA will fail for these clients. That is the tradeoff;
github.com, pypi.org and Sectigo's own sites still work.

For the Keychain, deny the emSign roots and the eight intermediates (all of
them, including the AAA-signed G3B and G3C copies). Don't deny AAA Certificate
Services itself: it anchors a large part of the web.

```bash
# Save each certificate's "pem" field from the advisory's feeds
# (impacted-intermediates.json, roots.json) as its own file first
for c in emsign-ecc-root-g3.pem emsign-root-tls-g3.pem emsign-root-cs-g3.pem em-*-g3b.pem em-*-g3c.pem; do
  security add-trusted-cert -r deny -k ~/Library/Keychains/login.keychain-db "$c"
done
security verify-cert -c em-dv-tls-g3b.pem   # must report "Trust Setting: deny"
```

Environment variables reach only shells. Anything launched by launchd, a GUI app or
cron never sees them, and `/usr/bin/curl` that shows 12/12 refused in your shell
shows 0/12 there. So run `probe_runtime.sh` twice: once in a new shell, and once
with `env -i HOME="$HOME" PATH=/usr/bin:/bin sh probe_runtime.sh`. The machine is
done only when both show 12/12 refused for every client it uses, or when each
client that fails the second run is one that never runs outside a shell.

Also update Homebrew's `ca-certificates`, Docker Desktop (4.96.3), Claude Code
(2.1.303), mise (2026.10.17), uv, and every python.org install's pip and certifi.
`docker desktop update` restarts Docker and kills running containers, so warn
whoever owns them first. Homebrew's `bun` formula can lag the fix: check
`bun --version` against 1.4.4, not the formula's name.

### Version managers keep the old runtimes

nvm, fnm, volta, asdf, mise, pyenv, uv's managed Pythons, Homebrew's versioned
formulas and SDKMAN keep every runtime they ever installed, and a project's
version file can select an old one at any time. List each manager's installs
(`fnm list`, `nvm ls`, `asdf list`, `mise ls`, `uv python list --only-installed`,
`pyenv versions`, `sdk list java`), probe each one with `PROBE_NODE=` /
`PROBE_PYTHON=`, and uninstall the ones that fail. `fnm uninstall` silently drops
aliases such as `lts-latest`, so recreate them. uv-managed Pythons have no certifi
of their own; their pip upgrade needs `--break-system-packages`.

### Fix the trust before you upgrade

An upgrade downloads over the connection you are trying to fix: `bun upgrade`,
`uv self update`, `npm i -g`, `brew upgrade` and `rustup update` all run on the
vulnerable client. Apply the trust fix first (the filtered bundle, or run the
upgrade with a client already known to refuse the chains), then upgrade, then
verify the hash or signature of what arrived where the tool offers one.

### Binaries that embed a runtime

A CLI built with Node SEA, `pkg`, `nexe`, `bun build --compile` or `deno compile`
carries its own runtime and roots, and ignores the shell fixes above. They hide in
`npm`/`pnpm` globals, `~/.local/bin`, `/usr/local/bin`, `/opt/homebrew/bin` and
`/Applications`. Sweep those directories:

```bash
for f in ~/.local/bin/* /usr/local/bin/* /opt/homebrew/bin/* "$(npm root -g)"/.bin/*; do
  [ -f "$f" ] || continue
  if grep -qa NODE_SEA_FUSE "$f"; then echo "node SEA: $f"
  elif grep -qa 'Bun v1\.' "$f"; then echo "bun: $f ($(BUN_BE_BUN=1 "$f" --version 2>/dev/null))"
  fi
done
python3 scan_repo.py ~/.local/bin /usr/local/bin   # embedded roots, by key
```

`BUN_BE_BUN=1 <binary> --version` prints the embedded Bun. For an embedded Node,
run `<binary> -p process.version` where the tool allows it, or read the tool's
release notes. Report the embedded version, not the file's mtime: a binary whose
mtime changed can still carry the old runtime. Some CLIs can be told to run on
the PATH runtime instead (for example `VERCEL_CLI_USE_NATIVE_BINARY=0` for the
Vercel CLI releases that embed Node 24.14.1); otherwise wait for a vendor build
on a fixed runtime and treat the binary as exposed until then.

## Python

| Component | Fixed | Trust source |
|---|---|---|
| certifi | 2026.10.19 | requests, httpx, boto3, google-auth, the openai SDK (through httpx). botocore falls back to its own vendored `cacert.pem` when certifi isn't installed (1.43.108 accepts the 6 AAA chains, 1.43.117 is fixed), grpcio ships `roots.pem`, and httplib2 uses certifi if importable, else its bundled `cacerts.txt`: check those files with `trust_store.py` too |
| The OS store, not certifi | fix the OS store | the anthropic SDK 1.14+ (httpx2 with truststore: bumping certifi changed nothing there), PyJWT's `PyJWKClient`, aiohttp, slack_sdk, and Ubuntu's `python3-requests` |
| pip | 26.2.2 | vendored certifi plus the system store, always both |
| uv | 0.13.4 | bundled webpki-roots unless `UV_SYSTEM_CERTS=true` / `--native-tls` |
| pixi | 0.82.1 | |
| sigstore | 4.5.1 | |
| CPython `ssl` | 3.15.1, 3.14.9 and 3.13.17 shipped 2026-10-21. Their release notes describe one fix: the bundled pip is now 26.2.2 (with certifi 2026.10.19), so `ensurepip` and new venvs get it. They describe no change to `ssl`, which still trusts the OS store. Field runs disagreed on whether 3.14.9 blocks the keys, so count it only when the probe's `python-ssl-default` line shows `ok` with an unpatched OS store | the OS store, through OpenSSL |

To fix:

- Bump `certifi>=2026.10.19` in **every lockfile**: `uv lock --upgrade-package certifi`,
  `poetry update certifi`, `pip-compile -P certifi`.
- Upgrade pip securely first: `python -m pip install --upgrade "pip>=26.2.2"`. On a
  network you do not trust, install the wheel from its URL with the SHA-256 in the
  Python thread.
- Container builds: add `RUN python -m pip install --no-cache-dir --upgrade "pip>=26.2.2" "certifi>=2026.10.19"`
  before installing anything else. `PIP_CERT` is **not** a fix on its own: an
  older pip pointed at a patched store still accepted 12 of 12, and pip 26.2.2
  trusts its certifi and the OS store together, so both have to be fixed.
- Python 3.8 and 3.9 can't install pip 26.2.2. Move off them, or rewrite pip's
  vendored bundle with `trust_store.py --filter` and check it again; record it as
  a mitigation, not a fix.
- Every existing venv carries its own pip and certifi: dev machines, CI caches,
  AMIs, and Lambda deployment packages and layers, which vendor certifi. A venv
  made by a Python older than 3.15.1, 3.14.9 or 3.13.17 starts with a vulnerable
  pip, so upgrade pip right after `python -m venv`.
- conda 26.9.4, sigstore 4.5.1, and `pypa/gh-action-pypi-publish` 1.14.3 in
  release workflows.
- The AWS, Google Cloud and Azure CLIs are frozen Python apps with their own
  certifi (or botocore bundle). Update the CLI itself; the system Python's certifi
  doesn't reach them. Point `scan_repo.py` at the CLI's install directory to
  check its bundle.
- uv: run `UV_SYSTEM_CERTS=true uv self update` on machines, and in images bump
  `COPY --from=ghcr.io/astral-sh/uv:0.13.4` (or later).

To confirm in the artifact, `probe_runtime.sh` covers both `ssl` and certifi. For
the bundles alone, run `trust_store.py python` (certifi and pip's vendored copy, for
every python on PATH), or `trust_store.py /path/to/venv/bin/python` for one env.

### Conda, mamba, pixi environments

A conda environment carries its **own** `ca-certificates`, OpenSSL and certifi.
Python in the env reads `$CONDA_PREFIX/ssl/cacert.pem`, not the OS store, so a
patched base image does nothing for it.

```bash
conda update -n ENV ca-certificates certifi openssl     # or: mamba / micromamba
python3 trust_store.py "$CONDA_PREFIX/ssl/cacert.pem" "$CONDA_PREFIX/bin/python"
```

Bump `ca-certificates` and `certifi` in `environment.yml`, conda-lock files, and
explicit lockfiles. Any `ca-certificates` build dated before 2026-10-19 is
vulnerable. For pixi, upgrade pixi itself (0.82.1) and run
`pixi update ca-certificates certifi`. Conda base images
(`continuumio/miniconda3`, `condaforge/miniforge3`, `mambaorg/micromamba`) need
the update inside the image. Rebuilding on a newer tag isn't enough until
those images republish.

## Node.js, npm, yarn, pnpm, Electron, Deno, Bun

| Runtime | Fixed | Notes |
|---|---|---|
| Node.js | 22.23.4, 24.22.1, 26.12.1 | Bundled NSS roots plus a public-key block. No other line is patched: Node 20 and other EOL majors must move to a supported line |
| Electron | 44.9.1, 43.8.1, 42.11.16 | The app ships its own Node and Chromium net stack, so users need a new app build |
| Deno | 2.9.8 | |
| Bun | 1.4.4 (roots updated to NSS 3.131.1, released 2026-10-22) | 1.3.11 through 1.4.3 trust the six emSign-path chains. This includes `bun build --compile` binaries, which embed Bun's roots, so rebuild and reship them. See "Bun" below |

`NODE_EXTRA_CA_CERTS` only *adds* roots, so it cannot fix anything.
`NODE_USE_SYSTEM_CA=1` / `--use-system-ca` did **not** fix Node in field tests: it
still accepted the emSign chains on a fixed OS store. `--use-openssl-ca` with a
fixed OS store refused all 12, so it is a stopgap, confirmed by the probe.
Upgrading Node is the real fix. npm, yarn and pnpm use Node's TLS, so CI and every
build image need the new Node too.

Electron bundles its own Node; judge it by Electron's version, not the Node
version it reports (Electron 44.9.3 reports Node 24.22.0 and refuses all 12).
Don't raise a `.mcpb` manifest's `compatibility.runtimes.node` to 24.22.1: Claude
Desktop matches it against Electron's reported 24.22.0 and falls back to any
system Node on a mismatch, which is worse.
Probe from the main process, where Node's `tls` runs, not from a renderer.

To confirm, `node --version` in the running container, plus `probe_runtime.sh`.

**Stopgap where Node can't be upgraded yet.** Use this rarely: see "Trust patching
in application code" in SKILL.md step 3. For most services on a managed runtime,
the answer is to record the gap and redeploy when the platform ships a fixed Node.
On Node 22.19+ and 24.5+, which have `tls.setDefaultCACertificates`, drop the affected roots from the default store at
startup, before any connection is made, for example in Next.js's
`instrumentation.ts`. Filter by key, not by name. Tested on a managed runtime,
this took the advisory's hosts from 6 of 12 accepted to 12 of 12 refused.

```js
import tls from "node:tls";
import { X509Certificate, createHash } from "node:crypto";
// The SPKI SHA-256 values in scripts/emudhra_certs.py (BAD_ROOTS and BAD_INTERMEDIATES)
const AFFECTED = new Set(["8D417DB2DD8BF5E3084D1E3F196D583849D81BDD4C00C70B9D39369E96B8C782", /* ... */]);
const spki = (pem) => createHash("sha256")
  .update(new X509Certificate(pem).publicKey.export({ type: "spki", format: "der" })).digest("hex").toUpperCase();
tls.setDefaultCACertificates(tls.getCACertificates("default").filter((pem) => {
  try { return !AFFECTED.has(spki(pem)); } catch { return false; }  // unparsable: drop it
}));
```

Load it before build-time scripts too (migrations, `next build` data fetching),
which run in the same exposed runtime with credentials, for example with
`node --import ./tls-trust.mjs`. A redeploy alone does not move a managed
platform's Node.

It covers only connections that use the default store: a client given its own
`ca:` option, a child process, or a worker that loads before it is not covered.
Probe the deployed runtime after shipping it, and keep the Node upgrade on the
list. Keep the stopgap to one small file, and say in the PR when to delete it: once
the runtime's Node is at a fixed version. The pnpm standalone build (`@pnpm/exe`, `get.pnpm.io`) embeds its own Node,
so it needs its own update.

### Bun

Bun ships its own copy of the Mozilla roots, and `bun build --compile` bakes that
copy into the binary. Nothing outside the binary fixes it, and a LaunchAgent or
service never reads the shell variables from the macOS steps. The fix is Bun 1.4.4
or later, then a rebuild and a new release of every compiled binary.

Bun has no environment-variable CA override: `NODE_USE_SYSTEM_CA` had no effect on
Bun 1.3.10, and Bun 1.3.11 on macOS accepted all 12 chains. `bunfig.toml`
`[install] cafile` covers `bun install` and `bunx` only. A CLI compiled with Bun
(Supabase's was on Bun 1.4.2) needs its vendor's rebuild. Probe it in place with
`BUN_BE_BUN=1 <binary> probe.js`.

- **Don't use a per-request CA pin as a stopgap.** Bun's `fetch` accepts
  `tls: { ca: [...] }`, but on Bun 1.3.11 a fetch with that option still accepted
  certificates outside the pinned CA when tested against the advisory's hosts.
  If a release can't move to 1.4.4 yet, treat it as exposed, and say so in your
  report.
- **Prove the rebuild.** Run `probe_runtime.sh` where `bun` is the shipped
  version, or, for a compiled binary, point the same code path it uses at a test
  host: the request must fail.
- **On macOS, don't rely on the system store for Bun.** It is the one with the G3B
  soft-fail.
- Record what credentials an old binary sent: a device token or API key that went
  over these connections belongs on the rotation list for the security owner.

## Go

The fixed toolchains are **1.27.3 and 1.26.10** (CVE-2026-111943, which adds an SPKI
blocklist in `crypto/x509`).

- The block is compiled into each binary, so **every Go binary must be rebuilt**:
  services, CLIs, sidecars, operators, Terraform providers you build yourself.
- On Linux, Go reads the OS store (`/etc/ssl/certs/...`). In `scratch` images it reads
  whatever bundle you copied in, or `golang.org/x/crypto/x509roots/fallback` if
  you import it. Fix those too.
- Bump the toolchain in `go.mod` (`toolchain go1.27.3`), in the Dockerfile
  (`FROM golang:1.27.3`), and in CI (`setup-go` `go-version`).
- Go modules are protected by sumdb, so `go get` content is safe. The exposure is
  your program's own HTTPS calls.

To confirm on the deployed binary itself, run `go version /path/to/binary`, or
`go version -m`, on a copy pulled from the image. It must print 1.26.10+ or 1.27.3+.
`probe_runtime.sh` cannot probe a Go binary from outside.

### Third-party Go tools

terraform and its providers, OpenTofu, packer, helm, kubectl, gh, the docker CLI and
daemon, containerd and runc, git-lfs, golangci-lint, trivy, goreleaser, and many
cloud and vendor CLIs are Go programs. Each one carries the `crypto/x509` of the Go
it was built with. They pick up the OS store on Linux, but the SPKI block is only
in binaries built on Go ≥ 1.26.10 / 1.27.3. On a test container on 2026-10-22,
`go_binaries.py` found docker, containerd, runc, gh, git-lfs and golangci-lint all
built on unpatched Go.

- Upgrade each tool once its vendor publishes a release built on a fixed Go. Check
  the actual binary, not the release notes: `go_binaries.py $(command -v terraform helm kubectl gh)`.
- Until then, a fixed OS store covers the emSign-path chains for these tools on
  Linux. On Debian and Ubuntu, though, the AAA cross-sign path stays open until
  `ca-certificates` itself is the fixed version. The OS store is therefore the
  stopgap, and has to be updated first.
- The AWS provider needs a major bump: no 5.x release is built on a fixed Go, and
  6.70 is the first that is.
- Terraform providers are downloaded per workspace. After the vendors rebuild,
  run `terraform init -upgrade` and check `.terraform/providers/**` with
  `go_binaries.py`.

## Java / JVM (Maven, Gradle, Kotlin, Scala, Android builds)

The OpenJDK advisory (CVE-2026-91403) lists 27.0.1, 25.0.5, 21.0.13, 17.0.21, 11.0.33
and 8u512 "and earlier" as affected. The advisory's tracker lists 27.0.1.0.2,
25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2 and 8u511 as patched. The two lists
disagree, so **confirm the exact build with your vendor**: Temurin, Corretto, Zulu or
Oracle. Treat a JDK as fixed only if its release notes name the fix, or if the
`trust_store.py java` check below comes back clean.

A `jssecacerts` file next to `cacerts` replaces it as the default trust store, and
`-Djavax.net.ssl.trustStore=` in `JAVA_TOOL_OPTIONS`, `JDK_JAVA_OPTIONS` or
`_JAVA_OPTIONS` replaces both. `trust_store.py java` checks all of them; patch
whichever one the JVM actually reads.

- **Distro JDKs** (Debian, Ubuntu, RHEL, Fedora, Arch, Gentoo, Oracle Linux) use the OS
  cacerts. Updating `ca-certificates` (and `ca-certificates-java`) is enough.
- **Vendor JDKs and images** (`eclipse-temurin`, `amazoncorretto`, and so on) ship their own
  `cacerts` (`$JAVA_HOME/lib/security/cacerts`, or `$JAVA_HOME/jre/lib/security/cacerts`
  on JDK 8), which includes **both** roots. Until you have a patched build, remove
  them in the image:

  ```dockerfile
  COPY emudhra_certs.py trust_store.py /tmp/
  RUN python3 /tmp/trust_store.py --delete "$JAVA_HOME/lib/security/cacerts" \
   && python3 /tmp/trust_store.py "$JAVA_HOME/lib/security/cacerts" \
   && rm /tmp/emudhra_certs.py /tmp/trust_store.py
  ```

  The script finds entries by public key, since alias names and subjects differ by
  vendor, deletes them with keytool by path (JDK 8's keytool has no `-cacerts`
  option), and re-reads the store: the build fails if keytool errors or an affected
  entry survives. It needs Python in the build stage; in a JDK image without it,
  do the deletion in a stage that has both, or copy `cacerts` out and back. Don't hand-roll this as
  `keytool -cacerts … -delete … ; true`: on JDK 8 that fails silently and leaves both
  roots in place.
- An app-specific truststore (`-Djavax.net.ssl.trustStore=...`) needs the same edit.
- Maven and Gradle downloads use the build JDK, so patch CI as well. A Gradle
  toolchain (`JavaLanguageVersion.of(N)`) may auto-provision a separate JDK
  through the foojay resolver into `~/.gradle/jdks/`. Its `cacerts` needs the
  same check, and so does the JDK that Gradle itself runs on.

To confirm in the running JVM's image, run `trust_store.py java` (or pass the
keystore path for an app truststore; set `STOREPASS` if it isn't `changeit`). It
must print CLEAN and exit 0. ERROR or exit 2 means the store couldn't be read
completely, which is not a pass. If a vendor's patched build still holds an
affected root but says it blocks the keys another way, it stays VULNERABLE in
your inventory until `probe_runtime.sh`'s java line in that image exits `ok` on all
12 chains.

## Rust

| Crate or tool | Fixed |
|---|---|
| webpki-roots, webpki-root-certs | 1.0.10 (0.26.x re-exports 1.x, so check the 1.x entry in `Cargo.lock`) |
| rustls-webpki | 0.103.16 |
| rustup | 1.29.2 |

Run `cargo update -p webpki-roots -p rustls-webpki`, then rebuild and redeploy every
binary. Crates that use `native-tls`, or `rustls-native-certs` /
`rustls-platform-verifier`, follow the OS store instead. cargo itself uses the OS
store through curl.

## PHP, Ruby, Elixir/Erlang, Perl, .NET

| Stack | Fix |
|---|---|
| PHP | `composer/ca-bundle` 1.4.16 or 1.6.0 (1.5.x is not fixed). Guzzle and Symfony HttpClient otherwise use the OS store or `openssl.cafile` |
| Ruby | Uses OpenSSL's store: fix the OS store. Check for vendored bundles (`ssl_ca_file`, the `certified` gem) |
| Elixir | `castore` 1.0.22 |
| Erlang | hex `certifi`: pending (certifi/erlang-certifi#56). Point `:ssl` at the fixed OS bundle via `public_key:cacerts_get()` (OTP 25+) |
| Perl | `Mozilla::CA` 20261020 |
| .NET (and NuGet) | Windows: Microsoft's CTL update. Linux and macOS: the OS store, through OpenSSL on Linux. Rebuild `mcr.microsoft.com/dotnet/*` images on a base published after 2026-10-20, and check the image's store with `trust_store.py system`. `probe_runtime.sh`'s curl/openssl line stands in for .NET on Linux, because both read the same store |

## Tools and platforms

| Tool | Fixed |
|---|---|
| Claude Code | 2.1.303 |
| Docker Desktop | 4.96.3. The advisory says 4.96.2, but Docker shipped the fix in batches and 4.96.3 carries the last of its bundled components (kubectl, Init, Model Runner, Debug, MCP) |
| mise | 2026.10.17 |
| Cloudflare CFSSL trust store | 2026.10.1 |
| Freedesktop SDK (Flatpak) | 25.08.19, 26.08.3 |

GitHub-hosted runners pick up new images on GitHub's schedule, and old and new
images serve jobs side by side. Until all are on ca-certificates 20260816, upgrade
the package in the job (deployed-verification.md, "CI/CD runners"). Confirm by
running `probe_runtime.sh` in a workflow on a throwaway branch, not in a merged
change. BuildKit from `docker/setup-buildx-action`'s default
`moby/buildkit:buildx-stable-1` was built on go1.26.8. v0.34.1 is on go1.26.10:
pin it with `driver-opts: image=moby/buildkit:v0.34.1`. Self-hosted runners, ARC runner images and
GitLab runners are yours to patch: OS store, Node, JDK, pip and uv.

## Databases and other clients that skip verification

`sslmode=require`, `prefer` and `allow` (libpq, psycopg, postgres.js `ssl:
'require'` or `?sslmode=require` in `DATABASE_URL`, which it turns into
`rejectUnauthorized: false`, node-postgres) encrypt without checking the server's certificate, so
a certificate from the compromised intermediates is accepted like any other.
`scan_repo.py` flags them. Use `sslmode=verify-full` with a patched CA file
(`sslrootcert=`), or `ssl: { rejectUnauthorized: true, ca: ... }`.

## Things that are not fixes

- Setting `NODE_EXTRA_CA_CERTS`, or adding roots anywhere. Adding never removes.
- Bumping a version in the repo without rebuilding and redeploying.
- `docker build` with a warm cache.
- Turning verification off (`verify=False`, `rejectUnauthorized: false`,
  `InsecureSkipVerify`). If you find these while scanning, report them: each one
  trusts every certificate, not just these sixteen.
- Re-adding emSign ECC Root CA - G3 because an emSign-certified site broke.
