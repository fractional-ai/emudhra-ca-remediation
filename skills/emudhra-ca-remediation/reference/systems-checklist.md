# Systems checklist

This is a sweep by category, to make sure no kind of system was overlooked. For
each category it gives **where trust comes from** and **how to check and fix
it**. Fixed versions are in `remediation.md`. Anything not listed here still
gets the five questions in SKILL.md.

The scripts are POSIX sh and Python. On Windows, translate them: PowerShell's
`Invoke-WebRequest` / `System.Net.Http` probe the Windows store, and
`certutil -verify -urlfetch` checks a chain. Or run them under WSL, which only
tests WSL's own Linux store.

## Operating systems and their stores

| System | Trust source | Check / fix |
|---|---|---|
| Debian, Ubuntu, Devuan | `/etc/ssl/certs/ca-certificates.crt`, built from `/etc/ca-certificates.conf`. **Debian 12 trusts AAA for TLS**; stock Ubuntu 24.04 and 26.04 refused the AAA chains in field tests. EOL releases (bullseye, Ubuntu 20.04) get no fixed package: remove both roots | Install the fixed `ca-certificates`. Then `trust_store.py system` |
| RHEL, Rocky, Alma, CentOS Stream, Fedora, Amazon Linux | p11-kit, `update-ca-trust`, `/etc/pki/ca-trust/` | Install the fixed package, or use the blocklist commands in remediation.md. Then check `/etc/pki/tls/certs/ca-bundle.crt` |
| Alpine, Wolfi, Chainguard | `/etc/ssl/certs/ca-certificates.crt`, from `ca-certificates` or only `ca-certificates-bundle` | `apk upgrade ca-certificates ca-certificates-bundle`: on bundle-only images, upgrading `ca-certificates` alone is a silent no-op |
| SUSE / openSUSE | p11-kit, `/etc/pki/trust/` | Fixed package, or the blocklist |
| Arch, Gentoo, NixOS, Guix | The distro package, or `security.pki.caCertificateBlacklist` on NixOS | Update, then check |
| FreeBSD, NetBSD, OpenBSD, OmniOS | `caroot` / `ca_root_nss` / `certctl` | Fixed packages or `certctl untrust` (incident.md) |
| Distroless, scratch, busybox images | Whatever bundle was copied in at build time | Rebuild from a refreshed base, or copy in a fixed bundle |
| macOS | Keychain and Security.framework (soft-fails on G3B), plus `/etc/ssl/cert.pem` for LibreSSL tools. Apple's `/usr/bin/python3` reads only `/etc/ssl/cert.pem` | remediation.md's macOS section. Probe all 12 chains, in a shell and with the environment cleared |
| Windows / Windows Server | CryptoAPI and Schannel. Microsoft blocked these through CTL updates on 2026-10-20 | Confirm the 16 certs are in `Cert:\LocalMachine\Disallowed`: `Get-ChildItem Cert:\LocalMachine\Disallowed`, matched against the thumbprints in `impacted-intermediates.json`. Offline or WSUS-isolated hosts need the advisory's script. Apps with their own bundle (Git for Windows, Python, Node, Java) are separate |
| iOS / iPadOS | System store and Apple Valid DB, with CT enforced by the platform | OS update. Apps that pin or bundle their own trust need an app release |
| Android | System store, updatable through Google Play system updates on Android 14+ | Android 13 and older keep both roots. Raw WebViews and apps with a custom TrustManager need an app-level fix |
| ChromeOS, Linux desktops | Chrome's root store plus CRLSets for the browser; the distro store for everything else | Update the distro store |

## Language runtimes and their bundled roots

| Runtime | Trust source | Notes |
|---|---|---|
| Python | `ssl` uses OpenSSL's default paths; requests and httpx use certifi; pip adds its vendored certifi; `truststore` uses the OS store | Patch every source, in every venv, conda env and Lambda package |
| Node.js, Electron | Bundled NSS roots, or the OS store with `--use-openssl-ca` | Version upgrade. `NODE_EXTRA_CA_CERTS` only adds roots, and `NODE_USE_SYSTEM_CA=1` didn't stop the emSign chains in field tests. Judge Electron by its own version |
| Deno, Bun | Bundled roots | Deno 2.9.8; Bun 1.4.4, then rebuild `bun build --compile` binaries |
| Go | The OS store on Linux, the platform verifier on macOS and Windows, plus `x509roots/fallback` if imported. The key block is compiled into the binary | Rebuild on Go ≥ 1.26.10 / 1.27.3. Check binaries with `go_binaries.py` |
| Java / Kotlin / Scala / Clojure | `$JAVA_HOME/lib/security/cacerts`, or the OS cacerts for distro JDKs. `jssecacerts`, or `-Djavax.net.ssl.trustStore` in `JAVA_TOOL_OPTIONS`, replaces it | Holds both roots. Check and fix with `trust_store.py java` and `--delete` (remediation.md) |
| .NET | The OS store (OpenSSL on Linux) | Fix the OS store or image |
| Rust | rustls with webpki-roots, or the platform verifier, native-tls or OpenSSL | Use `Cargo.lock`, rebuild |
| Ruby | OpenSSL's store; some gems vendor bundles | Fix the OS store; look for `ssl_ca_file` |
| PHP | `openssl.cafile` / `curl.cainfo` in php.ini, `composer/ca-bundle`, or the OS store | Check php.ini and composer.lock |
| Perl | `Mozilla::CA`, or IO::Socket::SSL with the OS store | Mozilla::CA 20261020 |
| Elixir / Erlang | castore, hex `certifi`, or `public_key:cacerts_get()` | castore 1.0.22; erlang certifi pending |
| Swift (server), Objective-C | Linux: the OS store via OpenSSL or BoringSSL. Apple platforms: the system store | OS update or image rebuild |
| Dart / Flutter | Dart VM: the OS store on most platforms, or a `SecurityContext` with a bundled PEM | Check for bundled PEMs and custom `SecurityContext`s |
| R | libcurl's store: the OS store on Linux, and a bundled `curl-ca-bundle.crt` on Windows and macOS builds | Update R, or point `CURL_CA_BUNDLE` at a fixed bundle |
| Julia | `MozillaCACerts_jll` (bundled) | Update the package, or set `JULIA_SSL_CA_ROOTS_PATH` to a fixed bundle |
| Haskell, OCaml, Nim, Zig, Crystal, Lua | Usually the OS store through OpenSSL, sometimes a bundled PEM | Find the TLS library, then its trust source |
| C / C++ | OpenSSL, BoringSSL, GnuTLS, mbedTLS, wolfSSL or Schannel. Trust is wherever the app points them, often a bundled `cacert.pem` or one compiled in | Search the binary and package for embedded PEMs. Static builds need a rebuild |
| WebAssembly / embedded JS engines | The host's fetch stack | Check the host |
| Managed function runtimes (Vercel, Netlify, Lambda, Cloud Functions, buildpacks) | The platform's Node or Python, at a patch version the platform picks | Unproven is exposed: probe from inside with a preview route (deployed-verification.md, "Managed runtimes") |
| CLIs that embed a runtime (Node SEA, `pkg`, `bun build --compile`, `deno compile`, standalone pnpm) | The embedded runtime's roots; shell fixes don't reach them | Sweep for them, report the embedded version (remediation.md, "Binaries that embed a runtime") |

## Package managers and build tools

Content integrity often survives a TLS compromise (lockfile hashes, signed
repositories, Go's sumdb), **but credentials sent to registries do not**. That
includes private-registry tokens, `.npmrc`, `.pypirc`, `~/.m2/settings.xml`, Docker
logins, and PATs used to fetch git dependencies.

| Tool | TLS stack | Notes |
|---|---|---|
| pip, Poetry, Pipenv, PDM, Hatch, pip-tools | pip's vendored certifi plus the system store, or certifi through requests | Upgrade pip and certifi in the tool's own environment too (pipx venvs) |
| uv, pixi, rye | Bundled webpki-roots unless system certs are enabled | Version upgrade |
| conda, mamba, micromamba | The env's own `ca-certificates` and OpenSSL | remediation.md's conda section |
| npm, yarn, pnpm, corepack | Node's TLS | Node upgrade |
| Maven, Gradle, sbt, Leiningen, Bazel (JVM) | The JDK `cacerts` | Fix the build JDK, and toolchain JDKs too |
| NuGet / dotnet | The OS store | Fix the OS store |
| Cargo, rustup | Cargo uses curl with the OS store; rustup uses rustls | rustup 1.29.2 |
| go (modules) | Go's `crypto/x509` | Upgrade the toolchain. Modules are sumdb-protected |
| RubyGems, Bundler | Ruby OpenSSL | Fix the OS store |
| Composer | `composer/ca-bundle` or the OS store | composer/ca-bundle 1.4.16 / 1.6.0 |
| Hex / mix, rebar3 | castore / certifi | castore 1.0.22 |
| CPAN, cpanm | Mozilla::CA or the OS store | Mozilla::CA 20261020 |
| CocoaPods, SwiftPM, Carthage | git over HTTPS with the system store; CocoaPods runs on Ruby | OS update; git's store |
| pub (Dart), CRAN, Julia Pkg, Cabal and Stack, opam, LuaRocks, vcpkg, Conan | Their language runtime or libcurl | See the runtime row above |
| apt, dnf/yum, apk, zypper, pacman | GnuTLS or OpenSSL with the OS store. Packages are signature-checked | Fix the OS store. Repo credentials (private mirrors) are the exposure |
| Homebrew | Its own curl and `ca-certificates` formula | `brew upgrade ca-certificates` |
| Chocolatey, winget, Scoop | The Windows store (Chocolatey uses .NET) | Windows CTL update |
| Nix | `NIX_SSL_CERT_FILE` / `cacert` | Update nixpkgs' `cacert` |
| asdf, mise, nvm, pyenv, rbenv, sdkman | curl or git, plus their own release downloads | mise 2026.10.17; others follow curl/git |
| git | OpenSSL or GnuTLS (`http.sslCAInfo`), Schannel on Windows, Security.framework on macOS | Check `git config --show-origin --get http.sslCAInfo` |
| Docker / Podman / containerd pulls | Go `crypto/x509` plus the OS store plus `/etc/docker/certs.d` | Docker Desktop 4.96.3. Check the daemon binaries with `go_binaries.py` |
| Helm, Terraform / OpenTofu (and providers), Packer, kubectl, cloud CLIs | Mostly Go | `go_binaries.py`. Upgrade when vendors rebuild |

## Infrastructure that verifies upstreams

| Component | Where its trust lives |
|---|---|
| nginx (`proxy_ssl_trusted_certificate`, `proxy_ssl_verify on`), Apache (`SSLProxyCACertificateFile`), HAProxy (`ca-file`), Traefik, Caddy | A configured file, or the OS store in the image |
| Envoy, Istio, Linkerd, Consul | A configured `trusted_ca`, mesh-issued roots for internal traffic, and egress gateways for external traffic |
| Kubernetes trust distribution: cert-manager `trust-manager` Bundles, ConfigMaps of CA bundles mounted into pods | The source the Bundle pulls from (often a Debian package image), which needs a refresh |
| API gateways (Kong, Apigee, AWS API Gateway, Azure APIM) | Managed gateways belong to the provider; self-hosted ones use their image's store |
| TLS-inspecting proxies, secure web gateways, firewalls with decryption (Zscaler, Netskope, Palo Alto, Fortinet, Squid ssl-bump, mitmproxy) | Their own upstream trust store. **One stale store exposes everyone behind it**, because clients only see the proxy's certificate |
| Artifact proxies and mirrors (Artifactory, Nexus, Harbor, Verdaccio, devpi, pull-through registry caches) | JVM `cacerts` (Artifactory, Nexus), Go (Harbor), or Node (Verdaccio) |
| CI/CD systems (Jenkins, TeamCity, GitLab runners, Buildkite agents, Argo CD, Flux, Spinnaker) | The JVM, Go or Node store of the controller and of every agent |
| Secrets and identity (Vault, Keycloak, Dex, oauth2-proxy, SSSD) | Go or JVM stores. They fetch JWKS or federation metadata over TLS |
| Databases and brokers connecting out (replication, FDW, Kafka Connect, Debezium, Logstash) | JVM or OS stores |
| Monitoring and logging agents (Datadog, New Relic, OpenTelemetry Collector, Fluent Bit, Vector, Prometheus exporters, blackbox probes) | Mostly Go or Rust: rebuilds from the vendor. Datadog Agent 7.84.5 is the first on Go 1.26.10; 7.60.0 is exposed. An image tag pinned to a patch release needs a version bump, not `--pull` |
| Mail (Postfix `smtp_tls_CAfile`, Exim, Sendmail), LDAP clients, RADIUS, VPN clients (OpenVPN, strongSwan, WireGuard UIs that fetch config) | Configured files or the OS store |
| Load balancers and CDNs verifying origins (ALB to HTTPS targets, Cloudflare Full (strict), Fastly, Akamai) | The provider's store. Note when origin verification is off |

## Applications and devices

- **Desktop apps.** Electron and CEF embed Chromium and Node, while Qt, Tauri,
  Java, .NET, Go and Bun apps use their own stack. Native apps use the platform.
  Ship a rebuild, then check the version the update channel serves.
- **Mobile apps.** OkHttp with custom trust, Flutter or Dart `SecurityContext`, React
  Native with pinned trust, WebViews on old Android, and SDKs with pinning
  config.
- **Browser automation.** Playwright, Puppeteer and Selenium grids ship a bundled
  Chromium or Firefox. Playwright's Chromium 151 and Puppeteer's Chrome 127
  accepted the compromised chains, and there was no fixed Playwright Chromium yet.
  A Chromium `CADistrustedCertificates` managed policy listing the affected
  certificates works for headful Chromium; the headless shell ignores policies.
  Playwright on amd64 uses Chrome for Testing, which reads
  `/etc/opt/chrome_for_testing/policies/`, not `/etc/chromium/policies/`. Remove
  the policy once Playwright ships a fixed Chromium.
- **Binary wheels with their own TLS.** hf-xet (rustls-webpki 0.103.13),
  psycopg-binary (its own OpenSSL) and similar wheels don't use certifi.
  `scan_repo.py --all` on the installed environment finds embedded roots; the
  wheel needs a new release otherwise. Model downloads without a pinned
  revision or hash took whatever the connection served.
- **Cloud CLIs with vendored bundles.** gcloud 590.0.0 carries four, one of which
  trusts all 12 chains; AWS CLI v2 2.37.13 trusts the 6 AAA chains (on Amazon
  Linux 2023 the packaged AWS CLI uses the system store instead). Run
  `scan_repo.py --all` on the install directory.
- **Embedded and IoT firmware.** A `ca.pem` compiled into the firmware image, or an
  mbedTLS or wolfSSL bundle. Ship firmware or OTA updates.
- **Printers, NAS, cameras, smart TVs and kiosks** you administer: vendor
  firmware.
- **Code-signing verifiers.** Windows Authenticode (blocked through CTL), your own
  updaters that verify signatures against a pinned CA, driver installs, and
  MSIX/AppX.
- **Data and ML tooling.** Notebook images, Spark/Databricks runtimes, Airflow
  workers, dbt, model and dataset downloaders (Hugging Face hub uses requests and
  certifi), and vector DB clients.
- **SaaS you can configure but not patch.** Check the vendor's statement, and
  record it as "vendor-owned" with a link.
