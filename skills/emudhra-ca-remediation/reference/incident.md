# The eMudhra intermediate CA compromise (October 2026)

Snapshot as of 2026-10-22. Re-check the advisory's patched-versions table before
relying on a "pending" entry: https://emudhra.we-have-a-problem.com/

## What happened

eMudhra generated the private keys of eight intermediate CA certificates
incorrectly, in April 2025. Each private key is an integer below 256 (the keys were
4, 56, 66, 115, 155, 156, 230 and 237), so anyone can recover them from the public
certificates. Whoever holds one can issue a certificate for any hostname, and it
chains to roots that most TLS clients trust.

- 2026-10-17: a researcher signed a test message with each key and reported it to
  the Apple, Google, Microsoft and Mozilla root programs. Firefox and Chrome block
  the intermediates (OneCRL, CRLite, CRLSets).
- 2026-10-18 and 19: eMudhra and Sectigo revoke the intermediates and the
  cross-signs. Apple blocks them on the 19th, and downstream trust stores are
  notified the same day.
- 2026-10-20: Microsoft blocks them through Windows' automatic CTL updates. The
  advisory is published.

There were no CT log entries for these intermediates, so CT-enforcing browsers
(Chrome, Safari, Edge, and Firefox) could not have been attacked. **Most non-browser
clients do not enforce CT or check revocation.** That covers package managers,
server-side HTTP clients, SDKs, CLIs, CI runners, and mobile apps that use a raw
WebView. Nobody knows whether these keys were exploited against such clients during
the 18 months they were recoverable.

## What an attacker can do with it

Anyone who can intercept the network path can impersonate any HTTPS server to a
client that still trusts the intermediates. That covers public Wi-Fi, a compromised
router or ISP, a cloud network neighbour, and DNS hijacking. Concretely:

- Steal credentials sent over TLS: API keys, OAuth tokens, registry tokens,
  database passwords sent to managed services, and webhook secrets.
- Tamper with downloads. This matters most where integrity rests on TLS alone: pip
  without `--require-hashes`, curl-pipe-sh installers, base image pulls by tag, and
  binary downloads in CI. Lockfile hashes (npm `integrity`, `uv.lock`, Cargo,
  Go's sumdb) still protect package *contents*, but they do not protect the auth
  token sent with the request.
- Code signing: two of the eight are code-signing CAs, so Authenticode signatures
  from them could be forged on Windows hosts that have not received Microsoft's
  block.

Servers that only *present* certificates are not affected. A server is affected
wherever it acts as a TLS client: outbound API calls, webhooks it sends, database
and queue connections to public endpoints, and mTLS that trusts public roots.

## The certificates

There are eight intermediates, each issued twice: once under eMudhra's own root and
once as a Sectigo cross-sign, which makes 16 certificates.

| Intermediate | Use | SPKI SHA-256 (same for both issuances) |
|---|---|---|
| EM DV TLS CA - G3B | TLS | `EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105` |
| EM OV TLS CA - G3B | TLS | `43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B` |
| EM EV TLS CA - G3B | TLS | `E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41` |
| EM DV TLS CA - G3C | TLS | `49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F` |
| EM OV TLS CA - G3C | TLS | `63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8` |
| EM EV TLS CA - G3C | TLS | `5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0` |
| EM OV CS CA - G3B | code signing | `EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6` |
| EM OV CS CA - G3C | code signing | `92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30` |

The full list, with certificate fingerprints and PEMs, is at
https://emudhra.we-have-a-problem.com/impacted-intermediates.json. Its SHA-256 is
`F67B3ABE9B4879F4E91874ED041BECCD71257F1DB41C588C724CCF12AA90C59E`, the same value the
advisory's Windows script pins.

They reach trust through two roots, and those two roots are what bundle fixes
remove:

| Root | SHA-256 | Where it is trusted |
|---|---|---|
| **emSign ECC Root CA - G3** (cross-signs eMudhra's emSign Root TLS CA - G3) | `86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B` | Apple, Chrome, Microsoft, Mozilla, so every Mozilla-derived bundle (certifi, curl's bundle, distro ca-certificates, Node, webpki-roots) |
| **AAA Certificate Services** (Sectigo, "Comodo AAA Services root") | `D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4` | Apple and Microsoft. Mozilla and Chrome had already removed it, but older bundles, the **JDK `cacerts` (alias `comodoaaaca`)**, Android ≤ 13, and **the Debian and Ubuntu system stores** (`Comodo_AAA_Services_root`) still carry it |

Checked on 2026-10-22: certifi 2026.07.22 trusts the six emSign-path test
chains and none of the AAA ones, and certifi 2026.10.19 trusts none of the twelve.
So a bundle that follows Mozilla's TLS trust bits (certifi, Node's built-in roots,
webpki-roots) is exposed through the emSign root only. The Debian 12 system store
also trusts the AAA cross-signed chains, which UlisesGascon's reproducible check
confirms (https://gist.github.com/UlisesGascon/10ed0724930e5382b3ed48fa2b0d3e02).
So are JDKs and the Apple and Windows platform stores. Where AAA is trusted, removing
the emSign root is not enough: you need the fixed distro package, a key-based
(SPKI) block, or revocation checking. That is why every probe tests all 12 chains.

Side effect: removing emSign ECC Root CA - G3 also breaks legitimate sites with
eMudhra certificates, which are mostly Indian government, banking and
e-signature services. If a client integration talks to one of those, expect TLS
failures after patching and tell the owner. Never re-add the root to work around
it.

## Test endpoints

There are twelve hosts, one for each of the 6 TLS intermediates by 2 issuers:
`{dv,ov,ev}-{g3b,g3c}[-aaa]-emudhra.we-have-a-problem.com`. Each serves a valid leaf
issued by the compromised intermediate. A client that completes the handshake is
vulnerable. `https://emudhra.we-have-a-problem.com/chains.zip` holds the same
chains for offline checks (SHA-256
`8a2edc81b6c51e3ad27d45ca1e441ec84c961e2dee0fc547f2a02c0f74315f95` as of 2026-10-20).
The site logs the user-agent of every successful connection. That is harmless,
but don't point a client carrying secrets at it: the probes send no
credentials, and yours shouldn't either.

## Known traps

- **macOS** (reported 2026-10-21 by Anzal Abidi after testing all 12 chains, and
  consistent with the advisory): Apple marked the emSign root for OCSP checking
  instead of removing it. `ocsp-b.emsign.com`, which serves the G3B intermediates,
  returns 503, so `Security.framework` soft-fails open and trusts the 3 G3B
  chains. The advisory's `/etc/ssl/cert.pem` edit is not enough either, because
  Apple's LibreSSL falls back to `TrustEvaluationAgent` for certificates it does
  not find in the file. `OPENSSL_X509_TEA_DISABLE=1` was suggested for that, but
  made no difference in a later test, and Apple's `/usr/bin/python3` ignores
  `SSL_CERT_FILE` altogether. Follow `remediation.md`'s macOS section, and
  **always probe all 12 chains**, with the shell's variables and without them.
  Later, macOS 27.0.1's Security.framework refused all 12, G3B included, so the
  soft-fail may be fixed there: probe rather than assume either way. Clients on
  rustls-platform-verifier delegate to it, and those connections took about 50 s,
  so run the probe with `TIMEOUT=90` on macOS.
- **Managed runtimes lag**: a Vercel production function on Node 24.21.0
  accepted 6 of the 12 chains while the repo named Node 24, and a Vercel build
  ran Bun 1.3.14 although `packageManager` said 1.4.4. Probe from inside.
- **Embedded runtimes**: CLIs built with Node SEA or `bun build --compile` carry
  their own roots. One widely used deploy CLI embedded Node 24.14.1 in two
  consecutive releases.
- **pip** always loads its vendored certifi alongside the system store, so fixing
  the OS does not fix pip below 26.2.2. `PIP_CERT` overrides this.
- **Docker official `python:` images** still shipped an old pip on 2026-10-21:
  `python:3.12-slim` had pip 25.0.1 with certifi 2024.08.30.
- **`PIP_CERT` doesn't fix an old pip**: pip 25.0.1 pointed at a patched store still
  accepted 12 of 12. **`NODE_USE_SYSTEM_CA=1` doesn't fix Node** either: Node
  still accepted the emSign chains with it set on a fixed OS store, while
  `--use-openssl-ca` refused all 12.
- **Alpine's `apk upgrade ca-certificates`** exits 0 and does nothing on images
  that ship only `ca-certificates-bundle` (the `node:*-alpine` and `oven/bun:*-alpine`
  images): upgrade `ca-certificates-bundle`.
- **A redeploy doesn't move a platform's runtime.** Fresh Vercel previews still ran
  Node 24.21.0 on 2026-10-22.
- **Long-running processes keep the roots they loaded.** A daemon started before
  the fix (a runner's dockerd, a JVM, a worker pool) needs a restart.
- **Go** compiles `crypto/x509` into every binary. Go on Linux reads the OS store,
  but the SPKI block lives in the toolchain, so a binary is protected only after a
  rebuild with Go 1.26.10 or 1.27.3, *and* the image needs a fixed OS store.
- **Docker layer cache**: `RUN apt-get install ca-certificates` from last month is
  cached. Rebuild with `--pull --no-cache`, or the "fixed" image is the old one.
- **Digest-pinned base images** never change until someone bumps the digest.
- **Android ≤ 13** gets no Play-system CA updates. Apps that use a raw WebView, where
  CT is off by default, trust both roots until the user disables them by hand.
- **Firefox for Android < 158.0.2** had a OneCRL sync bug (Bug 2084311).

## Sources

- Advisory and patched-versions table: https://emudhra.we-have-a-problem.com/ (source: https://github.com/galadran/we-have-a-problem.com)
- Python guidance: https://discuss.python.org/t/information-for-python-users-regarding-emudhra-emsign-ca-certificate-security-incident/109576
- Mozilla incident bug: https://bugzilla.mozilla.org/show_bug.cgi?id=2083449, and trust-store guidance: https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/0R3XLJL6FuE
- Go CVE-2026-111943: https://groups.google.com/g/golang-announce/c/66pojueaQek
- OpenJDK CVE-2026-91403: https://openjdk.org/groups/vulnerability/advisories/2026-10-21
- macOS and Java test results: https://x.com/AnzalAbidi/status/2112943256522850576
- eMudhra's statement: https://www.bseindia.com/xml-data/corpfiling/AttachLive/6be0c423-b335-494b-86f3-54c561c3a5f9.pdf
