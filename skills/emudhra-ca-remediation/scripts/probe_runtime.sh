#!/bin/sh
# Part of the emudhra-ca-remediation skill.
# Live check, run where the code actually runs: a production container, a CI
# runner, a VM, a laptop. It needs nothing but sh, so it can be piped in:
#
#   kubectl exec -i POD -c CONTAINER -- sh -s < probe_runtime.sh
#   docker run --rm -i --entrypoint sh IMAGE@sha256:DIGEST -s < probe_runtime.sh
#   ssh host sh -s < probe_runtime.sh
#
# For each TLS client present (curl, wget, Python's ssl with its default
# store and with certifi, node, bun, deno, ruby, java), it opens a TLS
# connection to each of the advisory's test hosts and does nothing else: no
# HTTP request, no download, nothing fetched is executed. Each host serves a
# leaf issued by a compromised intermediate.
#
# Two facts decide each verdict, and neither comes from reading a tool's
# messages:
#   1. Did the client's own verification accept the chain? This comes from an
#      exit status, an exception type, or a verification flag.
#   2. Was the chain it was shown really the test host's? The intermediate's
#      public-key fingerprint, or the leaf's Authority Key Identifier, must be
#      one of the eight compromised ones. A chain without them was re-signed
#      by something on the path, such as a TLS-inspecting proxy, and says
#      nothing about this client. Clients that can't report their own chain
#      (curl before 7.88, wget, deno) use the chain openssl, python or node
#      saw for that host.
#
#   VULNERABLE    accepted, and the chain is the compromised one. Also printed
#                 when a client accepted and no chain could be read at all:
#                 that is not proof of safety, so it fails closed.
#   ok            refused for a trust reason (no path to a trusted root, an
#                 untrusted or rejected issuer), and the chain shown was the
#                 compromised one
#   INCONCLUSIVE  everything else: a re-signed chain, a network error, a
#                 refusal of a chain that wasn't the test host's, a refusal for
#                 another reason (expired or not-yet-valid leaf, a wrong clock,
#                 a hostname mismatch, revocation, which an attacker can block),
#                 a client that went through a proxy and reported no chain of
#                 its own, and a client that is installed but printed nothing
#
# wget, deno, and curl on TLS backends that give no verify code, can't say why
# they refused. Their refusal counts as `ok` only when no proxy variable is
# set and openssl shows the test leaf is currently valid for that host name.
#
# Exit status: 1 if anything is VULNERABLE, else 2 if anything is INCONCLUSIVE
# or no client could be tested, else 0. Only 0 is a pass. Exit 2 behind an
# intercepting proxy means "run this somewhere with direct egress", not "fine".
#
# All twelve test hosts are probed by default, because clients differ by
# chain: on macOS the three G3B chains pass while G3C is blocked (Apple
# soft-fails OCSP for G3B). QUICK=1 probes one chain per root, and is only for
# a first look: it can miss exactly that kind of difference.
#
# Not probed here: Go and Rust binaries, .NET, PHP, and any binary that embeds
# its own runtime (Node SEA, pkg, bun build --compile, deno compile). Check
# those with go_binaries.py, scan_repo.py on the binary, Cargo.lock and
# trust_store.py (see remediation.md). The probe tests the python3, node and
# java on PATH: if the app runs another interpreter (a venv, a bundled node),
# point PROBE_PYTHON / PROBE_NODE at it.

set -u
T=${TIMEOUT:-15}
# PROBE_HOSTS overrides the host list (the skill's tests use it with a local
# server); PORT the port.
PORT=${PORT:-443}
if [ -n "${PROBE_HOSTS:-}" ]; then
  HOSTS=$PROBE_HOSTS
elif [ "${QUICK:-0}" = 1 ]; then
  HOSTS="dv-g3b-emudhra.we-have-a-problem.com dv-g3b-aaa-emudhra.we-have-a-problem.com"
else
  HOSTS=""
  for kind in dv ov ev; do for gen in g3b g3c; do for via in "" -aaa; do
    HOSTS="$HOSTS $kind-$gen$via-emudhra.we-have-a-problem.com"
  done; done; done
fi
# SPKI SHA-256 of the eight compromised intermediates, and their Subject Key
# Identifiers. Kept identical to emudhra_certs.py; tests/test_scripts.py checks.
BAD_SPKI="EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105 43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41 49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F 63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8 5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0 EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6 92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30"
BAD_SKI="E21E2FE71C19390E554B62C120245735248A2514 9BD86551AFE7E72C37AD08EE6919D9BF3784AE0A 3EDC20D9894698877B873FD88147B25C15D84706 AE7E105C3C2996C1A847270559F1E03DD4E50AF3 34EAEA0CEBC90ADAF9D0C5E2ED9B78C9879E1B6C A6255E80A94DB7F3967C1BC791DF92BCEE4BEB5F 79FAE8ECCFDB0D758DA458D69FB6EDDC7C49DEE6 EE6F73298D6FBFA7B31BC39534F61556447866B7"
PROBE_T=$T
PY=${PROBE_PYTHON:-python3}
NODE=${PROBE_NODE:-node}
# OpenSSL verify codes that mean "this chain is not trusted": unable to get
# issuer (2, 20), self-signed (18, 19), leaf signature unverifiable (21),
# untrusted (27), rejected (28). Expiry, hostname and revocation are not here.
TRUST_CODES="2 18 19 20 21 27 28"
PROXIED=0
for v in https_proxy HTTPS_PROXY all_proxy ALL_PROXY; do eval "[ -n \"\${$v:-}\" ]" && PROXIED=1; done
export BAD_SPKI BAD_SKI PORT PROBE_T TRUST_CODES

have() { command -v "$1" >/dev/null 2>&1; }
WORK=$(mktemp -d 2>/dev/null || echo "/tmp/emudhra-probe.$$")
mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT
# Every external call gets a deadline, in plain sh because macOS has no
# timeout(1). A call that hits it fails, which can only make a result
# INCONCLUSIVE (or VULNERABLE, for an accepted chain that couldn't be read).
to() {
  "$@" &
  pid=$!
  ( sleep $((T + 10)); kill "$pid" ) >/dev/null 2>&1 &
  killer=$!
  wait "$pid"
  rc=$?
  kill "$killer" >/dev/null 2>&1
  return $rc
}

echo "== where"
echo "host: $(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null)"
[ -r /etc/os-release ] && . /etc/os-release && echo "os: ${PRETTY_NAME:-unknown}"
uname -sm 2>/dev/null

# This output ends up in CI logs, so anything that can carry a secret is cut:
# URL credentials, query strings, a proxy URL's path, and the value of any
# option whose name looks like a token, key, secret, password or credential.
redact() {
  case $1 in
    # A proxy may be written without a scheme (user:pass@host:3128), which
    # curl and most clients accept. Userinfo ends at the last @ before the first /, so a password
    # with a raw @, # or ? is cut whole (a stray @ later only over-redacts).
    *[Pp][Rr][Oo][Xx][Yy]*) printf '%s' "$2" | sed -E -e 's|^([^/@[:space:]]*//)?[^/[:space:]]*@|\1***@|' \
         -e 's#(://[^/?[:space:]]*)[/?].*#\1#' -e '/:\/\//!s#^([^/?[:space:]]*)[/?].*#\1#' ;;
    *) printf '%s' "$2" | sed -E -e 's|//[^/[:space:]]*@|//***@|g' -e 's#\?[^[:space:]]*#?***#g' \
         -e 's#([A-Za-z0-9_.-]*([Tt][Oo][Kk][Ee][Nn]|[Ss][Ee][Cc][Rr][Ee][Tt]|[Kk][Ee][Yy]|[Aa][Uu][Tt][Hh]|[Pp][Aa][Ss][Ss]|[Pp][Ww][Dd]|[Cc][Rr][Ee][Dd])[A-Za-z0-9_.-]*[=:])[^[:space:]]*#\1***#g' ;;
  esac | cut -c1-160
}

echo "== versions and trust settings (for the report; they decide nothing below)"
if have dpkg-query; then
  dpkg-query -W -f='ca-certificates ${Version}\n' ca-certificates 2>/dev/null
  dpkg-query -W -f='ca-certificates-java ${Version}\n' ca-certificates-java 2>/dev/null
elif have apk; then apk info -v ca-certificates 2>/dev/null
elif have rpm; then rpm -q ca-certificates 2>/dev/null
fi
for v in CONDA_PREFIX OPENSSL_X509_TEA_DISABLE SSL_CERT_FILE SSL_CERT_DIR REQUESTS_CA_BUNDLE CURL_CA_BUNDLE GIT_SSL_CAINFO PIP_CERT NODE_EXTRA_CA_CERTS NODE_OPTIONS NODE_USE_SYSTEM_CA UV_NATIVE_TLS UV_SYSTEM_CERTS JAVA_TOOL_OPTIONS HTTPS_PROXY https_proxy; do
  eval "val=\${$v:-}"
  [ -n "$val" ] && echo "env $v=$(redact "$v" "$val")"
done
for c in "$PY" "$NODE" bun deno ruby java curl wget openssl uv pip; do
  have $c || continue
  case $c in
    java) echo "java: $(java -version 2>&1 | grep -v 'Picked up' | head -1)" ;;
    *) echo "$c: $($c --version 2>&1 | head -1)" ;;
  esac
done

# --- chain classification ---------------------------------------------------
# A probe line is: CLIENT HOST RESULT CHAIN DETAIL
#   RESULT  ACCEPTED | REJECTED | ERROR
#   CHAIN   BAD (the test host's own chain) | OTHER (re-signed) | - (not read)

is_bad_spki() { case " $BAD_SPKI " in *" $1 "*) return 0 ;; esac; return 1; }
is_bad_ski() { case " $BAD_SKI " in *" $1 "*) return 0 ;; esac; return 1; }

# Classify a PEM file of certificates with the openssl CLI: BAD, OTHER or -.
chain_of_pem() {
  have openssl || { echo -; return; }
  n=0; verdict=OTHER
  # Copy only the lines from each BEGIN to its END into its own file.
  awk -v d="$WORK/split" '/-----BEGIN CERTIFICATE-----/{n++; f=sprintf("%s.%03d", d, n); p=1} p{print > f} /-----END CERTIFICATE-----/{p=0; close(f)}' "$1"
  for f in "$WORK"/split.*; do
    [ -f "$f" ] || continue
    n=$((n + 1))
    fp=$(openssl x509 -in "$f" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null \
         | openssl dgst -sha256 -binary 2>/dev/null | od -An -tx1 | tr -d ' \n' | tr 'a-f' 'A-F')
    [ -n "$fp" ] && is_bad_spki "$fp" && verdict=BAD
    # The leaf's Authority Key Identifier names its issuer's key. The hex dump
    # can only match by being exactly one of the eight identifiers.
    if [ "$n" = 1 ]; then
      aki=$(openssl x509 -in "$f" -noout -ext authorityKeyIdentifier 2>/dev/null | sed -n '2p' \
            | sed 's/^ *keyid://' | tr -dc '0-9A-Fa-f' | tr 'a-f' 'A-F')
      [ -n "$aki" ] && is_bad_ski "$aki" && verdict=BAD
    fi
    rm -f "$f"
  done
  [ "$n" -gt 0 ] && echo "$verdict" || echo -
}

# The chain openssl sees for a host, independently of any client, and whether
# its leaf is valid right now for that name: "BAD 1", "OTHER 0", "- 0".
ref_openssl() {
  have openssl || { echo "- 0"; return; }
  echo | to openssl s_client -connect "$1:$PORT" -servername "$1" -showcerts > "$WORK/ref.pem" 2>/dev/null
  awk '/-----BEGIN CERTIFICATE-----/{p=1} p{print} /-----END CERTIFICATE-----/{exit}' "$WORK/ref.pem" > "$WORK/leaf.pem"
  # Trusting the leaf itself leaves only its dates and name to check, by exit code.
  valid=0
  [ -s "$WORK/leaf.pem" ] && openssl verify -partial_chain -trusted "$WORK/leaf.pem" -verify_hostname "$1" \
    "$WORK/leaf.pem" >/dev/null 2>&1 && valid=1
  echo "$(chain_of_pem "$WORK/ref.pem") $valid"
}

# --- in-process probes --------------------------------------------------------

# Python: connection 1 verifies with the context the app would use; connection 2
# doesn't verify and reads the chain. Prints one probe line per variant.
PYPROBE='
import hashlib, os, socket, ssl, sys
host, t, port = sys.argv[1], float(sys.argv[2]), int(os.environ.get("PORT", "443"))
BAD_SPKI, BAD_SKI = set(os.environ["BAD_SPKI"].split()), set(os.environ["BAD_SKI"].split())
def tlv(b, i):
    tag, n = b[i], b[i + 1]; i += 2
    if n & 0x80:
        k = n & 0x7F; n = int.from_bytes(b[i:i + k], "big"); i += k
    return tag, i, i + n
def kids(b, s, e):
    while s < e:
        t, cs, ce = tlv(b, s); yield t, s, cs, ce; s = ce
def fields(der):
    _, s, e = tlv(der, 0); _, s, e = tlv(der, s)
    f = list(kids(der, s, e))
    return f[1:] if f[0][0] == 0xA0 else f
def spki(der):
    _, i, _, e = fields(der)[5]
    return hashlib.sha256(der[i:e]).hexdigest().upper()
def aki(der):
    for t, _, s, e in fields(der)[6:]:
        if t != 0xA3: continue
        _, s, e = tlv(der, s)
        for _, _, xs, xe in kids(der, s, e):
            p = list(kids(der, xs, xe))
            if der[p[0][2]:p[0][3]] == bytes.fromhex("551d23"):
                v = der[p[-1][2]:p[-1][3]]; _, vs, ve = tlv(v, 0)
                for tt, _, cs, ce in kids(v, vs, ve):
                    if tt == 0x80: return v[cs:ce].hex().upper()
    return None
def chain():
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), t) as raw, ctx.wrap_socket(raw, server_hostname=host) as s:
            ders = [c if isinstance(c, bytes) else c.public_bytes(ssl.Encoding.DER) for c in s.get_unverified_chain()] \
                if hasattr(s, "get_unverified_chain") else [s.getpeercert(True)]
    except Exception:
        return "-"
    try:
        bad = any(spki(d) in BAD_SPKI for d in ders) or aki(ders[0]) in BAD_SKI
    except Exception:
        return "-"
    return "BAD" if bad else "OTHER"
TRUST = {int(x) for x in os.environ["TRUST_CODES"].split()}
def accept(cafile):
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    try:
        with socket.create_connection((host, port), t) as raw, ctx.wrap_socket(raw, server_hostname=host):
            return "ACCEPTED", ""
    except ssl.SSLCertVerificationError as e:
        return ("REJECTED" if e.verify_code in TRUST else "INVALID"), "verify-error-%s" % e.verify_code
    except Exception as e:
        return "ERROR", type(e).__name__
c = chain()
variants = [("python-ssl-default", None)]
try:
    import certifi
    variants.append(("python-certifi", certifi.where()))
except Exception:
    print("NOTE", host, "certifi-not-importable", "-", sys.executable)
for name, cafile in variants:
    r, d = accept(cafile)
    print(name, host, r, c, d or "-")
'

# Node and Bun: one connection with rejectUnauthorized off, so the chain is
# always readable; `authorized` is the default verification's own decision.
JSPROBE='
const tls = require("tls"), crypto = require("crypto");
const host = process.argv[process.argv.length - 1];
const BAD = new Set(process.env.BAD_SPKI.split(" ")), BADSKI = new Set(process.env.BAD_SKI.split(" "));
// Minimal DER walk for the leaf Authority Key Identifier (2.5.29.35).
function tlv(b, i) { let n = b[i + 1], j = i + 2; if (n & 0x80) { const k = n & 0x7f; n = 0; for (let q = 0; q < k; q++) n = n * 256 + b[j++]; } return [b[i], j, j + n]; }
function kids(b, s, e) { const out = []; while (s < e) { const t = tlv(b, s); out.push(t); s = t[2]; } return out; }
function aki(der) {
  let [, s, e] = tlv(der, 0); [, s, e] = tlv(der, s);
  let f = kids(der, s, e); if (f[0][0] === 0xa0) f = f.slice(1);
  for (const [t, cs, ce] of f.slice(6)) {
    if (t !== 0xa3) continue;
    const [, xs, xe] = tlv(der, cs);
    for (const [, es, ee] of kids(der, xs, xe)) {
      const p = kids(der, es, ee);
      if (Buffer.from(der.slice(p[0][1], p[0][2])).toString("hex") !== "551d23") continue;
      const v = der.slice(p[p.length - 1][1], p[p.length - 1][2]); const [, vs, ve] = tlv(v, 0);
      for (const [tt, a, z] of kids(v, vs, ve)) if (tt === 0x80) return Buffer.from(v.slice(a, z)).toString("hex").toUpperCase();
    }
  }
  return null;
}
const name = typeof Bun !== "undefined" ? "bun" : "node";
// CERT_REVOKED counts here: node and bun never fetch revocation data (no CRL is
// passed), so it can only come from a block compiled into the runtime, which
// is how fixed Node refuses these intermediates. Nothing on the path can fake it.
const TRUST = new Set(["CERT_REVOKED", "UNABLE_TO_GET_ISSUER_CERT", "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", "SELF_SIGNED_CERT_IN_CHAIN",
  "DEPTH_ZERO_SELF_SIGNED_CERT", "UNABLE_TO_VERIFY_LEAF_SIGNATURE", "CERT_UNTRUSTED", "CERT_REJECTED"]);
let finished = false;
// The first definitive verdict stands; later errors or timeouts are ignored.
const done = (r, c, d) => { if (finished) return; finished = true; console.log([name, host, r, c, d || "-"].join(" ")); process.exit(0); };
const s = tls.connect({ host, port: Number(process.env.PORT || 443), servername: host, rejectUnauthorized: false }, () => {
  let chain = "-";
  try {
    let c = s.getPeerCertificate(true), seen = new Set(), bad = false, n = 0;
    try { if (c && c.raw && BADSKI.has(aki(c.raw))) bad = true; } catch (e) {}
    while (c && c.raw && !seen.has(c.fingerprint256)) {
      seen.add(c.fingerprint256); n++;
      const der = new crypto.X509Certificate(c.raw).publicKey.export({ type: "spki", format: "der" });
      if (BAD.has(crypto.createHash("sha256").update(der).digest("hex").toUpperCase())) bad = true;
      c = c.issuerCertificate;
    }
    if (n > 0) chain = bad ? "BAD" : "OTHER";
  } catch (e) { chain = "-"; }
  const why = String(s.authorizationError && (s.authorizationError.code || s.authorizationError));
  done(s.authorized ? "ACCEPTED" : (TRUST.has(why) ? "REJECTED" : "INVALID"), chain, s.authorized ? "" : why);
});
s.setTimeout(Number(process.env.PROBE_T || 15) * 1000, () => done("ERROR", "-", "timeout"));
s.on("error", (e) => done("ERROR", "-", e.code || e.name));
'

# Ruby: verify with the default store, but let a verify callback record the
# result and continue, so the chain can be read either way.
RBPROBE='
require "socket"; require "openssl"; require "digest"
host = ARGV[0]; bad = ENV["BAD_SPKI"].split
ok = true
ctx = OpenSSL::SSL::SSLContext.new
ctx.set_params(verify_mode: OpenSSL::SSL::VERIFY_PEER)
ctx.verify_hostname = false
codes = []
# Record every verification error and carry on, so the chain can still be read.
ctx.verify_callback = proc { |pre, store| codes << store.error unless pre; ok &&= pre; true }
begin
  tcp = Socket.tcp(host, Integer(ENV["PORT"] || 443), connect_timeout: Integer(ENV["PROBE_T"] || 15))
  s = OpenSSL::SSL::SSLSocket.new(tcp, ctx); s.hostname = host; s.connect
  chain = "-"
  begin
    certs = s.peer_cert_chain || []
    fps = certs.map { |c| Digest::SHA256.hexdigest(c.public_key.public_to_der).upcase }
    leaf_aki = (certs.first.authority_key_identifier.unpack1("H*").upcase rescue nil)
    hit = fps.any? { |f| bad.include?(f) } || ENV["BAD_SKI"].split.include?(leaf_aki)
    chain = certs.empty? ? "-" : (hit ? "BAD" : "OTHER")
  rescue StandardError
    chain = "-"
  end
  trust = !codes.empty? && (codes - ENV["TRUST_CODES"].split.map(&:to_i)).empty?
  puts ["ruby", host, ok ? "ACCEPTED" : (trust ? "REJECTED" : "INVALID"), chain, ok ? "-" : "verify-errors-#{codes.uniq.join(",")}"].join(" ")
rescue StandardError => e
  puts ["ruby", host, "ERROR", "-", e.class.name].join(" ")
end
'

# Java: the default TrustManager decides; a wrapper records the chain it was
# given. Needs a JDK 11+ (source-file launch); with a bare JRE it reports ERROR.
JAVAPROBE='
import javax.net.ssl.*; import java.security.*; import java.security.cert.*; import java.util.*;
public class P {
  public static void main(String[] a) throws Exception {
    String host = a[0]; Set<String> bad = new HashSet<>(Arrays.asList(System.getenv("BAD_SPKI").split(" ")));
    TrustManagerFactory f = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    f.init((KeyStore) null);
    X509TrustManager d = null;
    for (TrustManager t : f.getTrustManagers()) if (t instanceof X509TrustManager) d = (X509TrustManager) t;
    final X509TrustManager def = d; final String[] chain = {"-"}; final boolean[] ok = {false}; final String[] why = {"-"};
    X509TrustManager rec = new X509TrustManager() {
      public void checkClientTrusted(X509Certificate[] c, String s) {}
      public void checkServerTrusted(X509Certificate[] c, String s) throws CertificateException {
        boolean b = false;
        try {
          for (X509Certificate x : c) {
            byte[] h = MessageDigest.getInstance("SHA-256").digest(x.getPublicKey().getEncoded());
            StringBuilder sb = new StringBuilder(); for (byte y : h) sb.append(String.format("%02X", y));
            if (bad.contains(sb.toString())) b = true;
          }
          if (c.length > 0) {
            byte[] ext = c[0].getExtensionValue("2.5.29.35");  // OCTET STRING { SEQUENCE { [0] keyid ... } }
            if (ext != null) {
              int i = 2; if ((ext[1] & 0x80) != 0) i += ext[1] & 0x7f;   // inside the OCTET STRING
              i += 2; if ((ext[i - 1] & 0x80) != 0) i += ext[i - 1] & 0x7f; // inside the SEQUENCE
              if ((ext[i] & 0xff) == 0x80) {
                int n = ext[i + 1]; StringBuilder k = new StringBuilder();
                for (int q = 0; q < n; q++) k.append(String.format("%02X", ext[i + 2 + q]));
                if (Arrays.asList(System.getenv("BAD_SKI").split(" ")).contains(k.toString())) b = true;
              }
            }
          }
          chain[0] = c.length > 0 ? (b ? "BAD" : "OTHER") : "-";
        } catch (Exception e) { chain[0] = "-"; }
        try { def.checkServerTrusted(c, s); ok[0] = true; } catch (CertificateException e) {
          // Only "no path to a trusted anchor" is a trust refusal; expiry and the rest are not.
          ok[0] = false; why[0] = "INVALID";
          for (Throwable x = e; x != null; x = x.getCause()) {
            if (x instanceof CertPathBuilderException) why[0] = "REJECTED";
            if (x instanceof CertificateExpiredException || x instanceof CertificateNotYetValidException) { why[0] = "INVALID"; break; }
          }
          throw e;
        }
      }
      public X509Certificate[] getAcceptedIssuers() { return def.getAcceptedIssuers(); }
    };
    SSLContext ctx = SSLContext.getInstance("TLS"); ctx.init(null, new TrustManager[]{rec}, null);
    try (SSLSocket s = (SSLSocket) ctx.getSocketFactory().createSocket()) {
      s.connect(new java.net.InetSocketAddress(host, Integer.parseInt(System.getenv().getOrDefault("PORT", "443"))), 15000); s.setSoTimeout(15000);
      SSLParameters p = s.getSSLParameters(); p.setServerNames(List.of(new SNIHostName(host))); s.setSSLParameters(p);
      s.startHandshake();
      System.out.println("java " + host + " " + (ok[0] ? "ACCEPTED" : why[0]) + " " + chain[0] + " -");
    } catch (Exception e) {
      if (!ok[0] && !why[0].equals("-")) System.out.println("java " + host + " " + why[0] + " " + chain[0] + " " + e.getClass().getSimpleName());
      else System.out.println("java " + host + (ok[0] ? " ACCEPTED " : " ERROR ") + chain[0] + " " + e.getClass().getSimpleName());
    }
  }
}
'
# macOS ships a /usr/bin/java stub that only says no JRE is installed. Only
# that stub is skipped: any other java that fails to start is still reported.
if have java && ! { [ "$(uname -s)" = Darwin ] && [ "$(command -v java)" = /usr/bin/java ] &&
                    ! /usr/libexec/java_home >/dev/null 2>&1; }; then
  printf '%s' "$JAVAPROBE" > "$WORK/P.java"
fi

probe_curl() {
  # First line: the TLS library's verify code (OpenSSL builds); then the chain.
  if curl -sS -o /dev/null --max-time "$T" -w '%{ssl_verify_result}\n%{certs}' "https://$1:$PORT/" > "$WORK/curl.out" 2>/dev/null; then rc=0; else rc=$?; fi
  code=$(head -1 "$WORK/curl.out" | tr -dc '0-9')
  sed 1d "$WORK/curl.out" > "$WORK/curl.pem"
  if grep -q 'BEGIN CERTIFICATE' "$WORK/curl.pem"; then c=$(chain_of_pem "$WORK/curl.pem"); else c=-; fi
  case $rc in
    0) echo "curl $1 ACCEPTED $c -" ;;
    60) case " $TRUST_CODES " in
          *" ${code:-x} "*) echo "curl $1 REJECTED $c exit-60-verify-$code" ;;
          *) if [ "${code:-0}" = 0 ]; then echo "curl $1 REFUSED $c exit-60"; else echo "curl $1 INVALID $c exit-60-verify-$code"; fi ;;
        esac ;;
    *) echo "curl $1 ERROR $c exit-$rc" ;;
  esac
}

probe_wget() {
  # GNU wget: 0 or 8 (an HTTP error status) means the handshake was accepted,
  # 5 means TLS verification failed. busybox wget exits 1 for everything, so
  # anything but 0 is an ERROR there.
  if wget --version 2>/dev/null | grep -q 'GNU Wget'; then gnu=1; else gnu=0; fi
  to wget -q -O /dev/null -T "$T" -t 1 "https://$1:$PORT/" >/dev/null 2>&1; rc=$?
  case "$gnu:$rc" in
    *:0|1:8) echo "wget $1 ACCEPTED - -" ;;
    1:5) echo "wget $1 REFUSED - exit-5" ;;
    *) echo "wget $1 ERROR - exit-$rc" ;;
  esac
}

probe_deno() {
  out=$(to deno eval --quiet "
    const h = '$1';
    try { const c = await Deno.connectTls({ hostname: h, port: $PORT }); await c.handshake(); c.close(); console.log('ACCEPTED'); }
    catch (e) { console.log(e instanceof Deno.errors.InvalidData ? 'REJECTED' : 'ERROR'); }" 2>/dev/null | tail -1)
  case "$out" in
    ACCEPTED) echo "deno $1 ACCEPTED - -" ;;
    REJECTED) echo "deno $1 REFUSED - InvalidData" ;;
    *) echo "deno $1 ERROR - ${out:-no-output}" ;;
  esac
}

run_clients() {
  : > "$WORK/expected"
  have "$PY" && { echo python-ssl-default >> "$WORK/expected"; to "$PY" -c "$PYPROBE" "$1" "$T" 2>/dev/null; }
  have "$NODE" && { echo node >> "$WORK/expected"; to "$NODE" -e "$JSPROBE" "$1" 2>/dev/null; }
  have bun && { echo bun >> "$WORK/expected"; to bun -e "$JSPROBE" "$1" 2>/dev/null; }
  have ruby && { echo ruby >> "$WORK/expected"; to ruby -e "$RBPROBE" "$1" 2>/dev/null; }
  [ -f "$WORK/P.java" ] && { echo java >> "$WORK/expected"; to java "$WORK/P.java" "$1" 2>/dev/null | grep '^java ' || echo "java $1 ERROR - needs-JDK-11+"; }
  have curl && { echo curl >> "$WORK/expected"; probe_curl "$1"; }
  have wget && { echo wget >> "$WORK/expected"; probe_wget "$1"; }
  have deno && { echo deno >> "$WORK/expected"; probe_deno "$1"; }
}

echo "== compromised chains"
: > "$WORK/results"
for h in $HOSTS; do
  set -- $(ref_openssl "$h")
  ref=$1 refvalid=$2
  run_clients "$h" > "$WORK/lines"
  # If openssl couldn't read the chain, use what python or node saw.
  if [ "$ref" = - ]; then
    ref=$(awk '$4 == "BAD" || $4 == "OTHER" { print $4; exit }' "$WORK/lines")
    [ -n "$ref" ] || ref=-
  fi
  [ "$ref" = BAD ] && [ "$refvalid" != 1 ] && \
    echo "WARNING: the test leaf for $h is not valid right now for that name (expired, not yet valid, wrong clock?): refusals of unknown reason can't count"
  while read -r client host result chain detail; do
    if [ "$client" = NOTE ]; then
      echo "NOTE         python certifi not importable by $detail; if the app uses certifi, set PROBE_PYTHON to its interpreter"
      continue
    fi
    own=1
    if [ "$chain" = - ]; then chain=$ref; own=0; fi
    # A client that honours proxy variables and showed no chain of its own may
    # have refused the proxy's certificate, not the test host's.
    if [ "$own" = 0 ] && [ "$PROXIED" = 1 ] && [ "$result" != ACCEPTED ]; then
      case $client in curl|wget) result=PROXIED ;; esac
    fi
    case "$result:$chain" in
      ACCEPTED:BAD) v="VULNERABLE   $client accepted $host" ;;
      ACCEPTED:OTHER) v="INCONCLUSIVE $client accepted $host, but the chain was re-signed on the path (TLS inspection?)" ;;
      ACCEPTED:*) v="VULNERABLE   $client accepted $host; its chain could not be read, so this is not ruled out" ;;
      REJECTED:BAD) v="ok           $client refused $host as untrusted ($detail)" ;;
      REFUSED:BAD)
        if [ "$refvalid" = 1 ]; then v="ok           $client refused $host ($detail; the leaf is valid, so the refusal is about trust)"
        else v="INCONCLUSIVE $client refused $host, but it gives no reason and the leaf is not shown valid ($detail)"; fi ;;
      INVALID:*) v="INCONCLUSIVE $client refused $host for a reason other than trust ($detail): expired leaf, clock, hostname or revocation" ;;
      PROXIED:*) v="INCONCLUSIVE $client goes through a proxy and showed no chain, so it may have refused the proxy, not $host ($detail)" ;;
      REJECTED:*|REFUSED:*) v="INCONCLUSIVE $client refused $host, but the chain it saw was not the test host's ($detail)" ;;
      *) v="INCONCLUSIVE $client could not complete a handshake with $host ($detail)" ;;
    esac
    echo "$v" | tee -a "$WORK/results"
  done < "$WORK/lines"
  # An installed client that printed nothing was not tested.
  while read -r want; do
    grep -q "^$want " "$WORK/lines" || echo "INCONCLUSIVE $want is installed but produced no result for $h" | tee -a "$WORK/results"
  done < "$WORK/expected"
done

clients=$(awk '{print $2}' "$WORK/results" | sort -u | tr '\n' ' ')
nv=$(grep -c '^VULNERABLE' "$WORK/results")
ni=$(grep -c '^INCONCLUSIVE' "$WORK/results")
nok=$(grep -c '^ok' "$WORK/results")
echo "== summary: ${nv} vulnerable, ${ni} inconclusive, ${nok} ok; clients tested: ${clients:-none}"
if [ "$nv" -gt 0 ]; then exit 1; fi
if [ "$ni" -gt 0 ] || [ "$nok" -eq 0 ]; then
  echo "   Not a pass: some results could not be proven. Re-run where egress reaches the test hosts directly."
  exit 2
fi
exit 0
