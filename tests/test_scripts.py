#!/usr/bin/env python3
"""Part of the emudhra-ca-remediation skill: tests for its scripts.

Every test asserts on exit codes and verdicts, and most build the affected
certificates on the fly from the public keys in emudhra_certs.py, so no copy
of a compromised certificate is kept in the repository (a scanner run over it
would rightly flag one). The certificates are not validly signed; the tools
decide by public key, so they don't need to be.

    python3 tests/test_scripts.py            # PyYAML needed for the YAML cases
    python3 tests/test_scripts.py -k Probe   # only the TLS probe (needs openssl)
"""

import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.join(os.path.dirname(HERE), "skills", "emudhra-ca-remediation", "scripts")
sys.path.insert(0, SCRIPTS)
import emudhra_certs as E  # noqa: E402

OID_EC = "2a8648ce3d0201"
OID_P384 = "2b81040022"
OID_RSA = "2a864886f70d010101"
OID_ECDSA_SHA256 = "2a8648ce3d040302"


def der(tag, body):
    n = len(body)
    if n < 0x80:
        head = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        head = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + head + body


def seq(*parts):
    return der(0x30, b"".join(parts))


def spki_for(key):
    """SubjectPublicKeyInfo around a raw public key from emudhra_certs."""
    if len(key) == 97:  # uncompressed P-384 point
        alg = seq(der(0x06, bytes.fromhex(OID_EC)), der(0x06, bytes.fromhex(OID_P384)))
    else:
        alg = seq(der(0x06, bytes.fromhex(OID_RSA)), b"\x05\x00")
    return seq(alg, der(0x03, b"\x00" + key))


def make_cert(spki, cn, ski=None, aki=None):
    name = seq(der(0x31, seq(der(0x06, bytes.fromhex("550403")), der(0x0C, cn.encode()))))
    exts = []
    if ski:
        exts.append(seq(der(0x06, bytes.fromhex("551d0e")), der(0x04, der(0x04, ski))))
    if aki:
        exts.append(seq(der(0x06, bytes.fromhex("551d23")), der(0x04, seq(der(0x80, aki)))))
    sig = seq(der(0x06, bytes.fromhex(OID_ECDSA_SHA256)))
    tbs = seq(der(0xA0, der(0x02, b"\x02")), der(0x02, os.urandom(8)), sig, name,
              seq(der(0x17, b"260101000000Z"), der(0x17, b"361231000000Z")), name, spki,
              *([der(0xA3, seq(*exts))] if exts else []))
    return seq(tbs, sig, der(0x03, b"\x00" + os.urandom(16)))


def pem(ders):
    out = b""
    for d in ders:
        b = base64.b64encode(d)
        out += b"-----BEGIN CERTIFICATE-----\n" + b"\n".join(b[i:i + 64] for i in range(0, len(b), 64)) \
            + b"\n-----END CERTIFICATE-----\n"
    return out


KEYS = {name: key for key, name in E.BAD_PUBLIC_KEYS.items()}
BAD_ROOT = make_cert(spki_for(KEYS["emSign ECC Root CA - G3"]), "emSign ECC Root CA - G3")
AAA_ROOT = make_cert(spki_for(KEYS["AAA Certificate Services"]), "AAA Certificate Services")
BAD_INT = make_cert(spki_for(KEYS["EM DV TLS CA - G3B"]), "EM DV TLS CA - G3B",
                    ski=bytes.fromhex("E21E2FE71C19390E554B62C120245735248A2514"))
CLEAN = [make_cert(spki_for(b"\x04" + os.urandom(96)), "Clean Root %d" % i) for i in range(3)]


def jks(entries):
    """A JKS keystore of trusted-certificate entries [(alias, der)]."""
    out = b"\xfe\xed\xfe\xed" + (2).to_bytes(4, "big") + len(entries).to_bytes(4, "big")
    for alias, d in entries:
        out += (2).to_bytes(4, "big") + len(alias).to_bytes(2, "big") + alias.encode() + b"\x00" * 8
        out += (5).to_bytes(2, "big") + b"X.509" + len(d).to_bytes(4, "big") + d
    return out + hashlib.sha1(out).digest()


def working_keytool():
    """keytool, if it runs. macOS ships a /usr/bin/keytool stub that fails without a JDK."""
    kt = shutil.which("keytool")
    try:
        ok = kt and subprocess.run([kt, "-help"], capture_output=True, timeout=60).returncode == 0
    except (OSError, subprocess.SubprocessError):
        ok = False
    return kt if ok else None


def run(script, *args, env=None, cwd=None, timeout=300):
    cmd = ([sys.executable, os.path.join(SCRIPTS, script)] if script.endswith(".py")
           else ["sh", os.path.join(SCRIPTS, script)]) + list(args)
    e = dict(os.environ, **(env or {}))
    r = subprocess.run(cmd, capture_output=True, text=True, env=e, cwd=cwd, timeout=timeout)
    return r.returncode, r.stdout + r.stderr


class Tmp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="emudhra-test-")
        self.addCleanup(shutil.rmtree, self.dir, True)

    def write(self, rel, data):
        p = os.path.join(self.dir, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb" if isinstance(data, bytes) else "w") as f:
            f.write(data)
        return p


class Constants(unittest.TestCase):
    def test_keys_match_fingerprints(self):
        hashes = {hashlib.sha256(spki_for(k)).hexdigest().upper() for k in E.BAD_PUBLIC_KEYS}
        self.assertEqual(hashes, set(E.BAD_SPKIS))
        for k, name in E.BAD_PUBLIC_KEYS.items():
            self.assertEqual(E.BAD_SPKIS[hashlib.sha256(spki_for(k)).hexdigest().upper()], name)

    def test_shell_lists_match(self):
        with open(os.path.join(SCRIPTS, "probe_runtime.sh")) as f:
            src = f.read()
        spki = set(re.search(r'^BAD_SPKI="([^"]*)"', src, re.M).group(1).split())
        ski = set(re.search(r'^BAD_SKI="([^"]*)"', src, re.M).group(1).split())
        self.assertEqual(spki, set(E.BAD_INTERMEDIATES))
        self.assertEqual(ski, set(E.BAD_INTERMEDIATE_SKIS))

    def test_classify(self):
        self.assertEqual(E.classify(BAD_ROOT), ("root", "emSign ECC Root CA - G3"))
        self.assertEqual(E.classify(BAD_INT)[0], "intermediate")
        self.assertEqual(E.classify(CLEAN[0]), (None, None))
        leaf = make_cert(spki_for(b"\x04" + os.urandom(96)), "leaf",
                         aki=bytes.fromhex("E21E2FE71C19390E554B62C120245735248A2514"))
        self.assertTrue(E.chain_is_compromised([leaf]))
        self.assertFalse(E.chain_is_compromised([CLEAN[0], CLEAN[1]]))

    def test_pem_variants(self):
        text = pem([BAD_ROOT]).replace(b"\n", b"\\n")  # as inside a JSON string
        self.assertEqual(E.pem_certificates(text), [BAD_ROOT])
        payloads = E.base64_payloads(base64.b64encode(pem([BAD_ROOT])))
        self.assertTrue(any(E.pem_certificates(p) == [BAD_ROOT] for p in payloads))
        with self.assertRaises(E.DERError):
            E.pem_certificates(b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----")


class KeychainPems(Tmp):
    def test_pinned_list(self):
        stems = set(E.KEYCHAIN_DENY.values())
        self.assertEqual(len(E.KEYCHAIN_DENY), 19)
        self.assertEqual(len([x for x in stems if x.startswith("em-")]), 16)
        self.assertFalse(any("aaa-certificate" in x for x in stems))

    def test_only_pinned_certificates_are_written(self):
        real = dict(E.KEYCHAIN_DENY)
        self.addCleanup(lambda: (E.KEYCHAIN_DENY.clear(), E.KEYCHAIN_DENY.update(real)))
        E.KEYCHAIN_DENY.clear()
        E.KEYCHAIN_DENY.update({E.cert_sha256(BAD_ROOT): "root", E.cert_sha256(BAD_INT): "int"})
        # A substitute with the same key but different bytes is not the pinned certificate.
        swapped = make_cert(spki_for(KEYS["emSign ECC Root CA - G3"]), "emSign ECC Root CA - G3")
        feed = self.write("feed.json", json.dumps([{"pem": pem([swapped]).decode()},
                                                   {"pem": pem([BAD_INT]).decode()}, {"pem": pem([CLEAN[0]]).decode()}]))
        out = os.path.join(self.dir, "a")
        os.makedirs(out)
        self.assertEqual(E.keychain_pems(out, [feed]), ["root"])
        self.assertEqual(os.listdir(out), [])
        good = self.write("roots.pem", pem([BAD_ROOT]))
        self.assertEqual(E.keychain_pems(out, [feed, good]), [])
        self.assertEqual(sorted(os.listdir(out)), ["int.pem", "root.pem"])
        with open(os.path.join(out, "root.pem"), "rb") as f:
            self.assertEqual(E.pem_certificates(f.read()), [BAD_ROOT])

    def test_cli_fails_closed(self):
        out = os.path.join(self.dir, "deny")
        self.assertEqual(run("emudhra_certs.py", "--keychain-pems", out, self.write("c.pem", pem(CLEAN)))[0], 2)
        self.assertEqual(os.listdir(out), [])
        self.write("deny/old.pem", pem(CLEAN))
        self.assertEqual(run("emudhra_certs.py", "--keychain-pems", out, os.path.join(self.dir, "c.pem"))[0], 2)
        self.assertEqual(run("emudhra_certs.py")[0], 2)
        code, out = run("emudhra_certs.py", "--keychain-pems", os.path.join(self.dir, "c.pem", "x"), out)
        self.assertEqual(code, 2, out)
        self.assertNotIn("Traceback", out)


class TrustStore(Tmp):
    def check(self, *paths):
        return run("trust_store.py", *paths)

    def test_pem(self):
        self.assertEqual(self.check(self.write("bad.pem", pem(CLEAN + [AAA_ROOT])))[0], 1)
        self.assertEqual(self.check(self.write("ok.pem", pem(CLEAN)))[0], 0)

    def test_der_and_jks(self):
        self.assertEqual(self.check(self.write("r.der", BAD_INT))[0], 1)
        self.assertEqual(self.check(self.write("bad.jks", jks([("a", CLEAN[0]), ("emsign", BAD_ROOT)])))[0], 1)
        self.assertEqual(self.check(self.write("ok.jks", jks([("a", CLEAN[0])])))[0], 0)

    def test_unreadable_is_never_clean(self):
        for name, data in (("empty.pem", b""), ("junk.p12", b"\x30\x03\x02\x01\x00"), ("text.txt", b"hello")):
            code, out = self.check(self.write(name, data))
            self.assertEqual(code, 2, out)
        self.assertEqual(self.check(os.path.join(self.dir, "missing.pem"))[0], 2)

    def test_directory(self):
        self.write("d/a.pem", pem(CLEAN))
        self.write("d/README", "notes")
        self.assertEqual(self.check(os.path.join(self.dir, "d"))[0], 0)
        self.write("d/b.crt", pem([BAD_ROOT]))
        self.assertEqual(self.check(os.path.join(self.dir, "d"))[0], 1)

    def test_directory_with_unreadable_store(self):
        self.write("e/a.pem", pem(CLEAN))
        self.write("e/broken.jks", b"\xfe\xed\xfe\xed\x00\x00\x00\x09")
        code, out = self.check(os.path.join(self.dir, "e"))
        self.assertEqual(code, 2, out)

    def test_key_in_unparsed_bytes(self):
        # Not a store format, but it carries the root's key: VULNERABLE, not ERROR.
        p = self.write("blob.bin", b"\x00" * 64 + KEYS["emSign Root TLS CA - G3"] + b"\x00" * 64)
        self.assertEqual(self.check(p)[0], 1)

    def test_filter(self):
        src = self.write("mixed.pem", pem(CLEAN + [BAD_ROOT, AAA_ROOT]))
        out = os.path.join(self.dir, "fixed.pem")
        run("trust_store.py", "--filter", out, src)
        self.assertEqual(self.check(out)[0], 0)
        with open(out, "rb") as f:
            self.assertEqual(len(E.pem_certificates(f.read())), len(CLEAN))

    @unittest.skipUnless(shutil.which("openssl"), "needs openssl")
    def test_java_options_trust_store(self):
        store = self.write("custom.pem", pem([BAD_ROOT]))
        code, out = run("trust_store.py", "java", env={"PATH": self.dir, "JAVA_HOME": "",
                                                       "JAVA_TOOL_OPTIONS": "-Djavax.net.ssl.trustStore=%s" % store})
        self.assertEqual(code, 1, out)
        self.assertIn("custom.pem", out)

    def test_image_root_named_targets(self):
        fs = os.path.join(self.dir, "fs")
        self.write("fs/etc/ssl/certs/ca-certificates.crt", pem(CLEAN))
        self.write("fs/usr/lib/jvm/j/lib/server/libjvm.so", b"\x7fELF")
        self.write("fs/usr/lib/jvm/j/lib/security/cacerts", jks([("ok", CLEAN[0])]))
        big = self.write("fs/usr/lib/jvm/j/lib/modules", b"")
        with open(big, "wb") as f:  # a JDK jimage is larger than any store
            f.seek(70 << 20)
            f.write(b"\x00")
        code, out = run("trust_store.py", "--root", fs, "system", "java", "python")
        self.assertEqual(code, 0, out)
        self.assertIn("NONE", out)
        self.assertEqual(run("trust_store.py", "--root", fs, os.path.join(fs, "usr/lib/jvm"))[0], 0)
        self.write("fs/usr/lib/jvm/j/lib/security/jssecacerts", jks([("emsign", BAD_ROOT)]))
        code, out = run("trust_store.py", "--root", fs, "java")
        self.assertEqual(code, 1, out)
        # On a Mac, "system" under --root is still the image's bundle.
        os.remove(os.path.join(fs, "usr/lib/jvm/j/lib/security/jssecacerts"))
        code = ("import sys, runpy; sys.platform = 'darwin'; sys.argv = ['trust_store.py', '--root', %r, 'system']; "
                "runpy.run_path(%r, run_name='__main__')" % (fs, os.path.join(SCRIPTS, "trust_store.py")))
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_certifi_where_is_followed(self):
        bundle = self.write("system-bundle.pem", pem(CLEAN))
        self.write("site/certifi/__init__.py", "def where():\n    return %r\n" % bundle)
        code, out = run("trust_store.py", sys.executable, env={"PYTHONPATH": os.path.join(self.dir, "site")})
        self.assertIn("CLEAN      " + bundle, out)

    def test_keytool_listing_pairs_aliases(self):
        import trust_store as T
        listing = (b"Alias name: emsigneccrootcag3\nEntry type: trustedCertEntry\n\n" + pem([BAD_ROOT]) +
                   b"\nAlias name: server\nEntry type: PrivateKeyEntry\nCertificate chain length: 1\n" + pem([AAA_ROOT]))
        got = T.keytool_entries(listing, E.pem_certificates(listing))
        self.assertEqual([(a, t) for _, a, t in got], [("emsigneccrootcag3", True), ("server", False)])
        self.assertIsNone(T.keytool_entries(pem([BAD_ROOT]), [BAD_ROOT]))

    def test_delete_keeps_a_backup_and_hides_the_password(self):
        kt = working_keytool()
        if not kt:
            self.skipTest("no working keytool")
        store = os.path.join(self.dir, "cacerts")
        for alias, d in (("clean", CLEAN[0]), ("emsign", BAD_ROOT)):
            r = subprocess.run([kt, "-importcert", "-noprompt", "-alias", alias, "-file", self.write(alias + ".der", d),
                                "-keystore", store, "-storetype", "PKCS12", "-storepass", "s3cret-pw"],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        code, out = run("trust_store.py", "--delete", store, env={"STOREPASS": "s3cret-pw"})
        self.assertEqual(code, 0, out)
        backups = [f for f in os.listdir(self.dir) if f.startswith("cacerts.bak-")]
        self.assertEqual(len(backups), 1, out)
        self.assertIn("backup at", out)
        self.assertEqual(run("trust_store.py", os.path.join(self.dir, backups[0]), env={"STOREPASS": "s3cret-pw"})[0], 1)
        self.assertEqual(run("trust_store.py", store, env={"STOREPASS": "s3cret-pw"})[0], 0)
        with open(os.path.join(SCRIPTS, "trust_store.py")) as f:
            self.assertNotIn('"-storepass", pw', f.read())

    def test_delete_no_backup(self):
        kt = working_keytool()
        if not kt:
            self.skipTest("no working keytool")
        store = os.path.join(self.dir, "cacerts")
        r = subprocess.run([kt, "-importcert", "-noprompt", "-alias", "emsign", "-file", self.write("r.der", BAD_ROOT),
                            "-keystore", store, "-storetype", "PKCS12", "-storepass", "changeit"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        code, out = run("trust_store.py", "--delete", "--no-backup", store)
        self.assertEqual(code, 0, out)
        self.assertEqual([f for f in os.listdir(self.dir) if ".bak-" in f], [])

    def test_pkcs12_passwordless(self):
        src = self.write("c.pem", pem([CLEAN[0], BAD_ROOT]))
        p12 = os.path.join(self.dir, "s.p12")
        r = subprocess.run(["openssl", "pkcs12", "-export", "-nokeys", "-in", src, "-out", p12, "-passout", "pass:",
                            "-certpbe", "NONE", "-keypbe", "NONE", "-nomac"], capture_output=True)
        if r.returncode:
            self.skipTest("this openssl cannot write a password-less PKCS12: %s" % r.stderr[:200])
        code, out = self.check(p12)
        self.assertEqual(code, 1, out)
        # localKeyId with no key bag in the file: still an anchor.
        import trust_store as T
        data = open(p12, "rb").read()
        self.assertTrue(all(anchor for _, _, anchor in T.read_pkcs12(data)), T.read_pkcs12(data))
        # With a key bag in plain SafeContents, the key's own certificate is not
        # an anchor, and the other certificates still are.
        key = os.path.join(self.dir, "k.pem")
        leaf = os.path.join(self.dir, "leaf.pem")
        r = subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=t", "-days", "1",
                            "-keyout", key, "-out", leaf], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        p12k = os.path.join(self.dir, "k.p12")
        r = subprocess.run(["openssl", "pkcs12", "-export", "-inkey", key, "-in", leaf, "-certfile", src, "-out", p12k,
                            "-passout", "pass:", "-certpbe", "NONE", "-keypbe", "NONE", "-nomac"], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        code, out = self.check(p12k)
        self.assertEqual(code, 1, out)


class ScanRepo(Tmp):
    def scan(self, *extra):
        code, out = run("scan_repo.py", "--json", self.dir, *extra)
        try:
            data = json.loads(out[out.index("{"):])
        except ValueError:
            self.fail(out)
        self.assertEqual(code, data["exit"])
        return code, data["findings"]

    def has(self, rows, status, component, version=None):
        return any(r["status"] == status and r["component"].startswith(component)
                   and (version is None or r["version"] == version) for r in rows)

    def test_nothing_recognised_is_an_error(self):
        self.write("README.md", "hello")
        self.assertEqual(self.scan()[0], 2)

    def test_fixed_pins_pass(self):
        self.write("requirements.txt", "certifi==2026.10.19\nrequests==2.32.0\n")
        self.write(".nvmrc", "22.23.4\n")
        code, rows = self.scan()
        self.assertEqual(code, 0, rows)

    def test_versions(self):
        self.write("requirements.txt", "certifi==2026.10.18 --hash=sha256:00\npip<26.2.2\nuv>=0.10\n")
        self.write(".tool-versions", "nodejs 20.11.0\n")
        code, rows = self.scan()
        self.assertEqual(code, 1)
        self.assertTrue(self.has(rows, "VULNERABLE", "certifi", "2026.10.18"))
        self.assertTrue(self.has(rows, "VULNERABLE", "pip"))
        self.assertTrue(self.has(rows, "REVIEW", "uv"))
        self.assertTrue(self.has(rows, "VULNERABLE", "node", "20.11.0"))

    def test_certificates_by_bytes(self):
        self.write("bundle.js", "module.exports = %s;\n" % json.dumps(pem(CLEAN + [BAD_ROOT]).decode()))
        self.write("k8s/secret.yaml", "kind: Secret\ndata:\n  ca.crt: %s\n" % base64.b64encode(pem([AAA_ROOT])).decode())
        self.write("bin/app", b"\x7fELF" + b"\x00" * 100 + KEYS["EM OV TLS CA - G3C"] + b"\x00" * 100)
        self.write("certs/clean.pem", pem(CLEAN))
        code, rows = self.scan()
        self.assertEqual(code, 1)
        flagged = {r["path"].replace(os.sep, "/") for r in rows if r["status"] == "VULNERABLE"}
        self.assertTrue({"bundle.js", "k8s/secret.yaml", "bin/app"} <= flagged, rows)
        self.assertTrue(self.has(rows, "INFO", "certificates"))

    def test_parse_errors_are_errors(self):
        self.write("package.json", "{not json")
        self.write("Cargo.lock", "[[package]\nname=")
        code, rows = self.scan()
        self.assertEqual(code, 2)
        self.assertEqual(sum(r["status"] == "ERROR" for r in rows), 2, rows)

    def test_dockerfile(self):
        self.write("Dockerfile", "ARG V=22.20.0\nFROM node:${V}-alpine AS build\nRUN npm ci \\\n && npx pkg .\n"
                                 "FROM $NOPE\nFROM python:3.12\nCOPY --from=build /a /a\n")
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "VULNERABLE", "node (image tag)", "22.20.0-alpine"))
        self.assertTrue(self.has(rows, "REVIEW", "image (FROM)", "$NOPE"))
        self.assertTrue(self.has(rows, "REVIEW", "pip in image"))
        self.assertTrue(self.has(rows, "REVIEW", "node single-executable"))

    def test_electron_resolution(self):
        self.write("app/package.json", json.dumps({"devDependencies": {"electron": "^42.0.0"}}))
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "REVIEW", "electron"))
        self.write("app/package-lock.json", json.dumps({"packages": {"node_modules/electron": {"version": "42.1.0"}}}))
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "VULNERABLE", "electron", "42.1.0"))
        self.write("app/yarn.lock", 'electron@^42.0.0:\n  version "42.11.16"\n')
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "FIXED", "electron", "42.11.16"))

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "needs PyYAML")
    def test_workflow(self):
        self.write(".github/workflows/ci.yml", """
jobs:
  t:
    strategy: {matrix: {node: [20, 24.22.1]}}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4
        with: {node-version: "${{ matrix.node }}"}
      - uses: actions/setup-go@v5
      - run: pip install certifi==2025.1.1
  g: !reference [.a, b]
""")
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "VULNERABLE", "node (setup-node)", "20"))
        self.assertTrue(self.has(rows, "FIXED", "node (setup-node)", "24.22.1"))
        self.assertTrue(self.has(rows, "REVIEW", "actions/setup-go"))
        self.assertTrue(self.has(rows, "VULNERABLE", "certifi", "2025.1.1"))

    @unittest.skipUnless(importlib.util.find_spec("yaml"), "needs PyYAML")
    def test_hosted_runner_and_setup_node_cache(self):
        self.write(".github/workflows/ci.yml", """
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-node@v4
        with: {node-version: "24"}
""")
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "REVIEW", "hosted runner"), rows)
        self.assertTrue(self.has(rows, "VULNERABLE", "node (setup-node)", "24"), rows)
        self.write(".github/workflows/ci.yml", """
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - run: sudo apt-get update && sudo apt-get install -y --only-upgrade ca-certificates
      - uses: actions/setup-node@v4
        with: {node-version: "24", check-latest: true}
""")
        code, rows = self.scan()
        self.assertFalse(self.has(rows, "REVIEW", "hosted runner"), rows)
        self.assertTrue(self.has(rows, "REVIEW", "node (setup-node)", "24"), rows)
        # Judged per job: a matrix runs-on, and an upgrade in another (container) job.
        self.write(".github/workflows/ci.yml", """
jobs:
  lint:
    runs-on: ubuntu-latest
    container: debian:12
    steps:
      - run: apt-get update && apt-get install -y ca-certificates git
  test:
    strategy:
      matrix:
        os: [macos-latest, ubuntu-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v5
  mac:
    runs-on: [macos-latest]
    steps:
      - uses: actions/checkout@v5
""")
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "REVIEW", "hosted runner (job test)"), rows)
        self.assertTrue(self.has(rows, "REVIEW", "hosted runner (job lint)"), rows)
        self.assertFalse(self.has(rows, "REVIEW", "hosted runner (job mac)"), rows)
        # No apt-get update first: the stale index installs nothing.
        self.write(".github/workflows/ci.yml", "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
                   "      - run: sudo apt-get install -y --only-upgrade ca-certificates\n")
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "REVIEW", "hosted runner (job t)"), rows)
        self.write(".github/workflows/ci.yml", "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n"
                   "      - run: sudo apt-get update && sudo apt-get install -y ca-certificates-java\n")
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "REVIEW", "hosted runner (job t)"), rows)

    def test_version_variables_and_downloads(self):
        self.write("pins.env", "CLAUDE_CODE_VERSION=2.1.239\nNODE_VERSION=24.22.1\n")
        self.write("Dockerfile", "FROM debian:bookworm\nARG BUN_VERSION=1.3.14\n"
                   "RUN curl -fsSL https://example.invalid/install.sh | bash\n"
                   "RUN curl -LO https://github.com/o/r/releases/download/v1/tool.tar.gz\n")
        self.write(".github/workflows/b.yml", "jobs:\n  b:\n    runs-on: self-hosted\n    steps:\n"
                   "      - uses: docker/setup-buildx-action@v3\n")
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "VULNERABLE", "claude-code", "2.1.239"), rows)
        self.assertTrue(self.has(rows, "VULNERABLE", "bun"), rows)
        self.assertTrue(self.has(rows, "REVIEW", "script piped to a shell"), rows)
        self.assertTrue(self.has(rows, "REVIEW", "binary downloaded at build time"), rows)
        self.assertTrue(any(r["status"] == "REVIEW" and "setup-buildx" in r["component"] + r["version"] + r["detail"]
                            for r in rows), rows)

    def test_go_tools_copied_and_templated_terraform_images(self):
        self.write("Dockerfile", "FROM python:3.13\nCOPY --from=hashicorp/terraform:1.9.5 /bin/terraform /usr/local/bin/\n")
        self.write("infra/main.tf", 'resource "x" "y" {\n  image = var.image\n}\n'
                   'resource "x" "z" {\n  image = "${var.repo}:1.2"\n}\n'
                   'locals {\n  defs = <<EOF\n[{"image": "node:20.1.0"}]\nEOF\n}\n')
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "REVIEW", "Go-built image (COPY --from)"), rows)
        self.assertTrue(self.has(rows, "REVIEW", "image (terraform image)", "var.image"), rows)
        self.assertTrue(self.has(rows, "REVIEW", "image (terraform image)", "${var.repo}:1.2"), rows)
        self.assertTrue(self.has(rows, "VULNERABLE", "node (image tag)", "20.1.0"), rows)

    def test_more_sources(self):
        self.write("tool.py", '# /// script\n# dependencies = ["certifi==2025.1.1"]\n# ///\nprint(1)\n')
        self.write("infra/main.tf", 'resource "x" "y" {\n  image = "node:20.1.0"\n}\n')
        self.write(".devcontainer/devcontainer.json", '{"image": "golang:1.25.1"}')
        self.write("pyproject.toml", '[project]\nname = "x"\ndependencies = ["certifi>=2026.10.19"]\n')
        self.write("Dockerfile", "FROM python:3.13\nENV PIP_CERT=/etc/ssl/certs/ca-certificates.crt\n")
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "VULNERABLE", "certifi", "2025.1.1"), rows)
        self.assertTrue(self.has(rows, "VULNERABLE", "node (image tag)", "20.1.0"), rows)
        self.assertTrue(self.has(rows, "VULNERABLE", "go toolchain (image tag)", "1.25.1"), rows)
        self.assertTrue(self.has(rows, "FIXED", "certifi", ">=2026.10.19"), rows)
        self.assertTrue(self.has(rows, "REVIEW", "pip in image"), rows)

    def test_missing_yaml_parser_is_an_error(self):
        self.write("compose.yaml", "services:\n  a:\n    image: node:22.1.0\n")
        code = (
            "import sys, runpy; sys.modules['yaml'] = None; sys.argv = ['scan_repo.py', %r]; "
            "runpy.run_path(%r, run_name='__main__')" % (self.dir, os.path.join(SCRIPTS, "scan_repo.py")))
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        # The fallback still finds the vulnerable image, and the parser gap is an ERROR row.
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("PyYAML", r.stdout)


    def test_utf16_and_archives(self):
        self.write("requirements.txt", "certifi==2026.1.1\n".encode("utf-16"))
        self.write("notes.txt", pem([BAD_ROOT]).decode().encode("utf-16-le"))
        import io, tarfile, zipfile
        jar = io.BytesIO()
        with zipfile.ZipFile(jar, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("META-INF/truststore.jks", jks([("emsign", BAD_ROOT)]))
        tgz = io.BytesIO()
        with tarfile.open(fileobj=tgz, mode="w:gz") as tf:
            info = tarfile.TarInfo("lib/app.jar")
            info.size = len(jar.getvalue())
            tf.addfile(info, io.BytesIO(jar.getvalue()))
        self.write("dist/app.tgz", tgz.getvalue())
        self.write("dist/other.7z", b"7z\xbc\xaf\x27\x1c" + os.urandom(64))
        code, rows = self.scan()
        self.assertEqual(code, 1)
        self.assertTrue(self.has(rows, "VULNERABLE", "certifi", "2026.1.1"), rows)
        flagged = {r["path"].replace(os.sep, "/") for r in rows if r["status"] == "VULNERABLE"}
        self.assertIn("notes.txt", flagged)
        self.assertIn("dist/app.tgz!lib/app.jar!META-INF/truststore.jks", flagged)
        self.assertTrue(self.has(rows, "REVIEW", "archive (7-Zip)"))

    def test_heredocs(self):
        self.write("Dockerfile", 'FROM python:3.13\nRUN cat <<<"x" > /f\nFROM node:20.1.0\nRUN <<EOF\npip install pip==26.2.2\nEOF\n')
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "VULNERABLE", "node (image tag)", "20.1.0"), rows)
        self.write("Dockerfile", "FROM node:24.22.1\nRUN <<EOF\necho\nFROM node:20.1.0\n")
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "ERROR", "Dockerfile"), rows)
        self.assertTrue(self.has(rows, "VULNERABLE", "node (image tag)", "20.1.0"), rows)

    def test_installers_and_version_managers(self):
        self.write("setup.sh", "curl -fsSL https://deb.nodesource.com/setup_20.x | bash -\n"
                               "curl -fsSL https://bun.sh/install | bash\nnvm install 22.1.0\nnpm i -g bun@1.4.3\n"
                               "curl -LsSf https://astral.sh/uv/install.sh | sh\n")
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "VULNERABLE", "node (nodesource)", "20"), rows)
        self.assertTrue(self.has(rows, "REVIEW", "bun (bun.sh/install)"), rows)
        self.assertTrue(self.has(rows, "VULNERABLE", "node (nvm)", "22.1.0"), rows)
        self.assertTrue(self.has(rows, "VULNERABLE", "bun (global install)", "1.4.3"), rows)
        self.assertTrue(self.has(rows, "REVIEW", "uv (unversioned install script)"), rows)

    def test_fail_closed_edges(self):
        self.write("requirements.txt", "requests==2.32.0\n")
        self.write(".nvmrc", "24.22.1-rc.1\n")
        self.write(".java-version", "21.0.13\n")
        self.write(".env", "DATABASE_URL=postgres://db/app?sslmode=require\n")
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "REVIEW", "certifi (not pinned)"), rows)
        self.assertTrue(self.has(rows, "REVIEW", "node (node)", "24.22.1-rc.1"), rows)
        self.assertTrue(self.has(rows, "VULNERABLE", "java runtime", "21.0.13"), rows)
        self.assertTrue(self.has(rows, "REVIEW", "TLS without certificate verification"), rows)

    def test_large_binary_with_embedded_pem_roots(self):
        # A runtime binary (node, bun) over the size limit embeds its roots as PEM text;
        # put one across the 16 MB chunk edge.
        block = pem(CLEAN + [BAD_ROOT])
        p = self.write("bin/runtime", b"")
        with open(p, "wb") as f:
            f.seek((16 << 20) - len(block) // 2)
            f.write(block)
            f.seek(70 << 20)
            f.write(b"\x00")
        code, rows = self.scan()
        self.assertEqual(code, 1, rows)
        self.assertTrue(self.has(rows, "VULNERABLE", "emSign ECC Root CA - G3"), rows)

    def test_uv_required_version(self):
        self.write("pyproject.toml", '[tool.uv]\nrequired-version = "0.6.0"\n')
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "VULNERABLE", "uv", "0.6.0"), rows)
        self.write("pyproject.toml", '[tool.uv]\nrequired-version = ">=0.10"\n')
        code, rows = self.scan()
        self.assertTrue(self.has(rows, "REVIEW", "uv"), rows)

    def test_package_json_without_node_version(self):
        self.write("package.json", json.dumps({"name": "x", "dependencies": {"next": "15.0.0"}}))
        code, rows = self.scan()
        self.assertEqual(code, 3)
        self.assertTrue(self.has(rows, "REVIEW", "node (no version source)"), rows)


class GoBinaries(Tmp):
    def test_empty_path_is_not_a_pass(self):
        self.assertEqual(run("go_binaries.py", env={"PATH": self.dir})[0], 3)

    def test_unknown_and_missing(self):
        self.assertEqual(run("go_binaries.py", os.path.join(self.dir, "nope"))[0], 2)
        p = self.write("fake", b"\x7fELF" + b"\x00" * (600 * 1024) + b"runtime.goexit")
        code, out = run("go_binaries.py", p)
        self.assertEqual(code, 1, out)

    def test_not_a_go_binary_is_review(self):
        p = self.write("shim", "#!/bin/sh\nexec real \"$@\"\n")
        self.assertEqual(run("go_binaries.py", p)[0], 3)


class CheckAdvisory(unittest.TestCase):
    def test_table_parser(self):
        import check_advisory as C
        page = ('<table id="patched"><thead><tr><th>Software</th><th>Patched version</th></tr></thead><tbody>'
                + "".join('<tr><td>%s</td><td><a href="x">%s</a></td></tr>' % (k, v.replace(", ", ",<br>"))
                          for k, v in C.SNAPSHOT.items()) + "</tbody></table>")
        self.assertEqual(C.parse_table(page), C.SNAPSHOT)
        # Since 2026-10-23 the page splits the table by category.
        items = list(C.SNAPSHOT.items())
        split = "".join('<table class="patched"><thead><tr><th>Software</th><th>Patched version</th></tr></thead>'
                        + "".join("<tr><td>%s</td><td>%s</td></tr>" % kv for kv in items[i:i + 10]) + "</table>"
                        for i in range(0, len(items), 10))
        self.assertEqual(C.parse_table('<table id="results"><tr><th>CA</th></tr></table>' + split), C.SNAPSHOT)
        self.assertEqual(C.parse_table(split.replace('class="patched"', 'id="patched"', 1)), C.SNAPSHOT)
        with self.assertRaises(ValueError):
            C.parse_table(split + split)
        with self.assertRaises(ValueError):
            C.parse_table("<table id='other'></table>")
        with self.assertRaises(ValueError):
            C.parse_table('<table id="patched"><tr><td>a</td></tr></table>')

    def test_unknown_certificate(self):
        import check_advisory as C
        feed = {"roots.json": [{"name": "known", "pem": pem([BAD_ROOT]).decode()}]}
        self.assertEqual(C.unknown_certificates(feed), [])
        feed["roots.json"].append({"name": "new", "pem": pem([CLEAN[0]]).decode()})
        self.assertEqual(len(C.unknown_certificates(feed)), 1)

    def test_new_issuance_of_a_known_key(self):
        import check_advisory as C
        real = dict(E.KEYCHAIN_DENY)
        self.addCleanup(lambda: (E.KEYCHAIN_DENY.clear(), E.KEYCHAIN_DENY.update(real)))
        E.KEYCHAIN_DENY.clear()
        E.KEYCHAIN_DENY[E.cert_sha256(BAD_ROOT)] = "root"
        feed = {"roots.json": [{"name": "pinned", "pem": pem([BAD_ROOT]).decode()},
                               {"name": "aaa", "pem": pem([AAA_ROOT]).decode()}]}
        self.assertEqual(C.unpinned_issuances(feed), [])
        feed["roots.json"].append({"name": "cross-sign", "pem": pem([BAD_INT]).decode()})
        self.assertEqual(len(C.unpinned_issuances(feed)), 1)
        self.assertEqual(C.unknown_certificates(feed), [])


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@unittest.skipUnless(shutil.which("openssl"), "needs openssl")
class Probe(Tmp):
    """A local server whose intermediate carries a compromised intermediate's
    Subject Key Identifier, so the leaf's AKI marks the chain as the test one."""

    def setUp(self):
        Tmp.setUp(self)
        d = self.dir

        def ossl(*a):
            subprocess.run(["openssl"] + list(a), cwd=d, check=True, capture_output=True)

        root_ext = "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
        self.write("int.ext", "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
                              "subjectKeyIdentifier=E21E2FE71C19390E554B62C120245735248A2514\nauthorityKeyIdentifier=keyid\n")
        self.write("leaf.ext", "subjectAltName=DNS:localhost\nauthorityKeyIdentifier=keyid\nbasicConstraints=CA:FALSE\n"
                               "extendedKeyUsage=serverAuth\nkeyUsage=critical,digitalSignature\n")
        for n in ("root", "int", "leaf", "other"):
            ossl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", n + ".key")
        ossl("req", "-new", "-x509", "-key", "root.key", "-subj", "/CN=Test Root", "-days", "30",
             "-extensions", "v3", "-config", self.write("r.cnf", "[req]\ndistinguished_name=dn\n[dn]\n[v3]\n" + root_ext), "-out", "root.pem")
        ossl("req", "-new", "-key", "int.key", "-subj", "/CN=Test Intermediate", "-out", "int.csr")
        ossl("x509", "-req", "-in", "int.csr", "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial",
             "-days", "30", "-extfile", "int.ext", "-out", "int.pem")
        ossl("req", "-new", "-key", "leaf.key", "-subj", "/CN=localhost", "-out", "leaf.csr")
        ossl("x509", "-req", "-in", "leaf.csr", "-CA", "int.pem", "-CAkey", "int.key", "-CAcreateserial",
             "-days", "30", "-extfile", "leaf.ext", "-out", "leaf.pem")
        ossl("req", "-new", "-x509", "-key", "other.key", "-subj", "/CN=localhost", "-days", "30",
             "-addext", "subjectAltName=DNS:localhost", "-out", "other.pem")

    def serve(self, name, chain=None):
        port = free_port()
        args = ["openssl", "s_server", "-quiet", "-accept", str(port), "-cert", name + ".pem", "-key", name + ".key"]
        args += ["-cert_chain", chain] if chain else []
        p = subprocess.Popen(args, cwd=self.dir, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                return port
            except OSError:
                time.sleep(0.1)
        self.fail("s_server did not start")

    def probe(self, port, trust):
        env = {"PROBE_HOSTS": "localhost", "PORT": str(port), "TIMEOUT": "10", "NO_PROXY": "localhost,127.0.0.1",
               "no_proxy": "localhost,127.0.0.1", "SSL_CERT_FILE": os.path.join(self.dir, trust),
               "NODE_EXTRA_CA_CERTS": os.path.join(self.dir, trust) if trust == "root.pem" else ""}
        for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"):
            env[k] = ""
        return run("probe_runtime.sh", env=env, timeout=600)

    def test_trusted_compromised_chain_is_vulnerable(self):
        port = self.serve("leaf", chain="int.pem")
        code, out = self.probe(port, "root.pem")
        self.assertEqual(code, 1, out)
        self.assertIn("VULNERABLE", out)

    def test_untrusted_compromised_chain_passes(self):
        port = self.serve("leaf", chain="int.pem")
        code, out = self.probe(port, "other.pem")
        self.assertEqual(code, 0, out)

    def test_other_chain_is_inconclusive(self):
        port = self.serve("other")
        code, out = self.probe(port, "other.pem")
        self.assertEqual(code, 2, out)

    def expired_leaf(self):
        d = self.dir
        self.write("ca.cnf", "[ca]\ndefault_ca=c\n[c]\ndatabase=index.txt\nserial=serial\nnew_certs_dir=.\n"
                             "default_md=sha256\npolicy=p\n[p]\ncommonName=supplied\n")
        self.write("index.txt", "")
        self.write("serial", "01\n")
        subprocess.run(["openssl", "ca", "-batch", "-config", "ca.cnf", "-cert", "int.pem", "-keyfile", "int.key",
                        "-in", "leaf.csr", "-out", "expired.pem", "-extfile", "leaf.ext", "-notext",
                        "-startdate", "20200101000000Z", "-enddate", "20200102000000Z"],
                       cwd=d, check=True, capture_output=True)
        shutil.copy(os.path.join(d, "leaf.key"), os.path.join(d, "expired.key"))

    def test_expired_trusted_leaf_never_passes(self):
        # The store trusts the chain; clients refuse only because the leaf expired.
        # That is not proof of a fix, so nothing may print ok.
        self.expired_leaf()
        port = self.serve("expired", chain="int.pem")
        code, out = self.probe(port, "root.pem")
        self.assertNotEqual(code, 0, out)
        # These read SSL_CERT_FILE / NODE_EXTRA_CA_CERTS, so they trust the chain.
        self.assertFalse(re.search(r"^ok +(python-ssl-default|node|bun|ruby) ", out, re.M), out)

    def test_proxied_refusal_is_not_ok(self):
        # curl and wget honour proxy variables: a refusal without their own
        # chain may be of the proxy's certificate. A dead proxy is enough here.
        port = self.serve("leaf", chain="int.pem")
        dead = free_port()
        env = {"PROBE_HOSTS": "localhost", "PORT": str(port), "TIMEOUT": "10",
               "SSL_CERT_FILE": os.path.join(self.dir, "other.pem"),
               "https_proxy": "http://127.0.0.1:%d" % dead, "HTTPS_PROXY": "http://127.0.0.1:%d" % dead,
               "NO_PROXY": "", "no_proxy": ""}
        code, out = run("probe_runtime.sh", env=env, timeout=600)
        self.assertFalse(re.search(r"^ok +(curl|wget) ", out, re.M), out)
        self.assertNotEqual(code, 0, out)

    def test_secrets_are_not_logged(self):
        env = {"PROBE_HOSTS": "localhost", "PORT": str(free_port()), "TIMEOUT": "5",
               "HTTPS_PROXY": "http://user:hunter2#sekritA?sekritB@proxy.invalid:3128/p?access_token=sekrit1",
               "https_proxy": "user:sekrit4@proxy.invalid:3128/p?access_token=sekrit5",
               "NODE_OPTIONS": "--x=http://u:sek@rit6@h.invalid/ --y=http://u:se#k?rit7@h.invalid/",
               "JAVA_TOOL_OPTIONS": "-DapiToken=sekrit2 -Dhttp.proxyPassword=sekrit3"}
        code, out = run("probe_runtime.sh", env=env, timeout=600)
        for secret in ("hunter2", "sekrit1", "sekrit2", "sekrit3", "sekrit4", "sekrit5", "rit6", "rit7", "se#k", "sekritA", "sekritB"):
            self.assertNotIn(secret, out)
        self.assertIn("env HTTPS_PROXY=http://***@proxy.invalid:3128\n", out)
        self.assertIn("env https_proxy=***@proxy.invalid:3128\n", out)

    def test_nothing_listening_is_inconclusive(self):
        code, out = self.probe(free_port(), "root.pem")
        self.assertEqual(code, 2, out)


if __name__ == "__main__":
    unittest.main()
