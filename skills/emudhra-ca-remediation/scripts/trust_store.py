#!/usr/bin/env python3
"""Part of the emudhra-ca-remediation skill.

Does a trust store hold a root (or intermediate) that the compromised eMudhra
intermediates chain to? Every certificate is decoded and identified by the
SHA-256 of its public key (see emudhra_certs.py), so names, aliases, locale,
expiry dates and the wording of other tools' output never decide the verdict.

    trust_store.py STORE [STORE ...]
    trust_store.py system java python          # this machine's usual stores
    trust_store.py --root fs system java python  # an exported image's stores
    trust_store.py --delete /path/to/cacerts   # remove affected trusted entries
    trust_store.py --filter clean.pem bundle.pem         # write a fixed copy

STORE is a file or directory, or one of these words (with --root, they name
the image's stores instead: its OS bundle, every lib/security/cacerts and
jssecacerts, and every certifi, pip and botocore cacert.pem in it):
  system   OpenSSL's default CA file and directory, plus the usual distro paths
  java     the cacerts and jssecacerts of $JAVA_HOME and of the java on PATH,
           and any -Djavax.net.ssl.trustStore in JAVA_TOOL_OPTIONS,
           JDK_JAVA_OPTIONS or _JAVA_OPTIONS
  python   certifi and pip's vendored certifi, for each python on PATH. A path
           to an interpreter (a venv's bin/python) checks that one instead

Formats: PEM (any number of certificates, including TRUSTED CERTIFICATE
blocks), single DER certificates, directories of either (OpenSSL hash dirs,
anchors dirs), JKS, and PKCS12 (password-less, as JDK 18+ cacerts are; for a
password-protected one keytool is used, with STOREPASS, default "changeit").

Verdicts, one line per store:
  VULNERABLE  it holds an affected root or intermediate as a trust anchor
  CLEAN       it was read completely and holds none of them
  ERROR       it could not be read completely. That is never CLEAN.
  NONE        with --root: the image has no store of that kind (no JVM, no
              certifi). It does not change the exit status
  NOTE        an affected certificate inside a private key's chain. It is not
              a trust anchor, so it is reported but never deleted.

CLEAN is about the store only. A runtime that ignores this store, or that adds
roots of its own, is not made safe by it: probe_runtime.sh tests the client.

Exit status: 1 if any store is VULNERABLE, else 2 if any is ERROR, else 0.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import emudhra_certs as E  # noqa: E402

JKS_MAGIC = b"\xfe\xed\xfe\xed"
JCEKS_MAGIC = b"\xce\xce\xce\xce"
OID_DATA = bytes.fromhex("2a864886f70d010701")
OID_CERT_BAG = bytes.fromhex("2a864886f70d010c0a0103")
OID_SAFE_CONTENTS_BAG = bytes.fromhex("2a864886f70d010c0a0106")
OID_FRIENDLY_NAME = bytes.fromhex("2a864886f70d010914")
OID_LOCAL_KEY_ID = bytes.fromhex("2a864886f70d010915")
OID_KEY_BAGS = (bytes.fromhex("2a864886f70d010c0a0101"), bytes.fromhex("2a864886f70d010c0a0102"))  # keyBag, shrouded
SYSTEM_PATHS = [
    "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem", "/usr/local/etc/openssl/cert.pem", "/etc/ssl/certs",
]
MAX_FILE = 64 * 1024 * 1024


class StoreError(Exception):
    pass


class NotAStore(StoreError):
    """The file is in no certificate format this tool knows."""


class PartialRead(StoreError):
    """A directory was read, but some of its certificate files could not be."""

    def __init__(self, entries, problems):
        StoreError.__init__(self, "could not read %d of its files: %s" % (
            len(problems), "; ".join("%s (%s)" % p[:2] for p in problems[:5])))
        self.entries, self.problems = entries, problems


def realpath_in(root, path):
    """realpath() as seen from inside root (an exported image filesystem)."""
    parts = os.path.relpath(path, root).split(os.sep)
    resolved, hops = [], 0
    while parts:
        c = parts.pop(0)
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
                raise StoreError("symlink loop at %s" % cand)
            target = os.readlink(cand)
            if target.startswith("/"):
                resolved = []
            parts = target.split("/") + parts
        else:
            resolved.append(c)
    return os.path.join(root, *resolved)


# --- readers. Each returns a list of entries: (der, label, is_trust_anchor). ---

def read_jks(data):
    magic, version, count = data[:4], int.from_bytes(data[4:8], "big"), int.from_bytes(data[8:12], "big")
    if version not in (1, 2):
        raise StoreError("unknown JKS version %d" % version)
    i, out = 12, []

    def u16(i):
        return int.from_bytes(data[i:i + 2], "big"), i + 2

    def u32(i):
        return int.from_bytes(data[i:i + 4], "big"), i + 4

    def utf(i):
        n, i = u16(i)
        return data[i:i + n].decode("utf-8", "replace"), i + n

    def cert(i):
        if version == 2:
            _, i = utf(i)  # certificate type, "X.509"
        n, i = u32(i)
        return data[i:i + n], i + n

    for _ in range(count):
        tag, i = u32(i)
        alias, i = utf(i)
        i += 8  # timestamp
        if tag == 1:  # private key entry: protected key, then its chain
            n, i = u32(i)
            i += n
            chain, i = u32(i)
            for _ in range(chain):
                der, i = cert(i)
                out.append((der, alias, False))
        elif tag == 2:  # trusted certificate entry
            der, i = cert(i)
            out.append((der, alias, True))
        else:
            # JCEKS secret-key entries are Java-serialized objects of unknown length.
            raise StoreError("entry type %d (%s) can't be parsed; use keytool" % (tag, "JCEKS secret key" if tag == 3 else "unknown"))
        if i > len(data):
            raise StoreError("truncated keystore")
    return out


def _bmp(b):
    return b.decode("utf-16-be", "replace")


def read_pkcs12(data):
    """Password-less PKCS12 only. Encrypted content raises, so the caller falls back."""
    t, s, e = E.tlv(data, 0)
    pfx = list(E.children(data, s, e))
    _, _, cs, ce = pfx[1]  # authSafe ContentInfo
    ci = list(E.children(data, cs, ce))
    if data[ci[0][2]:ci[0][3]] != OID_DATA:
        raise StoreError("PKCS12 authSafe is not plain data (signed?)")
    _, xs, xe = E.tlv(data, ci[1][2])  # [0] EXPLICIT -> OCTET STRING
    if data[ci[1][2]] != 0x04:
        raise StoreError("PKCS12 uses BER constructed encoding")
    _, as_, ae = E.tlv(data, xs)  # AuthenticatedSafe SEQUENCE
    out = []
    for _, _, ps, pe in E.children(data, as_, ae):
        part = list(E.children(data, ps, pe))
        if data[part[0][2]:part[0][3]] != OID_DATA:
            raise StoreError("encrypted PKCS12 contents")
        _, os_, oe = E.tlv(data, part[1][2])
        _, ss, se = E.tlv(data, os_)  # SafeContents
        out += _p12_bags(data, ss, se)
    # A certificate counts as part of a key's chain only when a key bag in this
    # file carries the same localKeyId. Anything else is an anchor.
    keys = {kid for kind, kid, _ in out if kind == "key"}
    return [(p[0], p[1], kid is None or kid not in keys) for kind, kid, p in out if kind == "cert"]


def _p12_bags(data, ss, se):
    out = []
    for _, _, bs, be in E.children(data, ss, se):
        bag = list(E.children(data, bs, be))
        kind = data[bag[0][2]:bag[0][3]]
        if kind == OID_SAFE_CONTENTS_BAG:  # nested SafeContents
            _, ns, ne = E.tlv(data, bag[1][2])
            out += _p12_bags(data, ns, ne)
            continue
        if kind in OID_KEY_BAGS:
            out.append(("key", _p12_local_key_id(data, bag), None))
            continue
        if kind != OID_CERT_BAG:
            continue  # CRLs, secrets
        _, cbs, cbe = E.tlv(data, bag[1][2])  # CertBag SEQUENCE
        cb = list(E.children(data, cbs, cbe))
        _, vs, ve = E.tlv(data, cb[1][2])  # [0] EXPLICIT -> OCTET STRING
        der = data[vs:ve]
        alias = "?"
        if len(bag) > 2:
            for _, _, ats, ate in E.children(data, bag[2][2], bag[2][3]):
                attr = list(E.children(data, ats, ate))
                if data[attr[0][2]:attr[0][3]] == OID_FRIENDLY_NAME:
                    _, vs2, ve2 = E.tlv(data, attr[1][2])
                    alias = _bmp(data[vs2:ve2])
        out.append(("cert", _p12_local_key_id(data, bag), (der, alias)))
    return out


def _p12_local_key_id(data, bag):
    if len(bag) > 2:
        for _, _, ats, ate in E.children(data, bag[2][2], bag[2][3]):
            attr = list(E.children(data, ats, ate))
            if data[attr[0][2]:attr[0][3]] == OID_LOCAL_KEY_ID:
                return data[attr[1][2]:attr[1][3]]
    return None


def read_with_keytool(path):
    kt = shutil.which("keytool")
    if not kt:
        raise StoreError("password-protected keystore and no keytool to read it")
    for pw in ([os.environ["STOREPASS"]] if os.environ.get("STOREPASS") else ["changeit", ""]):
        r = subprocess.run([kt, "-J-Duser.language=en", "-list", "-rfc", "-keystore", path, "-storepass", pw],
                           capture_output=True, timeout=120)
        if r.returncode == 0:
            certs = E.pem_certificates(r.stdout)
            if not certs:
                raise StoreError("keytool listed no certificates")
            entries = keytool_entries(r.stdout, certs)
            if entries:
                return entries
            # Entries could not be paired with their aliases: every certificate
            # counts as an anchor, and none can be deleted by alias.
            return [(der, "#%d (via keytool)" % n, True) for n, der in enumerate(certs, 1)]
    raise StoreError("keytool could not open it (set STOREPASS)")


def keytool_entries(listing, certs):
    """(der, alias, anchor) from `keytool -list -rfc` output, read in English
    (user.language=en). Each entry's header precedes its PEM blocks. Returns
    None unless every certificate is paired with an entry, so a listing this
    does not understand never yields a wrong alias."""
    out, alias, trusted = [], None, False
    pos = 0
    text = listing.decode("utf-8", "replace")
    for m in re.finditer(r"^Alias name: (.*)$|^Entry type: (.*)$|-----BEGIN CERTIFICATE-----", text, re.M):
        if m.group(1) is not None:
            alias, trusted = m.group(1).strip(), False
        elif m.group(2) is not None:
            trusted = m.group(2).strip() == "trustedCertEntry"
        else:
            if alias is None or pos >= len(certs):
                return None
            out.append((certs[pos], alias, trusted))
            pos += 1
    return out if pos == len(certs) else None


def read_file(path):
    if os.path.getsize(path) > MAX_FILE:
        raise StoreError("larger than %d MB" % (MAX_FILE >> 20))
    with open(path, "rb") as f:
        return read_data(f.read(), path)


def read_data(data, path=None):
    """Entries of a store held in memory. keytool, the fallback for
    password-protected stores, reads path, or a temporary copy when the bytes
    came from somewhere else (an archive member)."""
    if not data:
        raise StoreError("empty file")
    if b"-----BEGIN" in data:
        certs = E.pem_certificates(data)
        if certs:
            return [(der, "#%d" % n, True) for n, der in enumerate(certs, 1)], "PEM"
    if data[:4] == JKS_MAGIC:
        return read_jks(data), "JKS"
    if data[:4] == JCEKS_MAGIC:
        try:
            return read_jks(data), "JCEKS"
        except StoreError:
            return keytool_data(data, path), "JCEKS (keytool)"
    if data[:1] == b"\x30":
        try:
            E.spki_sha256(data)
            return [(data[:E.cert_length(data)], "#1", True)], "DER"
        except E.DERError:
            pass
        try:
            return read_pkcs12(data), "PKCS12"
        except (StoreError, E.DERError, IndexError):
            return keytool_data(data, path), "PKCS12 (keytool)"
    raise NotAStore("not a certificate store this tool can read")


def keytool_data(data, path):
    if path:
        return read_with_keytool(path)
    fd, tmp = tempfile.mkstemp(suffix=".store")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        return read_with_keytool(tmp)
    finally:
        os.unlink(tmp)


def read_dir(path, root):
    entries, seen, files, problems = [], set(), 0, []
    for dirpath, dirnames, filenames in os.walk(path):
        dirnames.sort()
        for fn in sorted(filenames):
            p = os.path.join(dirpath, fn)
            real = realpath_in(root, p) if root else os.path.realpath(p)
            if real in seen or not os.path.isfile(real):
                continue
            seen.add(real)
            try:
                if os.path.getsize(real) > MAX_FILE:
                    # Not a store (a JDK's lib/modules, a binary): it counts only if
                    # it carries an affected key.
                    raise NotAStore("too large to be a store")
                got, _ = read_file(real)
            except NotAStore:
                # A directory holds other files too (READMEs, CRLs). One that
                # carries an affected key in some other encoding still counts.
                keys = raw_keys(real)
                if keys:
                    problems.append((os.path.relpath(p, path), "not a readable store, but holds the key of "
                                     + ", ".join(keys), keys))
                continue
            except (StoreError, E.DERError, IndexError, OSError) as e:
                problems.append((os.path.relpath(p, path), str(e) or e.__class__.__name__, raw_keys(real)))
                continue
            files += 1
            entries += [(der, "%s %s" % (os.path.relpath(p, path), label), anchor) for der, label, anchor in got]
    if problems:
        raise PartialRead(entries, problems)
    if not files:
        raise StoreError("no certificate files in this directory")
    return entries


def raw_keys(path):
    """Affected public keys present in the file's bytes, in any encoding of a
    certificate or key (see emudhra_certs.public_keys_in). The whole file is
    read, in overlapping chunks."""
    longest = max(len(k) for k in E.BAD_PUBLIC_KEYS)
    found, tail = set(), b""
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(16 << 20)
                if not chunk:
                    break
                found |= set(E.public_keys_in(tail + chunk))
                tail = chunk[-longest:]
    except OSError:
        return []
    return sorted(found)


# --- named targets ---

def system_targets():
    out = []
    try:
        import ssl
        paths = ssl.get_default_verify_paths()
        out += [p for p in (paths.cafile, paths.capath, paths.openssl_cafile, paths.openssl_capath) if p]
    except Exception:  # noqa: BLE001
        pass
    for v in ("SSL_CERT_FILE", "SSL_CERT_DIR"):
        if os.environ.get(v):
            out.append(os.environ[v])
    out += SYSTEM_PATHS
    seen, uniq = set(), []
    for p in out:
        if os.path.exists(p) and os.path.realpath(p) not in seen:
            seen.add(os.path.realpath(p))
            uniq.append(p)
    return uniq


def java_targets():
    homes = []
    if os.environ.get("JAVA_HOME"):
        homes.append(os.environ["JAVA_HOME"])
    j = shutil.which("java")
    if j:
        homes.append(os.path.dirname(os.path.dirname(os.path.realpath(j))))
    out = []
    # jssecacerts, when present, replaces cacerts as the JDK's default trust
    # store, so both are checked.
    for h in homes:
        for rel in ("lib/security/jssecacerts", "lib/security/cacerts",
                    "jre/lib/security/jssecacerts", "jre/lib/security/cacerts"):
            p = os.path.join(h, rel)
            if os.path.exists(p) and p not in out:
                out.append(p)
    # A trustStore set in the options every JVM reads replaces both.
    for var in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS"):
        for word in split_options(os.environ.get(var, "")):
            if word.startswith("-Djavax.net.ssl.trustStore="):
                p = word.split("=", 1)[1]
                if p and p not in out:
                    out.append(p)
    return out


def split_options(value):
    import shlex
    try:
        return shlex.split(value)
    except ValueError:
        return value.split()


def python_targets(interpreters=None):
    """The bundles each interpreter would actually load. Not run with -I: the
    user site and PYTHONPATH change what loads, so they must count here too.
    It runs from an empty directory so nothing in the cwd is imported."""
    out = []
    # where() is what the module actually loads: distro builds (Fedora, RHEL)
    # delete cacert.pem and point it at the system bundle. Importing certifi
    # runs no network code.
    probe = ("import importlib, importlib.util as u, os\n"
             "for m in ('certifi', 'pip._vendor.certifi'):\n"
             "    try:\n"
             "        s = u.find_spec(m)\n"
             "    except Exception:\n"
             "        s = None\n"
             "    if not (s and s.origin):\n"
             "        continue\n"
             "    try:\n"
             "        print(importlib.import_module(m).where())\n"
             "    except Exception:\n"
             "        print(os.path.join(os.path.dirname(s.origin), 'cacert.pem'))\n")
    exes = interpreters or [shutil.which(n) for n in ("python3", "python")]
    for exe in [e for e in exes if e]:
        with tempfile.TemporaryDirectory() as cwd:
            r = subprocess.run([exe, "-c", probe], capture_output=True, text=True, timeout=60, cwd=cwd)
        for line in r.stdout.splitlines():
            if line and line not in out:
                out.append(line)
    return out


def is_python(path):
    return os.path.basename(path).startswith("python") and os.path.isfile(path) and os.access(path, os.X_OK)


NAMED = {"system": system_targets, "java": java_targets, "python": python_targets}


def image_targets(root, name):
    """The stores an exported image filesystem has for a named target, as
    paths under root: ([paths], error). An image with no JVM or no Python
    bundle has nothing to check for that name; one with a JVM but no store
    found is an error."""
    if name == "system":
        found = [os.path.join(root, p.lstrip("/")) for p in SYSTEM_PATHS]
        found = [p for p in found if os.path.lexists(p)]
        return found, None if found else "no OS trust store in this image (none of %s)" % ", ".join(SYSTEM_PATHS)
    stores, jvm = [], False
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if os.path.join(dirpath, d) not in
                       {os.path.join(root, x) for x in ("proc", "sys", "dev")}]
        unix = dirpath.replace(os.sep, "/")
        for fn in filenames:
            if name == "java":
                if fn in ("libjvm.so", "libjvm.dylib", "jvm.dll"):
                    jvm = True
                if fn in ("cacerts", "jssecacerts") and unix.endswith("/lib/security"):
                    stores.append(os.path.join(dirpath, fn))
            elif fn == "cacert.pem" and re.search(r"/(?:certifi|pip/_vendor/certifi|botocore)$", unix):
                stores.append(os.path.join(dirpath, fn))
    if name == "java" and jvm and not stores:
        return [], "the image has a JVM but no lib/security/cacerts was found; check its trust store by hand"
    return sorted(stores), None


def check(path, root):
    """(status, entries, detail)."""
    real = realpath_in(root, path) if root else path
    if not os.path.lexists(real):
        raise StoreError("does not exist")
    if os.path.isdir(real):
        return read_dir(real, root), "directory"
    if not os.path.isfile(real):
        raise StoreError("not a regular file")
    return read_file(real)


def delete_entries(path, aliases):
    kt = shutil.which("keytool")
    if not kt:
        raise StoreError("--delete needs keytool")
    pws = [os.environ["STOREPASS"]] if os.environ.get("STOREPASS") else ["changeit", ""]
    for a in aliases:
        for pw in pws:
            r = subprocess.run([kt, "-J-Duser.language=en", "-delete", "-noprompt", "-keystore", path,
                                "-storepass", pw, "-alias", a], capture_output=True, timeout=120)
            if r.returncode == 0:
                break
        else:
            raise StoreError("keytool could not delete %r" % a)


def main():
    argv = sys.argv[1:]
    opts = {"--json": False, "--delete": False}
    root = filter_out = None
    args = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in opts:
            opts[a] = True
        elif a in ("--root", "--filter"):
            if i + 1 >= len(argv):
                print("%s needs a value" % a, file=sys.stderr)
                return 2
            if a == "--root":
                root = os.path.abspath(argv[i + 1])
            else:
                filter_out = argv[i + 1]
            i += 1
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            args.append(a)
        i += 1
    if not args:
        print(__doc__, file=sys.stderr)
        return 2

    targets = []
    for a in args:
        if is_python(a):
            found = python_targets([a])
            targets += [(p, None) for p in found] or [(a, "this interpreter loads neither certifi nor pip")]
            continue
        if a == "system" and not root and sys.platform in ("darwin", "win32"):
            targets.append(("system", "the %s system store is not a file; check it with probe_runtime.sh and the "
                            "platform steps in remediation.md" % ("macOS" if sys.platform == "darwin" else "Windows")))
        if a in NAMED and root:
            found, err = image_targets(root, a)
            if err:
                targets.append((a, err))
            elif not found:
                targets.append((a, "NONE"))
            targets += [(p, None) for p in found]
        elif a in NAMED:  # a file of that name is reached as ./java
            found = NAMED[a]()
            if not found:
                targets.append((a, "no %s trust store found on this machine" % a))
            targets += [(p, None) for p in found]
        else:
            targets.append((a, None))

    rows = []
    for path, err in targets:
        row = {"store": path, "status": None, "format": "", "certificates": 0, "affected": [], "notes": [], "detail": ""}
        rows.append(row)
        if err == "NONE":
            row.update(status="NONE", detail="this image has none")
            continue
        if err:
            row.update(status="ERROR", detail=err)
            continue
        real = realpath_in(root, os.path.abspath(path)) if root else path
        try:
            entries, fmt = check(os.path.abspath(path) if root else path, root)
            if not entries:
                raise StoreError("read, but no certificates in it")
            row["format"], row["certificates"] = fmt, len(entries)
            named = set()
            for der, label, anchor in entries:
                kind, name = E.classify(der)
                if kind:
                    named.add(name)
                    (row["affected"] if anchor else row["notes"]).append({"name": name, "kind": kind, "entry": label})
            # Backstop: an affected key in the file's bytes that no parsed entry
            # accounts for sits in a part this reader skipped. Fail closed.
            if os.path.isfile(real):
                for name in raw_keys(real):
                    if name not in named:
                        row["affected"].append({"name": name, "kind": "key", "entry": "bytes no entry accounts for"})
            if row["affected"] and opts["--delete"]:
                if fmt == "PEM" or fmt == "DER" or fmt == "directory":
                    raise StoreError("--delete works on keystores; for a PEM bundle use --filter")
                if any(x["entry"].startswith("#") or x["kind"] == "key" for x in row["affected"]):
                    raise StoreError("some affected entries have no alias keytool can delete; fix this store by hand "
                                     "and run this check again")
                delete_entries(path, sorted({x["entry"] for x in row["affected"]}))
                again, _ = check(path, root)
                left = [x for x in again if x[2] and E.classify(x[0])[0]]
                if left:
                    raise StoreError("affected entries remain after --delete")
                row["detail"] = "deleted: " + ", ".join(sorted({x["entry"] for x in row["affected"]}))
                row["affected"] = []
            if filter_out and fmt == "PEM":
                with open(os.path.abspath(path) if not root else realpath_in(root, os.path.abspath(path)), "rb") as f:
                    data = f.read()
                keep = [m.group(0) for m in E.PEM_BLOCK.finditer(data)
                        if not E.classify(E.pem_certificates(m.group(0))[0])[0]]
                with open(filter_out, "wb") as f:
                    f.write(b"\n".join(keep) + b"\n")
                row["detail"] = (row["detail"] + "; " if row["detail"] else "") + \
                    "wrote %d certificates to %s" % (len(keep), filter_out)
            row["status"] = "VULNERABLE" if row["affected"] else "CLEAN"
        except (StoreError, E.DERError, IndexError, OSError, subprocess.SubprocessError) as e:
            row.update(status="ERROR", detail=str(e) or e.__class__.__name__, affected=[], notes=[])
            # Unreadable is never CLEAN, and an unreadable file that carries an
            # affected key is VULNERABLE: the key is there whatever the format.
            found = []
            if isinstance(e, PartialRead):
                for der, label, anchor in e.entries:
                    kind, name = E.classify(der)
                    if kind and anchor:
                        found.append({"name": name, "kind": kind, "entry": label})
                found += [{"name": k, "kind": "key", "entry": p[0]} for p in e.problems for k in p[2]]
            elif os.path.isfile(real):
                found = [{"name": k, "kind": "key", "entry": "raw bytes"} for k in raw_keys(real)]
            if found:
                row.update(status="VULNERABLE", affected=found)

    if opts["--json"]:
        json.dump(rows, sys.stdout, indent=2)
        print()
    else:
        for r in rows:
            if r["status"] == "VULNERABLE":
                what = ", ".join(sorted({"%s (%s)" % (x["name"], x["entry"]) for x in r["affected"]}))
                print("VULNERABLE %s [%s, %d certs]: trusts %s%s" % (r["store"], r["format"] or "?", r["certificates"],
                                                                    what, ("; " + r["detail"]) if r["detail"] else ""))
            elif r["status"] == "CLEAN":
                print("CLEAN      %s [%s, %d certs]: none affected%s" % (
                    r["store"], r["format"], r["certificates"], ("; " + r["detail"]) if r["detail"] else ""))
            elif r["status"] == "NONE":
                print("NONE       %s: no such store in this image" % r["store"])
            else:
                print("ERROR      %s: %s" % (r["store"], r["detail"]))
            for x in r["notes"]:
                print("NOTE       %s: %s is in the chain of key entry %s; not a trust anchor, left alone"
                      % (r["store"], x["name"], x["entry"]))
    if any(r["status"] == "VULNERABLE" for r in rows):
        return 1
    return 2 if any(r["status"] == "ERROR" for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
