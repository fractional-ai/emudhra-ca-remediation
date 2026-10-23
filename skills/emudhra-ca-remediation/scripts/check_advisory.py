#!/usr/bin/env python3
"""Part of the emudhra-ca-remediation skill.

Compare the advisory's live data with the snapshot this skill was written
against, and print what changed:

  - the "Who has patched?" table: new software, new patched versions, and
    fixes that were "pending" and have since shipped
  - the certificate feeds (impacted-intermediates.json, roots.json): any
    affected certificate whose public key the skill's tools do not know yet.
    Until emudhra_certs.py lists it, scan_repo.py, trust_store.py and
    probe_runtime.sh cannot see it, so this is the first thing to fix

Run it first, every time. Where the live data differs from the skill's
reference files or from scan_repo.py's thresholds, the live data wins.

    check_advisory.py            # diff against the live page and feeds
    check_advisory.py --live     # print the whole live table
    check_advisory.py --json     # the live table as JSON

Exit status: 0 no changes, 1 changes found, 2 could not fetch or parse
something. 2 is not "no changes": read the page by hand.
"""

import json
import os
import sys
import urllib.request
from html.parser import HTMLParser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import emudhra_certs as E  # noqa: E402

URL = "https://emudhra.we-have-a-problem.com/"
FEEDS = ("impacted-intermediates.json", "roots.json")
SOURCE = "https://github.com/galadran/we-have-a-problem.com"
SNAPSHOT_DATE = "2026-10-23"
SNAPSHOT = {
    "Alpine Linux ca-certificates": "20261020-r0",
    "Arch Linux ca-certificates-mozilla": "3.131.1-1",
    "Chainguard ca-certificates": "20260909-r3",
    "Debian ca-certificates": "20250419~deb12u2, 20250419+deb13u1, 20260816+nmu1",
    "Devuan ca-certificates": "Same as Debian",
    "Fedora ca-certificates": "2026.2.92_v9.0.319",
    "FreeBSD ca_root_nss": "1.131.1",
    "FreeBSD caroot": "15.1-RELEASE-p6, 14.5-RELEASE-p3, 14.4-RELEASE-p12",
    "Freedesktop SDK": "25.08.19, 26.08.3",
    "Gentoo ca-certificates": "20260816.3.125",
    "GNU Guix": "7608a99",
    "Homebrew ca-certificates": "2026-09-25_1",
    "OmniOS web/ca-bundle": "r151054by, r151056ay, r151058y",
    "OpenBSD": "current 8.0 7.9",
    "Ubuntu ca-certificates": "20260816ubuntu0.22.04.1, 20260816ubuntu0.24.04.1, 20260816ubuntu0.26.04.1, 20260816ubuntu0.26.10.1",
    "Bottlerocket": "pending",
    "Cloudflare CFSSL trust store": "2026.10.1",
    "curl CA bundle": "2026-10-20",
    "Elixir castore": "1.0.22",
    "NSS": "3.131.1",
    "Perl Mozilla::CA": "20261020",
    "Python certifi": "2026.10.19",
    "Rust rustls-webpki": "0.103.16",
    "Rust webpki-roots / webpki-root-certs": "1.0.10",
    "Composer ca-bundle": "pending (1.4.16, 1.6.0)",
    "Erlang certifi": "pending",
    "Bun": "1.4.4",
    "Deno": "2.9.8",
    "Electron": "44.9.1, 43.8.1, 42.11.16",
    "Go": "1.27.3, 1.26.10",
    "Java": "27.0.1.0.2, 25.0.5.0.2, 21.0.13.0.2, 17.0.21.0.2, 11.0.33.0.2, 8u511 (OpenJDK, Oracle JDK)",
    "Node.js": "26.12.1, 24.22.1, 22.23.4",
    "Python": "3.15.1, 3.14.9, 3.13.17",
    "ArgoCD": "3.3.18",
    "Claude Code": "2.1.303",
    "Docker Desktop": "4.96.2",
    "mise": "2026.10.17",
    "pip": "26.2.2",
    "pixi": "0.82.1",
    "pypi-publish GitHub Action": "1.14.3",
    "Rustup": "1.29.2",
    "uv": "0.13.4",
    "Conda": "26.9.4",
    "Godot": "pending",
}
# Fixes confirmed from the vendor's own release notes before the advisory's table
# caught up. Each is printed as AHEAD while the table still says "pending".
AHEAD = {
    "Composer ca-bundle": "1.4.16 and 1.6.0 (on Packagist 2026-10-20; both bundles drop emSign ECC Root CA - G3, "
                          "checked with trust_store.py)",
}


class Tables(HTMLParser):
    """Every <table> on the page as {"id", "rows"}, each row a list of cell
    texts (th and td alike), with <br> read as a space."""

    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.tables, self.stack = [], []

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self.stack.append({"id": dict(attrs).get("id"), "rows": [], "row": None, "cell": None})
        elif not self.stack:
            return
        elif tag == "tr":
            self.stack[-1]["row"] = []
        elif tag in ("td", "th") and self.stack[-1]["row"] is not None:
            self.stack[-1]["cell"] = []
        elif tag == "br" and self.stack[-1]["cell"] is not None:
            self.stack[-1]["cell"].append(" ")

    def handle_endtag(self, tag):
        if not self.stack:
            return
        t = self.stack[-1]
        if tag in ("td", "th") and t["cell"] is not None and t["row"] is not None:
            t["row"].append(" ".join("".join(t["cell"]).split()))
            t["cell"] = None
        elif tag == "tr" and t["row"] is not None:
            t["rows"].append(t["row"])
            t["row"] = None
        elif tag == "table":
            self.tables.append(self.stack.pop())

    def handle_data(self, data):
        if self.stack and self.stack[-1]["cell"] is not None:
            self.stack[-1]["cell"].append(data)


def get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "emudhra-ca-remediation/check_advisory"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.read()


def parse_table(page):
    p = Tables()
    p.feed(page)
    p.close()
    # The page has shipped this as one table and, since 2026-10-23, as one per
    # category (OS, bundles, runtimes, tools). Read every one with the header.
    tables = [t for t in p.tables if t["id"] == "patched"
              or t["rows"] and [c.lower() for c in t["rows"][0][:2]] == ["software", "patched version"]]
    if not tables:
        raise ValueError("found no patched-versions table; the layout changed, read it by hand")
    rows = []
    for t in tables:
        r = t["rows"]
        if r and [c.lower() for c in r[0][:2]] == ["software", "patched version"]:
            r = r[1:]
        rows += r
    bad = [r for r in rows if len(r) != 2 or not r[0]]
    if bad or not rows:
        raise ValueError("patched-versions table has %d rows, %d of them not two cells; read it by hand"
                         % (len(rows), len(bad)))
    live = {}
    for name, version in rows:
        if name in live:
            raise ValueError("%s is listed twice; read the table by hand" % name)
        live[name] = version
    return live


def feed_certificates(feeds):
    """(label, der, spki) for every certificate in the advisory's feeds. Every
    PEM is parsed here; the feed's own fingerprint field is only cross-checked,
    never trusted alone."""
    out = []
    for name, entries in feeds.items():
        if not isinstance(entries, list) or not entries:
            raise ValueError("%s is not a non-empty list" % name)
        for c in entries:
            ders = E.pem_certificates(str(c.get("pem", "")).encode())
            if len(ders) != 1:
                raise ValueError("%s: entry %r has %d certificates in its pem" % (name, c.get("name"), len(ders)))
            spki = E.spki_sha256(ders[0])
            if c.get("spki_sha256") and c["spki_sha256"].upper() != spki:
                raise ValueError("%s: %r says spki %s but its pem has %s" % (name, c.get("name"), c["spki_sha256"], spki))
            out.append(("%s (%s, spki %s)" % (c.get("name") or E.subject_cn(ders[0]), name, spki), ders[0], spki))
    return out


def unknown_certificates(feeds):
    """Certificates in the advisory's feeds whose key the skill's tools do not list."""
    return [label for label, _, spki in feed_certificates(feeds) if spki not in E.BAD_SPKIS]


# Not denied in the Keychain on purpose (see emudhra_certs.KEYCHAIN_DENY).
KEYCHAIN_KEEP = {spki for spki, name in E.BAD_ROOTS.items() if name == "AAA Certificate Services"}


def missing_pins(feeds):
    """KEYCHAIN_DENY certificates the feeds no longer list. The certificate stays
    compromised, but --keychain-pems can't find it there any more."""
    seen = {E.cert_sha256(der) for _, der, _ in feed_certificates(feeds)}
    return sorted(stem for fp, stem in E.KEYCHAIN_DENY.items() if fp not in seen)


def unpinned_issuances(feeds):
    """Affected certificates whose key is known but whose exact certificate is
    not in KEYCHAIN_DENY: a new issuance or cross-sign of a known key. Keychain
    trust settings attach to a certificate, so the Keychain step would miss it."""
    return [label for label, der, spki in feed_certificates(feeds)
            if spki in E.BAD_SPKIS and spki not in KEYCHAIN_KEEP and E.cert_sha256(der) not in E.KEYCHAIN_DENY]


def main():
    try:
        live = parse_table(get(URL).decode("utf-8", "replace"))
    except Exception as e:  # network, proxy, layout change
        print("could not read the table at %s: %s" % (URL, e), file=sys.stderr)
        print("Read it by hand there or in %s, and compare it with remediation.md." % SOURCE, file=sys.stderr)
        return 2
    if "--json" in sys.argv:
        json.dump(live, sys.stdout, indent=2)
        print()
        return 0
    if "--live" in sys.argv:
        for k, v in live.items():
            print("%-40s %s" % (k, v))
        return 0
    changed = failed = False
    try:
        feeds = {f: json.loads(get(URL + f)) for f in FEEDS}
        new, reissued, gone = unknown_certificates(feeds), unpinned_issuances(feeds), missing_pins(feeds)
    except Exception as e:
        print("ERROR      could not check the certificate feeds (%s): %s" % (", ".join(FEEDS), e))
        failed = True
        new = reissued = gone = []
    for item in new:
        print("NEW CERT   %s: add its SPKI and SKI to emudhra_certs.py (and probe_runtime.sh), and its "
              "SHA-256 to KEYCHAIN_DENY; until then the tools cannot see it" % item)
        changed = True
    for stem in gone:
        print("REMOVED    pinned certificate %s is no longer in the feeds. It is still compromised: keep it "
              "denied, and find out why it was dropped before trusting the feeds again" % stem)
        changed = True
    for item in reissued:
        print("NEW CERT   %s: a new certificate for a known key; add its SHA-256 to KEYCHAIN_DENY in "
              "emudhra_certs.py, or the macOS Keychain step will not deny it" % item)
        changed = True
    for name, now in live.items():
        was = SNAPSHOT.get(name)
        if was is None:
            print("NEW        %s: %s" % (name, now))
        elif was != now:
            tag = "SHIPPED   " if was.startswith("pending") and not now.startswith("pending") else "CHANGED   "
            print("%s %s: %s  (snapshot: %s)" % (tag, name, now, was))
        else:
            continue
        changed = True
    for name in SNAPSHOT:
        if name not in live:
            print("REMOVED    %s (snapshot: %s)" % (name, SNAPSHOT[name]))
            changed = True
    for name, note in AHEAD.items():
        if live.get(name, "").startswith("pending"):
            print("AHEAD      %s: the table says pending, but the vendor shipped %s" % (name, note))
    still = [n for n, v in live.items() if v.startswith("pending") and n not in AHEAD]
    if still:
        print("PENDING    " + ", ".join(still))
    if changed:
        print("\nThe live data wins over the skill's files, except where reference/remediation.md names a later "
              "version. Use these versions, and treat a SHIPPED fix as required.")
    elif not failed:
        print("No changes since the %s snapshot. That is about the advisory, not about any system: "
              "every system still has to be checked." % SNAPSHOT_DATE)
    return 1 if changed else 2 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
