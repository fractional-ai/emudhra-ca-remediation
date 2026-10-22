"""Part of the emudhra-ca-remediation skill.

The identities of the affected certificates, and the minimal X.509 parsing
needed to recognise them. Everything the skill's Python tools decide is
decided here, by public-key fingerprint, never by a name or a tool's output.

A certificate is identified by the SHA-256 of its SubjectPublicKeyInfo (SPKI).
The SPKI is the same in both issuances of each intermediate and survives a
re-issued root, so one set of fingerprints covers the 16 certificates and the
roots they chain to. A leaf is tied to its issuer by its Authority Key
Identifier, which equals the issuing intermediate's Subject Key Identifier.

Values were computed from the advisory's impacted-intermediates.json and
roots.json (https://emudhra.we-have-a-problem.com/) with this module's own
parser, and match the fingerprints the advisory publishes.
"""

import base64
import hashlib
import re

# The eight intermediates whose private keys are recoverable. SPKI SHA-256 -> name.
BAD_INTERMEDIATES = {
    "EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105": "EM DV TLS CA - G3B",
    "43BFFA19D6EF651451F6841E019931E96F6F2EAEFF28AB4B6F1CE4576DE2717B": "EM OV TLS CA - G3B",
    "E0254C7FCDC265E2F0F8A428DABB75AB4AE039B4872D62F5EE57F0877D5A8A41": "EM EV TLS CA - G3B",
    "49DD353DC2B919A3770645117D0E60C16115E7D1BC259EEFE734B00EA434FE5F": "EM DV TLS CA - G3C",
    "63ECEFEE431D49523BC1136C4E72D0206A477086CAF606CD5CF025686C109CF8": "EM OV TLS CA - G3C",
    "5C0660A2B164910D8FF589C18E14552E9E0EC237DCEFE2CB736D41A4811F81A0": "EM EV TLS CA - G3C",
    "EC4FFA1AD0AC88081314B7AAFFEF6A91F97CD57291BB5BA686C5415F5EB4F6B6": "EM OV CS CA - G3B",
    "92C063D67E8F14DB71D288E11266FFDAF69CBF115F7BAB14F3BC2F68D25E0E30": "EM OV CS CA - G3C",
}

# Their Subject Key Identifiers, which a leaf they issued names as its AKI.
BAD_INTERMEDIATE_SKIS = {
    "E21E2FE71C19390E554B62C120245735248A2514": "EM DV TLS CA - G3B",
    "9BD86551AFE7E72C37AD08EE6919D9BF3784AE0A": "EM OV TLS CA - G3B",
    "3EDC20D9894698877B873FD88147B25C15D84706": "EM EV TLS CA - G3B",
    "AE7E105C3C2996C1A847270559F1E03DD4E50AF3": "EM DV TLS CA - G3C",
    "34EAEA0CEBC90ADAF9D0C5E2ED9B78C9879E1B6C": "EM OV TLS CA - G3C",
    "A6255E80A94DB7F3967C1BC791DF92BCEE4BEB5F": "EM EV TLS CA - G3C",
    "79FAE8ECCFDB0D758DA458D69FB6EDDC7C49DEE6": "EM OV CS CA - G3B",
    "EE6F73298D6FBFA7B31BC39534F61556447866B7": "EM OV CS CA - G3C",
}

# Roots through which the intermediates chain. A trust store that holds any of
# these, as a trust anchor, trusts certificates the intermediates issue (unless
# its runtime blocks the intermediates' keys separately). SPKI SHA-256 -> name.
BAD_ROOTS = {
    "8D417DB2DD8BF5E3084D1E3F196D583849D81BDD4C00C70B9D39369E96B8C782": "emSign ECC Root CA - G3",
    "BD153ED7B0434F6886B17BCE8BBE84ED340C7132D702A8F4FA318F756ECBD6F3": "AAA Certificate Services",
    # The direct issuers. Microsoft's store includes these two as roots.
    "C619E4780ED8E0ABEDA24AD732567DE4383A7EA941338F6D1A7D1B49AC792FE9": "emSign Root TLS CA - G3",
    "0A6C2B2CA5B364207954171987AC9D2178561569D8205457E77CA90C32EDE282": "emSign Root CS CA - G3",
}

BAD_SPKIS = dict(BAD_INTERMEDIATES, **BAD_ROOTS)

# The raw public keys (subjectPublicKey contents) of all twelve. However a
# program embeds a trust anchor, as a certificate, a bare SPKI (rustls's
# webpki-roots) or a key, these bytes are in it, so finding them in a file or
# binary means that file carries the key, whatever its format.
_PUBLIC_KEYS = (
    ("EM DV TLS CA - G3B",
     "04E79ED9C04A9773C4735E51111DA85AC2BD5E64AB374B80E12CBC2038EC1E4F0E3B812FC9859E1E67AFB04E2F8BC97F"
     "7485BA65AA911EE8A4E45B62D5CC03D56BE678B3C38CB4DC937CA2460E238453C892935D29D44F91E15606B63CCEDAB4"
     "68"
     ),
    ("EM OV TLS CA - G3B",
     "0473897AA0EB3CFDCA8B12402FFAF0ABC4E1212BAF8DEE778AC9EE2D6DB83FAC280C5E05638AE7A2ACD71C322A8E361C"
     "DEB9F69C4302B9DD8D73D1CC6CAAB2CC0AEE4E216CE979DD518A4AF4B626E5684CDD658037ED0C854E4CC12F4CF8646D"
     "0D"
     ),
    ("EM EV TLS CA - G3B",
     "0425DBA85A64D397DA0B1052E9EA546E487BEFEA9C9D9D68A0C5EADCFEEF75A69BB5D6FC01F42BFBCA6EB40BCD64C076"
     "7E36FFD05D97A813C5AA0C6C9530E79CF5F0866468F13806420AA5C851840B1E252540E790E4B654C3852ED64AF1E865"
     "7D"
     ),
    ("EM DV TLS CA - G3C",
     "043A7A7862C8C44D324DDD69033A6782C0EFEEFE4055E68A123FA0371BA3BD9194514EE172A433E3630F02BD188037D9"
     "E5149F9B77DB94A281DF987B2FEA888B74BDFE8FDA4C1099EE6CA19566FE3EF0E5F6B09A556CCC8BA50561DF1B2A441D"
     "01"
     ),
    ("EM OV TLS CA - G3C",
     "04138251CD52AC9298C1C8AAD977321DEB97E709BD0B4CA0ACA55DC8AD51DCFC9D1589A1597E3A5120E1EFD631C63E18"
     "35CACAE29869A62E1631E8A28181AB56616DC45D918ABC09F3AB0E63CF792AA4DCED7387BE37BBA569549F1C02B270ED"
     "67"
     ),
    ("EM EV TLS CA - G3C",
     "042D56E829A6FB82C64A4697D960AF951E9067AE91F926D34306DA48A8AAEB7869B6A67E6D27426E0442AA03B36E1988"
     "DFF636514EE1CF07F5BA4B3FF2A06645AE7D31D5866AD31AA3D246EB0B3177EE99CB7566C516CE74808A668F91F0C47F"
     "CA"
     ),
    ("EM OV CS CA - G3B",
     "04AABB0FB0666ACFCF01FAD52BFCFD4C2BF2CB3C3497DE73950E5819B61FE695098741C8C491439B34A0431CAFFE5BF9"
     "B4C1C8E8AE0001F9F4DC8AD82C59F3639E96CD6C3D4DB0CEFEC26C3D62517B37761372743F8E8ADD77B10064F2ABE5E0"
     "50"
     ),
    ("EM OV CS CA - G3C",
     "04B9F0E0634702A69CA6AADD443CFD62C41B9BA4B20924697D7974E7691A126FB96AFB3E34C2FD3BC5F483061F265DC2"
     "A58436347323510436B28F04F3862363067980E2503E02532D6546235A7165A259A1EF496F741B5FDEE7787208E4B8FA"
     "EF"
     ),
    ("emSign Root TLS CA - G3",
     "045F0FDC3FAB5716C4BE83F5B3061FA090E2EFA0015E8637DB3E3F0431F41978842FB4894F103A4F2658EFD1C17432D7"
     "40C24B14FCBD22090A51CAA7E028E2A24A758795D12C19ECB310CE2C8B7F1214398E86AE36BFB101702CA61FF047435C"
     "0C"
     ),
    ("emSign Root CS CA - G3",
     "044A5F643390F4540FCE83BE9DCF95F3C35867190E1F491F7DF77FEA06492F238F295D054A39DC870A00194E18167A34"
     "3C3A91518932128E969B9F8B5F445398BB3840A51FD7C466E483D5FED9C12D6F282117D09DA05F755B6D95FD1D8455EE"
     "31"
     ),
    ("AAA Certificate Services",
     "3082010A0282010100BE409DF46EE1EA76871C4D45448EBE46C883069DC12AFE181F8EE402FAF3AB5D508A16310B9A06"
     "D0C57022CD492D5463CCB66E68460B53EACB4C24C0BC724EEAF115AEF4549A120AC37AB23360E2DA8955F32258F3DEDC"
     "CFEF8386A28C944F9F68F29890468427C776BFE3CC352C8B5E07646582C048B0A891F9619F762050A891C766B5EB7862"
     "0356F08A1A13EA31A31EA099FD38F6F62732586F07F56BB8FB142BAFB7AACCD6635F738CDA0599A838A8CB17783651AC"
     "E99EF4783A8DCF0FD942E2980CAB2F9F0E01DEEF9F9949F12DDFAC744D1B98B547C5E529D1F99018C7629CBE83C7267B"
     "3E8A25C7C0DD9DE6356810209D8FD8DED2C3849C0D5EE82FC90203010001"
     ),
    ("emSign ECC Root CA - G3",
     "0423A50CB82D12F528F3B1B2DDE20212809E395F494D9FC925345974ECBB061CE7C072AFE8AE2FE141548714A84AB2E8"
     "7C82E65B6AB5DCB375CE8B06D08623BF46D58E0F3F04F4D71C927EF6A563C2F55F8E2E4FA11819022B320A82647D1693"
     "D1"
     ),
)
BAD_PUBLIC_KEYS = {bytes.fromhex(h): name for name, h in _PUBLIC_KEYS}

OID_SKI = bytes.fromhex("551d0e")  # 2.5.29.14
OID_AKI = bytes.fromhex("551d23")  # 2.5.29.35
OID_CN = bytes.fromhex("550403")   # 2.5.4.3

# A block never spans another BEGIN, so a stray or templated BEGIN line cannot
# swallow the real certificate that follows it.
PEM_BLOCK = re.compile(rb"-----BEGIN (?:X509 |TRUSTED )?CERTIFICATE-----((?:(?!-----BEGIN ).)*?)"
                       rb"-----END (?:X509 |TRUSTED )?CERTIFICATE-----", re.S)


class DERError(ValueError):
    pass


def tlv(b, i, end=None):
    """(tag, content_start, content_end) of the DER element at b[i]."""
    end = len(b) if end is None else end
    if i + 2 > end:
        raise DERError("truncated")
    tag = b[i]
    n = b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or i + k > end:
            raise DERError("bad length")
        n = int.from_bytes(b[i:i + k], "big")
        i += k
    if i + n > end:
        raise DERError("element overruns its container")
    return tag, i, i + n


def children(b, start, end):
    i = start
    while i < end:
        t, s, e = tlv(b, i, end)
        yield t, i, s, e
        i = e


def _tbs(der):
    t, s, e = tlv(der, 0)
    if t != 0x30:
        raise DERError("not a certificate")
    t, ts, te = tlv(der, s, e)
    if t != 0x30:
        raise DERError("not a certificate")
    fields = list(children(der, ts, te))
    if fields and fields[0][0] == 0xA0:  # explicit version
        fields = fields[1:]
    if len(fields) < 6:
        raise DERError("short tbsCertificate")
    return fields  # serial, signature, issuer, validity, subject, spki, [extensions]


def cert_length(b, i=0):
    """Length of the certificate starting at b[i] (to split concatenated DER)."""
    _, _, e = tlv(b, i)
    return e - i


def spki_sha256(der):
    _, i, _, e = _tbs(der)[5]
    return hashlib.sha256(der[i:e]).hexdigest().upper()


def cert_sha256(der):
    return hashlib.sha256(der[:cert_length(der)]).hexdigest().upper()


def _extensions(der):
    for t, _, s, e in _tbs(der)[6:]:
        if t == 0xA3:  # [3] extensions
            _, ss, se = tlv(der, s, e)
            for _, _, xs, xe in children(der, ss, se):
                parts = list(children(der, xs, xe))
                oid = der[parts[0][2]:parts[0][3]]
                _, _, vs, ve = parts[-1]  # extnValue OCTET STRING
                yield oid, der[vs:ve]


def subject_key_id(der):
    for oid, val in _extensions(der):
        if oid == OID_SKI:
            _, s, e = tlv(val, 0)
            return val[s:e].hex().upper()
    return None


def authority_key_id(der):
    for oid, val in _extensions(der):
        if oid == OID_AKI:
            _, s, e = tlv(val, 0)
            for t, _, cs, ce in children(val, s, e):
                if t == 0x80:  # [0] keyIdentifier
                    return val[cs:ce].hex().upper()
    return None


def subject_cn(der):
    """For messages only; never used to decide anything."""
    _, s, e = tlv(der, _tbs(der)[4][1])
    for _, _, rs, re_ in children(der, s, e):
        for _, _, as_, ae in children(der, rs, re_):
            parts = list(children(der, as_, ae))
            if der[parts[0][2]:parts[0][3]] == OID_CN:
                return der[parts[1][2]:parts[1][3]].decode("utf-8", "replace")
    return "?"


def pem_blocks(data):
    """(der, None) for each PEM certificate block, or (None, error) for one that
    does not decode, so one bad block never hides the others."""
    for m in PEM_BLOCK.finditer(data):
        # Inside a JSON or source string the line breaks are escapes ("\\n").
        body = re.sub(rb"\\+[nr]", b"", m.group(1))
        try:
            der = base64.b64decode(re.sub(rb"[^A-Za-z0-9+/=]", b"", body), validate=True)
            yield der[:cert_length(der)], None
        except (ValueError, IndexError) as e:
            yield None, "a PEM block that does not decode: %s" % e


def pem_certificates(data):
    """DER of every certificate in PEM text, raising DERError on a bad block. A
    TRUSTED CERTIFICATE block holds the certificate followed by OpenSSL's trust
    settings; only the certificate is kept."""
    out = []
    for der, err in pem_blocks(data):
        if err:
            raise DERError(err)
        out.append(der)
    return out


B64_RUN = re.compile(rb"[A-Za-z0-9+/]{300,}={0,2}")
B64URL_RUN = re.compile(rb"[A-Za-z0-9_-]{300,}={0,2}")
WRAP = re.compile(rb"[ \t]*\r?\n[ \t]*")


def _decode(run, urlsafe=False):
    try:
        run = run.rstrip(b"=")
        return (base64.urlsafe_b64decode if urlsafe else base64.b64decode)(run + b"=" * (-len(run) % 4))
    except ValueError:
        return None  # not base64 after all; it carries nothing to find


def base64_payloads(data):
    """Decoded contents of every long base64 run in data: certificates stored
    without PEM armour, or PEM that was base64-encoded again (Kubernetes
    Secret data, Helm values, CI variables). Runs wrapped across lines (as
    base64(1) writes them) are joined first; since joining can glue a word from
    the line before onto the run, each joined run is also tried at offsets 1-3.
    The URL-safe alphabet is tried too."""
    out = []
    for m in B64_RUN.finditer(data):
        out.append(_decode(m.group(0)))
    joined = WRAP.sub(b"", data)
    if joined != data:
        for m in B64_RUN.finditer(joined):
            out += [_decode(m.group(0)[k:]) for k in range(4)]
    for m in B64URL_RUN.finditer(data):
        if re.search(rb"[_-]", m.group(0)):
            out.append(_decode(m.group(0), urlsafe=True))
    return [p for p in out if p]


def classify(der):
    """(kind, name) for one certificate: kind is 'root', 'intermediate' or None."""
    fp = spki_sha256(der)
    if fp in BAD_ROOTS:
        return "root", BAD_ROOTS[fp]
    if fp in BAD_INTERMEDIATES:
        return "intermediate", BAD_INTERMEDIATES[fp]
    return None, None


def public_keys_in(data):
    """Names of the affected keys whose raw bytes occur anywhere in data."""
    return sorted({name for key, name in BAD_PUBLIC_KEYS.items() if key in data})


def chain_is_compromised(chain):
    """True if a presented chain (list of DER, leaf first) was issued under a
    compromised intermediate: an intermediate's key is in it, or the leaf's AKI
    names one. False if it was not, which for a test host means something on the
    path re-signed it."""
    for der in chain:
        if spki_sha256(der) in BAD_INTERMEDIATES:
            return True
    return bool(chain) and authority_key_id(chain[0]) in BAD_INTERMEDIATE_SKIS
