"""Core scrub logic. Pure functions, no I/O, no logging of input."""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

MASK = "*REDACTED*"

CATEGORIES: dict[str, str] = {
    "ip": "IP addresses",
    "dns": "DNS names / hosts / servers",
    "url": "Non-standard URLs",
    "database": "Database names",
    "api_key": "API keys, tokens, secrets",
    "client_id": "Client IDs",
    "client_secret": "Client secrets",
    "tenant_id": "Tenant IDs",
    "password": "Passwords and user names",
    "guid": "Other GUIDs",
    "entropy": "Other high-entropy strings",
    "custom": "Custom terms and parameters",
}

# Lower index wins when two findings overlap.
_PRIORITY = {c: i for i, c in enumerate([
    "custom", "client_secret", "password", "api_key", "client_id", "tenant_id",
    "database", "url", "dns", "ip", "guid", "entropy",
])}

DEFAULT_ALLOWLIST = [
    "localhost",
    "schemas.microsoft.com", "schemas.xmlsoap.org", "schemas.openxmlformats.org",
    "www.w3.org", "w3.org", "json.schemastore.org", "json-schema.org",
    "login.microsoftonline.com", "login.windows.net", "sts.windows.net",
    "graph.microsoft.com", "management.azure.com", "go.microsoft.com", "aka.ms",
    "learn.microsoft.com", "docs.microsoft.com",
    "core.windows.net", "database.windows.net", "servicebus.windows.net",
    "vault.azure.net", "azurewebsites.net", "onmicrosoft.com",
    "github.com", "nuget.org", "api.nuget.org", "www.nuget.org",
    "registry.npmjs.org", "pypi.org",
    "example.com", "example.org", "*.example.com",
]

_SAFE_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "::", ".", "(local)", "+", "*"}

# ---------------------------------------------------------------- key rules

_KEY_IGNORE = re.compile(
    r"^publickeytoken$|(expir\w*|timeout|lifetime|duration|length|enabled|disabled|required|"
    r"type|format|version|mode|policy|provider|header|scheme|prefix|suffix|pattern|claim|"
    r"path|file|dir|folder|count|size|limit|interval|retry|retries|level|name?space)$"
)

_KEY_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"clientsecret|appsecret|applicationsecret|clientcredential"), "client_secret"),
    (re.compile(r"(clientid|applicationid|appid|audience|objectid|principalid)$"), "client_id"),
    (re.compile(r"(tenant|tenantid|tenantname|directoryid)$"), "tenant_id"),
    (re.compile(r"password|passwd|pwd|passphrase|user(name|id)?$|^uid$|^login$|"
                r"userprincipalname|serviceprincipalname|^upn$|^spn$"), "password"),
    (re.compile(r"apikey|accesskey|accountkey|secretkey|subscriptionkey|privatekey|sharedaccesskey$|"
                r"sharedaccesssignature|sastoken|signingkey|encryptionkey|masterkey|licensekey|"
                r"secret|token$|credential|authkey|instrumentationkey|hmac|salt$|webhook"), "api_key"),
    (re.compile(r"connectionstring|connstr"), "connstr"),
    (re.compile(r"(database|databasename|dbname|catalog|initialcatalog)$|^db$"), "database"),
    (re.compile(r"(server|servername|host|hosts|hostname|datasource|endpoint|endpoints|url|urls|uri|"
                r"uris|baseaddress|address|domain|authority|instance|fqdn|origin|origins|proxy)$|^dns$"), "dns"),
]


def _norm_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]", "", key.lower())


def _last_segment(key: str) -> str:
    return re.split(r"[:./]|__", key.strip())[-1]


def classify_key(key: str) -> str | None:
    norm = _norm_key(_last_segment(key))
    if not norm or _KEY_IGNORE.search(norm):
        return None
    for rx, cat in _KEY_RULES:
        if rx.search(norm):
            return cat
    return None


_TRIVIAL = {
    "true", "false", "null", "none", "nil", "yes", "no", "on", "off", "default",
    "string", "optional", "required", "common", "organizations", "consumers",
}
_PLACEHOLDER = re.compile(
    r"\$\{[^}]*\}|\$\(\w+\)|\{\{.*\}\}|%\w+%|<[^<>]+>|\{[\w\-]+\}|\*+(REDACTED\*+)?|-+|~"
)


def _trivial(v: str) -> bool:
    s = v.strip()
    return not s or s.lower() in _TRIVIAL or bool(_PLACEHOLDER.fullmatch(s))


# --------------------------------------------------------------- patterns

_Q = r"""(?:\\.|(?!(?P=q2))[^\\\n])*"""
KV_PATTERNS = [
    # "key": "value"
    re.compile(r"""(?P<q>["'])(?P<key>[^"'\n]{1,128}?)(?P=q)\s*:\s*(?P<q2>["'])(?P<val>""" + _Q + r")(?P=q2)"),
    # key = "value", key: "value", attr="value"
    re.compile(r"""(?<![\w.\-$])(?P<key>[A-Za-z_$][\w.\-]*(?::[\w.\-]+)*)\s*[:=]\s*(?P<q2>["'])(?P<val>""" + _Q + r")(?P=q2)"),
    # <add key="X" value="Y" />
    re.compile(r"""<add\b[^>]*?\b(?:key|name)\s*=\s*(?P<q>["'])(?P<key>[^"']*)(?P=q)[^>]*?\bvalue\s*=\s*(?P<q2>["'])(?P<val>[^"']*)(?P=q2)""", re.I),
    # <Key value="Y" />  (WCF identity etc.; attributes can span lines)
    re.compile(r"""<(?P<key>[A-Za-z_][\w.\-:]*)(?=[\s/>])[^<>]*?\bvalue\s*=\s*(?P<q2>["'])(?P<val>[^"'<>]*)(?P=q2)"""),
    # <setting name="Key"><value>Y</value></setting>  (.NET applicationSettings)
    re.compile(r"""<setting\b[^<>]*?\bname\s*=\s*(?P<q>["'])(?P<key>[^"']*)(?P=q)[^<>]*>\s*<value>(?P<val>[^<>]*)</value>""", re.I),
    # <Key>value</Key>
    re.compile(r"""<(?P<key>[A-Za-z_][\w.\-:]*)(?:\s[^<>]*)?>(?P<val>[^<>\n]{1,2000})</(?P=key)\s*>"""),
    # key = value / key: value  (yaml, ini, env, properties)
    re.compile(r"""(?m)^[ \t]*(?:export[ \t]+|-[ \t]+)?(?P<key>[A-Za-z_$][\w.\-\[\]]*(?::[\w.\-\[\]]+)*)[ \t]*(?:=|:(?=[ \t]))[ \t]*(?P<val>[^\s"'#;{\[|>&*!](?:[^\n#]|(?<=\S)#)*)"""),
]

_CONN_KEYS = {
    "server": "dns", "data source": "dns", "datasource": "dns", "address": "dns", "addr": "dns",
    "network address": "dns", "host": "dns", "hostname": "dns", "accountname": "dns",
    "endpoint": "url", "blobendpoint": "url", "queueendpoint": "url", "tableendpoint": "url",
    "fileendpoint": "url", "ingestionendpoint": "url", "liveendpoint": "url",
    "initial catalog": "database", "database": "database", "db": "database", "dbname": "database",
    "user id": "password", "userid": "password", "uid": "password", "user": "password",
    "username": "password", "user name": "password", "password": "password", "pwd": "password",
    "accountkey": "api_key", "sharedaccesskey": "api_key", "sharedaccesssignature": "api_key",
    "sastoken": "api_key", "instrumentationkey": "api_key",
    "tenantid": "tenant_id", "tenant id": "tenant_id", "tenant": "tenant_id",
    "clientid": "client_id", "client id": "client_id", "applicationid": "client_id",
    "clientsecret": "client_secret", "client secret": "client_secret",
}
CONN_RE = re.compile(
    r"(?i)(?<![\w\-])(?P<key>" + "|".join(re.escape(k) for k in sorted(_CONN_KEYS, key=len, reverse=True))
    + r""")\s*=\s*(?P<val>"[^"\n]*"|'[^'\n]*'|[^;"'<>\n\r]+)"""
)

SECRET_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"), "api_key"),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]{5,}"), "api_key"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "api_key"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "api_key"),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), "api_key"),
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), "api_key"),
    (re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b"), "api_key"),
    (re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "api_key"),
    (re.compile(r"\b[sr]k_(?:live|test)_[0-9A-Za-z]{16,}\b"), "api_key"),
    (re.compile(r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{20,}\b"), "api_key"),
    (re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), "api_key"),
    (re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), "api_key"),
    (re.compile(r"(?<![\w~.\-])[A-Za-z0-9_~.\-]{3}\dQ~[A-Za-z0-9_~.\-]{31,34}(?![\w~.\-])"), "client_secret"),
    (re.compile(r"(?i)\b(?:bearer|basic)\s+(?P<val>[A-Za-z0-9._~+/\-]{16,}=*)"), "api_key"),
]

GUID_RE = re.compile(r"(?<![0-9A-Fa-f\-])[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}(?![0-9A-Fa-f\-])")

_OCT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4_RE = re.compile(rf"(?<![\w.]){_OCT}(?:\.{_OCT}){{3}}(?:/\d{{1,2}})?(?!\w)(?!\.\d)")
_VERSION_BEFORE = re.compile(r"version\s*[=:]?\s*[\"']?\s*$", re.I)

_H = r"[0-9A-Fa-f]{1,4}"
IPV6_RE = re.compile(
    rf"(?<![\w:.])(?:(?:{_H}:){{7}}{_H}|(?:{_H}:){{1,7}}:|(?:{_H}:){{1,6}}:{_H}|(?:{_H}:){{1,5}}(?::{_H}){{1,2}}|"
    rf"(?:{_H}:){{1,4}}(?::{_H}){{1,3}}|(?:{_H}:){{1,3}}(?::{_H}){{1,4}}|(?:{_H}:){{1,2}}(?::{_H}){{1,5}}|"
    rf"{_H}:(?::{_H}){{1,6}}|:(?::{_H}){{1,7}})(?:%\w+)?(?:/\d{{1,3}})?(?![\w:])"
)

URL_RE = re.compile(r"""\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s"'<>`(){}\[\]\\|^,;]+""")

DNS_RE = re.compile(
    r"(?<![\w\-.])(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z][A-Za-z0-9\-]{0,23}(?![\w\-])"
)

TLDS = set("""
com net org edu gov mil int info biz name pro io co ai app dev cloud tech online site xyz top
me tv cc ly gg eu
se nu no dk fi is ee lv lt de at ch li nl be lu fr es it pt ie uk us ca mx br ar au nz jp cn kr
in sg hk tw ru ua pl cz sk hu ro gr tr za
local localdomain internal intern intra intranet lan corp home ad private
""".split())

_NS_ROOTS = set("""
System Microsoft Serilog NLog Newtonsoft Npgsql Dapper AutoMapper Swashbuckle Hangfire MassTransit
Polly Quartz Autofac Castle NUnit Xunit Moq MediatR FluentValidation Azure Amazon Google Grpc
StackExchange RabbitMQ Confluent Elastic Elasticsearch Oracle MySql MySqlConnector Owin Umbraco
EPiServer log4net Steeltoe Telerik DevExpress Syncfusion
""".split())
_NOT_HOSTS = {"asp.net", "ado.net", "vb.net", "dot.net"}

ENTROPY_RE = re.compile(r"(?<![A-Za-z0-9+/=_\-])[A-Za-z0-9+/_\-]{32,}={0,2}(?![A-Za-z0-9+/=_\-])")


# ---------------------------------------------------------------- helpers

class Allowlist:
    def __init__(self, entries):
        self.exact: set[str] = set()
        self.suffix: list[str] = []
        for raw in entries or []:
            e = raw.strip().lower()
            if not e or e.startswith("#"):
                continue
            e = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", e).split("/")[0]
            if e.startswith("*."):
                self.suffix.append(e[1:])
            else:
                self.exact.add(e)

    def host_ok(self, host: str) -> bool:
        h = host.lower().strip().strip("[]").rstrip(".")
        if h in _SAFE_HOSTS or h in self.exact:
            return True
        return any(h.endswith(s) or h == s[1:] for s in self.suffix)


def _strip_port(hostport: str) -> str:
    if hostport.startswith("["):
        return hostport[1:].split("]", 1)[0]
    if hostport.count(":") == 1:
        h, p = hostport.split(":")
        if p.isdigit() or p == "":
            return h
    return hostport


def _host_of(value: str) -> str:
    v = value.strip()
    if "://" in v:
        authority = re.split(r"[/?#]", v.split("://", 1)[1], maxsplit=1)[0]
        return _strip_port(authority.rsplit("@", 1)[-1])
    v = re.sub(r"^(tcp|np|lpc|admin):", "", v, flags=re.I)
    v = re.split(r"[,\\/]", v, maxsplit=1)[0]
    return _strip_port(v)


def _entropy(s: str) -> float:
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _namespace_like(labels: list[str]) -> bool:
    if labels[0] in _NS_ROOTS:
        return True
    if any(re.search(r"[a-z][A-Z]", lbl) for lbl in labels):
        return True
    return all(re.fullmatch(r"[A-Z][a-z0-9]+", lbl) for lbl in labels)


# ---------------------------------------------------------------- engine

@dataclass
class ScrubResult:
    text: str
    findings: list[dict] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)


class _Scrubber:
    def __init__(self, text, categories, allowlist, custom_terms, custom_keys=None):
        self.text = text
        self.enabled = set(categories) if categories is not None else set(CATEGORIES)
        self.allow = Allowlist(DEFAULT_ALLOWLIST if allowlist is None else allowlist)
        self.terms = [t.strip() for t in (custom_terms or []) if t.strip() and not t.strip().startswith("#")]
        self.keys = [k.strip() for k in (custom_keys or []) if k.strip() and not k.strip().startswith("#")]
        self.key_norms = {_norm_key(k) for k in self.keys} - {""}
        self.spans: list[tuple[int, int, str]] = []

    def _custom_key(self, key: str) -> bool:
        return bool(self.key_norms) and (
            _norm_key(_last_segment(key)) in self.key_norms or _norm_key(key) in self.key_norms)

    def add(self, s: int, e: int, cat: str):
        if e > s and cat in self.enabled:
            self.spans.append((s, e, cat))

    def _location_safe(self, val: str) -> bool:
        v = val.strip()
        return v.lower().startswith("(localdb)") or self.allow.host_ok(_host_of(v))

    # -- detectors

    def key_values(self):
        for pat in KV_PATTERNS:
            for m in pat.finditer(self.text):
                raw = m.group("val")
                val = raw.strip()
                if self._custom_key(m.group("key")):
                    if val and not re.fullmatch(r"\*+(REDACTED\*+)?", val):
                        s = m.start("val") + (len(raw) - len(raw.lstrip()))
                        self.add(s, s + len(val), "custom")
                    continue
                cat = classify_key(m.group("key"))
                if not cat or cat == "connstr":
                    continue
                if _trivial(val):
                    continue
                if "=" in val and ";" in val:
                    continue  # looks like a connection string; field detector handles it
                if cat == "dns":
                    if re.search(r"[;\s]", val) or val.isdigit() or self._location_safe(val):
                        continue
                    if "://" in val:
                        cat = "url"
                if cat == "database" and val.isdigit():
                    continue
                s = m.start("val") + (len(raw) - len(raw.lstrip()))
                self.add(s, s + len(val), cat)

    def conn_fields(self):
        for m in CONN_RE.finditer(self.text):
            cat = _CONN_KEYS[m.group("key").lower()]
            raw = m.group("val")
            s, e = m.span("val")
            if raw[:1] in "\"'":
                s, e, raw = s + 1, e - 1, raw[1:-1]
            val = raw.strip()
            if _trivial(val):
                continue
            if cat in ("dns", "url"):
                if self._location_safe(val):
                    continue
                if cat == "dns" and "://" in val:
                    cat = "url"
            s += len(raw) - len(raw.lstrip())
            self.add(s, s + len(val), cat)
        if self.keys:
            names = "|".join(re.escape(k) for k in sorted(set(self.keys), key=len, reverse=True))
            rx = re.compile(r"(?i)(?<![\w\-])(?:" + names + r""")\s*=\s*(?P<val>[^;"'<>\n\r]+)""")
            for m in rx.finditer(self.text):
                raw = m.group("val")
                s = m.start("val") + (len(raw) - len(raw.lstrip()))
                if raw.strip():
                    self.add(s, s + len(raw.strip()), "custom")

    def secrets(self):
        for rx, cat in SECRET_PATTERNS:
            for m in rx.finditer(self.text):
                g = "val" if "val" in rx.groupindex else 0
                self.add(*m.span(g), cat)

    def urls(self):
        for m in URL_RE.finditer(self.text):
            url = m.group(0).rstrip(".,:;!?)'\"")
            authority = re.split(r"[/?#]", url.split("://", 1)[1], maxsplit=1)[0]
            userinfo = authority.rsplit("@", 1)[0] if "@" in authority else ""
            host = _strip_port(authority.rsplit("@", 1)[-1])
            if ":" in userinfo or not self.allow.host_ok(host):
                self.add(m.start(), m.start() + len(url), "url")

    def dns(self):
        for m in DNS_RE.finditer(self.text):
            name = m.group(0)
            labels = name.split(".")
            if len(labels) < 2 or labels[-1].lower() not in TLDS:
                continue
            if name.lower() in _NOT_HOSTS or _namespace_like(labels) or self.allow.host_ok(name):
                continue
            self.add(*m.span(), "dns")

    def ips(self):
        for m in IPV4_RE.finditer(self.text):
            ip = m.group(0)
            if self.allow.host_ok(ip.split("/")[0]):
                continue
            if _VERSION_BEFORE.search(self.text[max(0, m.start() - 20):m.start()]):
                continue
            self.add(*m.span(), "ip")
        for m in IPV6_RE.finditer(self.text):
            ip = m.group(0)
            if ("::" not in ip and ip.count(":") < 7) or len(ip) < 6:
                continue
            if self.allow.host_ok(ip.split("/")[0]):
                continue
            self.add(*m.span(), "ip")

    def guids(self):
        for m in GUID_RE.finditer(self.text):
            if m.group(0).strip("0-") == "":
                continue  # all-zero GUID
            self.add(*m.span(), "guid")

    def high_entropy(self):
        for m in ENTROPY_RE.finditer(self.text):
            s = m.group(0)
            core = s.rstrip("=")
            if GUID_RE.fullmatch(core):
                continue
            if sum(ch.isdigit() for ch in core) < 2:
                continue
            is_hex = bool(re.fullmatch(r"[0-9a-fA-F]+", core))
            mixed = bool(re.search(r"[a-z]", core) and re.search(r"[A-Z]", core))
            if not (is_hex or mixed):
                continue
            if re.search(r"[/_\-]", core) and len(re.findall(r"[a-z]{4,}", core)) >= 3:
                continue  # path or identifier made of words
            if _entropy(core) < 3.5:
                continue
            self.add(*m.span(), "entropy")

    def custom(self):
        if not self.terms:
            return
        rx = re.compile("|".join(re.escape(t) for t in sorted(set(self.terms), key=len, reverse=True)), re.I)
        for m in rx.finditer(self.text):
            self.add(*m.span(), "custom")

    # -- assemble

    def run(self) -> ScrubResult:
        for det in (self.custom, self.key_values, self.conn_fields, self.secrets,
                    self.urls, self.dns, self.ips, self.guids, self.high_entropy):
            det()

        merged: list[list] = []
        for s, e, c in sorted(self.spans, key=lambda x: (x[0], -x[1])):
            if merged and s < merged[-1][1]:
                last = merged[-1]
                last[1] = max(last[1], e)
                if _PRIORITY[c] < _PRIORITY[last[2]]:
                    last[2] = c
            else:
                merged.append([s, e, c])

        out, pos, found = [], 0, Counter()
        for s, e, c in merged:
            out.append(self.text[pos:s])
            out.append(MASK)
            found[(c, self.text[s:e])] += 1
            pos = e
        out.append(self.text[pos:])

        counts: Counter = Counter()
        findings = []
        for (c, v), n in sorted(found.items(), key=lambda x: (_PRIORITY[x[0][0]], x[0][1].lower())):
            counts[c] += n
            findings.append({"category": c, "label": CATEGORIES[c], "value": v, "count": n})
        return ScrubResult("".join(out), findings, dict(counts))


def scrub(text: str, categories=None, allowlist=None, custom_terms=None, custom_keys=None) -> ScrubResult:
    """Return the text with sensitive values replaced by MASK.

    custom_terms: literal text to redact anywhere.
    custom_keys: parameter names whose values are redacted.
    """
    return _Scrubber(text, categories, allowlist, custom_terms, custom_keys).run()
