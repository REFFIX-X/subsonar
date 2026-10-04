"""Offline IP intelligence — country, ASN and AS organisation, no API, no key.

Why offline
-----------
Every other way to turn an address into a country flag means handing the address
to a third party (``ipapi``, ``ipinfo``, Google, …).  For a tool whose whole DNS
design exists to keep the target from correlating queries, that would be absurd:
the scanner would leak every resolved address of the target to an unrelated
company, in bulk, from one IP.

So the data is fetched **once** and used locally:

* primary source — `ip2asn.com <https://iptoasn.com/>`_, a free daily BGP dump
  (``ip2asn-v4-u32.tsv.gz`` + ``ip2asn-v6.tsv.gz``) mapping every announced
  range to its autonomous system, the AS organisation and the country,
* fallback source — the five RIR *delegation* files (RIPE, ARIN, APNIC, LACNIC,
  AFRINIC), which are country-only but served by the registries themselves.

Both are parsed into a compact SQLite index under ``.subsonar_cache/geoip`` and
every lookup after that is a local indexed query (~µs).  Nothing about a scan
ever leaves the machine.

Public API
----------
``ensure_index_async()`` builds/refreshes the index, ``enrich(ip)`` answers one
address, and the presentation helpers (:func:`flag_emoji`,
:func:`flag_image_url`, :func:`country_name`) are what the CLI/TUI/dashboard use
to draw the little flag next to a resolved IP.
"""

from __future__ import annotations

import asyncio
import gzip
import io
import ipaddress
import json
import logging
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence
from urllib.request import Request, urlopen

from .config import CACHE_DIR

_log = logging.getLogger("subsonar.geoip")

#: Bump when the table layout changes so stale indexes are rebuilt.
SCHEMA_VERSION = 2
DIR_NAME = "geoip"
INDEX_FILENAME = "ip2asn.sqlite3"
META_FILENAME = "ip2asn.json"
#: An index older than this is refreshed on the next scan (BGP changes daily).
DEFAULT_MAX_AGE_DAYS = 21.0

USER_AGENT = "subsonar-geoip/1.1 (+offline country+ASN index; no API key)"

#: Environment switch that forbids the one-off download entirely (CI, air-gapped
#: hosts, and the test suite use it).  An existing index is still used.
OFFLINE_ENV = "SUBSONAR_GEOIP_OFFLINE"


def downloads_forbidden() -> bool:
    """``True`` when :data:`OFFLINE_ENV` is set to a truthy value."""
    return str(os.environ.get(OFFLINE_ENV, "")).strip().lower() not in {
        "",
        "0",
        "false",
        "no",
        "off",
    }

#: ``name -> (url, format)`` where format is ``v4u32``, ``v4``, ``v6`` or ``rir``.
SOURCES: tuple[tuple[str, str, str], ...] = (
    (
        "iptoasn-v4u32",
        "https://iptoasn.com/data/ip2asn-v4-u32.tsv.gz",
        "v4u32",
    ),
    ("iptoasn-v6", "https://iptoasn.com/data/ip2asn-v6.tsv.gz", "v6"),
)

#: Country-only fallback, used when ip2asn.com cannot be reached.
RIR_SOURCES: tuple[tuple[str, str, str], ...] = (
    (
        "ripencc",
        "https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest",
        "rir",
    ),
    (
        "arin",
        "https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest",
        "rir",
    ),
    (
        "apnic",
        "https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest",
        "rir",
    ),
    (
        "lacnic",
        "https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest",
        "rir",
    ),
    (
        "afrinic",
        "https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest",
        "rir",
    ),
)

#: ``ISO-3166-1 alpha-2 -> English name`` (plus the handful of pseudo-codes that
#: actually occur in BGP / RIR data).  Bundled so no lookup table is downloaded.
_COUNTRY_DATA = """
AD Andorra
AE United Arab Emirates
AF Afghanistan
AG Antigua and Barbuda
AI Anguilla
AL Albania
AM Armenia
AO Angola
AQ Antarctica
AR Argentina
AS American Samoa
AT Austria
AU Australia
AW Aruba
AX Aland Islands
AZ Azerbaijan
BA Bosnia and Herzegovina
BB Barbados
BD Bangladesh
BE Belgium
BF Burkina Faso
BG Bulgaria
BH Bahrain
BI Burundi
BJ Benin
BL Saint Barthelemy
BM Bermuda
BN Brunei Darussalam
BO Bolivia
BQ Bonaire, Sint Eustatius and Saba
BR Brazil
BS Bahamas
BT Bhutan
BV Bouvet Island
BW Botswana
BY Belarus
BZ Belize
CA Canada
CC Cocos (Keeling) Islands
CD Congo, Democratic Republic of the
CF Central African Republic
CG Congo
CH Switzerland
CI Cote d'Ivoire
CK Cook Islands
CL Chile
CM Cameroon
CN China
CO Colombia
CR Costa Rica
CU Cuba
CV Cabo Verde
CW Curacao
CX Christmas Island
CY Cyprus
CZ Czechia
DE Germany
DJ Djibouti
DK Denmark
DM Dominica
DO Dominican Republic
DZ Algeria
EC Ecuador
EE Estonia
EG Egypt
EH Western Sahara
ER Eritrea
ES Spain
ET Ethiopia
FI Finland
FJ Fiji
FK Falkland Islands
FM Micronesia
FO Faroe Islands
FR France
GA Gabon
GB United Kingdom
GD Grenada
GE Georgia
GF French Guiana
GG Guernsey
GH Ghana
GI Gibraltar
GL Greenland
GM Gambia
GN Guinea
GP Guadeloupe
GQ Equatorial Guinea
GR Greece
GS South Georgia and the South Sandwich Islands
GT Guatemala
GU Guam
GW Guinea-Bissau
GY Guyana
HK Hong Kong
HM Heard Island and McDonald Islands
HN Honduras
HR Croatia
HT Haiti
HU Hungary
ID Indonesia
IE Ireland
IL Israel
IM Isle of Man
IN India
IO British Indian Ocean Territory
IQ Iraq
IR Iran
IS Iceland
IT Italy
JE Jersey
JM Jamaica
JO Jordan
JP Japan
KE Kenya
KG Kyrgyzstan
KH Cambodia
KI Kiribati
KM Comoros
KN Saint Kitts and Nevis
KP Korea, Democratic People's Republic of
KR Korea, Republic of
KW Kuwait
KY Cayman Islands
KZ Kazakhstan
LA Lao People's Democratic Republic
LB Lebanon
LC Saint Lucia
LI Liechtenstein
LK Sri Lanka
LR Liberia
LS Lesotho
LT Lithuania
LU Luxembourg
LV Latvia
LY Libya
MA Morocco
MC Monaco
MD Moldova
ME Montenegro
MF Saint Martin (French part)
MG Madagascar
MH Marshall Islands
MK North Macedonia
ML Mali
MM Myanmar
MN Mongolia
MO Macao
MP Northern Mariana Islands
MQ Martinique
MR Mauritania
MS Montserrat
MT Malta
MU Mauritius
MV Maldives
MW Malawi
MX Mexico
MY Malaysia
MZ Mozambique
NA Namibia
NC New Caledonia
NE Niger
NF Norfolk Island
NG Nigeria
NI Nicaragua
NL Netherlands
NO Norway
NP Nepal
NR Nauru
NU Niue
NZ New Zealand
OM Oman
PA Panama
PE Peru
PF French Polynesia
PG Papua New Guinea
PH Philippines
PK Pakistan
PL Poland
PM Saint Pierre and Miquelon
PN Pitcairn
PR Puerto Rico
PS Palestine, State of
PT Portugal
PW Palau
PY Paraguay
QA Qatar
RE Reunion
RO Romania
RS Serbia
RU Russian Federation
RW Rwanda
SA Saudi Arabia
SB Solomon Islands
SC Seychelles
SD Sudan
SE Sweden
SG Singapore
SH Saint Helena, Ascension and Tristan da Cunha
SI Slovenia
SJ Svalbard and Jan Mayen
SK Slovakia
SL Sierra Leone
SM San Marino
SN Senegal
SO Somalia
SR Suriname
SS South Sudan
ST Sao Tome and Principe
SV El Salvador
SX Sint Maarten (Dutch part)
SY Syrian Arab Republic
SZ Eswatini
TC Turks and Caicos Islands
TD Chad
TF French Southern Territories
TG Togo
TH Thailand
TJ Tajikistan
TK Tokelau
TL Timor-Leste
TM Turkmenistan
TN Tunisia
TO Tonga
TR Turkiye
TT Trinidad and Tobago
TV Tuvalu
TW Taiwan
TZ Tanzania, United Republic of
UA Ukraine
UG Uganda
UM United States Minor Outlying Islands
US United States
UY Uruguay
UZ Uzbekistan
VA Holy See
VC Saint Vincent and the Grenadines
VE Venezuela
VG Virgin Islands, British
VI Virgin Islands, U.S.
VN Viet Nam
VU Vanuatu
WF Wallis and Futuna
WS Samoa
YE Yemen
YT Mayotte
ZA South Africa
ZM Zambia
ZW Zimbabwe
A1 Anonymous Proxy
A2 Satellite Provider
AP Asia-Pacific (APNIC)
EU Europe (RIPE NCC)
O1 Other
T1 Tor exit node
XK Kosovo
ZZ Unknown / not allocated
"""

_COUNTRIES: dict[str, str] = {}
for _line in _COUNTRY_DATA.strip().splitlines():
    _code, _, _name = _line.strip().partition(" ")
    if _code:
        _COUNTRIES[_code.upper()] = _name.strip()
del _line, _code, _name

#: Read-only view of the bundled ISO table.
COUNTRIES = _COUNTRIES


# --------------------------------------------------------------------------- #
# Presentation helpers
# --------------------------------------------------------------------------- #


def country_name(code: str | None) -> str | None:
    """English name for an ISO-3166-1 alpha-2 code (``None`` when unknown)."""
    if not code:
        return None
    key = str(code).strip().upper()
    if not key or key in {"--", "N/A", "UNKNOWN"}:
        return None
    return COUNTRIES.get(key) or key


def flag_emoji(code: str | None) -> str:
    """Regional-indicator flag for *code* — ``""`` when it cannot be drawn.

    Renders as a real flag on macOS/Linux/Chrome; Windows terminals without a
    flag font show the two letters, which is still perfectly readable.
    """
    if not code:
        return ""
    key = str(code).strip().upper()
    if len(key) != 2 or not key.isalpha() or not key.isascii():
        return ""
    return "".join(chr(0x1F1E6 + (ord(char) - ord("A"))) for char in key)


def flag_image_url(code: str | None, size: str = "20x15") -> str | None:
    """Small PNG flag from flagcdn.com (free, keyless, 2-letter code only).

    Only the *country code* is ever requested — the address being scanned is
    never sent anywhere.  Returns ``None`` for codes that have no flag.
    """
    if not code:
        return None
    key = str(code).strip().lower()
    if len(key) != 2 or not key.isalpha() or not key.isascii():
        return None
    return f"https://flagcdn.com/{size}/{key}.png"


def _key_v4(value: int) -> str:
    return f"{value:08x}"


def _key_v6(value: int) -> str:
    return f"{value:032x}"


def address_key(address: str) -> tuple[int, str] | None:
    """Normalise *address* to ``(family, sortable-hex-key)`` (``None`` = n/a).

    IPv4 keys are 8 hex digits, IPv6 keys 32 — both sort correctly as TEXT,
    which is what lets one table answer both families.
    """
    text = str(address or "").strip()
    if not text:
        return None
    try:
        parsed = ipaddress.ip_address(text.split("%")[0])
    except ValueError:
        return None
    if parsed.version == 4:
        return (4, _key_v4(int(parsed)))
    return (6, _key_v6(int(parsed)))


def is_enrichable(address: str) -> bool:
    """``False`` for private / loopback / reserved addresses (nothing to look up)."""
    text = str(address or "").strip()
    if not text:
        return False
    try:
        parsed = ipaddress.ip_address(text.split("%")[0])
    except ValueError:
        return False
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )




# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class GeoRecord:
    """What the offline index knows about one address."""

    ip: str
    family: int = 4
    country_code: str = ""
    asn: int = 0
    as_org: str = ""
    range_start: int = 0
    range_end: int = 0
    source: str = ""

    @property
    def country(self) -> str | None:
        return country_name(self.country_code)

    @property
    def flag(self) -> str:
        return flag_emoji(self.country_code)

    @property
    def as_label(self) -> str | None:
        if not self.asn:
            return None
        return f"AS{self.asn}" + (f" {self.as_org}" if self.as_org else "")

    @property
    def label(self) -> str:
        """``🇩🇰 DK · AS15169 GOOGLE LLC`` — the one-line cell the UI shows."""
        head = f"{self.flag} {self.country_code}".strip() or "??"
        asn = self.as_label
        return f"{head} · {asn}" if asn else head

    @property
    def range_label(self) -> str:
        """Human form of the matched range (``23.227.38.0 - 23.227.38.255``)."""
        if not self.range_start and not self.range_end:
            return ""
        try:
            if self.family == 4:
                start = str(ipaddress.IPv4Address(self.range_start))
                end = str(ipaddress.IPv4Address(self.range_end))
            else:
                start = str(ipaddress.IPv6Address(self.range_start))
                end = str(ipaddress.IPv6Address(self.range_end))
        except Exception:  # pragma: no cover - defensive
            return ""
        return f"{start} - {end}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "country_code": self.country_code or None,
            "country": self.country,
            "asn": self.asn or None,
            "as_org": self.as_org or None,
            "range": self.range_label,
            "source": self.source or None,
        }


class GeoError(RuntimeError):
    """Raised when the offline index cannot be built or read."""


# --------------------------------------------------------------------------- #
# Parsers (pure functions — the network layer is separate)
# --------------------------------------------------------------------------- #


def _clean_country(value: str) -> str:
    text = str(value or "").strip().upper()
    if text in {"", "*", "-", "--", "N/A", "NONE"}:
        return ""
    return text[:8]


def parse_line(line: str, fmt: str) -> tuple[int, str, str, int, str, str] | None:
    """Parse one data line into ``(family, start_key, end_key, asn, cc, org)``.

    ``fmt`` is ``v4u32`` (dotted-free ip2asn), ``v4``/``v6`` (ip2asn dotted or
    colon form) or ``rir`` (RIR ``delegated-*-extended`` pipe format).
    """
    raw = str(line or "").strip()
    if not raw or raw.startswith("#") or raw.startswith(";"):
        return None
    if fmt == "rir":
        return parse_rir_line(raw)
    parts = raw.split("\t")
    if len(parts) < 3:
        return None
    try:
        asn = int(parts[2].strip() or 0)
    except ValueError:
        return None
    country = _clean_country(parts[3] if len(parts) > 3 else "")
    org = (parts[4].strip() if len(parts) > 4 else "") or ""
    start_text = parts[0].strip()
    end_text = parts[1].strip()
    if fmt == "v4u32":
        try:
            lower, upper = int(start_text), int(end_text)
        except ValueError:
            return None
        if not 0 <= lower <= upper <= 0xFFFFFFFF:
            return None
        return (4, _key_v4(lower), _key_v4(upper), asn, country, org)
    start = address_key(start_text)
    end = address_key(end_text)
    if start is None or end is None or start[0] != end[0] or start[1] > end[1]:
        return None
    if fmt == "v4" and start[0] != 4:
        return None
    if fmt == "v6" and start[0] != 6:
        return None
    return (start[0], start[1], end[1], asn, country, org)


def parse_rir_line(raw: str) -> tuple[int, str, str, int, str, str] | None:
    """Parse one ``registry|cc|type|start|count|date|status|…`` RIR record."""
    parts = raw.split("|")
    if len(parts) < 7:
        return None
    kind = parts[2].strip().lower()
    if kind not in {"ipv4", "ipv6"}:
        return None
    start_text = parts[3].strip()
    count_text = parts[4].strip()
    if not start_text or not count_text:
        return None
    start = address_key(start_text)
    if start is None:
        return None
    try:
        size = int(count_text)
    except ValueError:
        return None
    if size <= 0:
        return None
    family, start_key = start
    if family == 4:
        # IPv4 RIR records carry an *address count* in the value field.
        span = int(start_key, 16) + size - 1
        if span > 0xFFFFFFFF:
            return None
        end_key = _key_v4(span)
    else:
        # IPv6 RIR records carry a *prefix length*, not a count: ``2400:cb00::|32``
        # means 2**(128-32) addresses.  Treating 32 as a count collapsed the
        # range to nothing and mis-mapped the whole allocation.
        if size > 128:
            return None
        span = int(start_key, 16) + (1 << (128 - size)) - 1
        if span > (1 << 128) - 1:
            return None
        end_key = _key_v6(span)
    return (family, start_key, end_key, 0, _clean_country(parts[1]), "")


# --------------------------------------------------------------------------- #
# Index
# --------------------------------------------------------------------------- #


def index_dir(cache_dir: Path | str | None = None) -> Path:
    """Directory holding the downloaded data + the built SQLite index."""
    return Path(cache_dir or CACHE_DIR) / DIR_NAME


def index_path(cache_dir: Path | str | None = None) -> Path:
    return index_dir(cache_dir) / INDEX_FILENAME


def meta_path(cache_dir: Path | str | None = None) -> Path:
    return index_dir(cache_dir) / META_FILENAME


def read_meta(cache_dir: Path | str | None = None) -> dict[str, Any]:
    """Index metadata (schema, build time, counts, sources) or ``{}``."""
    path = meta_path(cache_dir)
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # pragma: no cover - corrupt meta is not fatal
        return {}
    return payload if isinstance(payload, dict) else {}


def index_available(cache_dir: Path | str | None = None) -> bool:
    """``True`` when a usable index is already on disk."""
    path = index_path(cache_dir)
    if not path.is_file():
        return False
    meta = read_meta(cache_dir)
    return not meta or int(meta.get("schema", SCHEMA_VERSION)) == SCHEMA_VERSION


def index_age_days(cache_dir: Path | str | None = None) -> float | None:
    """Age of the index in days (``None`` when there is no index)."""
    meta = read_meta(cache_dir)
    built = meta.get("built_at")
    if isinstance(built, (int, float)):
        return max(0.0, (time.time() - float(built)) / 86400.0)
    path = index_path(cache_dir)
    if path.is_file():
        return max(0.0, (time.time() - path.stat().st_mtime) / 86400.0)
    return None


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS ranges (
    family  INTEGER NOT NULL,
    start   TEXT    NOT NULL,
    end     TEXT    NOT NULL,
    asn     INTEGER NOT NULL DEFAULT 0,
    cc      TEXT    NOT NULL DEFAULT '',
    org     TEXT    NOT NULL DEFAULT '',
    source  TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS ranges_lookup ON ranges (family, start);
"""


class GeoIndex:
    """Read-only, lazily connected view of the built SQLite index."""

    def __init__(self, path: Path | str, meta: dict[str, Any] | None = None) -> None:
        self.path = Path(path)
        self.meta: dict[str, Any] = dict(meta or {})
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()

    # -- lifecycle ---------------------------------------------------------- #
    @property
    def connection(self) -> sqlite3.Connection:
        with self._lock:
            if self._conn is None:
                self._conn = sqlite3.connect(
                    f"file:{self.path.as_posix()}?mode=ro",
                    uri=True,
                    check_same_thread=False,
                )
                self._conn.row_factory = sqlite3.Row
            return self._conn

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.close()
                finally:
                    self._conn = None

    def __enter__(self) -> "GeoIndex":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # -- metadata ----------------------------------------------------------- #
    @property
    def built_at(self) -> float:
        value = self.meta.get("built_at")
        return float(value) if isinstance(value, (int, float)) else 0.0

    @property
    def age_days(self) -> float | None:
        if not self.built_at:
            return None
        return max(0.0, (time.time() - self.built_at) / 86400.0)

    @property
    def sources(self) -> list[str]:
        value = self.meta.get("sources")
        return [str(item) for item in value] if isinstance(value, list) else []

    @property
    def count(self) -> int:
        try:
            row = self.connection.execute("SELECT COUNT(*) FROM ranges").fetchone()
        except sqlite3.Error:  # pragma: no cover - unreadable index
            return 0
        return int(row[0] if row else 0)

    def family_counts(self) -> dict[int, int]:
        out: dict[int, int] = {}
        try:
            rows = self.connection.execute(
                "SELECT family, COUNT(*) FROM ranges GROUP BY family"
            ).fetchall()
        except sqlite3.Error:  # pragma: no cover
            return out
        for row in rows:
            out[int(row[0])] = int(row[1])
        return out


    # -- lookups ------------------------------------------------------------ #
    def lookup(self, address: str) -> GeoRecord | None:
        """Country + ASN for *address* (``None`` when unknown / not routable)."""
        key = address_key(address)
        if key is None:
            return None
        family, needle = key
        try:
            row = self.connection.execute(
                "SELECT start, end, asn, cc, org, source FROM ranges "
                "WHERE family = ? AND start <= ? ORDER BY start DESC LIMIT 1",
                (family, needle),
            ).fetchone()
        except sqlite3.Error:  # pragma: no cover - unreadable index
            return None
        if row is None or str(row["end"]) < needle:
            return None
        return GeoRecord(
            ip=str(address),
            family=family,
            country_code=str(row["cc"] or ""),
            asn=int(row["asn"] or 0),
            as_org=str(row["org"] or ""),
            range_start=int(str(row["start"]), 16),
            range_end=int(str(row["end"]), 16),
            source=str(row["source"] or ""),
        )

    def lookup_many(self, addresses: Sequence[str] | set[str]) -> dict[str, GeoRecord]:
        """Enrich several addresses (deduplicated, private ones skipped)."""
        out: dict[str, GeoRecord] = {}
        for address in dict.fromkeys(str(item) for item in addresses):
            if not is_enrichable(address):
                continue
            record = self.lookup(address)
            if record is not None:
                out[address] = record
        return out

    def stats(self) -> dict[str, Any]:
        counts = self.family_counts()
        return {
            "path": str(self.path),
            "built_at": self.built_at or None,
            "age_days": round(self.age_days, 2) if self.age_days is not None else None,
            "entries": self.count,
            "ipv4": counts.get(4, 0),
            "ipv6": counts.get(6, 0),
            "sources": self.sources,
            "schema": self.meta.get("schema", SCHEMA_VERSION),
        }


#: ``path -> GeoIndex`` so repeated lookups reuse one connection.
_INDEX_CACHE: dict[str, GeoIndex] = {}


def load_index(
    cache_dir: Path | str | None = None, *, force: bool = False
) -> GeoIndex | None:
    """Return the index from disk (no download); ``None`` when unavailable."""
    path = index_path(cache_dir)
    key = str(path.resolve()) if path.exists() else str(path)
    if not force and key in _INDEX_CACHE:
        return _INDEX_CACHE[key]
    if not path.is_file() or not index_available(cache_dir):
        return None
    index = GeoIndex(path, read_meta(cache_dir))
    if index.count == 0:
        index.close()
        return None
    previous = _INDEX_CACHE.get(key)
    if previous is not None:
        # A refresh must not leak the previous SQLite connection.
        previous.close()
    _INDEX_CACHE[key] = index
    return index


def reset_cache() -> None:
    """Close and forget every cached index (used by tests)."""
    for index in list(_INDEX_CACHE.values()):
        index.close()
    _INDEX_CACHE.clear()



# --------------------------------------------------------------------------- #
# Download / build
# --------------------------------------------------------------------------- #


class _Prefixed(io.RawIOBase):
    """A readable stream that starts with already-consumed bytes.

    Used to sniff the first two bytes of a response for the gzip magic number
    without buffering the whole (30 MB) delegation file in memory.
    """

    def __init__(self, head: bytes, stream: Any) -> None:
        self._head = bytes(head)
        self._stream = stream

    def readable(self) -> bool:  # pragma: no cover - trivial
        return True

    def readinto(self, buffer: Any) -> int:
        if self._head:
            size = min(len(buffer), len(self._head))
            buffer[:size] = self._head[:size]
            self._head = self._head[size:]
            return size
        chunk = self._stream.read(len(buffer))
        if not chunk:
            return 0
        buffer[: len(chunk)] = chunk
        return len(chunk)


def open_source(url: str, timeout: float = 120.0) -> io.TextIOWrapper:
    """Open *url* as a text stream, transparently gunzipping it.

    Streaming matters: the RIR fallback files are ~35 MB of text each and the
    BGP dump ~60 MB decompressed, so nothing is ever read into one string.
    """
    request = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    response = urlopen(request, timeout=timeout)
    head = response.read(4)
    binary = io.BufferedReader(_Prefixed(head, response), buffer_size=1 << 16)
    stream: Any = binary
    if head[:2] == b"\x1f\x8b":
        stream = gzip.GzipFile(fileobj=binary)
    return io.TextIOWrapper(stream, encoding="utf-8", errors="replace")


def iter_source_rows(
    url: str, fmt: str, *, source: str = "", timeout: float = 120.0
) -> Iterator[tuple[Any, ...]]:
    """Yield every parsed range in one source, skipping malformed lines."""
    handle = open_source(url, timeout=timeout)
    try:
        for line in handle:
            row = parse_line(line, fmt)
            if row is None:
                continue
            yield (*row, source) if source else row
    finally:
        handle.close()


def _insert_rows(
    connection: sqlite3.Connection, rows: Iterator[tuple[Any, ...]], batch: int = 20000
) -> int:
    """Insert rows in batches; returns the number written."""
    total = 0
    buffer: list[tuple[Any, ...]] = []
    for row in rows:
        asn = int(row[3] or 0)
        country = str(row[4] or "")
        org = str(row[5] or "")
        label = str(row[6]) if len(row) > 6 else ""
        if not country and not asn and not org:
            continue  # nothing to report for this range
        buffer.append(
            (int(row[0]), str(row[1]), str(row[2]), asn, country, org, label)
        )
        if len(buffer) >= batch:
            connection.executemany(
                "INSERT INTO ranges (family, start, end, asn, cc, org, source) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                buffer,
            )
            total += len(buffer)
            buffer.clear()
    if buffer:
        connection.executemany(
            "INSERT INTO ranges (family, start, end, asn, cc, org, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            buffer,
        )
        total += len(buffer)
    return total



def build_index(
    cache_dir: Path | str | None = None,
    *,
    bus: Any = None,
    sources: Sequence[tuple[str, str, str]] | None = None,
    include_rir_fallback: bool = True,
    timeout: float = 180.0,
) -> dict[str, Any]:
    """Download the free dumps and (re)build the SQLite index.

    Raises :class:`GeoError` when not a single range could be loaded.  The
    previous index is only replaced once the new one is complete, so an aborted
    build never destroys a working index.
    """
    directory = index_dir(cache_dir)
    directory.mkdir(parents=True, exist_ok=True)
    target = index_path(cache_dir)
    temporary = directory / (INDEX_FILENAME + ".building")
    for path in (temporary, Path(str(temporary) + "-journal")):
        if path.exists():  # pragma: no cover - leftover from an aborted build
            path.unlink()

    primary = tuple(sources) if sources is not None else SOURCES
    used: list[str] = []
    counts: dict[int, int] = {4: 0, 6: 0}
    total = 0
    connection = sqlite3.connect(temporary)
    try:
        connection.executescript(_SCHEMA_SQL)
        for name, url, fmt in primary:
            try:
                written = _insert_rows(
                    connection, iter_source_rows(url, fmt, source=name, timeout=timeout)
                )
            except Exception as exc:  # noqa: BLE001 - one dead source is fine
                _warn(bus, f"Geo source {name} failed ({exc.__class__.__name__}: {exc})")
                continue
            if written:
                used.append(name)
                total += written
                _info(bus, f"Geo source {name}: {written:,} range(s) loaded")
        if total == 0 and include_rir_fallback:
            _info(bus, "Falling back to the five RIR delegation files (country only)")
            for name, url, fmt in RIR_SOURCES:
                try:
                    written = _insert_rows(
                        connection,
                        iter_source_rows(url, fmt, source=name, timeout=timeout),
                    )
                except Exception as exc:  # noqa: BLE001
                    _warn(
                        bus,
                        f"Geo source {name} failed ({exc.__class__.__name__}: {exc})",
                    )
                    continue
                if written:
                    used.append(name)
                    total += written
                    _info(bus, f"Geo source {name}: {written:,} range(s) loaded")
        if total == 0:
            raise GeoError("no geo data could be downloaded")
        rows = connection.execute(
            "SELECT family, COUNT(*) FROM ranges GROUP BY family"
        ).fetchall()
        for family, count in rows:
            counts[int(family)] = int(count)
        connection.commit()
    finally:
        connection.close()

    summary = {
        "schema": SCHEMA_VERSION,
        "built_at": time.time(),
        "entries": total,
        "ipv4": counts.get(4, 0),
        "ipv6": counts.get(6, 0),
        "sources": used,
        "generator": "subsonar.geoip",
    }
    os.replace(temporary, target)
    meta_path(cache_dir).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def write_index(
    rows: Sequence[tuple[int, str, str, int, str, str]],
    cache_dir: Path | str | None = None,
    *,
    sources: Sequence[str] = ("test-fixture",),
    built_at: float | None = None,
) -> dict[str, Any]:
    """Build an index from rows directly (tests, offline seeding)."""
    directory = index_dir(cache_dir)
    directory.mkdir(parents=True, exist_ok=True)
    target = index_path(cache_dir)
    temporary = directory / (INDEX_FILENAME + ".building")
    if temporary.exists():
        temporary.unlink()
    connection = sqlite3.connect(temporary)
    try:
        connection.executescript(_SCHEMA_SQL)
        total = _insert_rows(connection, iter(rows))
        connection.commit()
    finally:
        connection.close()
    if total == 0:
        temporary.unlink(missing_ok=True)
        raise GeoError("no rows to index")
    os.replace(temporary, target)
    summary = {
        "schema": SCHEMA_VERSION,
        "built_at": built_at if built_at is not None else time.time(),
        "entries": total,
        "ipv4": sum(1 for row in rows if int(row[0]) == 4),
        "ipv6": sum(1 for row in rows if int(row[0]) == 6),
        "sources": list(sources),
        "generator": "subsonar.geoip.write_index",
    }
    meta_path(cache_dir).write_text(json.dumps(summary, indent=2), encoding="utf-8")
    reset_cache()
    return summary



# --------------------------------------------------------------------------- #
# Public entry points
# --------------------------------------------------------------------------- #


def _info(bus: Any, message: str) -> None:
    _log.info(message)
    if bus is None:
        return
    try:
        bus.emit(message, "info", "geo")
    except Exception:  # pragma: no cover - a logging failure is not fatal
        pass


def _warn(bus: Any, message: str) -> None:
    _log.warning(message)
    if bus is None:
        return
    try:
        bus.warn(message)
    except Exception:  # pragma: no cover
        pass


def ensure_index(
    cache_dir: Path | str | None = None,
    *,
    bus: Any = None,
    offline: bool = False,
    allow_download: bool = True,
    max_age_days: float = DEFAULT_MAX_AGE_DAYS,
    refresh: bool = False,
    require: bool = False,
) -> GeoIndex | None:
    """Return a usable index, downloading/building it when needed.

    * a fresh index on disk is used as-is,
    * a stale one is refreshed when downloads are allowed (and kept when the
      refresh fails),
    * with ``offline``/``allow_download=False`` an existing index is used no
      matter how old, and ``None`` is returned when there is none,
    * ``require=True`` raises :class:`GeoError` instead of returning ``None``.
    """
    existing = load_index(cache_dir)
    age = index_age_days(cache_dir)
    stale = refresh or (age is not None and age > max_age_days)
    if existing is not None and not stale:
        return existing
    if allow_download and downloads_forbidden():
        _info(
            bus,
            f"{OFFLINE_ENV} is set — using the existing geo index without "
            "downloading (unset it to refresh)",
        )
        allow_download = False
    if offline or not allow_download:
        if existing is not None:
            _info(
                bus,
                f"Offline geo index in use ({age:.0f} day(s) old, no refresh)"
                if age is not None
                else "Offline geo index in use",
            )
            return existing
        if require:
            raise GeoError("offline and no geo index available")
        return None
    reason = "building" if existing is None else "refreshing"
    _info(
        bus,
        f"Geo index {reason} from ip2asn.com/RIR here — one-off download, "
        f"all lookups are local afterwards",
    )
    try:
        summary = build_index(cache_dir, bus=bus)
    except Exception as exc:  # noqa: BLE001 - geo is enrichment, never fatal
        if existing is not None:
            _warn(bus, f"Geo refresh failed ({exc}) — keeping the previous index")
            return existing
        _warn(bus, f"Geo index unavailable ({exc}) — flags/ASN disabled")
        if require:
            raise
        return None
    _info(
        bus,
        f"Geo index ready — {summary['entries']:,} range(s) "
        f"({summary['ipv4']:,} IPv4 / {summary['ipv6']:,} IPv6) from "
        f"{', '.join(summary['sources'])}",
    )
    return load_index(cache_dir, force=True)


async def ensure_index_async(
    cache_dir: Path | str | None = None, **kwargs: Any
) -> GeoIndex | None:
    """Async wrapper — the download/parse runs on a worker thread."""
    return await asyncio.to_thread(lambda: ensure_index(cache_dir, **kwargs))


def enrich(address: str, cache_dir: Path | str | None = None) -> GeoRecord | None:
    """One-shot lookup against the local index (never downloads)."""
    if not is_enrichable(address):
        return None
    index = load_index(cache_dir)
    if index is None:
        return None
    return index.lookup(address)


def describe(address: str, cache_dir: Path | str | None = None) -> str:
    """``🇩🇰 DK · AS15169 GOOGLE LLC`` for *address* (``""`` when unknown)."""
    record = enrich(address, cache_dir)
    return record.label if record is not None else ""


__all__ = [
    "COUNTRIES",
    "DEFAULT_MAX_AGE_DAYS",
    "GeoError",
    "GeoIndex",
    "GeoRecord",
    "RIR_SOURCES",
    "SOURCES",
    "address_key",
    "build_index",
    "country_name",
    "describe",
    "downloads_forbidden",
    "enrich",
    "ensure_index",
    "ensure_index_async",
    "flag_emoji",
    "flag_image_url",
    "index_available",
    "index_age_days",
    "index_dir",
    "index_path",
    "is_enrichable",
    "iter_source_rows",
    "load_index",
    "meta_path",
    "open_source",
    "parse_line",
    "parse_rir_line",
    "read_meta",
    "reset_cache",
    "write_index",
]

