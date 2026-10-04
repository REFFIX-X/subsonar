"""Apex DNS intelligence — free, DNS-only OSINT (no API, no key, no signup).

Everything in here is answered by ordinary DNS queries through the same
anonymous resolver pool the rest of the scanner uses, so it adds a handful of
lookups and zero new exposure:

* **MX** — which mail platform the organisation runs (Microsoft 365, Google
  Workspace, Proofpoint, Mimecast, …),
* **SPF** — the ``include:`` chain, recursively expanded, which names the
  sending infrastructure (and often the vendors in use),
* **DKIM** — which selectors exist (``selector._domainkey``),
* **DMARC** — policy, reporting addresses, subdomain policy,
* **CAA** — which certificate authorities are allowed to issue for the domain,
* **NS / SOA** — hosting provider and the administrative mailbox in the SOA,
* **DNSSEC** — whether the zone is signed,
* **TXT verification tokens** — Google/Microsoft/Atlassian/Facebook/… site
  verifications, which leak which SaaS the company has adopted.

All of it is data an organisation publishes about itself; nothing here probes the
target's hosts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

__all__ = [
    "CAA_ISSUERS",
    "DNSIntel",
    "DKIM_SELECTORS",
    "MAIL_PROVIDER_SUFFIXES",
    "NAMESERVER_SUFFIXES",
    "VERIFICATION_PREFIXES",
    "collect_dns_intel",
    "infer_mail_provider",
    "infer_nameserver_provider",
    "parse_spf_includes",
    "provider_for_host",
    "verification_vendor",
]

#: ``suffix -> provider`` for MX hosts.  Most specific first.
MAIL_PROVIDER_SUFFIXES: tuple[tuple[str, str], ...] = (
    ("mail.protection.outlook.com", "Microsoft 365 (Exchange Online)"),
    ("olc.protection.outlook.com", "Microsoft 365 (Exchange Online)"),
    ("outlook.com", "Microsoft 365 (Exchange Online)"),
    ("aspmx.l.google.com", "Google Workspace"),
    ("googlemail.com", "Google Workspace"),
    ("google.com", "Google Workspace"),
    ("pphosted.com", "Proofpoint"),
    ("proofpoint.com", "Proofpoint"),
    ("mimecast.com", "Mimecast"),
    ("messagelabs.com", "Symantec/Broadcom Email Security"),
    ("barracudanetworks.com", "Barracuda"),
    ("iphmx.com", "Cisco Email Security"),
    ("hornetsecurity.com", "Hornetsecurity"),
    ("spamexperts.com", "SpamExperts"),
    ("zoho.com", "Zoho Mail"),
    ("zoho.eu", "Zoho Mail"),
    ("yandex.net", "Yandex Mail"),
    ("yandex.ru", "Yandex Mail"),
    ("qq.com", "Tencent Exmail"),
    ("163.com", "NetEase Mail"),
    ("icloud.com", "Apple iCloud Mail"),
    ("secureserver.net", "GoDaddy Email"),
    ("registrar-servers.com", "Namecheap Email"),
    ("mailgun.org", "Mailgun"),
    ("sendgrid.net", "SendGrid"),
    ("amazonses.com", "Amazon SES"),
    ("mail.ru", "Mail.ru"),
    ("orange.fr", "Orange"),
    ("ovh.net", "OVH Mail"),
    ("one.com", "One.com"),
    ("simply.com", "Simply.com"),
    ("curanet.dk", "Curanet"),
    ("dandomain.dk", "DanDomain"),
    ("scannet.dk", "ScanNet"),
    ("nordicemail.com", "Nordic Email"),
    ("loopia.se", "Loopia"),
    ("binero.se", "Binero"),
    ("citynetwork.se", "City Network"),
    ("active24.com", "Active24"),
    ("webhosting.dk", "Webhosting.dk"),
    ("gigahost.dk", "Gigahost"),
    ("meebox.net", "Meebox"),
    ("hostedemail.com", "Open-Xchange Hosted Email"),
    ("emailsrvr.com", "Rackspace Email"),
    ("transip.email", "TransIP"),
    ("combell.com", "Combell"),
    ("ionos.com", "IONOS"),
    ("1and1.com", "IONOS"),
    ("kundenserver.de", "IONOS"),
    ("strato.com", "STRATO"),
    ("hetzner.com", "Hetzner"),
    ("fastmail.com", "Fastmail"),
    ("messagingengine.com", "Fastmail"),
    ("tutanota.de", "Tuta"),
    ("protonmail.ch", "Proton Mail"),
    ("proton.me", "Proton Mail"),
    ("gandi.net", "Gandi Mail"),
    ("gmail.com", "Google Workspace"),
)

#: ``suffix -> provider`` for NS hosts (zone hosting, anycast DNS).
NAMESERVER_SUFFIXES: tuple[tuple[str, str], ...] = (
    ("ns.cloudflare.com", "Cloudflare DNS"),
    ("awsdns", "Amazon Route 53"),
    ("azure-dns", "Azure DNS"),
    ("googledomains.com", "Google Cloud DNS"),
    ("nsone.net", "NS1"),
    ("ultradns.net", "UltraDNS"),
    ("ultradns.com", "UltraDNS"),
    ("dnsmadeeasy.com", "DNS Made Easy"),
    ("dynect.net", "Oracle Dyn"),
    ("akam.net", "Akamai DNS"),
    ("cdnetworks.net", "CDNetworks"),
    ("dnsimple.com", "DNSimple"),
    ("registrar-servers.com", "Namecheap DNS"),
    ("hover.com", "Hover"),
    ("digitalocean.com", "DigitalOcean DNS"),
    ("linode.com", "Linode DNS"),
    ("loopia.se", "Loopia DNS"),
    ("binero.se", "Binero DNS"),
    ("citynetwork.se", "City Network DNS"),
    ("dandomain.dk", "DanDomain DNS"),
    ("curanet.dk", "Curanet DNS"),
    ("simply.com", "Simply.com DNS"),
    ("one.com", "One.com DNS"),
    ("gandi.net", "Gandi DNS"),
    ("ovh.net", "OVH DNS"),
    ("ovh.com", "OVH DNS"),
    ("ionos.com", "IONOS DNS"),
    ("ui-dns", "IONOS DNS"),
    ("strato.com", "STRATO DNS"),
    ("hetzner.com", "Hetzner DNS"),
    ("hetzner.de", "Hetzner DNS"),
    ("transip.nl", "TransIP DNS"),
    ("combell.com", "Combell DNS"),
    ("netcup.net", "Netcup DNS"),
    ("serveriai.lt", "Interneto vizija"),
    ("gigahost.dk", "Gigahost DNS"),
    ("google.com", "Google Cloud DNS"),
)

#: CAA ``issue`` values worth naming.
CAA_ISSUERS: dict[str, str] = {
    "letsencrypt.org": "Let's Encrypt",
    "digicert.com": "DigiCert",
    "sectigo.com": "Sectigo",
    "comodoca.com": "Sectigo (Comodo)",
    "usertrust.com": "Sectigo (USERTrust)",
    "globalsign.com": "GlobalSign",
    "godaddy.com": "GoDaddy",
    "amazon.com": "Amazon Trust Services",
    "amazontrust.com": "Amazon Trust Services",
    "pki.goog": "Google Trust Services",
    "microsoft.com": "Microsoft",
    "entrust.net": "Entrust",
    "certum.pl": "Certum",
    "buypass.com": "Buypass",
    "harica.gr": "HARICA",
    "zerossl.com": "ZeroSSL",
    "actalis.it": "Actalis",
    "swisssign.com": "SwissSign",
    "emsign.com": "Emsign",
    "telia.se": "Telia",
    "teliacompany.com": "Telia",
}

#: DKIM selectors probed when the zone does not advertise them.
DKIM_SELECTORS: tuple[str, ...] = (
    "default",
    "google",
    "selector1",
    "selector2",
    "s1",
    "s2",
    "k1",
    "mail",
    "smtp",
    "mandrill",
    "amazonses",
    "mailchimp",
    "sendgrid",
    "dkim",
    "mta",
)

#: ``TXT prefix -> vendor`` for site-verification tokens.
VERIFICATION_PREFIXES: tuple[tuple[str, str], ...] = (
    ("google-site-verification=", "Google Search Console"),
    ("atlassian-domain-verification=", "Atlassian"),
    ("facebook-domain-verification=", "Meta / Facebook"),
    ("shopify-verification=", "Shopify"),
    ("apple-domain-verification=", "Apple Business"),
    ("adobe-idp-site-verification=", "Adobe"),
    ("slack-domain-verification=", "Slack"),
    ("zoom-verification=", "Zoom"),
    ("docusign=", "DocuSign"),
    ("cisco-ci-domain-verification=", "Cisco"),
    ("stripe-verification=", "Stripe"),
    ("twilio-domain-verification=", "Twilio"),
    ("wrike-verification=", "Wrike"),
    ("teamviewer-sso-verification=", "TeamViewer"),
    ("globalsign-domain-verification=", "GlobalSign"),
    ("detectify-verification=", "Detectify"),
    ("firebase=", "Firebase"),
    ("yandex-verification=", "Yandex"),
    ("baidu-site-verification=", "Baidu"),
    ("pardot_verification=", "Pardot"),
    ("have-i-been-pwned-verification=", "Have I Been Pwned"),
    ("logmein-verification-code=", "LogMeIn"),
    ("status-page-domain-verification=", "Atlassian Statuspage"),
    ("knowbe4-site-verification=", "KnowBe4"),
    ("miro-verification=", "Miro"),
    ("onetrust-domain-verification=", "OneTrust"),
)

#: ``ms=`` is case-insensitive but conventionally upper-case; checked separately
#: so a random ``ms=`` in an unrelated TXT record is still attributed.
VERIFICATION_PREFIXES_CASEFOLD: tuple[tuple[str, str], ...] = (
    ("ms=", "Microsoft (Office 365 / Azure AD)"),
)

_SPF_INCLUDE_RE = re.compile(r"include:([A-Za-z0-9_.\-]+)", re.IGNORECASE)
_SPF_IP_RE = re.compile(r"ip[46]:([0-9A-Fa-f:./]+)")
_SPF_ALL_RE = re.compile(r"(?P<mod>[-~+]?)all\b", re.IGNORECASE)
_DMARC_TAG_RE = re.compile(r"\b([a-z]{1,5})\s*=\s*([^;\s]+)", re.IGNORECASE)



# --------------------------------------------------------------------------- #
# Pure helpers (unit-testable without any network)
# --------------------------------------------------------------------------- #


def provider_for_host(host: str, table: Sequence[tuple[str, str]]) -> str | None:
    """First ``suffix -> provider`` entry matching *host* (most specific first)."""
    text = str(host or "").strip().lower().rstrip(".")
    if not text:
        return None
    for suffix, provider in table:
        if text.endswith(suffix):
            return provider
    return None


def infer_mail_provider(mx_hosts: Iterable[str]) -> list[str]:
    """Provider names for a set of MX hosts (deduplicated, ordered)."""
    found: list[str] = []
    for host in mx_hosts:
        provider = provider_for_host(host, MAIL_PROVIDER_SUFFIXES)
        if provider and provider not in found:
            found.append(provider)
    return found


def infer_nameserver_provider(ns_hosts: Iterable[str]) -> list[str]:
    """Provider names for a set of NS hosts (deduplicated, ordered)."""
    found: list[str] = []
    for host in ns_hosts:
        provider = provider_for_host(host, NAMESERVER_SUFFIXES)
        if provider and provider not in found:
            found.append(provider)
    return found


def parse_spf_includes(record: str) -> list[str]:
    """``include:`` targets inside an SPF record, in order."""
    return [match.group(1).lower() for match in _SPF_INCLUDE_RE.finditer(record or "")]


def parse_spf_ips(record: str) -> list[str]:
    """``ip4:``/``ip6:`` mechanisms inside an SPF record."""
    return [match.group(1) for match in _SPF_IP_RE.finditer(record or "")]


def parse_spf_all(record: str) -> str | None:
    """The ``all`` qualifier of an SPF record (``-``, ``~``, ``+`` or ``?``)."""
    match = _SPF_ALL_RE.search(record or "")
    if not match:
        return None
    return match.group("mod") or "+"


def is_spf(record: str) -> bool:
    return str(record or "").strip().lower().startswith("v=spf1")


def parse_dmarc(record: str) -> dict[str, str]:
    """DMARC record as ``{tag: value}`` (``p``, ``rua``, ``sp``, ``pct``, …)."""
    return {
        match.group(1).lower(): match.group(2)
        for match in _DMARC_TAG_RE.finditer(record or "")
    }


def verification_vendor(record: str) -> tuple[str, str] | None:
    """``(vendor, token)`` when a TXT record is a site-verification token."""
    text = str(record or "").strip()
    lowered = text.lower()
    for prefix, vendor in VERIFICATION_PREFIXES:
        if lowered.startswith(prefix.lower()):
            return vendor, text[len(prefix) :].strip()
    for prefix, vendor in VERIFICATION_PREFIXES_CASEFOLD:
        if lowered.startswith(prefix):
            return vendor, text[len(prefix) :].strip()
    return None


def caa_issuer_name(value: str) -> str:
    """Friendly name for a CAA ``issue`` value (falls back to the raw value)."""
    text = str(value or "").strip().lower().strip(";").strip('"')
    issuer = text.split(";")[0].strip()
    for suffix, name in CAA_ISSUERS.items():
        if issuer == suffix or issuer.endswith("." + suffix):
            return name
    return issuer or "unknown"



# --------------------------------------------------------------------------- #
# Result object
# --------------------------------------------------------------------------- #


@dataclass
class DNSIntel:
    """Everything the apex zones published about itself."""

    domain: str
    mx: list[tuple[int, str]] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    soa: dict[str, str] = field(default_factory=dict)
    txt: list[str] = field(default_factory=list)
    spf: list[str] = field(default_factory=list)
    spf_includes: list[str] = field(default_factory=list)
    spf_ips: list[str] = field(default_factory=list)
    spf_all: str | None = None
    dmarc: dict[str, str] = field(default_factory=dict)
    dmarc_record: str | None = None
    dkim_selectors: list[str] = field(default_factory=list)
    caa: list[tuple[str, str, str]] = field(default_factory=list)
    dnssec: bool = False
    mail_providers: list[str] = field(default_factory=list)
    dns_providers: list[str] = field(default_factory=list)
    verifications: dict[str, str] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    # -- derived ------------------------------------------------------------ #
    @property
    def mail_hosts(self) -> list[str]:
        return [host for _priority, host in self.mx]

    @property
    def caa_issuers(self) -> list[str]:
        out: list[str] = []
        for _flags, tag, value in self.caa:
            if tag.lower() != "issue":
                continue
            name = caa_issuer_name(value)
            if name not in out:
                out.append(name)
        return out

    @property
    def dmarc_policy(self) -> str | None:
        return self.dmarc.get("p")

    @property
    def dmarc_strong(self) -> bool:
        """``true`` for ``p=reject``/``quarantine`` with a full rollout."""
        policy = (self.dmarc_policy or "").lower()
        if policy not in {"reject", "quarantine"}:
            return False
        pct = self.dmarc.get("pct")
        return pct is None or pct.strip() in {"", "100"}

    @property
    def spf_strict(self) -> bool:
        return self.spf_all == "-"

    def posture_notes(self) -> list[str]:
        """What is missing or misconfigured, in plain English."""
        notes: list[str] = []
        if not self.spf:
            notes.append("no SPF record — anyone can spoof this domain's mail")
        elif not self.spf_strict:
            notes.append(
                f"SPF does not end in -all (qualifier {self.spf_all or '+all'}) — "
                "spoofing is only soft-failed"
            )
        if not self.dmarc_record:
            notes.append("no DMARC record — no policy for failed SPF/DKIM")
        elif not self.dmarc_strong:
            notes.append(
                f"DMARC policy is {self.dmarc_policy or 'none'} "
                f"(pct={self.dmarc.get('pct', '100')}) — weak or monitoring only"
            )
        if not self.dkim_selectors:
            notes.append("no DKIM selector answered — mail may be unsigned")
        if not self.caa:
            notes.append("no CAA record — any CA may issue for this domain")
        if not self.dnssec:
            notes.append("zone is not DNSSEC signed")
        return notes

    def signals(self) -> list[str]:
        """Short ``label: value`` lines for the live log and the report."""
        out: list[str] = []
        if self.mail_providers:
            out.append("mail: " + ", ".join(self.mail_providers))
        if self.mail_hosts:
            out.append("mx: " + ", ".join(self.mail_hosts[:6]))
        if self.dns_providers:
            out.append("dns: " + ", ".join(self.dns_providers))
        if self.spf_includes:
            out.append("spf includes: " + ", ".join(self.spf_includes[:8]))
        if self.dmarc_record:
            out.append(f"dmarc: p={self.dmarc_policy or '?'}" + (
                f" rua={self.dmarc['rua']}" if self.dmarc.get("rua") else ""
            ))
        if self.dkim_selectors:
            out.append("dkim selectors: " + ", ".join(self.dkim_selectors))
        if self.caa:
            out.append(
                "caa: "
                + ", ".join(
                    f"{tag}={value}" for _flags, tag, value in self.caa[:6]
                )
            )
        if self.soa.get("mailbox"):
            out.append(f"soa admin: {self.soa['mailbox']}")
        out.append("dnssec: " + ("signed" if self.dnssec else "unsigned"))
        if self.verifications:
            out.append(
                "verifications: "
                + ", ".join(sorted(self.verifications))
            )
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "mx": [{"priority": prio, "host": host} for prio, host in self.mx],
            "ns": list(self.ns),
            "soa": dict(self.soa),
            "txt": list(self.txt),
            "spf": list(self.spf),
            "spf_includes": list(self.spf_includes),
            "spf_ips": list(self.spf_ips),
            "spf_all": self.spf_all,
            "dmarc": dict(self.dmarc),
            "dmarc_record": self.dmarc_record,
            "dmarc_strong": self.dmarc_strong,
            "dkim_selectors": list(self.dkim_selectors),
            "caa": [
                {"flags": flags, "tag": tag, "value": value}
                for flags, tag, value in self.caa
            ],
            "caa_issuers": self.caa_issuers,
            "dnssec": self.dnssec,
            "mail_providers": list(self.mail_providers),
            "dns_providers": list(self.dns_providers),
            "verifications": dict(self.verifications),
            "notes": list(self.notes),
        }



# --------------------------------------------------------------------------- #
# Collection (network — uses the anonymous resolver pool)
# --------------------------------------------------------------------------- #


async def _records(
    resolver: Any, name: str, qtype: int, *, log: bool = False
) -> list[str]:
    """Answer values for one ``name``/``qtype``; ``[]`` on any failure."""
    try:
        result = await resolver.query_raw(name, qtype, log=log, use_cache=True)
    except Exception:  # noqa: BLE001 - intel is best effort
        return []
    if result is None:
        return []
    return [
        str(record.value)
        for record in getattr(result, "records", [])
        if record.rtype == qtype and record.value
    ]


async def collect_dns_intel(
    domain: str,
    resolver: Any,
    *,
    bus: Any = None,
    log: bool = False,
    spf_depth: int = 3,
    dkim_selectors: Sequence[str] | None = None,
    max_dkim: int = 6,
) -> DNSIntel:
    """Gather apex DNS intelligence for *domain* through *resolver*.

    Never raises: every lookup is independent and a failure simply leaves that
    section empty (a scan must not die because a zone hides its MX records).
    """
    from .dns import TYPE_CAA, TYPE_DS, TYPE_MX, TYPE_NS, TYPE_SOA, TYPE_TXT

    domain = str(domain or "").strip().lower().rstrip(".")
    intel = DNSIntel(domain=domain)

    # -- MX ---------------------------------------------------------------- #
    for value in await _records(resolver, domain, TYPE_MX, log=log):
        parts = value.split()
        if len(parts) >= 2 and parts[0].isdigit():
            intel.mx.append((int(parts[0]), parts[1].lower().rstrip(".")))
        elif parts:
            intel.mx.append((0, parts[-1].lower().rstrip(".")))
    intel.mx.sort(key=lambda item: item[0])
    intel.mail_providers = infer_mail_provider(intel.mail_hosts)

    # -- NS / SOA ---------------------------------------------------------- #
    for value in await _records(resolver, domain, TYPE_NS, log=log):
        host = value.lower().rstrip(".")
        if host and host not in intel.ns:
            intel.ns.append(host)
    intel.dns_providers = infer_nameserver_provider(intel.ns)
    for value in await _records(resolver, domain, TYPE_SOA, log=log):
        parts = value.split()
        if len(parts) >= 2:
            mailbox = parts[1].lower().rstrip(".")
            intel.soa = {
                "primary": parts[0].lower().rstrip("."),
                "mailbox": mailbox.replace(".", "@", 1) if "." in mailbox else mailbox,
            }
            if len(parts) >= 3 and parts[2].isdigit():
                intel.soa["serial"] = parts[2]
            if not intel.dns_providers:
                intel.dns_providers = infer_nameserver_provider([intel.soa["primary"]])

    # -- TXT: SPF + verification tokens ------------------------------------ #
    for value in await _records(resolver, domain, TYPE_TXT, log=log):
        text = value.strip()
        if text not in intel.txt:
            intel.txt.append(text)
        if is_spf(text) and text not in intel.spf:
            intel.spf.append(text)
        vendor = verification_vendor(text)
        if vendor is not None:
            intel.verifications.setdefault(vendor[0], vendor[1])
    if intel.spf:
        intel.spf_all = parse_spf_all(intel.spf[0])
        intel.spf_ips = parse_spf_ips(intel.spf[0])


    # -- SPF include chain (recursive, bounded) ----------------------------- #
    seen: set[str] = set()
    queue = list(parse_spf_includes(intel.spf[0])) if intel.spf else []
    depth = 0
    while queue and depth < max(1, spf_depth):
        depth += 1
        next_round: list[str] = []
        for include in queue:
            if include in seen:
                continue
            seen.add(include)
            if include not in intel.spf_includes:
                intel.spf_includes.append(include)
            for value in await _records(resolver, include, TYPE_TXT, log=False):
                if is_spf(value):
                    for nested in parse_spf_includes(value):
                        if nested not in seen:
                            next_round.append(nested)
                    for ip in parse_spf_ips(value):
                        if ip not in intel.spf_ips:
                            intel.spf_ips.append(ip)
        queue = next_round
    for vendor in infer_mail_provider(intel.spf_includes):
        if vendor not in intel.mail_providers:
            intel.mail_providers.append(vendor)

    # -- DKIM selectors ---------------------------------------------------- #
    candidates = list(dkim_selectors or DKIM_SELECTORS)[: max(0, max_dkim)]
    for selector in candidates:
        name = f"{selector}._domainkey.{domain}"
        for value in await _records(resolver, name, TYPE_TXT, log=False):
            lowered = value.lower()
            if "v=dkim1" in lowered or "p=" in lowered:
                if selector not in intel.dkim_selectors:
                    intel.dkim_selectors.append(selector)
                break

    # -- DMARC ------------------------------------------------------------- #
    for value in await _records(resolver, f"_dmarc.{domain}", TYPE_TXT, log=False):
        if value.strip().lower().startswith("v=dmarc1"):
            intel.dmarc_record = value.strip()
            intel.dmarc = parse_dmarc(value)
            break

    # -- CAA --------------------------------------------------------------- #
    for value in await _records(resolver, domain, TYPE_CAA, log=False):
        parts = value.split(" ", 2)
        if len(parts) == 3:
            intel.caa.append((parts[0], parts[1].lower(), parts[2]))
        elif len(parts) == 2:
            intel.caa.append((parts[0], parts[1].lower(), ""))

    # -- DNSSEC ------------------------------------------------------------ #
    intel.dnssec = bool(await _records(resolver, domain, TYPE_DS, log=False))

    intel.notes = intel.posture_notes()
    if bus is not None:
        try:
            bus.emit(
                f"Apex DNS intelligence for {domain} — "
                + "; ".join(intel.signals()[:4]),
                "info",
                "osint",
                host=domain,
            )
        except Exception:  # pragma: no cover - logging must not break a scan
            pass
    return intel

