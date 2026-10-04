"""Global configuration, anonymous DNS resolver pool and the Top-50 port matrix.

Nothing in this module — or anywhere else in subsonar — is allowed to contain a
Google (8.8.8.8 / 8.8.4.4) or Cloudflare (1.1.1.1 / 1.0.0.1) resolver.  The
privacy guarantee is enforced at import time by :func:`_assert_privacy`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #

PACKAGE_ROOT = Path(__file__).resolve().parent.parent
PROJECT_ROOT = PACKAGE_ROOT.parent
CACHE_DIR = Path(os.environ.get("SUBSONAR_CACHE", PROJECT_ROOT / ".subsonar_cache"))
OUTPUT_DIR = Path(os.environ.get("SUBSONAR_OUTPUT", PROJECT_ROOT / "output"))

#: Primary banner shown at the top of every interface.
BANNER_NAME = "subsonar"
TAGLINE = "asynchronous subdomain & web-interface sonar"

# --------------------------------------------------------------------------- #
# Anonymous / privacy-focused DNS resolver pool
# --------------------------------------------------------------------------- #
# Rotated round-robin for every query so a single vantage point is never
# reused.  Sources: Quad9 un-censored, Mullvad, OpenNIC (CA/NZ), Blindside
# Networks, Applied Privacy, DNS.WATCH, Swisscows, LibreOps, AdGuard.
DNS_RESOLVER_POOL: tuple[str, ...] = (
    "9.9.9.10",         # Quad9 un-censored
    "149.112.112.10",   # Quad9 un-censored secondary
    "194.242.2.2",      # Mullvad DNS (ad-blocking base)
    "194.242.2.4",      # Mullvad DNS (extended)
    "185.228.168.168",  # CleanBrowsing / privacy filter
    "185.228.169.168",  # CleanBrowsing secondary
    "76.76.2.0",        # ControlD (no-log)
    "76.76.19.19",      # ControlD secondary
    "94.140.14.14",     # AdGuard DNS (no-log policy)
    "94.140.15.15",     # AdGuard DNS secondary
    "194.150.168.168",  # OpenNIC (NZ)
    "5.175.46.10",      # OpenNIC (CA)
    "84.200.69.80",     # DNS.WATCH
    "84.200.70.40",     # DNS.WATCH secondary
    "91.239.100.100",   # UncensoredDNS (Chaos Computer Club)
    "89.233.43.71",     # UncensoredDNS secondary
    "159.89.120.20",    # Blindside Networks
    "185.95.218.42",    # Applied Privacy
)

#: Hard-blocked resolvers — the privacy contract of subsonar.
FORBIDDEN_DNS_SERVERS: frozenset[str] = frozenset(
    {
        "8.8.8.8",
        "8.8.4.4",
        "8.8.8.4",
        "1.1.1.1",
        "1.0.0.1",
        "1.1.1.2",
        "1.1.1.3",
        "9.9.9.9",  # Quad9 *filtered* variant — deliberately avoided
    }
)


def _assert_privacy() -> None:
    leaked = FORBIDDEN_DNS_SERVERS.intersection(DNS_RESOLVER_POOL)
    if leaked:
        raise RuntimeError(
            "subsonar privacy violation: forbidden resolver(s) configured: "
            + ", ".join(sorted(leaked))
        )


_assert_privacy()


# --------------------------------------------------------------------------- #
# Embedded Top-50 web / infrastructure port matrix
# --------------------------------------------------------------------------- #
#: Exactly 50 ports ordered by real-world frequency of web interfaces, dev
#: servers, administration panels and cloud infrastructure services.
PORT_MATRIX: dict[int, str] = {
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    8000: "HTTP-Alt / Django",
    8888: "HTTP-Alt / Jupyter",
    3000: "Node / Grafana / Dev",
    5000: "Flask / UPnP",
    9000: "Portainer / PHP-FPM",
    9443: "Portainer-SSL / vSphere",
    7001: "WebLogic",
    7002: "WebLogic-SSL",
    9090: "Cockpit / Prometheus",
    10000: "Webmin / Usermin",
    2082: "cPanel",
    2083: "cPanel-SSL",
    2086: "WHM",
    2087: "WHM-SSL",
    2095: "Webmail",
    2096: "Webmail-SSL",
    4443: "HTTPS-Alt",
    4444: "Metasploit / Alt-HTTP",
    7443: "HTTPS-Alt",
    8081: "HTTP-Alt / Nexus",
    8082: "HTTP-Alt / Consul",
    8083: "HTTP-Alt / K8s",
    8088: "HTTP-Alt / Hadoop-YARN",
    8090: "HTTP-Alt / Confluence",
    8161: "ActiveMQ",
    8180: "Tomcat",
    8280: "HTTP-Alt",
    8444: "HTTPS-Alt",
    8834: "Nessus",
    9001: "Supervisor / Tor",
    9043: "WebSphere-SSL",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Transport",
    10250: "Kubelet-API",
    10443: "HTTPS-Alt",
    10444: "HTTPS-Alt",
    11371: "OpenPGP-Keyserver",
    12443: "HTTPS-Alt",
    15672: "RabbitMQ-Management",
    18080: "HTTP-Alt",
    18443: "HTTPS-Alt",
    27017: "MongoDB",
    28017: "MongoDB-HTTP-Status",
    50000: "SAP / DB2",
    50070: "Hadoop-NameNode",
    61616: "ActiveMQ-OpenWire",
}

EXTENDED_PORT_MATRIX: dict[int, str] = {
    # -- alternative HTTP/HTTPS web ports ---------------------------------- #
    81: "HTTP-Alt",
    82: "HTTP-Alt",
    88: "HTTP-Alt",
    444: "HTTPS-Alt",
    591: "FileMaker-Web",
    1000: "HTTP-Alt",
    2081: "HTTP-Alt",
    2090: "HTTP-Alt",
    2100: "HTTP-Alt",
    3001: "HTTP-Alt / Gitea",
    3333: "HTTP-Alt",
    4000: "HTTP-Alt",
    4040: "HTTP-Alt",
    4200: "Angular-Dev",
    4321: "HTTP-Alt",
    5001: "Synology-DSM / HTTPS-Alt",
    5002: "HTTP-Alt",
    6666: "HTTP-Alt / IRC",
    7000: "Cassandra / HTTP-Alt",
    7080: "HTTP-Alt",
    7171: "HTTP-Alt",
    7777: "HTTP-Alt",
    8001: "HTTP-Alt / Tomcat",
    8002: "HTTP-Alt",
    8008: "HTTP-Alt",
    8010: "HTTP-Alt",
    8032: "HTTP-Alt",
    8043: "HTTPS-Alt",
    8050: "HTTP-Alt",
    8070: "HTTP-Alt",
    8084: "HTTP-Alt",
    8085: "HTTP-Alt",
    8087: "HTTP-Alt",
    8100: "HTTP-Alt",
    8181: "HTTP-Alt",
    8222: "HTTP-Alt",
    8281: "HTTP-Alt",
    8445: "HTTPS-Alt",
    8555: "HTTPS-Alt",
    8688: "HTTP-Alt",
    8800: "HTTP-Alt",
    8880: "HTTP-Alt",
    8889: "HTTP-Alt",
    8899: "HTTP-Alt",
    9002: "HTTP-Alt",
    9003: "HTTP-Alt",
    9010: "HTTP-Alt",
    9020: "HTTP-Alt",
    9060: "HTTP-Alt",
    9080: "HTTP-Alt",
    9444: "HTTPS-Alt",
    9999: "HTTP-Alt / Admin-Panel",
    10001: "HTTP-Alt",
    10010: "HTTP-Alt",
    20000: "HTTP-Alt",
    20480: "HTTP-Alt",
    30000: "Gitea / Grafana-Alt",
    # -- admin / management consoles --------------------------------------- #
    2200: "HTTP-Alt",
    2222: "SSH-Alt",
    3389: "RDP",
    4848: "GlassFish-Admin",
    5900: "VNC",
    5901: "VNC-1",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    8042: "Intel-AMT",
    8006: "Proxmox-VE",
    8140: "Puppet-Console",
    8200: "Vault-UI",
    8500: "Consul-HTTP",
    8530: "WSUS-HTTP",
    8531: "WSUS-HTTPS",
    8787: "RStudio-Server",
    9090: "Cockpit / Prometheus",  # also in the core matrix
    9418: "Git-Protocol",
    10000: "Webmin",  # also in the core matrix
    # -- dev / CI / containers --------------------------------------------- #
    2375: "Docker-API",
    2376: "Docker-API-TLS",
    4243: "Docker-API-Alt",
    4505: "Salt-Master",
    4506: "Salt-EventBus",
    5000: "Flask / UPnP",  # also in the core matrix
    6443: "Kubernetes-API",
    7077: "Spark-Master",
    10255: "Kubelet-ReadOnly",
    11434: "Ollama-API",
    15672: "RabbitMQ-Management",  # also in the core matrix
    # -- data stores with an HTTP surface ---------------------------------- #
    5432: "PostgreSQL",
    5433: "PostgreSQL-Alt",
    5984: "CouchDB",
    6379: "Redis",
    7474: "Neo4j-Browser",
    8069: "Odoo",
    8086: "InfluxDB",
    8243: "HTTPS-Alt",
    8983: "Solr-Admin",
    9042: "Cassandra-CQL",
    9092: "Kafka",
    11211: "Memcached",
    17500: "Dropbox-LAN-Sync",
    27018: "MongoDB-Shard",
    28017: "MongoDB-HTTP",  # also in the core matrix
    # -- monitoring / observability ---------------------------------------- #
    5601: "Kibana",
    8089: "Splunkd",
    8096: "Jellyfin",
    8123: "Home-Assistant",
    8883: "MQTT-TLS",
    9091: "Pushgateway",
    9093: "Alertmanager",
    9100: "Node-Exporter",
    9160: "Cassandra-Thrift",
    9229: "Node-Inspector",
    10050: "Zabbix-Agent",
    16686: "Jaeger-UI",
    19999: "Netdata",
    # -- misc infrastructure ----------------------------------------------- #
    3128: "Squid-Proxy",
    5060: "SIP",
    5061: "SIP-TLS",
    5222: "XMPP-Client",
    5269: "XMPP-Server",
    5672: "AMQP",
    5678: "n8n-Webhook",
    7547: "TR-069-CWMP",
    8118: "Privoxy",
    22000: "Syncthing",
    25565: "Minecraft",
    32400: "Plex",
}

#: The matrix a user gets with ``--port-matrix extended``: the core 50 first (so
#: the most likely ports are probed first), then the extended set.
PORT_MATRIX_EXTENDED: dict[int, str] = {**PORT_MATRIX, **EXTENDED_PORT_MATRIX}

#: Every known port → label, used by :func:`subsonar.core.ports.describe`.
PORT_LABELS: dict[int, str] = {**EXTENDED_PORT_MATRIX, **PORT_MATRIX}

#: Ports that only ever speak TLS — probed with HTTPS first.
#:
#: The cPanel/WHM ``20xx`` family is included deliberately: although the matrix
#: also lists the cleartext twins (2082/2086/2095), the ``*3``/``*7``/``*6``
#: ports are *TLS-only* and answer a plain HTTP request with
#: ``400 The plain HTTP request was sent to HTTPS port``.  Probing them with
#: ``https`` first is what keeps that protocol error out of the findings.
TLS_FIRST_PORTS: frozenset[int] = frozenset(
    {
        443, 2083, 2087, 2096, 4443, 7002, 7443, 8443, 8444, 8834, 9043,
        9443, 10000, 10443, 10444, 12443, 18443,
        # extended matrix: TLS-only listeners
        2376, 5001, 5061, 5986, 6443, 8243, 8531, 8883,
    }
)

#: Dedicated alternative-admin matrix used by the *Infrastructure Audit* profile.
INFRASTRUCTURE_PORTS: tuple[int, ...] = (
    8443, 9443, 10000, 10443, 10444, 12443, 18443, 4443, 7443, 8444,
    8834, 9043, 2083, 2087, 2096, 2082, 2086, 2095, 9000, 9001, 9090,
    9200, 9300, 10250, 15672, 28017, 50070, 11371, 8161, 61616,
)

# --------------------------------------------------------------------------- #
# Free OSINT endpoints (no paid APIs, ever)
# --------------------------------------------------------------------------- #
CRTSH_ENDPOINT = "https://crt.sh/?q=%25.{domain}&output=json"
CRTSH_FALLBACK_ENDPOINT = "https://crt.sh/?q={domain}&output=json"
HACKERTARGET_ENDPOINT = (
    "https://api.hackertarget.com/hostsearch/?q={domain}"
)
ANUBIS_ENDPOINT = "https://jldc.me/anubis/subdomains/{domain}"

#: Raw SecLists URL — streamed, never manually downloaded.
SECLISTS_URL = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
    "Discovery/DNS/subdomains-top1million-110000.txt"
)
SECLISTS_FALLBACK_URLS: tuple[str, ...] = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
    "Discovery/DNS/subdomains-top1million-5000.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/"
    "Discovery/DNS/namelist.txt",
)

#: Registry name of the brute-force wordlist used when none is chosen.
#: The registry itself lives in :mod:`subsonar.core.wordlists`.
DEFAULT_WORDLIST = "seclists-top1m"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 subsonar/1.0"
)

# --------------------------------------------------------------------------- #
# Scan configuration
# --------------------------------------------------------------------------- #
DEFAULT_DNS_TIMEOUT = 2.5
DEFAULT_TCP_TIMEOUT = 1.8
#: First-pass port timeout. Most filtered ports cost exactly this much, so it is
#: deliberately aggressive; only ports that time out on a *responsive* host are
#: retried with :data:`DEFAULT_TCP_TIMEOUT`.
DEFAULT_TCP_FAST_TIMEOUT = 0.45
DEFAULT_HTTP_TIMEOUT = 4.0
DEFAULT_DNS_CONCURRENCY = 400
#: Total wall-clock seconds one hostname may spend across all its failover
#: attempts.  The attempt budget alone allowed ``attempts × dns_timeout`` (6 ×
#: 2.5 s = 15 s) for a single dead name; a brute list is mostly dead names, so
#: that — not the rate limit — used to be the ceiling on the DNS phase.  ``0``
#: restores "as many attempts as it takes".
DEFAULT_DNS_NAME_DEADLINE = 6.0

DEFAULT_PORT_CONCURRENCY = 300
DEFAULT_HTTP_CONCURRENCY = 60
#: Hosts swept together in one port-major batch, and how many batches run at once.
DEFAULT_HOST_BATCH = 32
DEFAULT_HOST_BATCH_WORKERS = 8


@dataclass(slots=True)
class ScanConfig:
    """Runtime knobs for a single subsonar scan."""

    domain: str
    profile_id: int = 3
    resolver_pool: tuple[str, ...] = DNS_RESOLVER_POOL
    ports: dict[int, str] = field(default_factory=lambda: dict(PORT_MATRIX))
    dns_timeout: float = DEFAULT_DNS_TIMEOUT
    #: Per-name time budget across failover attempts (0 = unlimited).
    dns_name_deadline: float = DEFAULT_DNS_NAME_DEADLINE
    tcp_timeout: float = DEFAULT_TCP_TIMEOUT
    tcp_fast_timeout: float = DEFAULT_TCP_FAST_TIMEOUT
    http_timeout: float = DEFAULT_HTTP_TIMEOUT
    dns_concurrency: int = DEFAULT_DNS_CONCURRENCY
    port_concurrency: int = DEFAULT_PORT_CONCURRENCY
    http_concurrency: int = DEFAULT_HTTP_CONCURRENCY
    host_batch: int = DEFAULT_HOST_BATCH
    host_batch_workers: int = DEFAULT_HOST_BATCH_WORKERS
    adaptive_timeout: bool = True
    #: Active discovery (SAN harvesting, CNAME chasing, permutations).
    enable_discovery: bool = True
    #: Extra free no-signup OSINT plugins (CertSpotter, RapidDNS, urlscan, OTX,
    #: ThreatMiner, Common Crawl) on top of the built-in three.
    enable_plugin_sources: bool = True
    plugin_sources: tuple[str, ...] = ()
    enable_san: bool = True
    enable_permutations: bool = True
    enable_cnames: bool = True
    permutation_depth: int = 1
    permutation_limit: int = 10_000
    #: Registry name of the brute-force wordlist (see
    #: :mod:`subsonar.core.wordlists` — ``seclists-top1m``, ``ai-super``, …).
    wordlist: str = DEFAULT_WORDLIST
    #: Mutate every brute-force label with env/region/number affixes (``admin`` →
    #: ``admin-dev``, ``dev-admin``, ``admin2``, ``admin.staging``, …).
    wordlist_permutations: bool = False
    #: Hard cap on the extra labels the mutation pass may produce.
    wordlist_permutation_limit: int = 50_000
    #: Merge the newest previous report for the same domain into this run so a
    #: profile change (passive → brute) never clears what was already found.
    carry_over: bool = True
    #: Do not scan hosts that live on third-party infrastructure (Office 365 /
    #: Exchange Online, SharePoint, S3, Heroku, CDNs, …).  Neither a port sweep
    #: nor an HTTP probe against somebody else's shared infrastructure says
    #: anything about the target; the hosts are recorded with their provider
    #: instead of being reported as findings.
    skip_provider_hosts: bool = True
    #: Hard cap on the candidate pool.
    max_candidates: int | None = None
    #: Resolve AAAA records and scan IPv6 addresses too.
    ipv6: bool = False
    #: Fingerprint confirmed interfaces (favicon hash, technologies, data files).
    fingerprint_findings: bool = True
    #: Score and rank findings by confidence.
    score_findings: bool = True
    #: Run template-style exposure checks (severity-labelled, status-only).
    template_checks: bool = True
    #: Stream every confirmed finding to a live NDJSON (.jsonl) file.
    jsonl: bool = False
    #: Ask this many resolvers to agree on an address before trusting it (0/1 = off).
    confirm_resolvers: int = 0
    #: Durable DNS answer cache across runs, and multiplexed UDP transport.
    disk_cache: bool = True
    multiplex_dns: bool = True
    #: Global DNS query rate limit in queries/second for every resolver together
    #: (0 = unlimited).  A token bucket, so short bursts are still allowed up to
    #: :attr:`dns_rate_burst`.
    dns_rate_limit: float = 0.0
    #: Burst size for :attr:`dns_rate_limit` (0 = one second worth, min 1).
    dns_rate_burst: float = 0.0
    #: Optional per-resolver cap (queries/second per nameserver, 0 = unlimited).
    dns_rate_per_server: float = 0.0
    #: Global TCP connect rate for the port sweep, in connects/second (0 = the
    #: profile's sane default).  A firewall/IPS notices 900 connects a second from
    #: one source long before it notices the concurrency setting.
    port_rate_limit: float = 0.0
    #: Burst allowance for :attr:`port_rate_limit` (0 = one second worth, min 1).
    port_rate_burst: float = 0.0
    #: Per-host connects/second cap, so a single target is never hammered even
    #: while the global budget is shared across a large host batch.
    port_rate_per_host: float = 0.0
    #: Offline country/ASN enrichment (flags next to every resolved IP).
    geoip: bool = True
    #: Allow the one-off download of the BGP/RIR dumps that build the geo index.
    geoip_download: bool = True
    #: Refresh the geo index when it is older than this many days.
    geoip_max_age_days: float = 21.0
    #: Reverse-DNS (PTR) lookups for resolved addresses — free OSINT, DNS only.
    reverse_dns: bool = True
    #: Cap on PTR lookups per scan (unique addresses).
    max_ptr_lookups: int = 128
    #: Apex DNS intelligence: MX/NS/SOA/TXT(SPF,DKIM,DMARC)/CAA/DNSSEC + providers.
    dns_intel: bool = True
    #: Mine robots.txt/sitemap.xml/security.txt/headers for extra in-scope hosts.
    web_mining: bool = True
    #: Resolve and scan hostnames that mining discovered (second wave).
    mining_wave2: bool = True
    #: Cap on second-wave hosts.
    max_wave2_hosts: int = 200
    stealth_delay: tuple[float, float] = (0.0, 0.0)
    verify_tls: bool = False
    wildcard_filter: bool = True
    offline: bool = False
    cache_dir: Path = CACHE_DIR
    output_dir: Path = OUTPUT_DIR

    #: Registered wordlist name, ``--ports``/``--port-matrix`` handling, etc.
    #: True when the port list was chosen explicitly (CLI, TOML or a direct
    #: ``ScanConfig(ports=…)``), so :func:`~subsonar.core.profiles.apply_profile`
    #: must not replace it with the profile's matrix.
    ports_override: bool = False
    #: Set automatically when a DNS rate limit was supplied explicitly, so the
    #: profile's politeness default does not overwrite a deliberate choice.
    dns_rate_override: bool = False
    #: Same idea for the port-sweep rate limit.
    port_rate_override: bool = False

    def __post_init__(self) -> None:
        self.domain = self.domain.strip().lower().rstrip(".")
        for prefix in ("https://", "http://"):
            if self.domain.startswith(prefix):
                self.domain = self.domain[len(prefix) :]
        self.domain = self.domain.split("/")[0].split(":")[0]
        if not self.domain or "." not in self.domain:
            raise ValueError(
                f"invalid target domain: {self.domain!r} (expected e.g. example.com)"
            )
        self.cache_dir = Path(self.cache_dir)
        self.output_dir = Path(self.output_dir)
        if self.ports != PORT_MATRIX:
            # A caller who replaced the matrix meant it.
            self.ports_override = True
        if self.dns_rate_limit > 0 or self.dns_rate_per_server > 0:
            # A caller who asked for pacing meant it (profiles may set slower).
            self.dns_rate_override = True
        if self.port_rate_limit > 0 or self.port_rate_per_host > 0:
            self.port_rate_override = True


#: Singleton default configuration used by the CLI entry point.
CONFIG = ScanConfig(domain="example.com")
