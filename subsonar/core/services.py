"""Protocol identification for open ports that do not speak HTTP.

The port scanner already reads a short banner from every open, non-TLS port;
this module turns that banner — plus the port number — into a service label
(``SSH``, ``Redis``, ``MySQL``, ``SMTP``, ``FTP``, ``VNC``, …).

Everything runs in userland over the already-open TCP socket: no raw sockets,
no libpcap, no elevated privileges.  That makes it identical on Windows, macOS
and Linux.
"""

from __future__ import annotations

import re

__all__ = ["PORT_DEFAULTS", "detect_service"]

_SSH = re.compile(rb"^SSH-")
_RFB = re.compile(rb"^RFB ")
_HTTP = re.compile(rb"^HTTP/")
_SMTP = re.compile(rb"^220[ -]")
_FTP = re.compile(rb"^220[ -].*(ftp|filezilla|vsftpd|proftpd|pure-ftpd)", re.IGNORECASE)
_IMAP = re.compile(rb"^\* OK")
_POP3 = re.compile(rb"^\+OK")
_REDIS = re.compile(rb"^[-+](NOAUTH|ERR|PONG|OK)\b")
_RDP = re.compile(rb"^\x03\x00")

#: Well-known non-HTTP ports → probable service, used when no banner is spoken
#: (many binary protocols are silent until the client sends the first byte).
PORT_DEFAULTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    993: "IMAPS",
    995: "POP3S",
    1883: "MQTT",
    2049: "NFS",
    2375: "Docker API",
    2376: "Docker API",
    3306: "MySQL",
    3389: "RDP",
    5060: "SIP",
    5061: "SIP",
    5432: "PostgreSQL",
    5672: "AMQP",
    5900: "VNC",
    5901: "VNC",
    5984: "CouchDB",
    61616: "ActiveMQ",
    6379: "Redis",
    6443: "Kubernetes API",
    7001: "WebLogic",
    7002: "WebLogic",
    9092: "Kafka",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB",
    50070: "Hadoop NameNode",
}


def detect_service(port: int, banner: bytes | str | None) -> str | None:
    """Best-effort service name for an open *port* given a raw *banner*.

    Returns ``None`` when the port is a plain web port and nothing non-HTTP was
    identified.  Never raises.
    """
    if isinstance(banner, str):
        data = banner.encode("latin-1", "replace")
    else:
        data = banner or b""
    if not data:
        return PORT_DEFAULTS.get(port)
    if _SSH.match(data):
        return "SSH"
    if _RFB.match(data):
        return "VNC"
    if _HTTP.match(data):
        return "HTTP"
    if _FTP.search(data[:64]):
        return "FTP"
    if _SMTP.match(data):
        return "SMTP"
    if _IMAP.match(data):
        return "IMAP"
    if _POP3.match(data):
        return "POP3"
    if data[:1] == b"\x0a" and (
        b"mysql" in data[:128].lower() or b"mariadb" in data[:128].lower()
    ):
        return "MySQL"
    if _REDIS.match(data):
        return "Redis"
    if _RDP.match(data):
        return "RDP"
    return PORT_DEFAULTS.get(port)
