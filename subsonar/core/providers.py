"""Third-party hosting detection — "is this host on someone else's cloud?".

Recon turns up two very different kinds of provider-hosted name:

``mail`` / ``identity`` / ``collaboration`` (Office 365, Exchange Online,
``*.mail.protection.outlook.com``, SharePoint, Entra ID…)
    These are shared *tenants*.  ``autodiscover.example.com`` is Microsoft's
    infrastructure, not the target's: sweeping ports or probing HTTP there finds
    nothing about the target while sending traffic at a third party, so these
    hosts are **skipped entirely** by default
    (:attr:`ScanConfig.skip_provider_hosts`).

CDN / PaaS / hosting / cloud / SaaS (CloudFront, S3, Heroku, Netlify, Akamai…)
    The vhost is usually the target's *own* service, merely fronted by a
    provider, so it **is** scanned like any other host — the report just records
    where it lives (``provider`` column, ``provider_hosts`` in JSON).

The signal is the **CNAME chain**, which the DNS layer already returns for every
resolved host: no extra packets, no API, no address-range guessing.

Either way the host → provider mapping lands in the report with the reason it was
left alone.  ``--scan-provider-hosts`` / ``skip_provider_hosts = false`` scans the
skipped families too.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass

__all__ = [
    "PROVIDERS",
    "Provider",
    "SKIP_CATEGORIES",
    "cname_providers",
    "detect_batch",
    "detect_provider",
    "is_third_party",
    "provider_for",
    "provider_name",
]


@dataclass(frozen=True, slots=True)
class Provider:
    """One known third-party hosting provider."""

    name: str
    #: Domain suffix the provider's CNAME targets end with.
    suffix: str
    #: Grouping used in reports/logs (``mail``, ``cdn``, ``paas``, …).
    category: str

    @property
    def skip(self) -> bool:
        """True when a host on this provider is never scanned.

        Derived from :data:`SKIP_CATEGORIES` rather than stored, so the policy is
        defined in exactly one place.
        """
        return self.category in SKIP_CATEGORIES

    def matches(self, target: str) -> bool:
        """True when *target* (a CNAME target or hostname) belongs here."""
        return target == self.suffix or target.endswith("." + self.suffix)


#: Provider categories whose hosts are **never scanned**.
#:
#: These are shared *tenants*: ``autodiscover.example.com`` belongs to Microsoft's
#: Exchange Online fleet, not to the target, so a port sweep or an HTTP probe
#: against it says nothing about the target's own attack surface while sending
#: traffic at a third party.
#:
#: Everything else — CDNs, PaaS, hosting, cloud load balancers, SaaS — **is**
#: scanned: the vhost there is usually the target's own service, merely fronted by
#: a provider, and the report records where it is hosted.
SKIP_CATEGORIES: frozenset[str] = frozenset({"mail", "identity", "collaboration"})


#: Every known provider, **most specific suffix first**.
#:
#: Order matters: :func:`provider_for` returns the first match, so a broader
#: suffix placed before a narrower one shadows it (``elb.amazonaws.com`` must
#: precede ``amazonaws.com``).  :func:`_validate_order` enforces that at import
#: time so the table cannot silently rot.
PROVIDERS: tuple[Provider, ...] = (
    # -- Microsoft 365 / Exchange Online / Office 365 ----------------------- #
    Provider("Microsoft 365 (Exchange Online)", "mail.protection.outlook.com", "mail"),
    Provider("Microsoft 365 (Exchange Online)", "olc.protection.outlook.com", "mail"),
    Provider("Microsoft 365 (Autodiscover)", "autodiscover.outlook.com", "mail"),
    Provider("Microsoft 365 (Exchange Online)", "eo.outlook.com", "mail"),
    Provider("Microsoft 365 (Exchange Online)", "outlook.com", "mail"),
    Provider("Microsoft 365 (SharePoint)", "sharepoint.com", "collaboration"),
    Provider("Microsoft 365", "office365.com", "mail"),
    Provider("Microsoft 365", "onmicrosoft.com", "mail"),
    Provider("Microsoft Entra ID", "microsoftonline.com", "identity"),
    Provider("Microsoft Azure", "trafficmanager.net", "cloud"),
    Provider("Microsoft Azure", "azurefd.net", "cloud"),
    Provider("Microsoft Azure", "azurewebsites.net", "paas"),
    Provider("Microsoft Azure", "azurestaticapps.net", "paas"),
    Provider("Microsoft Azure", "cloudapp.azure.com", "cloud"),
    Provider("Microsoft Azure", "azureedge.net", "cdn"),
    Provider("Microsoft Azure", "windows.net", "cloud"),
    # -- AWS ---------------------------------------------------------------- #
    Provider("AWS CloudFront", "cloudfront.net", "cdn"),
    Provider("AWS ELB", "elb.amazonaws.com", "cloud"),
    Provider("AWS S3", "s3-website.amazonaws.com", "cloud"),
    Provider("AWS S3", "s3.amazonaws.com", "cloud"),
    Provider("AWS Elastic Beanstalk", "elasticbeanstalk.com", "paas"),
    Provider("AWS", "amazonaws.com", "cloud"),
    # -- other clouds / PaaS ------------------------------------------------ #
    Provider("Google Cloud", "googleusercontent.com", "cloud"),
    Provider("Google APIs", "googleapis.com", "cloud"),
    Provider("Google App Engine", "appspot.com", "paas"),
    Provider("Google Firebase", "firebaseapp.com", "paas"),
    Provider("Heroku", "herokudns.com", "paas"),
    Provider("Heroku", "herokuapp.com", "paas"),
    Provider("DigitalOcean", "ondigitalocean.app", "paas"),
    Provider("Render", "onrender.com", "paas"),
    Provider("Railway", "railway.app", "paas"),
    Provider("Fly.io", "fly.dev", "paas"),
    Provider("Vercel", "vercel-dns.com", "paas"),
    Provider("Vercel", "vercel.app", "paas"),
    Provider("Netlify", "netlify.com", "paas"),
    Provider("Netlify", "netlify.app", "paas"),
    Provider("Surge", "surge.sh", "paas"),
    Provider("GitHub Pages", "github.io", "paas"),
    Provider("GitLab Pages", "gitlab.io", "paas"),
    Provider("Cloudflare Pages", "pages.dev", "paas"),
    Provider("Cloudflare Workers", "workers.dev", "paas"),
    Provider("Cloudflare", "cloudflare.net", "cdn"),
    Provider("Fastly", "fastly.net", "cdn"),
    Provider("Akamai", "akamaiedge.net", "cdn"),
    Provider("Akamai", "edgekey.net", "cdn"),
    Provider("Akamai", "akamai.net", "cdn"),
    # -- SaaS / hosting ----------------------------------------------------- #
    Provider("Zendesk", "zendesk.com", "saas"),
    Provider("Salesforce", "force.com", "saas"),
    Provider("Salesforce", "salesforce.com", "saas"),
    Provider("Atlassian Cloud", "atlassian.net", "saas"),
    Provider("Shopify", "myshopify.com", "saas"),
    Provider("WP Engine", "wpengine.com", "hosting"),
    Provider("Pantheon", "pantheonsite.io", "hosting"),
    Provider("Okta", "okta.com", "identity"),
    Provider("Auth0", "auth0.com", "identity"),
    Provider("Statuspage", "statuspage.io", "saas"),
    Provider("Read the Docs", "readthedocs.io", "hosting"),
    Provider("SendGrid", "sendgrid.net", "mail"),
    Provider("Mailgun", "mailgun.org", "mail"),
)


def _validate_order() -> None:
    """Fail loudly if an earlier entry shadows a later, more specific one."""
    suffixes = [provider.suffix for provider in PROVIDERS]
    if len(suffixes) != len(set(suffixes)):
        duplicates = sorted({s for s in suffixes if suffixes.count(s) > 1})
        raise RuntimeError(f"duplicate provider suffix(es): {', '.join(duplicates)}")
    for index, provider in enumerate(PROVIDERS):
        for later in PROVIDERS[index + 1 :]:
            if provider.matches(later.suffix):
                raise RuntimeError(
                    f"provider table is out of order: the earlier entry "
                    f"{provider.suffix!r} shadows the later {later.suffix!r} "
                    f"(most specific suffix must come first)"
                )


_validate_order()


def _normalise(value: object) -> str:
    """Lower-case, dot-strip a hostname-ish value."""
    return str(value or "").strip().lower().rstrip(".")


def provider_for(target: object) -> Provider | None:
    """Provider owning *target* (a CNAME target or a hostname), if any."""
    host = _normalise(target)
    if not host:
        return None
    for provider in PROVIDERS:
        if provider.matches(host):
            return provider
    return None


def provider_name(target: object) -> str | None:
    """Display name of the provider owning *target*, if any."""
    provider = provider_for(target)
    return provider.name if provider else None


def detect_provider(cnames: Iterable[str] = (), host: object = "") -> Provider | None:
    """First provider found in the CNAME chain, then in *host* itself.

    The chain is walked from the last hop backwards: the terminal target is what
    identifies the hosting provider, an intermediate alias rarely does.
    """
    for cname in reversed([_normalise(name) for name in cnames]):
        provider = provider_for(cname)
        if provider is not None:
            return provider
    return provider_for(host)


def is_third_party(cnames: Iterable[str] = (), host: object = "") -> bool:
    """True when this host sits on shared third-party infrastructure."""
    provider = detect_provider(cnames, host)
    return bool(provider and provider.skip)


def cname_providers() -> tuple[tuple[str, str], ...]:
    """``(suffix, name)`` pairs for the discovery layer / legacy callers."""
    return tuple((provider.suffix, provider.name) for provider in PROVIDERS)


def detect_batch(chain_by_host: Mapping[str, Sequence[str]]) -> dict[str, Provider]:
    """``{host: provider}`` for every host whose chain matches a provider."""
    found: dict[str, Provider] = {}
    for host, chain in chain_by_host.items():
        provider = detect_provider(chain, host)
        if provider is not None:
            found[str(host)] = provider
    return found
