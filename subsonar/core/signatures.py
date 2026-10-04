"""Technology signature table for the fingerprinting subsystem.

This module is **pure data plus compilation helpers** — it has no network, no
``aiohttp`` and no dependency on any other subsonar module, so it can be
imported (and audited) on its own.

A :class:`Signature` is a set of *matchers*; a technology is reported when **any
one** of its matchers fires.  The matcher dimensions mirror what a single HTTP
response can prove about a server:

``header`` / ``header_re``
    Exact header name (case-insensitive presence) plus an optional regex over
    the header **value**: ``header="Server", header_re=r"nginx"`` matches
    ``Server: nginx/1.24.0``.
``header_name_re``
    Regex over header **names** — for header *families* that carry a variable
    suffix (``X-Magento-*``) or for a small set of names
    (``CF-RAY``/``CF-Cache-Status``).
``body_re``
    Regex over the response body (HTML/JSON, tags included).
``cookie`` / ``cookie_re``
    Exact cookie **name**, or a regex over cookie names.  Cookie *values* are
    never inspected — session tokens must not leak into detection output.
``meta_re``
    Regex over the ``<meta name="generator" content="...">`` value.
``favicon``
    Shodan-compatible favicon hash (see :mod:`subsonar.core.fingerprint`).
``path`` / ``path_status``
    A probed path that answered with one of ``path_status`` (default ``200``).

All patterns are compiled with :data:`FLAGS` (:data:`re.IGNORECASE`), so
signatures are written without inline ``(?i)``.

Accuracy policy: every entry corresponds to a marker the vendor or upstream
project actually emits.  Where a marker needs a caveat (a header that a related
project also sets, an obsolete cookie, an endpoint an API gateway answers) the
``note`` field records the reasoning instead of hiding it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from dataclasses import fields as dataclass_fields
from functools import lru_cache
from typing import Sequence

__all__ = [
    "CATEGORIES",
    "MATCH_FIELDS",
    "DEFAULT_PATH_STATUS",
    "REQUIRED_FIELDS",
    "Signature",
    "CompiledSignature",
    "SIGNATURES",
    "compile_signature",
    "compile_signatures",
    "signature_count",
    "category_breakdown",
    "validate_signatures",
    "KNOWN_FAVICON_HASHES",
]

#: Category vocabulary.  Detection output always uses one of these labels.
CATEGORIES: tuple[str, ...] = (
    "web server",
    "language",
    "framework",
    "CMS",
    "JS library",
    "analytics",
    "CDN",
    "WAF",
    "panel",
)

#: Fields that carry a matcher.  A signature must set at least one of them.
MATCH_FIELDS: tuple[str, ...] = (
    "header",
    "header_re",
    "header_name_re",
    "body_re",
    "cookie",
    "cookie_re",
    "meta_re",
    "favicon",
    "path",
)

#: Fields every signature must define.
REQUIRED_FIELDS: tuple[str, ...] = ("id", "name", "category")

#: Statuses accepted for a ``path`` matcher unless overridden.
DEFAULT_PATH_STATUS: tuple[int, ...] = (200,)

#: Favicon hashes that are publicly documented in Shodan's favicon corpus.
#: ``116323821`` is the well-known default Spring Boot favicon (the standard
#: ``http.favicon.hash:116323821`` query).  It is listed here rather than
#: invented because that specific value can be cited from public sources.
KNOWN_FAVICON_HASHES: dict[str, str] = {
    "116323821": "Spring Boot default favicon",
}

#: Regex flags used for every compiled signature pattern.
FLAGS = re.IGNORECASE


@dataclass(frozen=True, slots=True)
class Signature:
    """One technology and the evidence that proves it."""

    id: str
    name: str
    category: str
    header: str | None = None
    header_re: str | None = None
    header_name_re: str | None = None
    body_re: str | None = None
    cookie: str | None = None
    cookie_re: str | None = None
    meta_re: str | None = None
    favicon: str | None = None
    path: str | None = None
    path_status: tuple[int, ...] = DEFAULT_PATH_STATUS
    note: str = ""

    # -- introspection ---------------------------------------------------- #
    def matchers(self) -> tuple[str, ...]:
        """Matcher fields that are actually set on this signature."""
        out: list[str] = []
        for field_name in MATCH_FIELDS:
            value = getattr(self, field_name)
            if value is None or value == "" or value == ():
                continue
            out.append(field_name)
        return tuple(out)

    @property
    def is_matchable(self) -> bool:
        return bool(self.matchers())

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {}
        for field_info in dataclass_fields(self):
            value = getattr(self, field_info.name)
            if value is None or value == "" or value == ():
                continue
            data[field_info.name] = list(value) if isinstance(value, tuple) else value
        return data


@dataclass(frozen=True, slots=True)
class CompiledSignature:
    """A :class:`Signature` with every regex pattern compiled once."""

    signature: Signature
    header_re: re.Pattern[str] | None = None
    header_name_re: re.Pattern[str] | None = None
    body_re: re.Pattern[str] | None = None
    cookie_re: re.Pattern[str] | None = None
    meta_re: re.Pattern[str] | None = None

    @property
    def id(self) -> str:
        return self.signature.id

    @property
    def name(self) -> str:
        return self.signature.name

    @property
    def category(self) -> str:
        return self.signature.category


def compile_signature(signature: Signature) -> CompiledSignature:
    """Compile one signature.  Raises :class:`re.error` on a bad pattern."""

    def _compile(pattern: str | None) -> re.Pattern[str] | None:
        return re.compile(pattern, FLAGS) if pattern else None

    return CompiledSignature(
        signature=signature,
        header_re=_compile(signature.header_re),
        header_name_re=_compile(signature.header_name_re),
        body_re=_compile(signature.body_re),
        cookie_re=_compile(signature.cookie_re),
        meta_re=_compile(signature.meta_re),
    )


@lru_cache(maxsize=8)
def _compile_cached(signatures: tuple[Signature, ...]) -> tuple[CompiledSignature, ...]:
    return tuple(compile_signature(signature) for signature in signatures)


def compile_signatures(
    signatures: Sequence[Signature] | None = None,
) -> tuple[CompiledSignature, ...]:
    """Compile *signatures* (default: the full table) with memoisation."""
    table = tuple(signatures) if signatures is not None else SIGNATURES
    return _compile_cached(table)


def signature_count(signatures: Sequence[Signature] | None = None) -> int:
    return len(signatures) if signatures is not None else len(SIGNATURES)


def category_breakdown(
    signatures: Sequence[Signature] | None = None,
) -> dict[str, int]:
    """``{category: count}`` in :data:`CATEGORIES` order."""
    table = tuple(signatures) if signatures is not None else SIGNATURES
    counts: dict[str, int] = {category: 0 for category in CATEGORIES}
    for signature in table:
        counts[signature.category] = counts.get(signature.category, 0) + 1
    return counts


def validate_signatures(
    signatures: Sequence[Signature] | None = None,
) -> list[str]:
    """Return a list of human-readable integrity problems (empty == valid)."""
    table = tuple(signatures) if signatures is not None else SIGNATURES
    problems: list[str] = []
    seen_ids: set[str] = set()
    for signature in table:
        for required in REQUIRED_FIELDS:
            if not getattr(signature, required, None):
                problems.append(f"{signature.id or '<no id>'}: missing {required}")
        if signature.id in seen_ids:
            problems.append(f"duplicate signature id: {signature.id}")
        seen_ids.add(signature.id)
        if signature.category not in CATEGORIES:
            problems.append(f"{signature.id}: unknown category {signature.category!r}")
        if not signature.is_matchable:
            problems.append(f"{signature.id}: no matcher set")
        if signature.header_re and not signature.header:
            problems.append(f"{signature.id}: header_re without header")
        if signature.path and not signature.path_status:
            problems.append(f"{signature.id}: path without path_status")
        if signature.path and not str(signature.path).startswith("/"):
            problems.append(f"{signature.id}: path must start with '/'")
        if signature.favicon is not None:
            try:
                int(signature.favicon)
            except (TypeError, ValueError):
                problems.append(f"{signature.id}: favicon must be a decimal string")
        try:
            compile_signature(signature)
        except re.error as exc:  # pragma: no cover - guarded by the tests
            problems.append(f"{signature.id}: bad regex ({exc})")
    return problems


# --------------------------------------------------------------------------- #
# The table
# --------------------------------------------------------------------------- #

SIGNATURES: tuple[Signature, ...] = (
    # ------------------------------------------------------------- web server (20)
    Signature("nginx", "nginx", "web server",
              header="Server", header_re=r"\bnginx\b"),
    Signature("apache-httpd", "Apache httpd", "web server",
              header="Server", header_re=r"\bApache(?:/|\s|$)"),
    Signature("microsoft-iis", "Microsoft IIS", "web server",
              header="Server", header_re=r"Microsoft-IIS"),
    Signature("litespeed", "LiteSpeed", "web server",
              header="Server", header_re=r"LiteSpeed"),
    Signature("caddy", "Caddy", "web server",
              header="Server", header_re=r"\bCaddy\b"),
    Signature("openresty", "OpenResty", "web server",
              header="Server", header_re=r"openresty"),
    Signature("gunicorn", "Gunicorn", "web server",
              header="Server", header_re=r"gunicorn"),
    Signature("uvicorn", "Uvicorn", "web server",
              header="Server", header_re=r"uvicorn"),
    Signature("jetty", "Jetty", "web server",
              header="Server", header_re=r"\bJetty\b"),
    Signature("tomcat", "Apache Tomcat", "web server",
              header="Server", header_re=r"(?:Tomcat|Coyote)",
              note="Apache-Coyote/1.1 is Tomcat's HTTP/1.1 connector banner."),
    Signature("lighttpd", "lighttpd", "web server",
              header="Server", header_re=r"lighttpd"),
    Signature("kestrel", "Kestrel", "web server",
              header="Server", header_re=r"\bKestrel\b"),
    Signature("envoy", "Envoy", "web server",
              header="Server", header_re=r"\benvoy\b"),
    Signature("cowboy", "Cowboy", "web server",
              header="Server", header_re=r"\bCowboy\b"),
    Signature("akka-http", "Akka HTTP", "web server",
              header="Server", header_re=r"akka-http"),
    Signature("php-dev-server", "PHP built-in server", "web server",
              header="Server", header_re=r"PHP/[\d.]+ Development Server"),
    Signature("simplehttp", "Python SimpleHTTP", "web server",
              header="Server", header_re=r"SimpleHTTP/[\d.]+"),
    Signature("github-com", "GitHub.com", "web server",
              header="Server", header_re=r"^GitHub\.com$",
              note="GitHub Pages and raw.githubusercontent front end."),
    Signature("amazon-s3", "Amazon S3", "web server",
              header="Server", header_re=r"AmazonS3"),
    Signature("apache-mod-status", "Apache mod_status", "web server",
              path="/server-status", path_status=(200,),
              note="mod_status exposes /server-status when enabled."),
    Signature("apache-mod-info", "Apache mod_info", "web server",
              path="/server-info", path_status=(200,),
              note="mod_info exposes /server-info when enabled."),

    # --------------------------------------------------------------- language (10)
    Signature("php", "PHP", "language",
              header="X-Powered-By", header_re=r"\bPHP\b",
              cookie="PHPSESSID"),
    Signature("aspnet", "ASP.NET", "language",
              header="X-AspNet-Version",
              cookie="ASP.NET_SessionId",
              note="X-AspNet-Version is emitted by the classic ASP.NET pipeline."),
    Signature("aspnet-forms-auth", "ASP.NET Forms auth", "language",
              cookie=".ASPXAUTH"),
    Signature("java", "Java", "language",
              header="X-Powered-By", header_re=r"(?:Servlet|JSP)",
              cookie="JSESSIONID"),
    Signature("python", "Python", "language",
              header="X-Powered-By", header_re=r"\bPython\b"),
    Signature("python-http", "Python http.server", "language",
              header="Server", header_re=r"Python/[\d.]+"),
    Signature("ruby", "Ruby", "language",
              header="Server", header_re=r"(?:WEBrick|Puma|Unicorn)"),
    Signature("nodejs", "Node.js", "language",
              cookie="connect.sid",
              note="connect.sid is the default session cookie name of "
                   "Connect and therefore of Express applications."),
    Signature("erlang", "Erlang", "language",
              header="Server", header_re=r"(?:MochiWeb|Yaws|Cowboy)"),
    Signature("dotnet-core", "ASP.NET Core", "language",
              header="Server", header_re=r"\bKestrel\b",
              cookie_re=r"^\.AspNetCore\."),

    # -------------------------------------------------------------- framework (18)
    Signature("express", "Express", "framework",
              header="X-Powered-By", header_re=r"^Express$"),
    Signature("werkzeug", "Werkzeug", "framework",
              header="Server", header_re=r"Werkzeug",
              note="Werkzeug's banner is served by the Flask development server."),
    Signature("passenger", "Phusion Passenger", "framework",
              header="X-Powered-By", header_re=r"Phusion Passenger"),
    Signature("nextjs", "Next.js", "framework",
              body_re=r"__NEXT_DATA__",
              header="X-Powered-By", header_re=r"Next\.js"),
    Signature("nuxt", "Nuxt.js", "framework",
              body_re=r"__NUXT__|/\.nuxt/|/_nuxt/"),
    Signature("django", "Django", "framework",
              body_re=r"csrfmiddlewaretoken",
              cookie="csrftoken"),
    Signature("rails", "Ruby on Rails", "framework",
              body_re=r"""name=["']csrf-token["']""",
              note="Rails' csrf_meta_tags emits <meta name=\"csrf-token\">."),
    Signature("laravel", "Laravel", "framework",
              cookie="laravel_session"),
    Signature("aspnet-mvc", "ASP.NET MVC", "framework",
              cookie="__RequestVerificationToken"),
    Signature("codeigniter", "CodeIgniter", "framework",
              cookie="ci_session"),
    Signature("cakephp", "CakePHP", "framework",
              cookie="CAKEPHP"),
    Signature("spring-boot", "Spring Boot", "framework",
              favicon="116323821",
              header="X-Application-Context",
              path="/actuator/health", path_status=(200, 401, 403),
              note="favicon 116323821 is the documented default Spring Boot "
                   "favicon hash; X-Application-Context is the Spring Boot 1.x "
                   "actuator banner; /actuator/health is the Boot health "
                   "endpoint."),
    Signature("openapi-document", "OpenAPI document", "framework",
              path="/openapi.json", path_status=(200,),
              note="FastAPI, DRF and Springdoc all serve the schema here."),
    Signature("swagger-ui", "Swagger UI", "framework",
              body_re=r"swagger-ui",
              path="/swagger-ui.html", path_status=(200,)),
    Signature("graphql", "GraphQL endpoint", "framework",
              path="/graphql", path_status=(200, 400, 401, 403),
              note="A bare GET on a GraphQL endpoint commonly answers 400."),
    Signature("gatsby", "Gatsby", "framework",
              body_re=r"___gatsby"),
    Signature("sveltekit", "SvelteKit", "framework",
              body_re=r"__sveltekit|data-sveltekit-"),
    Signature("phoenix", "Phoenix", "framework",
              header="Server", header_re=r"\bCowboy\b",
              body_re=r"phoenix\.js|phx-",
              note="Phoenix ships Cowboy and renders phx-* bindings."),
    Signature("fastapi", "FastAPI", "framework",
              body_re=r"""["']detail["']\s*:\s*["']Not Found["']""",
              note="FastAPI's default 404 JSON body."),

    # -------------------------------------------------------------------- CMS (14)
    Signature("wordpress", "WordPress", "CMS",
              header="X-Pingback",
              body_re=r"wp-content|wp-includes|wp-json",
              path="/wp-login.php", path_status=(200, 302, 303, 401, 403),
              note="X-Pingback is WordPress's XML-RPC discovery header."),
    Signature("drupal", "Drupal", "CMS",
              header_name_re=r"^x-drupal-",
              header="X-Generator", header_re=r"Drupal",
              body_re=r"Drupal\.settings|sites/default/files|/core/misc/drupal\.js"),
    Signature("joomla", "Joomla", "CMS",
              body_re=r"""content=["']Joomla|com_content|/components/com_"""),
    Signature("magento", "Magento", "CMS",
              header_name_re=r"^x-magento-",
              cookie="X-Magento-Vary",
              body_re=r"Magento_|mage/cookies"),
    Signature("typo3", "TYPO3", "CMS",
              body_re=r"typo3temp|typo3conf"),
    Signature("ghost", "Ghost", "CMS",
              meta_re=r"Ghost",
              body_re=r"ghost-url|/assets/built/ghost"),
    Signature("prestashop", "PrestaShop", "CMS",
              cookie_re=r"^PrestaShop-",
              body_re=r"prestashop"),
    Signature("shopify", "Shopify", "CMS",
              header_name_re=r"^x-shopify-"),
    Signature("mediawiki", "MediaWiki", "CMS",
              body_re=r"mw-content-text|MediaWiki"),
    Signature("bitrix", "1C-Bitrix", "CMS",
              cookie_re=r"^BITRIX_SM_",
              body_re=r"bitrix/(?:js|templates)"),
    Signature("webflow", "Webflow", "CMS",
              body_re=r"data-wf-page|data-wf-site"),
    Signature("wix", "Wix", "CMS",
              header_name_re=r"^x-wix-"),
    Signature("squarespace", "Squarespace", "CMS",
              header="Server", header_re=r"Squarespace",
              body_re=r"static\d?\.squarespace\.com"),
    Signature("blogger", "Blogger", "CMS",
              meta_re=r"Blogger",
              body_re=r"blogspot\.com|blogger\.com"),

    # ------------------------------------------------------------- JS library (16)
    Signature("jquery", "jQuery", "JS library",
              body_re=r"jquery(?:-[\d.]+)?(?:\.min)?\.js|/jquery[/-]"),
    Signature("react", "React", "JS library",
              body_re=r"data-reactroot|react-dom|__REACT_DEVTOOLS_GLOBAL_HOOK__"),
    Signature("angular", "Angular", "JS library",
              body_re=r"ng-app|ng-version|ng-controller|ng-model"),
    Signature("vuejs", "Vue.js", "JS library",
              body_re=r"vue(?:\.min)?\.js|data-v-[0-9a-f]{8}|__vue__"),
    Signature("bootstrap", "Bootstrap", "JS library",
              body_re=r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)"),
    Signature("font-awesome", "Font Awesome", "JS library",
              body_re=r"font-?awesome"),
    Signature("momentjs", "Moment.js", "JS library",
              body_re=r"moment(?:\.min)?\.js"),
    Signature("lodash", "Lodash", "JS library",
              body_re=r"lodash(?:\.min)?\.js"),
    Signature("underscore", "Underscore.js", "JS library",
              body_re=r"underscore(?:\.min)?\.js"),
    Signature("d3js", "D3.js", "JS library",
              body_re=r"d3(?:\.min)?\.js"),
    Signature("socketio", "Socket.IO", "JS library",
              cookie="io",
              body_re=r"/socket\.io/socket\.io(?:\.min)?\.js"),
    Signature("alpinejs", "Alpine.js", "JS library",
              body_re=r"x-data=|alpinejs"),
    Signature("htmx", "htmx", "JS library",
              body_re=r"hx-get=|htmx(?:\.min)?\.js"),
    Signature("gsap", "GSAP", "JS library",
              body_re=r"gsap(?:\.min)?\.js"),
    Signature("threejs", "three.js", "JS library",
              body_re=r"three(?:\.min)?\.js"),
    Signature("google-maps", "Google Maps JS API", "JS library",
              body_re=r"maps\.googleapis\.com/maps/api/js"),

    # -------------------------------------------------------------- analytics (13)
    Signature("google-analytics", "Google Analytics", "analytics",
              body_re=r"google-analytics\.com/(?:analytics|ga)\.js|gtag\("),
    Signature("google-tag-manager", "Google Tag Manager", "analytics",
              body_re=r"googletagmanager\.com/gtm\.js|GTM-[A-Z0-9]{4,}"),
    Signature("google-adsense", "Google AdSense", "analytics",
              body_re=r"pagead2\.googlesyndication\.com"),
    Signature("facebook-pixel", "Facebook Pixel", "analytics",
              body_re=r"connect\.facebook\.net/[^\"']*fbevents\.js|fbq\("),
    Signature("hotjar", "Hotjar", "analytics",
              body_re=r"static\.hotjar\.com|hj\("),
    Signature("matomo", "Matomo", "analytics",
              body_re=r"matomo\.js|piwik\.js|_paq\.push"),
    Signature("mixpanel", "Mixpanel", "analytics",
              body_re=r"mixpanel\.init|cdn\.mixpanel\.com|cdn\.mxpanel\.com"),
    Signature("segment", "Segment", "analytics",
              body_re=r"cdn\.segment\.com/analytics\.js|analytics\.load\("),
    Signature("plausible", "Plausible", "analytics",
              body_re=r"plausible\.io/js/"),
    Signature("yandex-metrica", "Yandex Metrica", "analytics",
              body_re=r"mc\.yandex\.ru/metrika"),
    Signature("microsoft-clarity", "Microsoft Clarity", "analytics",
              body_re=r"clarity\.ms/tag"),
    Signature("new-relic", "New Relic Browser", "analytics",
              body_re=r"js-agent\.newrelic\.com|NREUM"),
    Signature("hubspot", "HubSpot", "analytics",
              body_re=r"hs-scripts\.com|hs-analytics\.net|hsforms\.net"),
    Signature("cloudflare-insights", "Cloudflare Insights", "analytics",
              body_re=r"static\.cloudflareinsights\.com"),

    # -------------------------------------------------------------------- CDN (11)
    Signature("cloudflare", "Cloudflare", "CDN",
              header_name_re=r"^(?:cf-ray|cf-cache-status|cf-request-id)$",
              header="Server", header_re=r"^cloudflare$",
              cookie="__cfduid",
              cookie_re=r"^(?:__cf_bm|cf_clearance|__cfduid)$",
              note="__cfduid is Cloudflare's historical bot cookie; __cf_bm and "
                   "cf_clearance are its current replacements."),
    Signature("akamai", "Akamai", "CDN",
              header_name_re=r"^(?:x-akamai-|akamai-|x-check-cacheable)",
              header="Server", header_re=r"AkamaiGHost"),
    Signature("fastly", "Fastly", "CDN",
              header_name_re=r"^(?:x-fastly-|x-served-by|x-timer)$"),
    Signature("amazon-cloudfront", "Amazon CloudFront", "CDN",
              header="Via", header_re=r"cloudfront",
              header_name_re=r"^x-amz-cf-id$"),
    Signature("azure-front-door", "Azure Front Door", "CDN",
              header_name_re=r"^x-azure-ref$"),
    Signature("varnish", "Varnish", "CDN",
              header="Via", header_re=r"\bvarnish\b",
              header_name_re=r"^x-varnish$"),
    Signature("keycdn", "KeyCDN", "CDN",
              header="Server", header_re=r"keycdn"),
    Signature("bunnycdn", "BunnyCDN", "CDN",
              header="Server", header_re=r"BunnyCDN"),
    Signature("stackpath", "StackPath", "CDN",
              header="Server", header_re=r"StackPath|Highwinds"),
    Signature("aws-elb", "AWS Elastic Load Balancer", "CDN",
              cookie_re=r"^AWSALB(?:CORS)?$"),
    Signature("google-cloud-gfe", "Google Cloud / GFE", "CDN",
              header="Server", header_re=r"(?:Google Frontend|\bgws\b)"),

    # -------------------------------------------------------------------- WAF (9)
    Signature("cloudflare-waf", "Cloudflare WAF", "WAF",
              body_re=r"Attention Required! \| Cloudflare|cf-error-details|cf-wrapper"),
    Signature("imperva", "Imperva Incapsula", "WAF",
              header_name_re=r"^x-iinfo$",
              cookie_re=r"^(?:incap_ses_|visid_incap_)"),
    Signature("sucuri", "Sucuri", "WAF",
              header_name_re=r"^x-sucuri",
              header="Server", header_re=r"Sucuri/Cloudproxy"),
    Signature("modsecurity", "ModSecurity", "WAF",
              header="Server", header_re=r"mod_security|ModSecurity"),
    Signature("f5-bigip", "F5 BIG-IP", "WAF",
              cookie_re=r"^BIGipServer",
              header="Server", header_re=r"BIG-IP"),
    Signature("barracuda", "Barracuda WAF", "WAF",
              cookie_re=r"^barra_counter_session$"),
    Signature("citrix-netscaler", "Citrix NetScaler", "WAF",
              cookie_re=r"^(?:NSC_|citrix_ns_id)"),
    Signature("fortinet-fortiweb", "Fortinet FortiWeb", "WAF",
              cookie_re=r"^FORTIWAFSID$"),
    Signature("wordfence", "Wordfence", "WAF",
              body_re=r"/wp-content/plugins/wordfence/|wordfence"),

    # ------------------------------------------------------------------ panel (17)
    Signature("grafana", "Grafana", "panel",
              cookie="grafana_session",
              body_re=r"grafana(?:-app|\.js|\.css)|<title>Grafana"),
    Signature("kibana", "Kibana", "panel",
              header_name_re=r"^kbn-",
              body_re=r"kibana"),
    Signature("jenkins", "Jenkins", "panel",
              header_name_re=r"^x-jenkins",
              body_re=r"Jenkins-CI|/static/[0-9a-f]+/jenkins"),
    Signature("gitlab", "GitLab", "panel",
              header_name_re=r"^x-gitlab",
              cookie_re=r"^_gitlab_session$",
              body_re=r"gitlab"),
    Signature("confluence", "Confluence", "panel",
              header_name_re=r"^x-confluence",
              body_re=r"confluence"),
    Signature("portainer", "Portainer", "panel",
              header_name_re=r"^x-portainer",
              body_re=r"portainer"),
    Signature("phpmyadmin", "phpMyAdmin", "panel",
              body_re=r"phpMyAdmin",
              cookie="phpMyAdmin",
              path="/phpmyadmin/", path_status=(200, 301, 302, 401, 403)),
    Signature("adminer", "Adminer", "panel",
              body_re=r"adminer",
              path="/adminer.php", path_status=(200,)),
    Signature("rabbitmq-management", "RabbitMQ Management", "panel",
              body_re=r"RabbitMQ Management"),
    Signature("minio", "MinIO", "panel",
              header="Server", header_re=r"MinIO",
              body_re=r"minio"),
    Signature("kubernetes-dashboard", "Kubernetes Dashboard", "panel",
              body_re=r"kubernetes-dashboard|Kubernetes Dashboard"),
    Signature("prometheus", "Prometheus", "panel",
              body_re=r"Prometheus Time Series Collection and Processing Server"),
    Signature("zabbix", "Zabbix", "panel",
              cookie_re=r"^zbx_session",
              body_re=r"zabbix"),
    Signature("cpanel", "cPanel", "panel",
              header="Server", header_re=r"cpsrvd"),
    Signature("webmin", "Webmin", "panel",
              header="Server", header_re=r"MiniServ",
              body_re=r"webmin"),
    Signature("jupyter", "Jupyter Notebook", "panel",
              body_re=r"jupyter(?:_notebook|\.js)|Jupyter Notebook"),
    Signature("tomcat-manager", "Tomcat Manager", "panel",
              path="/manager/html", path_status=(200, 401, 403)),
)
