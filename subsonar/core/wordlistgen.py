"""Generator for the built-in **AI Super** subdomain wordlist.

Why another list?  The public lists are frequency dumps: brilliant coverage of
everything that has ever existed, but they waste most of a short scan on dead
vocabulary and they lag behind the stacks teams actually deploy today.  This one
is the opposite: a curated, deliberately *ordered* list whose first few thousand
labels are the ones that resolve in practice, followed by systematic expansion
for depth.

Three ingredients:

``CURATED``
    Hand-picked names that come up over and over in real engagements —
    ``autodiscover``, ``adfs``, ``cpanel``, ``argocd``, ``vault``, ``sso`` …
``THEMES``
    ~20 curated vocabularies (role, env, mail, identity, infra, data, monitor,
    container, cloud, security, business, ai, …) so a scan covers *roles*, not
    just the popular strings.
``EXPANSION``
    Deterministic family/number/region combinations (``api-dev``, ``apidev``,
    ``api2``, ``api-eu``) with ``-`` and bare separators.

The output is *deterministic*: the same vocabularies always produce a
byte-identical file, which is what lets the test suite assert the shipped list
against :func:`build_labels`.  Licence: CC0-1.0 — it is generic naming
vocabulary, not data copied from a licensed corpus.

Regenerate with ``python tools/build_ai_wordlist.py``.
"""

from __future__ import annotations

import re
from pathlib import Path

__all__ = [
    "BUILTIN_PATH",
    "CURATED",
    "DEFAULT_LIMIT",
    "SEPARATORS",
    "THEMES",
    "build_labels",
    "render_default",
    "render_file",
    "validate_labels",
]

#: Hard cap on the generated list (keeps the packaged file ~0.5 MB).
DEFAULT_LIMIT = 40_000

#: Label separators tried between two vocabulary words.
SEPARATORS: tuple[str, ...] = ("-", "")

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

#: Environment / lifecycle words.  These turn any role into a plausible host.
ENV = (
    "dev development develop tst test testing qa uat sit stage staging stg "
    "prod production prd preprod pre preview beta alpha canary demo sandbox "
    "lab local internal intranet extranet legacy old new next green blue "
    "hotfix release rc nightly edge"
).split()

#: Numbers/versions appended to a role.
NUMBERS = "1 2 3 4 5 6 7 8 9 10 01 02 03 11 12 21 22 31 100 v1 v2 v3 v4".split()

#: Regions / availability zones used as prefix or suffix.
REGIONS = (
    "eu us uk de dk se no fi fr nl be ch at it es pt pl cz gr ie "
    "us-east us-west us-east-1 us-west-2 eu-west eu-west-1 eu-central-1 "
    "eu-north-1 ap-south-1 ap-southeast-1 ap-northeast-1 ca-central-1 sa-east-1"
).split()

#: Hand-picked, high-hit-rate names (the "AI special" part of the list).
CURATED = (
    "www mail smtp pop imap webmail owa autodiscover autoconfig exchange "
    "m mobile app api api2 apis rest graphql grpc ws wss socket realtime "
    "admin administrator adminportal adm adm1 panel manage mgmt manager "
    "portal console dashboard dash ui ux front frontend fe back backend be "
    "root web web1 web2 web01 www2 ww1 static assets img images image media "
    "files file download downloads upload uploads cdn cdn1 cdn2 cdn3 "
    "db db1 db2 sql mysql mariadb postgres pgsql mssql oracle mongo mongodb "
    "redis memcached elastic elasticsearch opensearch kibana logstash "
    "kafka zookeeper rabbitmq mq activemq airflow trino presto clickhouse "
    "influx prometheus grafana metrics monitoring monitor status uptime "
    "health healthcheck nagios zabbix icinga sentry jaeger loki tempo "
    "git gitlab github gitea bitbucket svn ci cd cicd jenkins bamboo "
    "teamcity drone build buildbot artifacts repo registry nexus harbor "
    "artifactory sonar sonarqube jupyter notebook vscode code codeserver "
    "k8s kubernetes kube k3s openshift rancher cluster nomad consul vault "
    "terraform ansible puppet chef salt docker helm istio kong traefik "
    "envoy portainer "
    "auth login signin sso sso-login oauth oidc saml saml2 idp adfs sts cas "
    "ldap ad dc dc1 dc2 radius mfa 2fa otp token keycloak okta auth0 "
    "vpn vpn1 vpn2 openvpn wireguard remote rdp ssh sftp ftp ftps tftp "
    "bastion jump jumpbox gateway gw proxy proxy1 squid haproxy nginx "
    "lb lb1 load loadbalancer ns ns1 ns2 ns3 dns dns1 dns2 dhcp ntp "
    "firewall fw router switch backup bak bkp archive restore nas san nfs "
    "crm erp sap salesforce hubspot jira confluence servicenow zendesk "
    "freshdesk intercom slack teams zoom webex sharepoint onedrive dropbox "
    "nextcloud owncloud o365 office outlook vdi citrix rds "
    "shop store cart checkout pay payment payments billing invoice "
    "account accounts my profile user users members customer customers "
    "partner partners vendor supplier order orders catalog search "
    "support help helpdesk faq kb docs doc documentation wiki forum "
    "community chat meet video stream live radio news blog press "
    "careers jobs hr people team about contact info events training "
    "ai ml model models inference llm gpt llmops mlflow kubeflow sagemaker "
    "vector vectordb weaviate qdrant ollama gpu gpu1 cuda dataset datasets "
    "security secure waf siem soc ids ips scanner scan nessus audit "
    "pentest redteam cloud aws azure gcp oci s3 storage blob bucket "
    "media1 tmp temp test1 test2 demo1 dev1 dev2 prod1 prod2 stage1 stage2 "
    "legacy1 old1 new1 www3 webmail2 mailer relay mta postfix lists "
    "newsletter marketing analytics bi data warehouse etl dw dwh lake "
    "printing print iot devices device sensor camera voip phone pbx "
    "hrms payroll finance legal procurement inventory logistics "
    "fleet tracking maps geo gis location store1 store2 "
    "internal1 intranet2 extranet2 partner1 partner2 client1 client2 "
    "api-dev api-test api-staging api-prod api-internal api-v1 api-v2 "
    "api-gateway gateway1 apigw ingress egress service-mesh mesh "
    "web-dev web-test web-staging web-prod app-dev app-test app-staging "
    "app-prod admin-dev admin-test admin-staging admin-prod admin-old "
    "www-dev www-test www-staging www-prod test-www dev-www stage-www "
    "staging-admin staging-api staging-app staging-web staging-www "
    "dev-api dev-app dev-web dev-admin dev-www test-api test-app test-admin "
    "prod-api prod-app prod-admin prod-web prod-www prod-db prod-cache "
    "uat-api uat-app uat-web uat-admin qa-api qa-app qa-web qa-admin "
    "beta-api beta-app beta-web beta1 demo-api demo-app demo-web demo1 "
    "autodiscover-mail mail-autodiscover mail1 mail2 mail3 mail-relay "
    "smtp1 smtp2 smtp-relay imap1 pop1 pop3 webmail3 exchange1"
).split()

#: Curated vocabularies: theme → words.  Kept as strings for readability.
THEME_TEXT: dict[str, str] = {
    "role": (
        "www web web1 web2 web3 app apps app1 app2 app3 api api1 api2 api3 "
        "apis rest graphql gql grpc service services svc micro microservice "
        "frontend front fe backend back be ui core base main hub node worker "
        "edge compute server host host1 host2 client client1 proxy proxy1 "
        "gateway gw ingress router1 balancer origin"
    ),
    "env": " ".join(ENV),
    "web": (
        "cms blog news shop store cart checkout pay payments billing invoice "
        "account accounts my me profile user users member members customer "
        "orders catalog search support help helpdesk faq kb docs documentation "
        "wiki forum community chat meet video stream live tv radio media music "
        "gallery photos press careers jobs hr people team about contact info "
        "events training academy university learning course survey feedback "
        "ticket tickets lead leads quote quotes price prices product products "
        "inventory delivery shipping returns warranty service1 services1"
    ),
    "mail": (
        "mail email smtp smtp1 smtp2 imap imap1 pop pop3 mx mx1 mx2 mail1 mail2 "
        "mail3 webmail owa owa1 owa2 exchange exch exch1 autodiscover "
        "autoconfig mta relay postfix sendmail lists newsletter mailer "
        "mailgun mailsrv mailhost webmail1 webmail2 relay1 outbound inbound "
        "spam filter1 quarantine dkim dmarc spf bounce"
    ),
    "identity": (
        "auth login signin sso oauth oauth2 oidc saml saml2 idp adfs sts cas "
        "cas1 ldap ldap1 ad dc dc1 dc2 radius mfa 2fa otp token tokens "
        "keycloak keycloak1 auth0 okta passport identity directory "
        "accounts1 profile1 permissions roles scim webauth connect login1 "
        "signup register password reset verify consent"
    ),
    "infra": (
        "ns ns1 ns2 ns3 ns4 dns dns1 dns2 dns3 dhcp dhcp1 ntp ntp1 time "
        "syslog loghost syslog1 vpn vpn1 vpn2 vpn3 openvpn wireguard ipsec "
        "ppp pppoe firewall fw fw1 router r1 r2 switch sw1 sw2 core1 core2 "
        "gw1 gw2 proxy2 squid haproxy nginx nginx1 lb lb1 lb2 load "
        "loadbalancer bastion jump jumpbox remote rdp ssh sftp ftp ftps tftp "
        "nfs smb cifs iscsi san nas backup bak bkp archive restore dr "
        "drsite failover warm cold standby primary secondary"
    ),
    "dev": (
        "git gitlab github gitea gogs bitbucket svn cvs mercurial ci cd cicd "
        "ci1 build buildbot jenkins jenkins1 jenkins2 bamboo teamcity drone "
        "argo argocd tekton spinnaker concourse runner runners executor "
        "artifacts artifact repo repos registry registry1 harbor nexus "
        "artifactory sonar sonarqube code codeserver vscode theia jupyter "
        "notebook notebooks lab1 smoke staging1 sandbox1 devops pipeline "
        "release releases deploy deployment rollout feature branch"
    ),
    "data": (
        "db db1 db2 db3 sql sql1 mysql mysql1 mariadb postgres postgresql "
        "pgsql pg pg1 oracle oracle1 mssql sqlserver sql01 mongo mongodb "
        "mongo1 redis redis1 redis2 memcache memcached elastic elasticsearch "
        "es es1 opensearch solr cassandra scylla clickhouse influx influxdb "
        "timescale couchdb neo4j dynamo datastore warehouse dw dwh lake "
        "lakehouse etl elt ingest datalake data1 analytics bi reports "
        "reporting ods replica primary-db"
    ),
    "stream": (
        "kafka kafka1 zookeeper zk rabbitmq rabbit rabbit1 mq mq1 activemq "
        "nats pulsar qpid queue queues worker1 worker2 consumer producer "
        "broker pubsub eventbus events event stream1 streaming cdc debezium "
        "flink beam spark hadoop hive hbase trino presto drill impala"
    ),
    "monitor": (
        "monitor monitoring mon uptime status statuspage health healthcheck "
        "checks check metrics prometheus prom prom1 grafana graf graf1 kibana "
        "kib loki tempo jaeger zipkin tracing trace alertmanager alerts alert "
        "alert1 nagios nagios1 zabbix zabbix1 icinga sensu datadog newrelic "
        "sentry sentry1 netdata cacti munin collectd telegraf victoriametrics "
        "thanos blackbox oncall pager pagerduty graylog splunk elk"
    ),
    "container": (
        "k8s kubernetes kube k3s k0s eks aks gke openshift okd rancher "
        "cluster clusters node1 node2 node3 node4 node5 master master1 "
        "master2 worker1 worker2 worker3 nomad consul consul1 vault vault1 "
        "packer terraform tf state ansible ansible1 puppet chef salt docker "
        "docker1 containerd podman helm helm1 istio linkerd kong traefik "
        "envoy coredns etcd flannel calico cilium crio kubelet"
    ),
    "cloud": (
        "cloud aws azure gcp oci s3 s3-1 storage storage1 blob bucket buckets "
        "static static1 assets assets1 assets2 img images image imgs media "
        "media1 files file1 download downloads upload uploads data data1 "
        "backup1 snapshots snapshot disk disks volume volumes efs fsx "
        "lambda serverless functions function queue1 topic topics cdn cdn1 "
        "edge1 origin origin1 waf1 cloudfront cloudfront1"
    ),
    "security": (
        "security sec secure secure1 waf waf1 antivirus av edr edr1 xdr soar "
        "siem siem1 splunk1 soc noc ids idps ips snort suricata scanner scan "
        "scan1 nessus qualys openvas burp zap proxy3 pentest redteam blue1 "
        "purple1 hunt threat intel threatintel cti soc1 audit compliance pci "
        "gdpr hipaa iso27001 soc2 forensics ir incident keys secrets "
        "certificates certs ca ca1 pki ocsp crl hsm"
    ),
    "business": (
        "crm crm1 erp erp1 sap sap1 netsuite salesforce salesforce1 hubspot "
        "zoho dynamics quickbooks xero sage jira jira1 confluence servicenow "
        "freshdesk zendesk intercom slack teams zoom webex gsuite o365 office "
        "sharepoint onedrive dropbox drive nextcloud owncloud seafile bpm "
        "workflow approval expenses travel budget finance accounting "
        "purchasing procurement contract contracts vendor1"
    ),
    "ai": (
        "ai ml model models inference llm llm1 gpt gpt4 llmops mlflow "
        "kubeflow sagemaker vertex watson vector vectordb weaviate pinecone "
        "milvus chroma qdrant ollama langserve flowise n8n hf huggingface "
        "dataset datasets training trainer gpu gpu1 gpu2 cuda tensorboard "
        "notebook1 rag agent agents copilot embedding reranker prompt studio "
        "genai aigw"
    ),
    "tooling": (
        "portainer cockpit webmin phpmyadmin pma adminer sqladmin pgadmin "
        "mongoexpress rediscommander grafana1 rundeck cron cron1 scheduler "
        "scheduler1 tasks task jobs job batch batch1 hue zeppelin superset "
        "metabase redash looker tableau powerbi qlik dbt airflow1 chatops"
    ),
    "network": (
        "tunnel tunnels zerotier tailscale ngrok cloudflared cloudflare1 "
        "relay1 relay2 nat nat1 snat vrrp bgp ospf multicast igmp qos vlan "
        "vlan1 dmz dmz1 trust untrust inside outside oob ilo idrac ipmi "
        "console1 serial kvm"
    ),
    "devices": (
        "print printing print1 fax scan1 copy printer1 label labels iot iot1 "
        "devices device device1 sensor sensors camera cameras cctv nvr dvr "
        "access badge hvac bms scada plc hmi telemetry fleet gps map maps "
        "geo gis location locator"
    ),
}

#: ``theme → words`` with duplicates removed, order preserved.
THEMES: dict[str, tuple[str, ...]] = {
    theme: tuple(dict.fromkeys(words.split())) for theme, words in THEME_TEXT.items()
}

#: Roles worth expanding with numbers, regions and environments.
CORE_ROLES = tuple(
    dict.fromkeys(
        "www web app apps api apis admin portal dashboard mail smtp imap owa "
        "vpn cdn static assets img media files db sql mysql postgres mongo "
        "redis git jenkins ci build test stage staging prod dev uat qa auth "
        "login sso idp ldap ns dns ns1 lb proxy gw gateway k8s kube grafana "
        "kibana prometheus kafka elastic search shop store my support help "
        "docs wiki blog news mobile m".split()
    )
)

#: Environment words used to build ``<role>-<env>`` / ``<env>-<role>`` names.
_FAMILY_ENVS = tuple(
    dict.fromkeys(
        "dev test tst qa uat stage staging stg prod production prd preprod pre "
        "beta alpha demo sandbox lab internal legacy old new".split()
    )
)


def _accept(label: str) -> bool:
    """Same rules the scanner enforces on a label."""
    return bool(label) and len(label) <= 63 and bool(_LABEL_RE.match(label))


def curated_labels() -> list[str]:
    """The hand-picked, highest-hit-rate names, in the curated order."""
    return [label for label in dict.fromkeys(CURATED) if _accept(label)]


def theme_labels() -> list[str]:
    """Every vocabulary word across every theme, in theme order."""
    out: dict[str, None] = {}
    for words in THEMES.values():
        for word in words:
            if _accept(word):
                out.setdefault(word, None)
    return list(out)


def family_labels() -> list[str]:
    """``role-env`` and ``roleenv`` for every core role × environment."""
    out: dict[str, None] = {}
    for role in CORE_ROLES:
        for env in _FAMILY_ENVS:
            for separator in SEPARATORS:
                candidate = f"{role}{separator}{env}"
                if _accept(candidate):
                    out.setdefault(candidate, None)
    return list(out)


def env_role_labels() -> list[str]:
    """``env-role`` / ``envrole`` — the other order (``dev-api``, ``prod-www``)."""
    out: dict[str, None] = {}
    for env in _FAMILY_ENVS:
        for role in CORE_ROLES:
            for separator in SEPARATORS:
                candidate = f"{env}{separator}{role}"
                if _accept(candidate):
                    out.setdefault(candidate, None)
    return list(out)


def numbered_labels() -> list[str]:
    """``role2`` / ``role-2`` / ``rolev2`` for every core role × number."""
    out: dict[str, None] = {}
    for role in CORE_ROLES:
        for number in NUMBERS:
            for separator in ("", "-"):
                candidate = f"{role}{separator}{number}"
                if _accept(candidate):
                    out.setdefault(candidate, None)
    return list(out)


def region_labels() -> list[str]:
    """``role-eu`` / ``eurole`` for every core role × region."""
    out: dict[str, None] = {}
    for role in CORE_ROLES:
        for region in REGIONS:
            for separator in SEPARATORS:
                candidate = f"{role}{separator}{region}"
                if _accept(candidate):
                    out.setdefault(candidate, None)
    return list(out)


#: Roles used for the ``word-role`` pair stage: the first slice of the role
#: vocabulary plus the four lifecycles that appear in product hostnames.
_PAIR_ROLES = THEMES["role"][:24] + ("dev", "test", "stage", "prod")


def theme_pair_labels() -> list[str]:
    """``<product-word>-<role|env>`` pairs across the service themes."""
    out: dict[str, None] = {}
    for theme in ("web", "business", "data", "monitor", "tooling", "devices"):
        for word in THEMES.get(theme, ()):
            for role in _PAIR_ROLES:
                candidate = f"{word}-{role}"
                if _accept(candidate):
                    out.setdefault(candidate, None)
    return list(out)


def build_labels(limit: int | None = None) -> list[str]:
    """Build the full list, in yield order, deduplicated and capped.

    Order is deliberate and stable: curated names first (a scan that stops after
    a few thousand labels has still tried the most likely ones), then single
    vocabulary words, then systematic expansion.
    """
    stages = (
        curated_labels(),
        theme_labels(),
        family_labels(),
        env_role_labels(),
        numbered_labels(),
        region_labels(),
        theme_pair_labels(),
    )
    cap = DEFAULT_LIMIT if limit is None else max(1, int(limit))
    seen: dict[str, None] = {}
    for stage in stages:
        for label in stage:
            seen.setdefault(label, None)
            if len(seen) >= cap:
                return list(seen)
    return list(seen)


def validate_labels(labels: list[str]) -> list[str]:
    """Return the labels that would be rejected by the scanner's parser."""
    return [label for label in labels if not _accept(label)]


def render_file(labels: list[str], *, source: str = "wordlistgen") -> str:
    """Serialise the list with a provenance header."""
    header = [
        "# subsonar AI Super subdomain wordlist",
        f"# generated by {source} — regenerate: python tools/build_ai_wordlist.py",
        "# licence: CC0-1.0 (public domain) — generic naming vocabulary",
        f"# labels: {len(labels)}",
        "# lines starting with '#' are ignored by the scanner",
    ]
    return "\n".join(header + labels) + "\n"


def render_default(*, source: str = "tools/build_ai_wordlist.py") -> str:
    """The exact file contents the packaged list is expected to have."""
    return render_file(build_labels(DEFAULT_LIMIT), source=source)


#: Shipped path of the generated list.
BUILTIN_PATH = Path(__file__).resolve().parent.parent / "data" / "ai-super-subdomains.txt"
