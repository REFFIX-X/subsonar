# Full subsonar image: CLI, TUI and the Streamlit dashboard.
# Reports and the on-disk cache go to /data (mount a volume there to keep them).
FROM python:3.12-slim

LABEL org.opencontainers.image.title="subsonar" \
      org.opencontainers.image.description="Asynchronous subdomain and web-interface scanner" \
      org.opencontainers.image.source="https://github.com/REFFIX-X/subsonar" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SUBSONAR_CACHE=/data/.subsonar_cache \
    SUBSONAR_OUTPUT=/data/output

WORKDIR /opt/subsonar

COPY LICENSE README.md pyproject.toml ./
COPY subsonar ./subsonar

RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 1000 --shell /usr/sbin/nologin subsonar \
    && mkdir -p /data/.subsonar_cache /data/output \
    && chown -R subsonar:subsonar /data \
    && command -v runuser >/dev/null

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

WORKDIR /data

# The entrypoint starts as root so it can fix ownership of a mounted /data,
# then execs `subsonar` as uid 1000. The scanner itself does not run as root.
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["--help"]
