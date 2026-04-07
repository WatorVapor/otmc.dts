FROM ghcr.io/spiffe/spire-agent:1.14.4 AS agent
FROM ghcr.io/spiffe/spiffe-helper:0.11.0 AS helper
FROM ubuntu:26.04
RUN apt-get update && apt-get install -y ca-certificates tini && rm -rf /var/lib/apt/lists/*
COPY --from=agent /opt/spire/bin/spire-agent /usr/local/bin/spire-agent
COPY --from=helper /spiffe-helper /usr/local/bin/spiffe-helper
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh
ENV SPIRE_SOCKET_PATH=/run/spire/sockets/agent.sock
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint.sh"]
