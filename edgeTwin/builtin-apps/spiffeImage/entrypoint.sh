#!/bin/bash

cleanup() {
    echo "Received termination signal. Shutting down..."
    kill -TERM "$AGENT_PID" 2>/dev/null
    kill -TERM "$HELPER_PID" 2>/dev/null
    wait "$AGENT_PID"
    wait "$HELPER_PID"
    exit 0
}
trap cleanup SIGTERM SIGINT

/usr/local/bin/spire-agent run -config /opt/spire/conf/agent/agent.conf &
AGENT_PID=$!

echo "Waiting for SPIRE socket..."
for i in {1..30}; do
    [ -S "$SPIRE_SOCKET_PATH" ] && break
    sleep 1
done

/usr/local/bin/spiffe-helper -config /etc/helper-config.conf &
HELPER_PID=$!

wait "$HELPER_PID" "$AGENT_PID"
