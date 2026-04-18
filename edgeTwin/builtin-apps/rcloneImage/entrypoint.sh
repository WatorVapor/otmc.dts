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

/usr/local/bin/rclone &
RCLONE_PID=$!

echo "Waiting for SPIRE socket..."
for i in {1..30}; do
    [ -S "$SPIRE_SOCKET_PATH" ] && break
    sleep 1
done

wait "$RCLONE_PID"
