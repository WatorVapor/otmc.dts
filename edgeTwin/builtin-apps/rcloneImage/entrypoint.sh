#!/bin/bash

cleanup() {
    echo "Received termination signal. Shutting down..."
    kill -TERM "$RCLONE_PID" 2>/dev/null
    wait "$RCLONE_PID"
    exit 0
}
trap cleanup SIGTERM SIGINT

/usr/local/bin/rclone &
RCLONE_PID=$!

wait "$RCLONE_PID"
