#!/bin/bash
# VulnGuard - Next.js standalone server with auto-restart
PORT=3000
HOST=0.0.0.0

while true; do
    echo "[$(date)] Starting Next.js standalone on ${HOST}:${PORT}..."
    cd /home/z/my-project
    node .next/standalone/server.js
    EXIT=$?
    echo "[$(date)] Next.js exited with code ${EXIT}, restarting in 2s..."
    sleep 2
done
