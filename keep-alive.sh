#!/bin/bash
cd /home/z/my-project
while true; do
    node .next/standalone/server.js &
    SERVER_PID=$!
    disown $SERVER_PID
    
    # Wait for server to be ready
    for i in $(seq 1 30); do
        if curl -s -m 1 http://127.0.0.1:3000/ >/dev/null 2>&1; then
            break
        fi
        sleep 0.3
    done
    
    # Wait for server to die - check every 0.5 seconds
    while kill -0 $SERVER_PID 2>/dev/null; do
        sleep 0.5
    done
    
    # Immediately restart (no delay)
done
