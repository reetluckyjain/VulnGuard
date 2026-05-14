#!/bin/bash
cd /home/z/my-project

# Clean up old log
> /home/z/my-project/dev.log

while true; do
    echo "[$(date)] Starting Next.js dev server on 0.0.0.0:3000..." >> /home/z/my-project/dev-keepalive.log
    
    # Start the server
    npx next dev -p 3000 -H 0.0.0.0 >> /home/z/my-project/dev.log 2>&1 &
    SERVER_PID=$!
    
    # Wait for it to be ready
    for i in $(seq 1 30); do
        if curl -s http://localhost:3000/ -o /dev/null -w "%{http_code}" 2>/dev/null | grep -q 200; then
            echo "[$(date)] Server ready after ${i}s (PID: $SERVER_PID)" >> /home/z/my-project/dev-keepalive.log
            break
        fi
        sleep 1
    done
    
    # Keep the server alive by periodically checking it
    while kill -0 $SERVER_PID 2>/dev/null; do
        sleep 30
        # Make a lightweight request to keep the process active
        curl -s http://localhost:3000/api/schedules > /dev/null 2>&1 || true
    done
    
    EXIT_CODE=$?
    echo "[$(date)] Server exited with code $EXIT_CODE, restarting in 3s..." >> /home/z/my-project/dev-keepalive.log
    sleep 3
done
