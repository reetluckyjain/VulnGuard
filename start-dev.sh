#!/bin/bash
cd /home/z/my-project
while true; do
    echo "[$(date)] Starting Next.js dev server..." >> /home/z/my-project/dev-keepalive.log
    npx next dev -p 3000 >> /home/z/my-project/dev.log 2>&1
    EXIT=$?
    echo "[$(date)] Next.js exited with code $EXIT, restarting in 3s..." >> /home/z/my-project/dev-keepalive.log
    sleep 3
done
