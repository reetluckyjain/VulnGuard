#!/bin/bash
cd /home/z/my-project
while true; do
    echo "[$(date)] Starting dev server..."
    bun run dev 2>&1 | tee -a /home/z/my-project/dev.log
    
    EXIT_CODE=$?
    echo "[$(date)] Dev server exited with code $EXIT_CODE, restarting in 2s..."
    sleep 2
done
