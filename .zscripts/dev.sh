#!/bin/bash
cd /home/z/my-project

# Install dependencies if needed
bun install 2>/dev/null

# Push database schema
bun run db:push 2>/dev/null

# Start the dev server with keepalive
while true; do
  npx next dev -p 3000 -H 0.0.0.0 >> /home/z/my-project/dev.log 2>&1
  echo "[$(date)] Server died, restarting in 5s..." >> /home/z/my-project/dev-keepalive.log
  sleep 5
done
