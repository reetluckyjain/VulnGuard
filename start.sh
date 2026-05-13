#!/bin/bash
# VulnGuard Service Starter
# Starts the Bun scan service and Next.js dev server

echo "Starting VulnGuard services..."

# Kill any existing instances
pkill -f "scan-service/index.ts" 2>/dev/null
pkill -f "next dev" 2>/dev/null
sleep 1

# Start the Bun scan service on port 3002
echo "Starting scan service on port 3002..."
cd /home/z/my-project/mini-services/scan-service
bun --hot index.ts &
SCAN_PID=$!
echo "Scan service PID: $SCAN_PID"

# Wait for scan service to be ready
for i in $(seq 1 10); do
  if curl -s http://localhost:3002/health > /dev/null 2>&1; then
    echo "Scan service is ready!"
    break
  fi
  sleep 1
done

# Start Next.js dev server on port 3000
echo "Starting Next.js on port 3000..."
cd /home/z/my-project
bun run dev &
NEXT_PID=$!
echo "Next.js PID: $NEXT_PID"

# Wait for Next.js to be ready
for i in $(seq 1 15); do
  if curl -s http://localhost:3000/ > /dev/null 2>&1; then
    echo "Next.js is ready!"
    break
  fi
  sleep 1
done

echo ""
echo "========================================="
echo "VulnGuard is running!"
echo "  Frontend: http://localhost:3000"
echo "  Scan API: http://localhost:3002"
echo "========================================="

# Keep the script running to keep processes alive
wait
