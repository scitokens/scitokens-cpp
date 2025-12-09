#!/bin/bash
#
# Teardown script for scitokens-cpp integration tests
# Stops the test server using PID from setup.sh
#

set -e

TEST_NAME=${1:-integration}

if [ -z "$BINARY_DIR" ]; then
  echo "\$BINARY_DIR environment variable is not set; cannot run test"
  exit 1
fi

echo "Tearing down integration test environment for $TEST_NAME"

TEST_DIR="$BINARY_DIR/tests/$TEST_NAME"
SETUP_FILE="$TEST_DIR/setup.sh"

if [ ! -f "$SETUP_FILE" ]; then
  echo "Setup file $SETUP_FILE not found - test may not have run"
  exit 0
fi

# Source the setup file to get variables
. "$SETUP_FILE"

if [ -z "$SERVER_PID" ]; then
  echo "SERVER_PID not found in setup file"
  exit 1
fi

echo "Stopping server (PID: $SERVER_PID)..."

# Check if process is running
if ! kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "Server process was already stopped"
  exit 0
fi

# Send SIGTERM to server
kill "$SERVER_PID" 2>/dev/null || true

# Wait for server to stop (with timeout)
TIMEOUT=5
ELAPSED=0
while kill -0 "$SERVER_PID" 2>/dev/null; do
  sleep 0.1
  ELAPSED=$((ELAPSED + 1))
  if [ $ELAPSED -ge $((TIMEOUT * 10)) ]; then
    echo "Timeout waiting for server to stop, sending SIGKILL"
    kill -9 "$SERVER_PID" 2>/dev/null || true
    sleep 0.1
    break
  fi
done

# Verify server is stopped (best effort - don't fail if already gone)
if kill -0 "$SERVER_PID" 2>/dev/null; then
  echo "Warning: Server may still be running"
else
  echo "Server stopped successfully"
fi

