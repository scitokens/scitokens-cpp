#!/bin/bash
#
# Setup script for scitokens-cpp integration tests
# Creates TLS certificates, keys, JWKS, and launches test server
#

set -e

TEST_NAME=${1:-integration}

if [ -z "$BINARY_DIR" ]; then
  echo "\$BINARY_DIR environment variable is not set; cannot run test"
  exit 1
fi

if [ -z "$SOURCE_DIR" ]; then
  echo "\$SOURCE_DIR environment variable is not set; cannot run test"
  exit 1
fi

echo "Setting up integration test environment for $TEST_NAME"

# Create test directory
TEST_DIR="$BINARY_DIR/tests/$TEST_NAME"
mkdir -p "$TEST_DIR"
RUNDIR=$(mktemp -d -p "$TEST_DIR" test_run.XXXXXXXX)
chmod 0755 "$RUNDIR"

if [ ! -d "$RUNDIR" ]; then
  echo "Failed to create test run directory; cannot run test"
  exit 1
fi

echo "Using $RUNDIR as the test run directory"
cd "$RUNDIR"

# Create link to rundir at fixed location for tests to find
if [ -L "$TEST_DIR/current" ]; then
  rm "$TEST_DIR/current"
fi
ln -sf "$RUNDIR" "$TEST_DIR/current"

############################
# Generate TLS certificates
############################
echo "Generating TLS CA and host certificate..."

# Generate CA key and certificate
openssl genrsa -out ca-key.pem 2048 2>/dev/null
openssl req -new -x509 -days 365 -key ca-key.pem -out ca-cert.pem \
  -subj "/C=US/ST=Test/L=Test/O=SciTokens Test/CN=Test CA" 2>/dev/null

# Generate server key and certificate
openssl genrsa -out server-key.pem 2048 2>/dev/null
openssl req -new -key server-key.pem -out server.csr \
  -subj "/C=US/ST=Test/L=Test/O=SciTokens Test/CN=localhost" 2>/dev/null

# Create server certificate signed by CA
cat > server-cert-ext.cnf <<EOF
subjectAltName = DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -days 365 -in server.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -out server-cert.pem -extfile server-cert-ext.cnf 2>/dev/null

echo "TLS certificates created"

##########################
# Generate signing keys
##########################
echo "Generating EC signing keys..."

# Generate EC private key
openssl ecparam -name prime256v1 -genkey -noout -out signing-key.pem 2>/dev/null

# Extract public key
openssl ec -in signing-key.pem -pubout -out signing-pub.pem 2>/dev/null

echo "Signing keys created"

##########################
# Generate JWKS
##########################
echo "Generating JWKS..."

# Use Python to convert EC public key to JWKS format
python3 - <<'PYTHON_SCRIPT' > jwks.json
import json
import base64
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Read the public key
with open('signing-pub.pem', 'rb') as f:
    pem_data = f.read()

# Load the public key
public_key = serialization.load_pem_public_key(pem_data, backend=default_backend())

# Get the public numbers
public_numbers = public_key.public_numbers()

# Convert to base64url format (without padding)
def int_to_base64url(num, length):
    num_bytes = num.to_bytes(length, byteorder='big')
    b64 = base64.urlsafe_b64encode(num_bytes).decode('ascii')
    return b64.rstrip('=')

# For P-256 curve, coordinates are 32 bytes
x_b64 = int_to_base64url(public_numbers.x, 32)
y_b64 = int_to_base64url(public_numbers.y, 32)

# Create JWKS
jwks = {
    "keys": [
        {
            "kty": "EC",
            "use": "sig",
            "crv": "P-256",
            "kid": "test-key-1",
            "x": x_b64,
            "y": y_b64,
            "alg": "ES256"
        }
    ]
}

print(json.dumps(jwks, indent=2))
PYTHON_SCRIPT

if [ ! -f jwks.json ]; then
  echo "Failed to generate JWKS"
  exit 1
fi

echo "JWKS created"

##########################
# Start Python web server
##########################
echo "Starting JWKS web server..."

# Start server in background, detached from terminal
python3 "$SOURCE_DIR/test/jwks_server.py" \
  --jwks "$RUNDIR/jwks.json" \
  --build-dir "$BINARY_DIR" \
  --test-name "$TEST_NAME" \
  --cert "$RUNDIR/server-cert.pem" \
  --key "$RUNDIR/server-key.pem" \
  </dev/null >/dev/null 2>&1 &

SERVER_PID=$!
echo "Server PID: $SERVER_PID"

# Wait for server to be ready
READY_FILE="$TEST_DIR/server_ready"
TIMEOUT=30
ELAPSED=0

while [ ! -f "$READY_FILE" ]; do
  sleep 0.5
  ELAPSED=$((ELAPSED + 1))
  if [ $ELAPSED -ge $((TIMEOUT * 2)) ]; then
    echo "Timeout waiting for server to start"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
  fi
  
  # Check if server process is still running
  if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "Server process died unexpectedly"
    exit 1
  fi
done

echo "Server ready"

# Read server info
. "$READY_FILE"

if [ -z "$ISSUER_URL" ]; then
  echo "Failed to get issuer URL from server"
  kill $PID 2>/dev/null || true
  exit 1
fi

echo "Issuer URL: $ISSUER_URL"

##########################
# Write setup.sh
##########################
cat > "$TEST_DIR/setup.sh" <<EOF
# Integration test environment
# This file is sourced by tests and teardown script

ISSUER_URL=$ISSUER_URL
SERVER_PID=$PID
SERVER_PORT=$PORT
RUNDIR=$RUNDIR
CA_CERT=$RUNDIR/ca-cert.pem
SERVER_CERT=$RUNDIR/server-cert.pem
SERVER_KEY=$RUNDIR/server-key.pem
SIGNING_KEY=$RUNDIR/signing-key.pem
SIGNING_PUB=$RUNDIR/signing-pub.pem
JWKS_FILE=$RUNDIR/jwks.json
READY_FILE=$READY_FILE
EOF

echo "Setup complete. Environment written to $TEST_DIR/setup.sh"
echo "Server PID: $PID"
echo "Issuer URL: $ISSUER_URL"
