# Integration Tests

This directory contains integration tests for scitokens-cpp that use a full end-to-end testing environment.

## Overview

The integration test framework provides:

1. **TLS Infrastructure**: Automatic generation of CA certificates and server certificates for HTTPS testing
2. **Key Management**: EC key generation and JWKS creation for token signing
3. **Test Server**: Python-based HTTPS server hosting JWKS and supporting OIDC discovery
4. **CTest Fixtures**: Automated setup and teardown using CTest fixture framework

## Architecture

The integration tests use a CTest fixture pattern with three components:

### Setup (`integration-test-setup.sh`)

The setup script:
- Creates a temporary test run directory
- Generates TLS certificates (CA and server certificate)
- Generates EC P-256 signing keys
- Converts public key to JWKS format
- Starts a Python HTTPS server on a dynamic port (port 0)
- Writes environment configuration to `build/tests/integration/setup.sh`

The setup script writes the following information to `setup.sh`:
- `ISSUER_URL`: The HTTPS URL of the test issuer (e.g., `https://localhost:12345`)
- `SERVER_PID`: Process ID of the running server
- `CA_CERT`: Path to the CA certificate for TLS verification
- `SIGNING_KEY`: Path to the EC private key
- `SIGNING_PUB`: Path to the EC public key
- `JWKS_FILE`: Path to the JWKS file

### Test (`integration_test.cpp`)

The integration test program:
- Reads configuration from `build/tests/integration/setup.sh`
- Configures scitokens to trust the test CA certificate
- Creates and signs tokens using the test issuer
- Verifies tokens using JWKS discovery from the test server
- Tests the enforcer functionality with dynamically issued tokens

Three test cases are included:
1. **CreateAndSignToken**: Verifies basic token creation and signing
2. **VerifyTokenWithJWKSDiscovery**: Tests token verification using JWKS discovery from the HTTPS server
3. **EnforcerWithDynamicIssuer**: Tests the enforcer API with tokens from the dynamic test issuer

### Teardown (`integration-test-teardown.sh`)

The teardown script:
- Reads the server PID from `setup.sh`
- Gracefully stops the server (SIGTERM, then SIGKILL if needed)
- Cleans up the test environment

## Running the Tests

### Build with Integration Tests

```bash
mkdir build
cd build
cmake -DSCITOKENS_BUILD_UNITTESTS=ON ..
make
```

### Run Integration Tests Only

```bash
ctest -R integration --output-on-failure
```

### Run All Tests

```bash
ctest --output-on-failure
```

## Test Server

The Python test server (`jwks_server.py`) implements:

- **OIDC Discovery**: Serves `.well-known/openid-configuration`
- **JWKS Endpoint**: Serves the JWKS at `/oauth2/certs`
- **HTTPS Support**: Uses TLS with generated certificates
- **Dynamic Port Allocation**: Binds to port 0 for automatic port selection

The server is designed to be minimal and focused solely on the requirements for integration testing.

## Requirements

- Python 3.6+
- OpenSSL command-line tools
- cryptography Python package (for JWKS generation)

## Troubleshooting

### Server fails to start

Check that Python 3 is available and the cryptography package is installed:
```bash
python3 -c "from cryptography.hazmat.primitives import serialization"
```

### TLS certificate errors

The test automatically generates self-signed certificates. The scitokens library is configured to trust the test CA certificate via the `tls.ca_file` configuration option.

### Server doesn't shut down cleanly

The teardown script will wait up to 10 seconds for graceful shutdown, then send SIGKILL. If tests are interrupted, you may need to manually kill the server process:
```bash
ps aux | grep jwks_server
kill <PID>
```

## Design Decisions

1. **Dynamic Port Allocation**: Using port 0 ensures tests can run in parallel and don't conflict with existing services.

2. **Self-Signed Certificates**: Generated on-the-fly to avoid committing secrets to the repository and to test the full TLS stack.

3. **HTTPS Required**: SciTokens requires HTTPS issuers, so we use HTTPS even for local testing.

4. **CTest Fixtures**: Using CTest's fixture framework ensures proper setup and teardown ordering, even when tests run in parallel.

5. **Detached Server Process**: The server runs detached from the shell to avoid blocking the setup script.

6. **Minimal Python Server**: Using Python's built-in `http.server` keeps dependencies minimal. Only the cryptography package is needed for JWKS generation.
