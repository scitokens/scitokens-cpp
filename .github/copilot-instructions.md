# GitHub Copilot Instructions for scitokens-cpp

## Project Overview

scitokens-cpp is a C++ library for creating and validating SciTokens (JWT-based authorization tokens for scientific computing). The library uses JWT-cpp for token operations and supports OIDC discovery with JWKS for public key distribution.

## Building the Project

### Prerequisites

- CMake 3.10 or later
- C++11 compatible compiler (gcc, clang)
- OpenSSL 1.1.1 or later (3.0+ recommended)
- libuuid
- sqlite3
- jwt-cpp (included as vendor submodule)

### Build Commands

```bash
# Create build directory
mkdir -p build
cd build

# Configure with CMake (enable tests with -DSCITOKENS_BUILD_UNITTESTS=ON)
cmake .. -DSCITOKENS_BUILD_UNITTESTS=ON

# Build all targets
make

# Install (optional)
sudo make install
```

### CMake Build Options

- Tests are **disabled by default** - use `-DSCITOKENS_BUILD_UNITTESTS=ON` to enable
- Build produces:
  - `libSciTokens.so` - Main library
  - `scitokens-test` - Unit tests (Google Test)
  - `scitokens-integration-test` - Integration tests with real HTTPS server
  - `scitokens-generate-jwks` - JWKS generation utility
  - Command-line tools: `scitokens-verify`, `scitokens-create`, `scitokens-list-access`, `scitokens-test-access`

## Running Tests

### Unit Tests

```bash
cd build
./scitokens-test
```

Expected: 29 unit tests should pass

### Integration Tests

Integration tests use CTest fixtures with setup/teardown phases:

```bash
cd build/test
ctest --output-on-failure
```

Or run specific test phases:
```bash
ctest -R integration::setup    # Start HTTPS JWKS server
ctest -R integration::test      # Run integration tests
ctest -R integration::teardown  # Stop server
```

**Integration test infrastructure:**
- `test/jwks_server.py` - Python HTTPS server with OIDC discovery and JWKS endpoints
- `test/integration-test-setup.sh` - Generates TLS certificates and starts server
- `test/integration-test-teardown.sh` - Stops server gracefully
- `test/integration_test.cpp` - C++ tests using real HTTPS connections

Expected: 3 integration tests should pass (total time ~1-2 seconds)

### All Tests

```bash
cd build/test
ctest --output-on-failure
```

Expected: 32 total tests (29 unit + 3 integration)

## Code Style

- C++11 standard
- Use `clang-format` for formatting (configuration in project root)
- Format before committing: `clang-format -i src/*.cpp src/*.h`

## Testing Infrastructure Details

### JWKS Server (test/jwks_server.py)

Python HTTPS server that provides:
- `/.well-known/openid-configuration` - OIDC discovery document
- `/oauth2/certs` - JWKS public key endpoint

Server features:
- HTTP/1.1 with keep-alive support
- TLS 1.2+ with self-signed certificates
- Graceful shutdown with SIGTERM
- Logs to `build/tests/integration/server.log`

### Integration Test Flow

1. **Setup**: Generate EC P-256 key pair, create JWKS, generate TLS certificates, start HTTPS server
2. **Test**: Create tokens, verify with JWKS discovery, test dynamic issuer enforcement
3. **Teardown**: Stop server, print logs if tests failed

### Debugging Integration Tests

If integration tests fail:
1. Check server log: `cat build/tests/integration/server.log`
2. Verify server started: `cat build/tests/integration/server_ready`
3. Test HTTPS manually: `curl -k https://localhost:<port>/.well-known/openid-configuration`

## Key Files

- `src/scitokens.cpp`, `src/scitokens.h` - Main library API
- `src/generate_jwks.cpp` - JWKS generation (EC P-256 keys)
- `src/scitokens_internal.cpp` - Token validation and OIDC discovery
- `src/scitokens_cache.cpp` - JWKS caching
- `test/integration_test.cpp` - End-to-end integration tests
- `test/main.cpp` - Google Test unit tests

## Development Workflow

1. Make code changes
2. Build: `cd build && cmake .. && make`
3. Run unit tests: `./scitokens-test`
4. Run integration tests: `cd test && ctest --output-on-failure`
5. Format code: `clang-format -i <modified-files>`
6. Commit with descriptive message

## CI/CD

GitHub Actions runs tests on:
- Ubuntu 22.04 (OpenSSL 3.0.2)
- Ubuntu 24.04 (OpenSSL 3.0.13)

Integration tests verify TLS compatibility across OpenSSL versions.
