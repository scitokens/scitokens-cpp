# SciTokens Offline Cache Support

This document describes the offline cache functionality added to the scitokens-cpp library.

## Overview

The scitokens library now supports offline operation through a direct SQLite cache file that can be pre-populated with JWKS data. This enables environments where external network access to fetch public keys is not available or desired.

## New Features

### 1. SCITOKENS_KEYCACHE_FILE Environment Variable

When set, this environment variable points directly to a SQLite database file that will be used for the key cache, bypassing the normal cache location resolution (XDG_CACHE_HOME, ~/.cache, etc.).

```bash
export SCITOKENS_KEYCACHE_FILE=/path/to/offline.db
```

### 2. scitokens-keycache Command Line Tool

A new command-line utility for creating and managing offline cache files.

#### Usage
```bash
scitokens-keycache --cache-file <cache_file> --jwks <jwks_file> --issuer <issuer> --valid-for <seconds>
```

#### Options
- `--cache-file <file>`: Path to the keycache SQLite database file
- `--jwks <file>`: Path to the JWKS file to store  
- `--issuer <issuer>`: Issuer URL for the JWKS
- `--valid-for <seconds>`: How long the key should be valid (in seconds)
- `--help`: Show help message

#### Example
```bash
scitokens-keycache --cache-file /opt/scitokens/offline.db \
                   --jwks issuer_keys.json \
                   --issuer https://tokens.example.com \
                   --valid-for 86400
```

### 3. New API Function

A new C API function allows programmatic storage of JWKS with explicit expiration times:

```c
int keycache_set_jwks_with_expiry(const char *issuer, const char *jwks, 
                                  int64_t expires_at, char **err_msg);
```

Where `expires_at` is the expiration time as a Unix timestamp (seconds since epoch).

## Usage Workflow

### Setting up an Offline Cache

1. **Create JWKS file**: Save the issuer's public keys in a JSON Web Key Set format
   ```json
   {
     "keys": [
       {
         "kty": "EC",
         "kid": "key-1", 
         "use": "sig",
         "alg": "ES256",
         "x": "...",
         "y": "...",
         "crv": "P-256"
       }
     ]
   }
   ```

2. **Create cache file**: Use the scitokens-keycache tool
   ```bash
   scitokens-keycache --cache-file /opt/tokens/cache.db \
                      --jwks issuer_keys.json \
                      --issuer https://tokens.example.com \
                      --valid-for 2592000  # 30 days
   ```

3. **Configure application**: Set the environment variable
   ```bash
   export SCITOKENS_KEYCACHE_FILE=/opt/tokens/cache.db
   ```

### Using the Offline Cache

Once configured, the existing scitokens API functions work normally:

```c
char *jwks = NULL;
char *err_msg = NULL;
int result = keycache_get_cached_jwks("https://tokens.example.com", &jwks, &err_msg);
if (result == 0 && jwks) {
    // Process the JWKS
    free(jwks);
}
```

## Backward Compatibility

All existing functionality remains unchanged. The new features are:
- Additive API extensions
- Optional environment variable
- New command-line tool

Existing code will continue to work without modification.

## Cache Location Priority

The cache file location is determined in this order:
1. `SCITOKENS_KEYCACHE_FILE` environment variable (highest priority - for offline use)
2. User-configured cache home via config API
3. `XDG_CACHE_HOME` environment variable
4. `~/.cache` directory (lowest priority)

## Security Considerations

- Ensure offline cache files have appropriate file permissions (600 or 640)
- Regularly update offline caches with fresh keys before expiration
- Consider key rotation policies when setting expiration times
- Validate JWKS content before adding to offline caches