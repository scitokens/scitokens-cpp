#!/usr/bin/env python3
"""
Simple Python web server that hosts JWKS and supports OIDC discovery.
Used for integration testing of scitokens-cpp.
"""

import argparse
import json
import os
import signal
import socket
import ssl
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path


class JWKSHandler(BaseHTTPRequestHandler):
    """HTTP handler for JWKS and discovery endpoints."""
    
    # Use HTTP/1.1 for proper connection handling
    protocol_version = 'HTTP/1.1'

    def log_message(self, format, *args):
        """Override to log to file instead of stderr."""
        if hasattr(self.server, 'log_file'):
            with open(self.server.log_file, 'a') as f:
                f.write("%s - - [%s] %s\n" % (
                    self.address_string(),
                    self.log_date_time_string(),
                    format % args))

    def do_GET(self):
        """Handle GET requests for JWKS and discovery."""
        if self.path == '/.well-known/openid-configuration':
            self.serve_discovery()
        elif self.path == '/oauth2/certs' or self.path == '/jwks':
            self.serve_jwks()
        else:
            self.send_error(404, "Not Found")

    def serve_discovery(self):
        """Serve OIDC discovery document."""
        issuer = self.server.issuer_url
        discovery = {
            "issuer": issuer,
            "jwks_uri": f"{issuer}/oauth2/certs",
            "token_endpoint": f"{issuer}/token",
            "authorization_endpoint": f"{issuer}/authorize",
        }
        
        content = json.dumps(discovery).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def serve_jwks(self):
        """Serve JWKS document."""
        with open(self.server.jwks_file, 'r') as f:
            jwks_content = f.read()
        
        content = jwks_content.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)


def main():
    parser = argparse.ArgumentParser(description='JWKS test server')
    parser.add_argument('--jwks', required=True, help='Path to JWKS file')
    parser.add_argument('--build-dir', required=True, help='Build directory')
    parser.add_argument('--test-name', default='integration', help='Test name')
    parser.add_argument('--cert', help='Path to TLS certificate file')
    parser.add_argument('--key', help='Path to TLS key file')
    args = parser.parse_args()

    # Determine if we're using HTTPS
    use_https = args.cert and args.key
    protocol = "https" if use_https else "http"
    
    # Create test directory
    test_dir = Path(args.build_dir) / 'tests' / args.test_name
    test_dir.mkdir(parents=True, exist_ok=True)
    
    # Create ready file to signal server is ready
    ready_file = test_dir / 'server_ready'
    log_file = test_dir / 'server.log'
    
    # Setup HTTP server - bind to port 0 to get a free port automatically
    server = HTTPServer(('localhost', 0), JWKSHandler)
    server.jwks_file = args.jwks
    server.log_file = str(log_file)
    
    # Setup TLS if certificates provided
    if use_https:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        # Set minimum TLS version to 1.2 for security
        # Use ssl.TLSVersion for Python 3.7+, fall back to options for Python 3.6 (EL8)
        try:
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        except AttributeError:
            # Python 3.6 doesn't have ssl.TLSVersion, use options instead
            context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        # Set cipher suites for OpenSSL 3.0.2 compatibility
        # SECLEVEL=1 allows 2048-bit RSA and SHA-1 for test certificates
        try:
            context.set_ciphers('DEFAULT:@SECLEVEL=1')
        except ssl.SSLError:
            # Fallback for older Python/OpenSSL
            context.set_ciphers('DEFAULT')
        # Disable TLS session tickets to avoid issues with session resumption
        context.options |= ssl.OP_NO_TICKET
        # Allow self-signed certificates for testing
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        server.socket = context.wrap_socket(server.socket, server_side=True)
    
    # Get the actual port that was assigned
    port = server.server_address[1]
    issuer_url = f"{protocol}://localhost:{port}"
    server.issuer_url = issuer_url
    
    # Write server info to ready file
    with open(ready_file, 'w') as f:
        f.write(f"PID={os.getpid()}\n")
        f.write(f"ISSUER_URL={issuer_url}\n")
        f.write(f"PORT={port}\n")
    
    print(f"Server started on {issuer_url}", flush=True)
    print(f"Server PID: {os.getpid()}", flush=True)
    print(f"Server ready file: {ready_file}", flush=True)
    
    # Handle shutdown gracefully - set a flag that will be checked
    shutdown_requested = [False]
    
    def signal_handler(signum, frame):
        print("Shutting down server...", flush=True)
        shutdown_requested[0] = True
        # Shutdown needs to be called from a different thread or we need to exit
        # Using os._exit to immediately terminate
        os._exit(0)
    
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
