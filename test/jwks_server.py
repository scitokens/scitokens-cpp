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
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(discovery).encode())

    def serve_jwks(self):
        """Serve JWKS document."""
        with open(self.server.jwks_file, 'r') as f:
            jwks_content = f.read()
        
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(jwks_content.encode())


def find_free_port():
    """Find a free port by binding to port 0."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Bind to localhost only for security
        s.bind(('localhost', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


def main():
    parser = argparse.ArgumentParser(description='JWKS test server')
    parser.add_argument('--jwks', required=True, help='Path to JWKS file')
    parser.add_argument('--build-dir', required=True, help='Build directory')
    parser.add_argument('--test-name', default='integration', help='Test name')
    parser.add_argument('--cert', help='Path to TLS certificate file')
    parser.add_argument('--key', help='Path to TLS key file')
    args = parser.parse_args()

    # Find a free port
    port = find_free_port()
    
    # Determine if we're using HTTPS
    use_https = args.cert and args.key
    protocol = "https" if use_https else "http"
    
    # Create issuer URL
    issuer_url = f"{protocol}://localhost:{port}"
    
    # Create test directory
    test_dir = Path(args.build_dir) / 'tests' / args.test_name
    test_dir.mkdir(parents=True, exist_ok=True)
    
    # Create ready file to signal server is ready
    ready_file = test_dir / 'server_ready'
    log_file = test_dir / 'server.log'
    
    # Setup HTTP server
    server = HTTPServer(('localhost', port), JWKSHandler)
    server.jwks_file = args.jwks
    server.issuer_url = issuer_url
    server.log_file = str(log_file)
    
    # Setup TLS if certificates provided
    if use_https:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        # Set minimum TLS version to 1.2 for security
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # Allow self-signed certificates for testing
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        server.socket = context.wrap_socket(server.socket, server_side=True)
    
    # Write server info to ready file
    with open(ready_file, 'w') as f:
        f.write(f"PID={os.getpid()}\n")
        f.write(f"ISSUER_URL={issuer_url}\n")
        f.write(f"PORT={port}\n")
    
    print(f"Server started on {issuer_url}", flush=True)
    print(f"Server PID: {os.getpid()}", flush=True)
    print(f"Server ready file: {ready_file}", flush=True)
    
    # Handle shutdown gracefully
    def signal_handler(signum, frame):
        print("Shutting down server...", flush=True)
        server.shutdown()
        sys.exit(0)
    
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
