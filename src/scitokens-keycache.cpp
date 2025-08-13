#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>

#include "scitokens.h"

void print_usage(const char *progname) {
    std::cout << "Usage: " << progname << " --cache-file <cache_file> --jwks <jwks_file> --issuer <issuer> --valid-for <seconds>\n";
    std::cout << "\n";
    std::cout << "Options:\n";
    std::cout << "  --cache-file <file>   Path to the keycache SQLite database file\n";
    std::cout << "  --jwks <file>         Path to the JWKS file to store\n";
    std::cout << "  --issuer <issuer>     Issuer URL for the JWKS\n";
    std::cout << "  --valid-for <seconds> How long the key should be valid (in seconds)\n";
    std::cout << "  --help               Show this help message\n";
    std::cout << "\n";
    std::cout << "Example:\n";
    std::cout << "  " << progname << " --cache-file /tmp/offline.db --jwks keys.json --issuer https://example.com --valid-for 86400\n";
}

std::string read_file(const std::string &filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file: " + filename);
    }
    
    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    return content;
}

int main(int argc, char *argv[]) {
    std::string cache_file;
    std::string jwks_file;
    std::string issuer;
    long valid_for = 0;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--cache-file") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "Error: --cache-file requires an argument\n";
                return 1;
            }
            cache_file = argv[++i];
        } else if (strcmp(argv[i], "--jwks") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "Error: --jwks requires an argument\n";
                return 1;
            }
            jwks_file = argv[++i];
        } else if (strcmp(argv[i], "--issuer") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "Error: --issuer requires an argument\n";
                return 1;
            }
            issuer = argv[++i];
        } else if (strcmp(argv[i], "--valid-for") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "Error: --valid-for requires an argument\n";
                return 1;
            }
            char *endptr;
            valid_for = strtol(argv[++i], &endptr, 10);
            if (*endptr != '\0' || valid_for <= 0) {
                std::cerr << "Error: --valid-for must be a positive integer\n";
                return 1;
            }
        } else {
            std::cerr << "Error: Unknown option " << argv[i] << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }
    
    // Validate required arguments
    if (cache_file.empty()) {
        std::cerr << "Error: --cache-file is required\n";
        print_usage(argv[0]);
        return 1;
    }
    if (jwks_file.empty()) {
        std::cerr << "Error: --jwks is required\n";
        print_usage(argv[0]);
        return 1;
    }
    if (issuer.empty()) {
        std::cerr << "Error: --issuer is required\n";
        print_usage(argv[0]);
        return 1;
    }
    if (valid_for == 0) {
        std::cerr << "Error: --valid-for is required\n";
        print_usage(argv[0]);
        return 1;
    }
    
    try {
        // Set the cache file environment variable
        if (setenv("SCITOKENS_KEYCACHE_FILE", cache_file.c_str(), 1) != 0) {
            std::cerr << "Error: Failed to set SCITOKENS_KEYCACHE_FILE environment variable\n";
            return 1;
        }
        
        // Read the JWKS file
        std::string jwks_content = read_file(jwks_file);
        
        // Calculate expiration time
        time_t now = time(nullptr);
        int64_t expires_at = static_cast<int64_t>(now) + valid_for;
        
        // Store the JWKS with expiration
        char *err_msg = nullptr;
        int result = keycache_set_jwks_with_expiry(issuer.c_str(), jwks_content.c_str(), expires_at, &err_msg);
        
        if (result != 0) {
            std::cerr << "Error: Failed to store JWKS: " << (err_msg ? err_msg : "Unknown error") << "\n";
            if (err_msg) {
                free(err_msg);
            }
            return 1;
        }
        
        std::cout << "Successfully stored JWKS for issuer: " << issuer << "\n";
        std::cout << "Cache file: " << cache_file << "\n";
        std::cout << "Expires at: " << ctime(&now) << " + " << valid_for << " seconds\n";
        
        if (err_msg) {
            free(err_msg);
        }
        
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}