#include <cstdlib>
#include <cstring>
#include <ctime>
#include <iostream>
#include <fstream>
#include <string>
#include <unistd.h>
#include <iomanip>
#include <sqlite3.h>

#ifndef PICOJSON_USE_INT64
#define PICOJSON_USE_INT64
#endif
#include <picojson/picojson.h>

#include "scitokens.h"

// Forward declarations
int test_cache_file_access(const std::string &cache_file);

void print_usage(const char *progname) {
    std::cout << "Usage: " << progname << " <command> [options]\n";
    std::cout << "\n";
    std::cout << "Commands:\n";
    std::cout << "  add       Add JWKS to a keycache file\n";
    std::cout << "  print     Print table of all public keys stored in cache\n";
    std::cout << "  location  Print location of scitokens keycache and access status\n";
    std::cout << "\n";
    std::cout << "Run '" << progname << " <command> --help' for command-specific help\n";
}

void print_add_usage(const char *progname) {
    std::cout << "Usage: " << progname << " add --cache-file <cache_file> --jwks <jwks_file> --issuer <issuer> --valid-for <seconds>\n";
    std::cout << "\n";
    std::cout << "Options:\n";
    std::cout << "  --cache-file <file>   Path to the keycache SQLite database file\n";
    std::cout << "  --jwks <file>         Path to the JWKS file to store\n";
    std::cout << "  --issuer <issuer>     Issuer URL for the JWKS\n";
    std::cout << "  --valid-for <seconds> How long the key should be valid (in seconds)\n";
    std::cout << "  --help               Show this help message\n";
    std::cout << "\n";
    std::cout << "Example:\n";
    std::cout << "  " << progname << " add --cache-file /tmp/offline.db --jwks keys.json --issuer https://example.com --valid-for 86400\n";
}

void print_print_usage(const char *progname) {
    std::cout << "Usage: " << progname << " print [--cache-file <cache_file>]\n";
    std::cout << "\n";
    std::cout << "Options:\n";
    std::cout << "  --cache-file <file>   Path to the keycache SQLite database file (optional)\n";
    std::cout << "                        If not specified, uses the default cache location\n";
    std::cout << "  --help               Show this help message\n";
    std::cout << "\n";
    std::cout << "Example:\n";
    std::cout << "  " << progname << " print\n";
    std::cout << "  " << progname << " print --cache-file /tmp/offline.db\n";
}

void print_location_usage(const char *progname) {
    std::cout << "Usage: " << progname << " location\n";
    std::cout << "\n";
    std::cout << "Prints the location of the scitokens keycache file and whether it can be read.\n";
    std::cout << "\n";
    std::cout << "Options:\n";
    std::cout << "  --help               Show this help message\n";
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

std::string truncate_string(const std::string &str, size_t max_length) {
    if (str.length() <= max_length) {
        return str;
    }
    return str.substr(0, max_length - 3) + "...";
}

int add_command(int argc, char *argv[]) {
    std::string cache_file;
    std::string jwks_file;
    std::string issuer;
    long valid_for = 0;
    
    // Parse command line arguments for add command
    for (int i = 2; i < argc; i++) {  // Start from 2 since argv[1] is "add"
        if (strcmp(argv[i], "--help") == 0) {
            print_add_usage(argv[0]);
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
            print_add_usage(argv[0]);
            return 1;
        }
    }
    
    // Validate required arguments
    if (cache_file.empty()) {
        std::cerr << "Error: --cache-file is required\n";
        print_add_usage(argv[0]);
        return 1;
    }
    if (jwks_file.empty()) {
        std::cerr << "Error: --jwks is required\n";
        print_add_usage(argv[0]);
        return 1;
    }
    if (issuer.empty()) {
        std::cerr << "Error: --issuer is required\n";
        print_add_usage(argv[0]);
        return 1;
    }
    if (valid_for == 0) {
        std::cerr << "Error: --valid-for is required\n";
        print_add_usage(argv[0]);
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

int print_command(int argc, char *argv[]) {
    std::string cache_file;
    
    // Parse command line arguments for print command
    for (int i = 2; i < argc; i++) {  // Start from 2 since argv[1] is "print"
        if (strcmp(argv[i], "--help") == 0) {
            print_print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--cache-file") == 0) {
            if (i + 1 >= argc) {
                std::cerr << "Error: --cache-file requires an argument\n";
                return 1;
            }
            cache_file = argv[++i];
        } else {
            std::cerr << "Error: Unknown option " << argv[i] << "\n";
            print_print_usage(argv[0]);
            return 1;
        }
    }
    
    // Get cache file location
    try {
        if (cache_file.empty()) {
            const char* cache_location = scitokens_get_cache_file_location();
            if (!cache_location || strlen(cache_location) == 0) {
                std::cerr << "Error: Could not determine cache file location\n";
                return 1;
            }
            cache_file = cache_location;
        } else {
            // Test if we can access the specified cache file
            if (test_cache_file_access(cache_file) != 0) {
                std::cerr << "Error: Cannot access cache file: " << cache_file << "\n";
                return 1;
            }
        }
        
        sqlite3 *db;
        int rc = sqlite3_open(cache_file.c_str(), &db);
        if (rc != SQLITE_OK) {
            std::cerr << "Error: Cannot open cache database: " << sqlite3_errmsg(db) << "\n";
            sqlite3_close(db);
            return 1;
        }
        
        sqlite3_stmt *stmt;
        rc = sqlite3_prepare_v2(db, "SELECT issuer, keys FROM keycache ORDER BY issuer", -1, &stmt, NULL);
        if (rc != SQLITE_OK) {
            std::cerr << "Error: Failed to prepare SQL statement: " << sqlite3_errmsg(db) << "\n";
            sqlite3_close(db);
            return 1;
        }
        
        // Print table header
        std::cout << std::left;
        std::cout << std::setw(40) << "Issuer" 
                  << std::setw(15) << "Key ID"
                  << std::setw(15) << "Key Type"
                  << std::setw(20) << "Expires"
                  << std::setw(20) << "Next Update"
                  << std::setw(25) << "Public Key (truncated)" << "\n";
        std::cout << std::string(135, '-') << "\n";
        
        bool has_entries = false;
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            has_entries = true;
            const unsigned char *issuer_data = sqlite3_column_text(stmt, 0);
            const unsigned char *keys_data = sqlite3_column_text(stmt, 1);
            
            if (!issuer_data || !keys_data) {
                continue;
            }
            
            std::string issuer_str(reinterpret_cast<const char *>(issuer_data));
            std::string keys_str(reinterpret_cast<const char *>(keys_data));
            
            // Parse the JSON
            picojson::value json_obj;
            std::string err = picojson::parse(json_obj, keys_str);
            if (!err.empty() || !json_obj.is<picojson::object>()) {
                std::cout << std::setw(40) << truncate_string(issuer_str, 37)
                          << std::setw(15) << "N/A"
                          << std::setw(15) << "N/A"
                          << std::setw(20) << "Invalid JSON"
                          << std::setw(20) << "N/A"
                          << std::setw(25) << "N/A" << "\n";
                continue;
            }
            
            auto top_obj = json_obj.get<picojson::object>();
            
            // Get expiry and next_update
            std::string expires_str = "N/A";
            std::string next_update_str = "N/A";
            
            auto expires_iter = top_obj.find("expires");
            if (expires_iter != top_obj.end() && expires_iter->second.is<int64_t>()) {
                time_t expires_time = static_cast<time_t>(expires_iter->second.get<int64_t>());
                char time_buf[20];
                strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M", gmtime(&expires_time));
                expires_str = time_buf;
            }
            
            auto next_update_iter = top_obj.find("next_update");
            if (next_update_iter != top_obj.end() && next_update_iter->second.is<int64_t>()) {
                time_t next_update_time = static_cast<time_t>(next_update_iter->second.get<int64_t>());
                char time_buf[20];
                strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M", gmtime(&next_update_time));
                next_update_str = time_buf;
            }
            
            // Get JWKS keys
            auto jwks_iter = top_obj.find("jwks");
            if (jwks_iter != top_obj.end() && jwks_iter->second.is<picojson::object>()) {
                auto jwks_obj = jwks_iter->second.get<picojson::object>();
                auto keys_array_iter = jwks_obj.find("keys");
                
                if (keys_array_iter != jwks_obj.end() && keys_array_iter->second.is<picojson::array>()) {
                    auto keys_array = keys_array_iter->second.get<picojson::array>();
                    
                    if (keys_array.empty()) {
                        std::cout << std::setw(40) << truncate_string(issuer_str, 37)
                                  << std::setw(15) << "N/A"
                                  << std::setw(15) << "No keys"
                                  << std::setw(20) << expires_str
                                  << std::setw(20) << next_update_str
                                  << std::setw(25) << "N/A" << "\n";
                    } else {
                        bool first_key = true;
                        for (const auto &key_val : keys_array) {
                            if (!key_val.is<picojson::object>()) continue;
                            
                            auto key_obj = key_val.get<picojson::object>();
                            
                            std::string kid = "N/A";
                            std::string kty = "N/A";
                            std::string public_key_snippet = "N/A";
                            
                            auto kid_iter = key_obj.find("kid");
                            if (kid_iter != key_obj.end() && kid_iter->second.is<std::string>()) {
                                kid = kid_iter->second.get<std::string>();
                            }
                            
                            auto kty_iter = key_obj.find("kty");
                            if (kty_iter != key_obj.end() && kty_iter->second.is<std::string>()) {
                                kty = kty_iter->second.get<std::string>();
                            }
                            
                            // Try to get some public key material for display
                            auto n_iter = key_obj.find("n");
                            auto x_iter = key_obj.find("x");
                            if (n_iter != key_obj.end() && n_iter->second.is<std::string>()) {
                                public_key_snippet = n_iter->second.get<std::string>();
                            } else if (x_iter != key_obj.end() && x_iter->second.is<std::string>()) {
                                public_key_snippet = x_iter->second.get<std::string>();
                            }
                            
                            std::cout << std::setw(40) << (first_key ? truncate_string(issuer_str, 37) : "")
                                      << std::setw(15) << truncate_string(kid, 12)
                                      << std::setw(15) << kty
                                      << std::setw(20) << (first_key ? expires_str : "")
                                      << std::setw(20) << (first_key ? next_update_str : "")
                                      << std::setw(25) << truncate_string(public_key_snippet, 22) << "\n";
                            first_key = false;
                        }
                    }
                } else {
                    std::cout << std::setw(40) << truncate_string(issuer_str, 37)
                              << std::setw(15) << "N/A"
                              << std::setw(15) << "No keys array"
                              << std::setw(20) << expires_str
                              << std::setw(20) << next_update_str
                              << std::setw(25) << "N/A" << "\n";
                }
            } else {
                std::cout << std::setw(40) << truncate_string(issuer_str, 37)
                          << std::setw(15) << "N/A"
                          << std::setw(15) << "No JWKS"
                          << std::setw(20) << expires_str
                          << std::setw(20) << next_update_str
                          << std::setw(25) << "N/A" << "\n";
            }
        }
        
        if (!has_entries) {
            std::cout << "No entries found in cache.\n";
        }
        
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    
    return 0;
}

int location_command(int argc, char *argv[]) {
    // Parse command line arguments for location command
    for (int i = 2; i < argc; i++) {  // Start from 2 since argv[1] is "location"
        if (strcmp(argv[i], "--help") == 0) {
            print_location_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Error: Unknown option " << argv[i] << "\n";
            print_location_usage(argv[0]);
            return 1;
        }
    }
    
    try {
        const char* cache_location = scitokens_get_cache_file_location();
        
        if (!cache_location || strlen(cache_location) == 0) {
            std::cout << "Cache file location: Unable to determine\n";
            std::cout << "Access status: Failed - could not determine location\n";
            return 1;
        }
        
        std::string cache_file = cache_location;
        std::cout << "Cache file location: " << cache_file << "\n";
        
        int access_result = test_cache_file_access(cache_file);
        if (access_result == 0) {
            std::cout << "Access status: Success - cache file can be read\n";
        } else {
            std::cout << "Access status: Failed - cache file cannot be read\n";
        }
        
        return access_result;
        
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}

int test_cache_file_access(const std::string &cache_file) {
    sqlite3 *db;
    int rc = sqlite3_open(cache_file.c_str(), &db);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 1;
    }
    
    // Try to read from the keycache table
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "SELECT COUNT(*) FROM keycache", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return 1;
    }
    
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    
    return (rc == SQLITE_ROW) ? 0 : 1;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    std::string command = argv[1];
    
    if (command == "add") {
        return add_command(argc, argv);
    } else if (command == "print") {
        return print_command(argc, argv);
    } else if (command == "location") {
        return location_command(argc, argv);
    } else if (command == "--help") {
        print_usage(argv[0]);
        return 0;
    } else {
        std::cerr << "Error: Unknown command '" << command << "'\n";
        print_usage(argv[0]);
        return 1;
    }
}