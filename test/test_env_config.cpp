/**
 * Test program to verify environment variable configuration loading.
 * This must be run as a separate process with environment variables set
 * before the library is loaded to properly test the constructor function.
 */

#include "../src/scitokens.h"
#include <cstdlib>
#include <cstring>
#include <iostream>

int main() {
    int failures = 0;
    char *err_msg = nullptr;
    
    // Test 1: Check if SCITOKEN_CONFIG_KEYCACHE_UPDATE_INTERVAL_S was loaded
    const char *env_update = std::getenv("SCITOKEN_CONFIG_KEYCACHE_UPDATE_INTERVAL_S");
    if (env_update) {
        int expected = std::atoi(env_update);
        int actual = scitoken_config_get_int("keycache.update_interval_s", &err_msg);
        if (actual != expected) {
            std::cerr << "FAIL: keycache.update_interval_s expected " << expected 
                      << " but got " << actual << std::endl;
            if (err_msg) {
                std::cerr << "Error: " << err_msg << std::endl;
                free(err_msg);
                err_msg = nullptr;
            }
            failures++;
        } else {
            std::cout << "PASS: keycache.update_interval_s = " << actual << std::endl;
        }
    }
    
    // Test 2: Check if SCITOKEN_CONFIG_KEYCACHE_EXPIRATION_INTERVAL_S was loaded
    const char *env_expiry = std::getenv("SCITOKEN_CONFIG_KEYCACHE_EXPIRATION_INTERVAL_S");
    if (env_expiry) {
        int expected = std::atoi(env_expiry);
        int actual = scitoken_config_get_int("keycache.expiration_interval_s", &err_msg);
        if (actual != expected) {
            std::cerr << "FAIL: keycache.expiration_interval_s expected " << expected 
                      << " but got " << actual << std::endl;
            if (err_msg) {
                std::cerr << "Error: " << err_msg << std::endl;
                free(err_msg);
                err_msg = nullptr;
            }
            failures++;
        } else {
            std::cout << "PASS: keycache.expiration_interval_s = " << actual << std::endl;
        }
    }
    
    // Test 3: Check if SCITOKEN_CONFIG_KEYCACHE_CACHE_HOME was loaded
    const char *env_cache = std::getenv("SCITOKEN_CONFIG_KEYCACHE_CACHE_HOME");
    if (env_cache) {
        char *actual = nullptr;
        int rv = scitoken_config_get_str("keycache.cache_home", &actual, &err_msg);
        if (rv != 0 || !actual) {
            std::cerr << "FAIL: Could not retrieve keycache.cache_home" << std::endl;
            if (err_msg) {
                std::cerr << "Error: " << err_msg << std::endl;
                free(err_msg);
                err_msg = nullptr;
            }
            failures++;
        } else if (strcmp(actual, env_cache) != 0) {
            std::cerr << "FAIL: keycache.cache_home expected '" << env_cache 
                      << "' but got '" << actual << "'" << std::endl;
            failures++;
        } else {
            std::cout << "PASS: keycache.cache_home = " << actual << std::endl;
        }
        if (actual) free(actual);
    }
    
    // Test 4: Check if SCITOKEN_CONFIG_TLS_CA_FILE was loaded
    const char *env_ca = std::getenv("SCITOKEN_CONFIG_TLS_CA_FILE");
    if (env_ca) {
        char *actual = nullptr;
        int rv = scitoken_config_get_str("tls.ca_file", &actual, &err_msg);
        if (rv != 0 || !actual) {
            std::cerr << "FAIL: Could not retrieve tls.ca_file" << std::endl;
            if (err_msg) {
                std::cerr << "Error: " << err_msg << std::endl;
                free(err_msg);
                err_msg = nullptr;
            }
            failures++;
        } else if (strcmp(actual, env_ca) != 0) {
            std::cerr << "FAIL: tls.ca_file expected '" << env_ca 
                      << "' but got '" << actual << "'" << std::endl;
            failures++;
        } else {
            std::cout << "PASS: tls.ca_file = " << actual << std::endl;
        }
        if (actual) free(actual);
    }
    
    // Test 5: Test case insensitivity (lowercase env var)
    const char *env_lower = std::getenv("scitoken_config_keycache_update_interval_s");
    if (env_lower) {
        int expected = std::atoi(env_lower);
        int actual = scitoken_config_get_int("keycache.update_interval_s", &err_msg);
        if (actual != expected) {
            std::cerr << "FAIL: lowercase env var - keycache.update_interval_s expected " 
                      << expected << " but got " << actual << std::endl;
            if (err_msg) {
                std::cerr << "Error: " << err_msg << std::endl;
                free(err_msg);
                err_msg = nullptr;
            }
            failures++;
        } else {
            std::cout << "PASS: lowercase env var - keycache.update_interval_s = " << actual << std::endl;
        }
    }
    
    if (failures == 0) {
        std::cout << "\nAll environment variable configuration tests passed!" << std::endl;
        return 0;
    } else {
        std::cerr << "\n" << failures << " test(s) failed!" << std::endl;
        return 1;
    }
}
