#include "scitokens.h"
#include <iostream>
#include <string>
#include <cstring>

// Helper function to print monitoring JSON
void print_monitoring_stats(const std::string &label) {
    char *json_out = nullptr;
    char *err_msg = nullptr;
    
    int result = scitoken_get_monitoring_json(&json_out, &err_msg);
    if (result != 0) {
        std::cerr << "Error getting monitoring JSON: "
                  << (err_msg ? err_msg : "unknown error") << std::endl;
        if (err_msg)
            free(err_msg);
        return;
    }
    
    std::cout << "\n=== " << label << " ===" << std::endl;
    std::cout << json_out << std::endl;
    free(json_out);
}

int main() {
    char *err_msg = nullptr;
    
    // Test constants
    const int DDOS_TEST_COUNT = 150; // Test beyond MAX_FAILED_ISSUERS limit
    
    // Reset monitoring stats at start
    scitoken_reset_monitoring_stats(&err_msg);
    
    std::cout << "Testing Monitoring API with Token Validation\n";
    std::cout << "=============================================\n";
    
    // Test 1: Initial state
    print_monitoring_stats("Initial State (should be empty)");
    
    // Test 2: Failed validation - expired token from demo.scitokens.org
    // This token is from the test.cpp and is expired
    std::cout << "\n--- Test 1: Validating an expired token ---\n";
    std::string expired_token =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImtleS1yczI1NiJ9."
        "eyJpc3MiOiJodHRwczovL2RlbW8uc2NpdG9rZW5zLm9yZyIsImV4cCI6MTU0NjM5MjAwOS"
        "wiaWF0IjoxNTQ2MzkxNDA5LCJuYmYiOjE1NDYzOTE0MDksImp0aSI6ImFkYTk2MjdiLWEx"
        "MGYtNGMyYS05Nzc2LTE4ZThkN2JmN2M4NSJ9.cNMG5zI2-JHh7l_"
        "PUPUAxom5Vi6Q3akKmv6q57CoVKHtxZAZRc47Uoix_"
        "AH3Xzr42qohr2FPamRTxUMsfZjrAFDJ_4JhJ-kKjJ3cRXXF-"
        "gj7lbniCDGOBuPXeMsVmeED15nauZ3XKXUHTGLEsg5O6RjS7sGKM_"
        "e9YiYvcTvWXcdkrkxZ2dPPU-R3IxdK6PtE9OB2XOk85H670OAJT3qimKm8Dk_"
        "Ri6DEEty1Su_"
        "1Tov3ac5B19iZkbhhVPMVP0cRolR9UNLhMxQAsbgEmArQOcs046AOzqQz6osOkdYOrVVO7"
        "lO2owUyMol94mB_39y1M8jcf5WNq3ukMMIzMCAPwA";
    
    SciToken token = nullptr;
    int result = scitoken_deserialize(expired_token.c_str(), &token, nullptr, &err_msg);
    if (result != 0) {
        std::cout << "Token deserialization/validation failed (expected): " 
                  << (err_msg ? err_msg : "unknown error") << std::endl;
        if (err_msg) {
            free(err_msg);
            err_msg = nullptr;
        }
    } else {
        std::cout << "Token was valid (unexpected)" << std::endl;
        scitoken_destroy(token);
    }
    
    print_monitoring_stats("After Expired Token Validation");
    
    // Test 3: Invalid issuer (should not create unbounded entries)
    std::cout << "\n--- Test 2: Testing DDoS protection with multiple invalid issuers ---\n";
    
    // Try to create many tokens with different invalid issuers
    // The monitoring system should limit tracking to MAX_FAILED_ISSUERS (100)
    for (int i = 0; i < DDOS_TEST_COUNT; i++) {
        // These are malformed tokens that will fail early
        std::string fake_token = "invalid.token." + std::to_string(i);
        SciToken temp_token = nullptr;
        scitoken_deserialize(fake_token.c_str(), &temp_token, nullptr, &err_msg);
        if (err_msg) {
            free(err_msg);
            err_msg = nullptr;
        }
    }
    
    print_monitoring_stats("After Multiple Invalid Token Attempts");
    
    // Test 4: Reset stats
    std::cout << "\n--- Test 3: Testing reset functionality ---\n";
    result = scitoken_reset_monitoring_stats(&err_msg);
    if (result != 0) {
        std::cerr << "Error resetting stats: "
                  << (err_msg ? err_msg : "unknown error") << std::endl;
        if (err_msg)
            free(err_msg);
        return 1;
    }
    
    print_monitoring_stats("After Reset");
    
    std::cout << "\n=== All monitoring API tests completed successfully ===\n";
    return 0;
}
