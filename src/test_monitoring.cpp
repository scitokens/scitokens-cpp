#include "scitokens.h"
#include <iostream>
#include <string>

int main() {
    char *json_out = nullptr;
    char *err_msg = nullptr;

    // Get initial monitoring statistics (should be empty)
    std::cout << "Getting initial monitoring statistics..." << std::endl;
    int result = scitoken_get_monitoring_json(&json_out, &err_msg);
    if (result != 0) {
        std::cerr << "Error getting monitoring JSON: "
                  << (err_msg ? err_msg : "unknown error") << std::endl;
        if (err_msg)
            free(err_msg);
        return 1;
    }

    std::cout << "Initial statistics: " << json_out << std::endl;
    free(json_out);

    // Test reset functionality
    std::cout << "\nResetting monitoring statistics..." << std::endl;
    result = scitoken_reset_monitoring_stats(&err_msg);
    if (result != 0) {
        std::cerr << "Error resetting monitoring stats: "
                  << (err_msg ? err_msg : "unknown error") << std::endl;
        if (err_msg)
            free(err_msg);
        return 1;
    }

    // Get statistics after reset
    std::cout << "Getting statistics after reset..." << std::endl;
    result = scitoken_get_monitoring_json(&json_out, &err_msg);
    if (result != 0) {
        std::cerr << "Error getting monitoring JSON: "
                  << (err_msg ? err_msg : "unknown error") << std::endl;
        if (err_msg)
            free(err_msg);
        return 1;
    }

    std::cout << "Statistics after reset: " << json_out << std::endl;
    free(json_out);

    std::cout << "\nMonitoring API test completed successfully!" << std::endl;
    return 0;
}
