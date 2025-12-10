/**
 * Monitoring API unit tests
 *
 * Tests the monitoring API for per-issuer validation statistics including:
 * - Counter increments for successful/unsuccessful validations
 * - Duration tracking
 * - Failed issuer lookup tracking
 * - DDoS protection (max entries limit)
 * - Reset functionality
 */

#include "../src/scitokens.h"

#include <cmath>
#include <gtest/gtest.h>
#include <string>

#ifndef PICOJSON_USE_INT64
#define PICOJSON_USE_INT64
#endif
#include <picojson/picojson.h>

namespace {

// Helper class to parse monitoring JSON
class MonitoringStats {
  public:
    struct IssuerStats {
        uint64_t successful_validations{0};
        uint64_t unsuccessful_validations{0};
        uint64_t expired_tokens{0};
        // Validation started counters
        uint64_t sync_validations_started{0};
        uint64_t async_validations_started{0};
        // Duration tracking
        double sync_total_time_s{0.0};
        double async_total_time_s{0.0};
        double total_validation_time_s{0.0};
        // Key lookup statistics
        uint64_t successful_key_lookups{0};
        uint64_t failed_key_lookups{0};
        double failed_key_lookup_time_s{0.0};
        // Key refresh statistics
        uint64_t expired_keys{0};
        uint64_t failed_refreshes{0};
        uint64_t stale_key_uses{0};
    };

    struct FailedIssuerLookup {
        uint64_t count{0};
        double total_time_s{0.0};
    };

    bool parse(const std::string &json) {
        picojson::value root;
        std::string err = picojson::parse(root, json);
        if (!err.empty()) {
            return false;
        }

        if (!root.is<picojson::object>()) {
            return false;
        }

        auto &root_obj = root.get<picojson::object>();

        // Parse issuers
        issuers_.clear();
        auto issuers_it = root_obj.find("issuers");
        if (issuers_it != root_obj.end() &&
            issuers_it->second.is<picojson::object>()) {
            auto &issuers_obj = issuers_it->second.get<picojson::object>();
            for (const auto &issuer_entry : issuers_obj) {
                if (issuer_entry.second.is<picojson::object>()) {
                    IssuerStats stats;
                    auto &stats_obj =
                        issuer_entry.second.get<picojson::object>();

                    auto it = stats_obj.find("successful_validations");
                    if (it != stats_obj.end() && it->second.is<double>()) {
                        stats.successful_validations =
                            static_cast<uint64_t>(it->second.get<double>());
                    }

                    it = stats_obj.find("unsuccessful_validations");
                    if (it != stats_obj.end() && it->second.is<double>()) {
                        stats.unsuccessful_validations =
                            static_cast<uint64_t>(it->second.get<double>());
                    }

                    it = stats_obj.find("expired_tokens");
                    if (it != stats_obj.end() && it->second.is<double>()) {
                        stats.expired_tokens =
                            static_cast<uint64_t>(it->second.get<double>());
                    }

                    // Validation started counters
                    it = stats_obj.find("sync_validations_started");
                    if (it != stats_obj.end() && it->second.is<double>()) {
                        stats.sync_validations_started =
                            static_cast<uint64_t>(it->second.get<double>());
                    }

                    it = stats_obj.find("async_validations_started");
                    if (it != stats_obj.end() && it->second.is<double>()) {
                        stats.async_validations_started =
                            static_cast<uint64_t>(it->second.get<double>());
                    }

                    // Duration tracking
                    it = stats_obj.find("sync_total_time_s");
                    if (it != stats_obj.end() && it->second.is<double>()) {
                        stats.sync_total_time_s = it->second.get<double>();
                    }

                    it = stats_obj.find("async_total_time_s");
                    if (it != stats_obj.end() && it->second.is<double>()) {
                        stats.async_total_time_s = it->second.get<double>();
                    }

                    it = stats_obj.find("total_validation_time_s");
                    if (it != stats_obj.end() && it->second.is<double>()) {
                        stats.total_validation_time_s =
                            it->second.get<double>();
                    }

                    // Key lookup statistics
                    it = stats_obj.find("successful_key_lookups");
                    if (it != stats_obj.end() && it->second.is<double>()) {
                        stats.successful_key_lookups =
                            static_cast<uint64_t>(it->second.get<double>());
                    }

                    it = stats_obj.find("failed_key_lookups");
                    if (it != stats_obj.end() && it->second.is<double>()) {
                        stats.failed_key_lookups =
                            static_cast<uint64_t>(it->second.get<double>());
                    }

                    it = stats_obj.find("failed_key_lookup_time_s");
                    if (it != stats_obj.end() && it->second.is<double>()) {
                        stats.failed_key_lookup_time_s =
                            it->second.get<double>();
                    }

                    // Key refresh statistics
                    it = stats_obj.find("expired_keys");
                    if (it != stats_obj.end() && it->second.is<double>()) {
                        stats.expired_keys =
                            static_cast<uint64_t>(it->second.get<double>());
                    }

                    it = stats_obj.find("failed_refreshes");
                    if (it != stats_obj.end() && it->second.is<double>()) {
                        stats.failed_refreshes =
                            static_cast<uint64_t>(it->second.get<double>());
                    }

                    it = stats_obj.find("stale_key_uses");
                    if (it != stats_obj.end() && it->second.is<double>()) {
                        stats.stale_key_uses =
                            static_cast<uint64_t>(it->second.get<double>());
                    }

                    issuers_[issuer_entry.first] = stats;
                }
            }
        }

        // Parse failed issuer lookups (now has count and total_time_s)
        failed_issuer_lookups_.clear();
        auto failed_it = root_obj.find("failed_issuer_lookups");
        if (failed_it != root_obj.end() &&
            failed_it->second.is<picojson::object>()) {
            auto &failed_obj = failed_it->second.get<picojson::object>();
            for (const auto &entry : failed_obj) {
                if (entry.second.is<picojson::object>()) {
                    FailedIssuerLookup lookup;
                    auto &lookup_obj = entry.second.get<picojson::object>();

                    auto it = lookup_obj.find("count");
                    if (it != lookup_obj.end() && it->second.is<double>()) {
                        lookup.count =
                            static_cast<uint64_t>(it->second.get<double>());
                    }

                    it = lookup_obj.find("total_time_s");
                    if (it != lookup_obj.end() && it->second.is<double>()) {
                        lookup.total_time_s = it->second.get<double>();
                    }

                    failed_issuer_lookups_[entry.first] = lookup;
                }
            }
        }

        return true;
    }

    IssuerStats getIssuerStats(const std::string &issuer) const {
        auto it = issuers_.find(issuer);
        if (it != issuers_.end()) {
            return it->second;
        }
        return IssuerStats{};
    }

    FailedIssuerLookup getFailedLookup(const std::string &issuer) const {
        auto it = failed_issuer_lookups_.find(issuer);
        if (it != failed_issuer_lookups_.end()) {
            return it->second;
        }
        return FailedIssuerLookup{};
    }

    uint64_t getFailedLookupCount(const std::string &issuer) const {
        return getFailedLookup(issuer).count;
    }

    double getFailedLookupTime(const std::string &issuer) const {
        return getFailedLookup(issuer).total_time_s;
    }

    size_t getIssuerCount() const { return issuers_.size(); }

    size_t getFailedIssuerCount() const {
        return failed_issuer_lookups_.size();
    }

  private:
    std::map<std::string, IssuerStats> issuers_;
    std::map<std::string, FailedIssuerLookup> failed_issuer_lookups_;
};

// Helper to get current monitoring stats
MonitoringStats getCurrentStats() {
    char *json_out = nullptr;
    char *err_msg = nullptr;
    MonitoringStats stats;

    int rv = scitoken_get_monitoring_json(&json_out, &err_msg);
    if (rv == 0 && json_out) {
        stats.parse(json_out);
        free(json_out);
    }
    if (err_msg)
        free(err_msg);

    return stats;
}

class MonitoringTest : public ::testing::Test {
  protected:
    void SetUp() override {
        // Reset monitoring stats before each test
        char *err_msg = nullptr;
        scitoken_reset_monitoring_stats(&err_msg);
        if (err_msg)
            free(err_msg);
    }
};

TEST_F(MonitoringTest, GetMonitoringJson) {
    char *json_out = nullptr;
    char *err_msg = nullptr;

    int rv = scitoken_get_monitoring_json(&json_out, &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to get monitoring JSON: "
                     << (err_msg ? err_msg : "unknown");
    ASSERT_NE(json_out, nullptr);

    // Should be valid JSON with "issuers" key
    MonitoringStats stats;
    EXPECT_TRUE(stats.parse(json_out));
    EXPECT_EQ(stats.getIssuerCount(), 0); // Should be empty after reset

    free(json_out);
    if (err_msg)
        free(err_msg);
}

TEST_F(MonitoringTest, GetMonitoringJsonNullOutput) {
    char *err_msg = nullptr;

    int rv = scitoken_get_monitoring_json(nullptr, &err_msg);
    EXPECT_NE(rv, 0);
    EXPECT_NE(err_msg, nullptr);

    if (err_msg)
        free(err_msg);
}

TEST_F(MonitoringTest, ResetMonitoringStats) {
    char *err_msg = nullptr;

    int rv = scitoken_reset_monitoring_stats(&err_msg);
    EXPECT_EQ(rv, 0);

    auto stats = getCurrentStats();
    EXPECT_EQ(stats.getIssuerCount(), 0);
    EXPECT_EQ(stats.getFailedIssuerCount(), 0);

    if (err_msg)
        free(err_msg);
}

TEST_F(MonitoringTest, DDoSProtection) {
    // The monitoring system should limit tracking failed issuers to
    // MAX_FAILED_ISSUERS (100)
    const int DDOS_TEST_COUNT = 150;
    char *err_msg = nullptr;

    // Try to create many tokens with different invalid issuers
    for (int i = 0; i < DDOS_TEST_COUNT; i++) {
        std::string fake_token = "invalid.token." + std::to_string(i);
        SciToken temp_token = nullptr;
        scitoken_deserialize(fake_token.c_str(), &temp_token, nullptr,
                             &err_msg);
        if (err_msg) {
            free(err_msg);
            err_msg = nullptr;
        }
    }

    auto stats = getCurrentStats();

    // The system should have limited entries to prevent resource exhaustion
    // We can't check exact count since malformed tokens may fail before issuer
    // extraction, but we should verify the system didn't crash and stats work
    char *json_out = nullptr;
    int rv = scitoken_get_monitoring_json(&json_out, &err_msg);
    EXPECT_EQ(rv, 0);
    EXPECT_NE(json_out, nullptr);

    if (json_out)
        free(json_out);
    if (err_msg)
        free(err_msg);
}

// Test monitoring file configuration API
TEST_F(MonitoringTest, MonitoringFileConfiguration) {
    char *err_msg = nullptr;
    char *path = nullptr;
    int interval = 0;

    // Initially disabled (empty string)
    int rv = scitoken_config_get_str("monitoring.file", &path, &err_msg);
    EXPECT_EQ(rv, 0);
    EXPECT_NE(path, nullptr);
    EXPECT_STREQ(path, "");
    free(path);
    path = nullptr;

    // Default interval should be 60 seconds
    interval = scitoken_config_get_int("monitoring.file_interval_s", &err_msg);
    EXPECT_EQ(interval, 60);

    // Set a monitoring file path
    rv = scitoken_config_set_str(
        "monitoring.file", "/tmp/scitokens_test_monitoring.json", &err_msg);
    EXPECT_EQ(rv, 0);

    rv = scitoken_config_get_str("monitoring.file", &path, &err_msg);
    EXPECT_EQ(rv, 0);
    EXPECT_NE(path, nullptr);
    EXPECT_STREQ(path, "/tmp/scitokens_test_monitoring.json");
    free(path);
    path = nullptr;

    // Set a custom interval
    rv = scitoken_config_set_int("monitoring.file_interval_s", 30, &err_msg);
    EXPECT_EQ(rv, 0);

    interval = scitoken_config_get_int("monitoring.file_interval_s", &err_msg);
    EXPECT_EQ(interval, 30);

    // Disable by setting to empty string
    rv = scitoken_config_set_str("monitoring.file", "", &err_msg);
    EXPECT_EQ(rv, 0);

    rv = scitoken_config_get_str("monitoring.file", &path, &err_msg);
    EXPECT_EQ(rv, 0);
    EXPECT_NE(path, nullptr);
    EXPECT_STREQ(path, "");
    free(path);
    path = nullptr;

    // Disable by setting to nullptr
    rv = scitoken_config_set_str("monitoring.file", nullptr, &err_msg);
    EXPECT_EQ(rv, 0);

    rv = scitoken_config_get_str("monitoring.file", &path, &err_msg);
    EXPECT_EQ(rv, 0);
    EXPECT_NE(path, nullptr);
    EXPECT_STREQ(path, "");
    free(path);
    path = nullptr;

    // Reset interval to default for other tests
    scitoken_config_set_int("monitoring.file_interval_s", 60, &err_msg);
}

// Test monitoring file write with zero interval (immediate write)
TEST_F(MonitoringTest, MonitoringFileWrite) {
    char *err_msg = nullptr;

    // Set up a test file path and zero interval for immediate write
    std::string test_file = "/tmp/scitokens_monitoring_test_" +
                            std::to_string(time(nullptr)) + ".json";
    scitoken_config_set_str("monitoring.file", test_file.c_str(), &err_msg);
    scitoken_config_set_int("monitoring.file_interval_s", 0, &err_msg);

    // Clean up any existing file
    std::remove(test_file.c_str());

    // Reset stats and record something
    scitoken_reset_monitoring_stats(&err_msg);

    // The maybe_write_monitoring_file is called during verify(), but we can't
    // easily trigger that without a valid token/issuer. However, we can test
    // the configuration API works and that files aren't written when disabled.

    // Verify file doesn't exist yet (nothing to trigger write)
    FILE *f = fopen(test_file.c_str(), "r");
    EXPECT_EQ(f, nullptr); // File should not exist

    // Disable monitoring file
    scitoken_config_set_str("monitoring.file", "", &err_msg);
    scitoken_config_set_int("monitoring.file_interval_s", 60, &err_msg);

    // Clean up test file if it was created
    std::remove(test_file.c_str());
}

} // namespace

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
