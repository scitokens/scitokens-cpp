#include "../src/scitokens.h"
#include "test_utils.h"

#include <atomic>
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <gtest/gtest.h>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

#ifndef PICOJSON_USE_INT64
#define PICOJSON_USE_INT64
#endif
#include <picojson/picojson.h>

using scitokens_test::SecureTempDir;

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
        // Background refresh statistics
        uint64_t background_successful_refreshes{0};
        uint64_t background_failed_refreshes{0};
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

                    // Background refresh statistics
                    it = stats_obj.find("background_successful_refreshes");
                    if (it != stats_obj.end() && it->second.is<double>()) {
                        stats.background_successful_refreshes =
                            static_cast<uint64_t>(it->second.get<double>());
                    }

                    it = stats_obj.find("background_failed_refreshes");
                    if (it != stats_obj.end() && it->second.is<double>()) {
                        stats.background_failed_refreshes =
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
MonitoringStats getCurrentMonitoringStats() {
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

// Helper to read environment variables from setup.sh
class TestEnvironment {
  public:
    static TestEnvironment &getInstance() {
        static TestEnvironment instance;
        return instance;
    }

    bool load() {
        if (loaded_)
            return true;

        const char *binary_dir = getenv("BINARY_DIR");
        if (!binary_dir) {
            std::cerr << "BINARY_DIR not set" << std::endl;
            return false;
        }

        std::string setup_file =
            std::string(binary_dir) + "/tests/integration/setup.sh";
        std::ifstream file(setup_file);
        if (!file.is_open()) {
            std::cerr << "Could not open " << setup_file << std::endl;
            return false;
        }

        std::string line;
        while (std::getline(file, line)) {
            // Skip comments and empty lines
            if (line.empty() || line[0] == '#')
                continue;

            // Parse KEY=VALUE
            auto pos = line.find('=');
            if (pos != std::string::npos) {
                std::string key = line.substr(0, pos);
                std::string value = line.substr(pos + 1);
                vars_[key] = value;
            }
        }

        loaded_ = true;
        return true;
    }

    std::string get(const std::string &key) const {
        auto it = vars_.find(key);
        if (it != vars_.end()) {
            return it->second;
        }
        return "";
    }

  private:
    TestEnvironment() : loaded_(false) {}
    bool loaded_;
    std::map<std::string, std::string> vars_;
};

class IntegrationTest : public ::testing::Test {
  protected:
    void SetUp() override {
        ASSERT_TRUE(TestEnvironment::getInstance().load())
            << "Failed to load test environment";

        issuer_url_ = TestEnvironment::getInstance().get("ISSUER_URL");
        signing_key_file_ = TestEnvironment::getInstance().get("SIGNING_KEY");
        signing_pub_file_ = TestEnvironment::getInstance().get("SIGNING_PUB");
        std::string ca_cert_file =
            TestEnvironment::getInstance().get("CA_CERT");

        ASSERT_FALSE(issuer_url_.empty()) << "ISSUER_URL not set";
        ASSERT_FALSE(signing_key_file_.empty()) << "SIGNING_KEY not set";
        ASSERT_FALSE(signing_pub_file_.empty()) << "SIGNING_PUB not set";
        ASSERT_FALSE(ca_cert_file.empty()) << "CA_CERT not set";

        // Set the TLS CA file for scitokens to use
        char *err_msg = nullptr;
        int rv = scitoken_config_set_str("tls.ca_file", ca_cert_file.c_str(),
                                         &err_msg);
        ASSERT_EQ(rv, 0) << "Failed to set TLS CA file: "
                         << (err_msg ? err_msg : "unknown error");
        if (err_msg)
            free(err_msg);

        // Load keys
        std::ifstream priv_ifs(signing_key_file_);
        ASSERT_TRUE(priv_ifs.is_open())
            << "Failed to open " << signing_key_file_;
        private_key_ = std::string(std::istreambuf_iterator<char>(priv_ifs),
                                   std::istreambuf_iterator<char>());

        std::ifstream pub_ifs(signing_pub_file_);
        ASSERT_TRUE(pub_ifs.is_open())
            << "Failed to open " << signing_pub_file_;
        public_key_ = std::string(std::istreambuf_iterator<char>(pub_ifs),
                                  std::istreambuf_iterator<char>());
    }

    std::string issuer_url_;
    std::string signing_key_file_;
    std::string signing_pub_file_;
    std::string private_key_;
    std::string public_key_;
};

TEST_F(IntegrationTest, CreateAndSignToken) {
    char *err_msg = nullptr;

    // Create a key
    std::unique_ptr<void, decltype(&scitoken_key_destroy)> key(
        scitoken_key_create("test-key-1", "ES256", public_key_.c_str(),
                            private_key_.c_str(), &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(key.get() != nullptr)
        << "Failed to create key: " << (err_msg ? err_msg : "unknown error");
    if (err_msg)
        free(err_msg);

    // Create a token
    std::unique_ptr<void, decltype(&scitoken_destroy)> token(
        scitoken_create(key.get()), scitoken_destroy);
    ASSERT_TRUE(token.get() != nullptr) << "Failed to create token";

    // Set issuer
    auto rv = scitoken_set_claim_string(token.get(), "iss", issuer_url_.c_str(),
                                        &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to set issuer: "
                     << (err_msg ? err_msg : "unknown error");
    if (err_msg)
        free(err_msg);

    // Set some claims
    rv =
        scitoken_set_claim_string(token.get(), "sub", "test-subject", &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to set subject: "
                     << (err_msg ? err_msg : "unknown error");
    if (err_msg)
        free(err_msg);

    rv =
        scitoken_set_claim_string(token.get(), "scope", "read:/test", &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to set scope: "
                     << (err_msg ? err_msg : "unknown error");
    if (err_msg)
        free(err_msg);

    // Set lifetime
    scitoken_set_lifetime(token.get(), 3600);

    // Serialize the token
    char *token_value = nullptr;
    rv = scitoken_serialize(token.get(), &token_value, &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to serialize token: "
                     << (err_msg ? err_msg : "unknown error");
    if (err_msg)
        free(err_msg);

    ASSERT_TRUE(token_value != nullptr);
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    EXPECT_GT(strlen(token_value), 50) << "Token seems too short";

    std::cout << "Created token: " << token_value << std::endl;
}

TEST_F(IntegrationTest, VerifyTokenWithJWKSDiscovery) {
    char *err_msg = nullptr;

    // Create a key
    std::unique_ptr<void, decltype(&scitoken_key_destroy)> key(
        scitoken_key_create("test-key-1", "ES256", public_key_.c_str(),
                            private_key_.c_str(), &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(key.get() != nullptr);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Create and sign a token
    std::unique_ptr<void, decltype(&scitoken_destroy)> token(
        scitoken_create(key.get()), scitoken_destroy);
    ASSERT_TRUE(token.get() != nullptr);

    auto rv = scitoken_set_claim_string(token.get(), "iss", issuer_url_.c_str(),
                                        &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    rv =
        scitoken_set_claim_string(token.get(), "sub", "test-subject", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    rv =
        scitoken_set_claim_string(token.get(), "scope", "read:/test", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    scitoken_set_lifetime(token.get(), 3600);

    char *token_value = nullptr;
    rv = scitoken_serialize(token.get(), &token_value, &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Now verify the token using JWKS discovery
    std::unique_ptr<void, decltype(&scitoken_destroy)> verify_token(
        scitoken_create(nullptr), scitoken_destroy);
    ASSERT_TRUE(verify_token.get() != nullptr);

    // This should fetch the JWKS from the server via discovery
    rv = scitoken_deserialize_v2(token_value, verify_token.get(), nullptr,
                                 &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to verify token: "
                     << (err_msg ? err_msg : "unknown error");
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Verify we can read back the claims
    char *value = nullptr;
    rv = scitoken_get_claim_string(verify_token.get(), "iss", &value, &err_msg);
    ASSERT_EQ(rv, 0);
    ASSERT_TRUE(value != nullptr);
    std::unique_ptr<char, decltype(&free)> value_ptr(value, free);
    EXPECT_EQ(std::string(value), issuer_url_);

    value_ptr.reset();
    rv = scitoken_get_claim_string(verify_token.get(), "sub", &value, &err_msg);
    ASSERT_EQ(rv, 0);
    ASSERT_TRUE(value != nullptr);
    value_ptr.reset(value);
    EXPECT_STREQ(value, "test-subject");

    value_ptr.reset();
    rv = scitoken_get_claim_string(verify_token.get(), "scope", &value,
                                   &err_msg);
    ASSERT_EQ(rv, 0);
    ASSERT_TRUE(value != nullptr);
    value_ptr.reset(value);
    EXPECT_STREQ(value, "read:/test");
}

TEST_F(IntegrationTest, EnforcerWithDynamicIssuer) {
    char *err_msg = nullptr;

    // Create a key and token
    std::unique_ptr<void, decltype(&scitoken_key_destroy)> key(
        scitoken_key_create("test-key-1", "ES256", public_key_.c_str(),
                            private_key_.c_str(), &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(key.get() != nullptr);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    std::unique_ptr<void, decltype(&scitoken_destroy)> token(
        scitoken_create(key.get()), scitoken_destroy);
    ASSERT_TRUE(token.get() != nullptr);

    auto rv = scitoken_set_claim_string(token.get(), "iss", issuer_url_.c_str(),
                                        &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    rv = scitoken_set_claim_string(token.get(), "aud",
                                   "https://test.example.com", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    rv =
        scitoken_set_claim_string(token.get(), "scope", "read:/data", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    rv =
        scitoken_set_claim_string(token.get(), "ver", "scitoken:2.0", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    scitoken_set_lifetime(token.get(), 3600);

    char *token_value = nullptr;
    rv = scitoken_serialize(token.get(), &token_value, &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Deserialize for verification
    std::unique_ptr<void, decltype(&scitoken_destroy)> verify_token(
        scitoken_create(nullptr), scitoken_destroy);
    ASSERT_TRUE(verify_token.get() != nullptr);

    rv = scitoken_deserialize_v2(token_value, verify_token.get(), nullptr,
                                 &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Create enforcer
    const char *audiences[] = {"https://test.example.com", nullptr};
    auto enforcer = enforcer_create(issuer_url_.c_str(), audiences, &err_msg);
    ASSERT_TRUE(enforcer != nullptr);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Test with valid ACL
    Acl acl;
    acl.authz = "read";
    acl.resource = "/data/file.txt";

    rv = enforcer_test(enforcer, verify_token.get(), &acl, &err_msg);
    EXPECT_EQ(rv, 0) << "Enforcer should allow read on /data/file.txt";
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Test with invalid ACL (wrong authz)
    acl.authz = "write";
    acl.resource = "/data/file.txt";

    rv = enforcer_test(enforcer, verify_token.get(), &acl, &err_msg);
    EXPECT_NE(rv, 0) << "Enforcer should deny write access";
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    enforcer_destroy(enforcer);
}

// =============================================================================
// Monitoring API Integration Tests
// =============================================================================

TEST_F(IntegrationTest, MonitoringCountersIncrease) {
    char *err_msg = nullptr;

    // Reset monitoring stats
    scitoken_reset_monitoring_stats(&err_msg);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Get initial stats
    auto initial_stats = getCurrentMonitoringStats();
    auto initial_issuer_stats = initial_stats.getIssuerStats(issuer_url_);

    // Create and verify a valid token
    std::unique_ptr<void, decltype(&scitoken_key_destroy)> key(
        scitoken_key_create("test-key-1", "ES256", public_key_.c_str(),
                            private_key_.c_str(), &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(key.get() != nullptr);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    std::unique_ptr<void, decltype(&scitoken_destroy)> token(
        scitoken_create(key.get()), scitoken_destroy);
    ASSERT_TRUE(token.get() != nullptr);

    auto rv = scitoken_set_claim_string(token.get(), "iss", issuer_url_.c_str(),
                                        &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    rv =
        scitoken_set_claim_string(token.get(), "sub", "test-subject", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    scitoken_set_lifetime(token.get(), 3600);

    char *token_value = nullptr;
    rv = scitoken_serialize(token.get(), &token_value, &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Verify the token (should increment successful_validations)
    std::unique_ptr<void, decltype(&scitoken_destroy)> verify_token(
        scitoken_create(nullptr), scitoken_destroy);
    ASSERT_TRUE(verify_token.get() != nullptr);

    rv = scitoken_deserialize_v2(token_value, verify_token.get(), nullptr,
                                 &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Check that counters increased
    auto after_stats = getCurrentMonitoringStats();
    auto after_issuer_stats = after_stats.getIssuerStats(issuer_url_);

    EXPECT_GT(after_issuer_stats.successful_validations,
              initial_issuer_stats.successful_validations)
        << "successful_validations should have increased";

    // Duration should also have increased
    EXPECT_GT(after_issuer_stats.total_validation_time_s,
              initial_issuer_stats.total_validation_time_s)
        << "total_validation_time_s should have increased";

    std::cout << "After successful validation:" << std::endl;
    std::cout << "  successful_validations: "
              << after_issuer_stats.successful_validations << std::endl;
    std::cout << "  total_validation_time_s: "
              << after_issuer_stats.total_validation_time_s << std::endl;
}

TEST_F(IntegrationTest, MonitoringFailedIssuerLookup404) {
    char *err_msg = nullptr;

    // Reset monitoring stats
    scitoken_reset_monitoring_stats(&err_msg);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Parse the issuer URL to construct a 404 path
    // The server returns 404 for paths other than
    // /.well-known/openid-configuration We need to use the same host but a path
    // that doesn't exist
    std::string issuer_404 = issuer_url_ + "/nonexistent-path";

    // Create a token with issuer that will get 404
    std::unique_ptr<void, decltype(&scitoken_key_destroy)> key(
        scitoken_key_create("test-key-1", "ES256", public_key_.c_str(),
                            private_key_.c_str(), &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(key.get() != nullptr);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    std::unique_ptr<void, decltype(&scitoken_destroy)> token(
        scitoken_create(key.get()), scitoken_destroy);
    ASSERT_TRUE(token.get() != nullptr);

    // Use issuer URL that will cause 404 on metadata lookup
    auto rv = scitoken_set_claim_string(token.get(), "iss", issuer_404.c_str(),
                                        &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    scitoken_set_lifetime(token.get(), 3600);

    char *token_value = nullptr;
    rv = scitoken_serialize(token.get(), &token_value, &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Try to verify - should fail with 404
    std::unique_ptr<void, decltype(&scitoken_destroy)> verify_token(
        scitoken_create(nullptr), scitoken_destroy);
    ASSERT_TRUE(verify_token.get() != nullptr);

    rv = scitoken_deserialize_v2(token_value, verify_token.get(), nullptr,
                                 &err_msg);
    EXPECT_NE(rv, 0) << "Verification should fail for 404 issuer";
    if (err_msg) {
        std::cout << "Expected error: " << err_msg << std::endl;
        free(err_msg);
        err_msg = nullptr;
    }

    // Check that failed issuer lookup was recorded
    auto stats = getCurrentMonitoringStats();
    auto issuer_stats = stats.getIssuerStats(issuer_404);

    EXPECT_GT(issuer_stats.unsuccessful_validations, 0u)
        << "unsuccessful_validations should have increased for 404 issuer";

    std::cout << "After 404 response:" << std::endl;
    std::cout << "  unsuccessful_validations: "
              << issuer_stats.unsuccessful_validations << std::endl;
}

TEST_F(IntegrationTest, MonitoringFailedDNSLookup) {
    char *err_msg = nullptr;

    // Reset monitoring stats
    scitoken_reset_monitoring_stats(&err_msg);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Use an issuer with a hostname that won't resolve
    std::string dns_fail_issuer =
        "https://this-hostname-does-not-exist-12345.invalid";

    // Create a token with issuer that will fail DNS lookup
    std::unique_ptr<void, decltype(&scitoken_key_destroy)> key(
        scitoken_key_create("test-key-1", "ES256", public_key_.c_str(),
                            private_key_.c_str(), &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(key.get() != nullptr);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    std::unique_ptr<void, decltype(&scitoken_destroy)> token(
        scitoken_create(key.get()), scitoken_destroy);
    ASSERT_TRUE(token.get() != nullptr);

    auto rv = scitoken_set_claim_string(token.get(), "iss",
                                        dns_fail_issuer.c_str(), &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    scitoken_set_lifetime(token.get(), 3600);

    char *token_value = nullptr;
    rv = scitoken_serialize(token.get(), &token_value, &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Try to verify - should fail with DNS error
    std::unique_ptr<void, decltype(&scitoken_destroy)> verify_token(
        scitoken_create(nullptr), scitoken_destroy);
    ASSERT_TRUE(verify_token.get() != nullptr);

    rv = scitoken_deserialize_v2(token_value, verify_token.get(), nullptr,
                                 &err_msg);
    EXPECT_NE(rv, 0) << "Verification should fail for DNS lookup failure";
    if (err_msg) {
        std::cout << "Expected error (DNS): " << err_msg << std::endl;
        free(err_msg);
        err_msg = nullptr;
    }

    // Check that failed issuer lookup was recorded
    auto stats = getCurrentMonitoringStats();
    auto issuer_stats = stats.getIssuerStats(dns_fail_issuer);

    EXPECT_GT(issuer_stats.unsuccessful_validations, 0u)
        << "unsuccessful_validations should have increased for DNS failure";

    std::cout << "After DNS failure:" << std::endl;
    std::cout << "  unsuccessful_validations: "
              << issuer_stats.unsuccessful_validations << std::endl;
}

TEST_F(IntegrationTest, MonitoringFailedTCPConnection) {
    char *err_msg = nullptr;

    // Reset monitoring stats
    scitoken_reset_monitoring_stats(&err_msg);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Use localhost with a privileged port (< 1024) that won't have a server
    // Port 1 is typically not used and requires root to bind
    std::string tcp_fail_issuer = "https://localhost:1";

    // Create a token with issuer that will fail TCP connection
    std::unique_ptr<void, decltype(&scitoken_key_destroy)> key(
        scitoken_key_create("test-key-1", "ES256", public_key_.c_str(),
                            private_key_.c_str(), &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(key.get() != nullptr);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    std::unique_ptr<void, decltype(&scitoken_destroy)> token(
        scitoken_create(key.get()), scitoken_destroy);
    ASSERT_TRUE(token.get() != nullptr);

    auto rv = scitoken_set_claim_string(token.get(), "iss",
                                        tcp_fail_issuer.c_str(), &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    scitoken_set_lifetime(token.get(), 3600);

    char *token_value = nullptr;
    rv = scitoken_serialize(token.get(), &token_value, &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Try to verify - should fail with connection refused
    std::unique_ptr<void, decltype(&scitoken_destroy)> verify_token(
        scitoken_create(nullptr), scitoken_destroy);
    ASSERT_TRUE(verify_token.get() != nullptr);

    rv = scitoken_deserialize_v2(token_value, verify_token.get(), nullptr,
                                 &err_msg);
    EXPECT_NE(rv, 0) << "Verification should fail for TCP connection failure";
    if (err_msg) {
        std::cout << "Expected error (TCP): " << err_msg << std::endl;
        free(err_msg);
        err_msg = nullptr;
    }

    // Check that failed issuer lookup was recorded
    auto stats = getCurrentMonitoringStats();
    auto issuer_stats = stats.getIssuerStats(tcp_fail_issuer);

    EXPECT_GT(issuer_stats.unsuccessful_validations, 0u)
        << "unsuccessful_validations should have increased for TCP failure";

    std::cout << "After TCP connection failure:" << std::endl;
    std::cout << "  unsuccessful_validations: "
              << issuer_stats.unsuccessful_validations << std::endl;
}

TEST_F(IntegrationTest, MonitoringDurationTracking) {
    char *err_msg = nullptr;

    // Reset monitoring stats
    scitoken_reset_monitoring_stats(&err_msg);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Perform multiple validations and check duration increases
    for (int i = 0; i < 3; i++) {
        std::unique_ptr<void, decltype(&scitoken_key_destroy)> key(
            scitoken_key_create("test-key-1", "ES256", public_key_.c_str(),
                                private_key_.c_str(), &err_msg),
            scitoken_key_destroy);
        ASSERT_TRUE(key.get() != nullptr);
        if (err_msg) {
            free(err_msg);
            err_msg = nullptr;
        }

        std::unique_ptr<void, decltype(&scitoken_destroy)> token(
            scitoken_create(key.get()), scitoken_destroy);
        ASSERT_TRUE(token.get() != nullptr);

        auto rv = scitoken_set_claim_string(token.get(), "iss",
                                            issuer_url_.c_str(), &err_msg);
        ASSERT_EQ(rv, 0);
        if (err_msg) {
            free(err_msg);
            err_msg = nullptr;
        }

        rv = scitoken_set_claim_string(token.get(), "sub", "test-subject",
                                       &err_msg);
        ASSERT_EQ(rv, 0);
        if (err_msg) {
            free(err_msg);
            err_msg = nullptr;
        }

        scitoken_set_lifetime(token.get(), 3600);

        char *token_value = nullptr;
        rv = scitoken_serialize(token.get(), &token_value, &err_msg);
        ASSERT_EQ(rv, 0);
        if (err_msg) {
            free(err_msg);
            err_msg = nullptr;
        }
        std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value,
                                                               free);

        std::unique_ptr<void, decltype(&scitoken_destroy)> verify_token(
            scitoken_create(nullptr), scitoken_destroy);
        ASSERT_TRUE(verify_token.get() != nullptr);

        rv = scitoken_deserialize_v2(token_value, verify_token.get(), nullptr,
                                     &err_msg);
        ASSERT_EQ(rv, 0);
        if (err_msg) {
            free(err_msg);
            err_msg = nullptr;
        }
    }

    // Check final stats
    auto stats = getCurrentMonitoringStats();
    auto issuer_stats = stats.getIssuerStats(issuer_url_);

    EXPECT_GE(issuer_stats.successful_validations, 3u)
        << "Should have at least 3 successful validations";
    EXPECT_GT(issuer_stats.total_validation_time_s, 0.0)
        << "total_validation_time_s should be positive";

    std::cout << "After multiple validations:" << std::endl;
    std::cout << "  successful_validations: "
              << issuer_stats.successful_validations << std::endl;
    std::cout << "  total_validation_time_s: "
              << issuer_stats.total_validation_time_s << std::endl;
}

// Test monitoring file output during token verification
TEST_F(IntegrationTest, MonitoringFileOutput) {
    char *err_msg = nullptr;

    // Create a secure temp directory for the monitoring file
    SecureTempDir temp_dir("monitoring_test_");
    ASSERT_TRUE(temp_dir.valid()) << "Failed to create temp directory";

    // Set up a test file path and zero interval for immediate write
    std::string test_file = temp_dir.path() + "/monitoring.json";
    scitoken_config_set_str("monitoring.file", test_file.c_str(), &err_msg);
    scitoken_config_set_int("monitoring.file_interval_s", 0, &err_msg);

    // Reset monitoring stats
    scitoken_reset_monitoring_stats(&err_msg);

    // Create and verify a token (this should trigger file write)
    // Use test-key-1 to match the key ID in the JWKS server
    SciTokenKey key =
        scitoken_key_create("test-key-1", "ES256", public_key_.c_str(),
                            private_key_.c_str(), &err_msg);
    ASSERT_TRUE(key != nullptr);
    std::unique_ptr<void, decltype(&scitoken_key_destroy)> key_ptr(
        key, scitoken_key_destroy);

    SciToken token = scitoken_create(key);
    ASSERT_TRUE(token != nullptr);
    std::unique_ptr<void, decltype(&scitoken_destroy)> token_ptr(
        token, scitoken_destroy);

    scitoken_set_claim_string(token, "iss", issuer_url_.c_str(), &err_msg);
    scitoken_set_claim_string(token, "sub", "test-user", &err_msg);
    scitoken_set_claim_string(token, "scope", "read:/test", &err_msg);

    char *token_value = nullptr;
    int rv = scitoken_serialize(token, &token_value, &err_msg);
    ASSERT_EQ(rv, 0);
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Verify the token - this should trigger monitoring file write
    std::unique_ptr<void, decltype(&scitoken_destroy)> verify_token(
        scitoken_create(nullptr), scitoken_destroy);
    ASSERT_TRUE(verify_token.get() != nullptr);

    rv = scitoken_deserialize_v2(token_value, verify_token.get(), nullptr,
                                 &err_msg);
    if (rv != 0 && err_msg) {
        std::cerr << "Token verification error: " << err_msg << std::endl;
    }
    ASSERT_EQ(rv, 0) << "Token verification should succeed";
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Check that the monitoring file was created
    std::ifstream file(test_file);
    EXPECT_TRUE(file.good())
        << "Monitoring file should have been created at " << test_file;

    if (file.good()) {
        // Read and parse the file
        std::stringstream buffer;
        buffer << file.rdbuf();
        std::string content = buffer.str();

        EXPECT_FALSE(content.empty()) << "Monitoring file should not be empty";

        // Try to parse it as JSON
        picojson::value root;
        std::string parse_err = picojson::parse(root, content);
        EXPECT_TRUE(parse_err.empty())
            << "Monitoring file should contain valid JSON: " << parse_err;

        if (parse_err.empty()) {
            // Verify it has the expected structure
            EXPECT_TRUE(root.is<picojson::object>());
            auto &root_obj = root.get<picojson::object>();
            EXPECT_TRUE(root_obj.find("issuers") != root_obj.end())
                << "Monitoring JSON should have 'issuers' key";
        }

        std::cout << "Monitoring file content:" << std::endl;
        std::cout << content << std::endl;
    }

    // Clean up - disable monitoring file
    scitoken_config_set_str("monitoring.file", "", &err_msg);
    scitoken_config_set_int("monitoring.file_interval_s", 60, &err_msg);
    // temp_dir destructor will clean up the directory and file
}

// =============================================================================
// Background JWKS Refresh Test
// =============================================================================

TEST_F(IntegrationTest, BackgroundRefreshTest) {
    char *err_msg = nullptr;

    // Reset monitoring stats to get a clean baseline
    scitoken_reset_monitoring_stats(&err_msg);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Set smaller intervals for testing (1 second refresh interval, 2 seconds
    // threshold)
    int rv =
        scitoken_config_set_int("keycache.refresh_interval_ms", 1000, &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to set refresh interval: "
                     << (err_msg ? err_msg : "unknown error");
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    rv = scitoken_config_set_int("keycache.refresh_threshold_ms", 2000,
                                 &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to set refresh threshold: "
                     << (err_msg ? err_msg : "unknown error");
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Set update interval to 1 second BEFORE first verification so the
    // cache entry will have next_update just 1 second in the future.
    // This ensures the background thread can refresh within the test window.
    rv = scitoken_config_set_int("keycache.update_interval_s", 1, &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Create a key and token
    std::unique_ptr<void, decltype(&scitoken_key_destroy)> key(
        scitoken_key_create("test-key-1", "ES256", public_key_.c_str(),
                            private_key_.c_str(), &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(key.get() != nullptr);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    std::unique_ptr<void, decltype(&scitoken_destroy)> token(
        scitoken_create(key.get()), scitoken_destroy);
    ASSERT_TRUE(token.get() != nullptr);

    rv = scitoken_set_claim_string(token.get(), "iss", issuer_url_.c_str(),
                                   &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    rv =
        scitoken_set_claim_string(token.get(), "sub", "test-subject", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    rv =
        scitoken_set_claim_string(token.get(), "scope", "read:/test", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    scitoken_set_lifetime(token.get(), 3600);

    char *token_value = nullptr;
    rv = scitoken_serialize(token.get(), &token_value, &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // First verification - this will fetch JWKS and track the issuer
    std::unique_ptr<void, decltype(&scitoken_destroy)> verify_token(
        scitoken_create(nullptr), scitoken_destroy);
    ASSERT_TRUE(verify_token.get() != nullptr);

    rv = scitoken_deserialize_v2(token_value, verify_token.get(), nullptr,
                                 &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to verify token: "
                     << (err_msg ? err_msg : "unknown error");
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Get the current JWKS to verify it exists
    char *jwks_before = nullptr;
    rv = keycache_get_cached_jwks(issuer_url_.c_str(), &jwks_before, &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to get cached JWKS: "
                     << (err_msg ? err_msg : "unknown error");
    ASSERT_TRUE(jwks_before != nullptr);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    std::cout << "Initial JWKS fetched successfully" << std::endl;

    // Re-set the JWKS to force a fresh cache entry with the current
    // update_interval (1 second). This ensures next_update is just 1 second
    // in the future so the background thread will refresh it.
    rv = keycache_set_jwks(issuer_url_.c_str(), jwks_before, &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to set JWKS: "
                     << (err_msg ? err_msg : "unknown error");
    free(jwks_before);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    std::cout << "JWKS re-set with 1-second update interval" << std::endl;

    // Get monitoring stats before background refresh
    auto before_stats = getCurrentMonitoringStats();
    auto before_issuer_stats = before_stats.getIssuerStats(issuer_url_);
    std::cout << "Before background refresh:" << std::endl;
    std::cout << "  background_successful_refreshes: "
              << before_issuer_stats.background_successful_refreshes
              << std::endl;
    std::cout << "  background_failed_refreshes: "
              << before_issuer_stats.background_failed_refreshes << std::endl;

    // Enable background refresh
    rv = keycache_set_background_refresh(1, &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to enable background refresh: "
                     << (err_msg ? err_msg : "unknown error");
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    std::cout << "Background refresh enabled" << std::endl;

    // Wait for background refresh to trigger (threshold is 2 seconds, interval
    // is 1 second) We need to wait at least 3 seconds: 1s for next_update to be
    // within threshold + 2s for detection Note: Using sleep() is acceptable for
    // integration tests as we're verifying real-time behavior of the background
    // thread against an actual HTTPS server
    std::cout << "Waiting 4 seconds for background refresh..." << std::endl;
    sleep(4);

    // Stop background refresh
    rv = keycache_stop_background_refresh(&err_msg);
    ASSERT_EQ(rv, 0) << "Failed to stop background refresh: "
                     << (err_msg ? err_msg : "unknown error");
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    std::cout << "Background refresh stopped successfully" << std::endl;

    // Verify we can still access the JWKS
    char *jwks_after = nullptr;
    rv = keycache_get_cached_jwks(issuer_url_.c_str(), &jwks_after, &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to get cached JWKS after background refresh: "
                     << (err_msg ? err_msg : "unknown error");
    ASSERT_TRUE(jwks_after != nullptr);
    std::unique_ptr<char, decltype(&free)> jwks_after_ptr(jwks_after, free);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Verify that background refresh statistics increased for our issuer
    auto after_stats = getCurrentMonitoringStats();
    auto after_issuer_stats = after_stats.getIssuerStats(issuer_url_);

    std::cout << "After background refresh:" << std::endl;
    std::cout << "  background_successful_refreshes: "
              << after_issuer_stats.background_successful_refreshes
              << std::endl;
    std::cout << "  background_failed_refreshes: "
              << after_issuer_stats.background_failed_refreshes << std::endl;

    // The background thread should have performed at least one refresh
    // for our issuer (either successful or failed)
    uint64_t total_background_refreshes =
        after_issuer_stats.background_successful_refreshes +
        after_issuer_stats.background_failed_refreshes;
    uint64_t before_total =
        before_issuer_stats.background_successful_refreshes +
        before_issuer_stats.background_failed_refreshes;

    EXPECT_GT(total_background_refreshes, before_total)
        << "Background refresh thread should have performed at least one "
           "refresh attempt for our issuer";

    std::cout << "Test completed successfully" << std::endl;
}

// Test that concurrent threads validating tokens from the same new issuer
// all succeed even when there's no pre-existing cache entry.
// Note: The per-issuer lock prevents the worst thundering herd scenarios
// by serializing DB checks after initial discovery, but the current
// implementation may still make multiple web requests if the fetch is async.
TEST_F(IntegrationTest, ConcurrentNewIssuerLookup) {
    char *err_msg = nullptr;

    // Use a unique secure cache directory to ensure no cached keys exist
    // This forces the code path where keys must be fetched from the server
    SecureTempDir unique_cache("concurrent_test_");
    ASSERT_TRUE(unique_cache.valid())
        << "Failed to create temp cache directory";

    int rv = scitoken_config_set_str("keycache.cache_home",
                                     unique_cache.path().c_str(), &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to set cache_home: "
                     << (err_msg ? err_msg : "unknown");
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Reset monitoring stats before the test
    rv = scitoken_reset_monitoring_stats(&err_msg);
    ASSERT_EQ(rv, 0) << "Failed to reset monitoring stats";
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Create a token with the test issuer
    std::unique_ptr<void, decltype(&scitoken_key_destroy)> key(
        scitoken_key_create("test-key-1", "ES256", public_key_.c_str(),
                            private_key_.c_str(), &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(key.get() != nullptr);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    std::unique_ptr<void, decltype(&scitoken_destroy)> token(
        scitoken_create(key.get()), scitoken_destroy);
    ASSERT_TRUE(token.get() != nullptr);

    rv = scitoken_set_claim_string(token.get(), "iss", issuer_url_.c_str(),
                                   &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    scitoken_set_lifetime(token.get(), 300);

    char *token_value = nullptr;
    rv = scitoken_serialize(token.get(), &token_value, &err_msg);
    ASSERT_EQ(rv, 0);
    std::string token_str(token_value);
    free(token_value);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Get initial counts before the concurrent test
    auto stats_before = getCurrentMonitoringStats();
    auto initial_successful_validations =
        stats_before.getIssuerStats(issuer_url_).successful_validations;
    auto initial_expired_keys =
        stats_before.getIssuerStats(issuer_url_).expired_keys;
    auto initial_key_lookups =
        stats_before.getIssuerStats(issuer_url_).successful_key_lookups;

    std::cout << "Using unique cache directory: " << unique_cache.path()
              << std::endl;
    std::cout << "Initial successful_validations: "
              << initial_successful_validations << std::endl;
    std::cout << "Initial expired_keys: " << initial_expired_keys << std::endl;
    std::cout << "Initial successful_key_lookups: " << initial_key_lookups
              << std::endl;

    // Launch multiple threads to concurrently validate the same token
    const int NUM_THREADS = 10;
    std::vector<std::thread> threads;
    std::atomic<int> success_count{0};
    std::atomic<int> failure_count{0};

    // Use a barrier to synchronize thread start
    std::atomic<bool> start_flag{false};

    for (int i = 0; i < NUM_THREADS; i++) {
        threads.emplace_back([&]() {
            // Wait for all threads to be ready
            while (!start_flag.load()) {
                std::this_thread::yield();
            }

            char *thread_err = nullptr;
            std::unique_ptr<void, decltype(&scitoken_destroy)> verify_token(
                scitoken_create(nullptr), scitoken_destroy);

            int result = scitoken_deserialize_v2(
                token_str.c_str(), verify_token.get(), nullptr, &thread_err);
            if (result == 0) {
                success_count++;
            } else {
                failure_count++;
                if (thread_err) {
                    std::cerr << "Thread validation error: " << thread_err
                              << std::endl;
                }
            }
            if (thread_err)
                free(thread_err);
        });
    }

    // Signal all threads to start simultaneously
    start_flag.store(true);

    // Wait for all threads to complete
    for (auto &t : threads) {
        t.join();
    }

    std::cout << "Threads completed - success: " << success_count.load()
              << ", failure: " << failure_count.load() << std::endl;

    // All threads should have successfully validated
    // This proves the per-issuer locking and caching mechanisms work correctly
    // even under concurrent load with an empty cache
    EXPECT_EQ(success_count.load(), NUM_THREADS)
        << "All threads should validate successfully";

    // Check monitoring stats to verify the code paths were exercised
    auto stats_after = getCurrentMonitoringStats();
    auto issuer_stats = stats_after.getIssuerStats(issuer_url_);
    auto new_expired_keys = issuer_stats.expired_keys - initial_expired_keys;
    auto new_key_lookups =
        issuer_stats.successful_key_lookups - initial_key_lookups;

    std::cout << "Final stats for issuer:" << std::endl;
    std::cout << "  successful_validations: "
              << issuer_stats.successful_validations << std::endl;
    std::cout << "  expired_keys: " << issuer_stats.expired_keys
              << " (new: " << new_expired_keys << ")" << std::endl;
    std::cout << "  successful_key_lookups: "
              << issuer_stats.successful_key_lookups
              << " (new: " << new_key_lookups << ")" << std::endl;

    // The per-issuer lock should ensure only ONE thread fetches keys from web.
    // All other threads should wait for the lock, then find keys in the cache.
    // This is the key assertion that proves the thundering herd prevention
    // works.
    EXPECT_EQ(new_key_lookups, 1u)
        << "Per-issuer lock should ensure only ONE web fetch for "
        << NUM_THREADS << " concurrent requests";

    // The expired_keys counter tracks entries into the "no cached keys" path.
    // With a fresh cache, all threads should hit this path because they all
    // check the DB before acquiring the per-issuer lock.
    EXPECT_EQ(new_expired_keys, static_cast<uint64_t>(NUM_THREADS))
        << "All threads should enter the expired_keys code path";

    // unique_cache destructor will clean up the temporary cache directory
}

// Stress test: repeatedly deserialize a valid token across multiple threads
// for a fixed duration and verify monitoring counters match actual counts
TEST_F(IntegrationTest, StressTestValidToken) {
    char *err_msg = nullptr;

    // Use a unique secure cache directory to ensure no cached keys exist from
    // prior tests. This forces fresh key lookup and prevents background refresh
    // interference.
    SecureTempDir unique_cache("stress_valid_");
    ASSERT_TRUE(unique_cache.valid())
        << "Failed to create temp cache directory";

    int rv = scitoken_config_set_str("keycache.cache_home",
                                     unique_cache.path().c_str(), &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to set cache_home: "
                     << (err_msg ? err_msg : "unknown");
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Ensure background refresh is disabled so it doesn't interfere
    rv = keycache_stop_background_refresh(&err_msg);
    ASSERT_EQ(rv, 0) << "Failed to stop background refresh";
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Reset update interval to default (600 seconds) - BackgroundRefreshTest
    // may have set it to 1 second
    rv = scitoken_config_set_int("keycache.update_interval_s", 600, &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to set update_interval_s";
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Reset monitoring stats before the test
    rv = scitoken_reset_monitoring_stats(&err_msg);
    ASSERT_EQ(rv, 0) << "Failed to reset monitoring stats";
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Create a valid token
    std::unique_ptr<void, decltype(&scitoken_key_destroy)> key(
        scitoken_key_create("test-key-1", "ES256", public_key_.c_str(),
                            private_key_.c_str(), &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(key.get() != nullptr);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }
    std::unique_ptr<void, decltype(&scitoken_destroy)> token(
        scitoken_create(key.get()), scitoken_destroy);
    ASSERT_TRUE(token.get() != nullptr);

    rv = scitoken_set_claim_string(token.get(), "iss", issuer_url_.c_str(),
                                   &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    rv = scitoken_set_claim_string(token.get(), "sub", "stress-test", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    scitoken_set_lifetime(token.get(), 3600);

    char *token_value = nullptr;
    rv = scitoken_serialize(token.get(), &token_value, &err_msg);
    ASSERT_EQ(rv, 0);
    std::string token_str(token_value);
    free(token_value);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Get initial stats
    auto stats_before = getCurrentMonitoringStats();
    auto initial_successful =
        stats_before.getIssuerStats(issuer_url_).successful_validations;
    auto initial_unsuccessful =
        stats_before.getIssuerStats(issuer_url_).unsuccessful_validations;
    auto initial_key_lookups =
        stats_before.getIssuerStats(issuer_url_).successful_key_lookups;

    // Stress test parameters
    const int NUM_THREADS = 10;
    const int TEST_DURATION_MS = 5000; // 5 seconds

    std::atomic<uint64_t> total_attempts{0};
    std::atomic<uint64_t> total_successes{0};
    std::atomic<uint64_t> total_failures{0};
    std::atomic<bool> stop_flag{false};

    std::vector<std::thread> threads;
    for (int i = 0; i < NUM_THREADS; i++) {
        threads.emplace_back([&]() {
            while (!stop_flag.load()) {
                total_attempts++;

                char *thread_err = nullptr;
                std::unique_ptr<void, decltype(&scitoken_destroy)> verify_token(
                    scitoken_create(nullptr), scitoken_destroy);

                int result = scitoken_deserialize_v2(token_str.c_str(),
                                                     verify_token.get(),
                                                     nullptr, &thread_err);

                if (result == 0) {
                    total_successes++;
                } else {
                    total_failures++;
                    if (thread_err) {
                        std::cerr << "Unexpected error: " << thread_err
                                  << std::endl;
                    }
                }
                if (thread_err)
                    free(thread_err);
            }
        });
    }

    // Run for the test duration
    std::this_thread::sleep_for(std::chrono::milliseconds(TEST_DURATION_MS));
    stop_flag.store(true);

    // Wait for all threads to complete
    for (auto &t : threads) {
        t.join();
    }

    // Get final stats
    auto stats_after = getCurrentMonitoringStats();
    auto issuer_stats = stats_after.getIssuerStats(issuer_url_);
    auto new_successful =
        issuer_stats.successful_validations - initial_successful;
    auto new_unsuccessful =
        issuer_stats.unsuccessful_validations - initial_unsuccessful;
    auto new_key_lookups =
        issuer_stats.successful_key_lookups - initial_key_lookups;

    std::cout << "Stress test (valid token) results:" << std::endl;
    std::cout << "  Test duration: " << TEST_DURATION_MS << " ms" << std::endl;
    std::cout << "  Threads: " << NUM_THREADS << std::endl;
    std::cout << "  Total attempts: " << total_attempts.load() << std::endl;
    std::cout << "  Total successes: " << total_successes.load() << std::endl;
    std::cout << "  Total failures: " << total_failures.load() << std::endl;
    std::cout << "  Monitoring successful_validations: " << new_successful
              << std::endl;
    std::cout << "  Monitoring unsuccessful_validations: " << new_unsuccessful
              << std::endl;
    std::cout << "  Monitoring successful_key_lookups: " << new_key_lookups
              << std::endl;

    // Verify all attempts succeeded
    EXPECT_EQ(total_failures.load(), 0u)
        << "All deserializations of valid token should succeed";

    // Verify monitoring counters match actual counts
    EXPECT_EQ(new_successful, total_successes.load())
        << "Monitoring successful_validations should match actual success "
           "count";

    EXPECT_EQ(new_unsuccessful, 0u)
        << "There should be no unsuccessful validations for valid token";

    // Verify at most one key lookup (keys should be cached after first fetch)
    // Using a fresh cache directory ensures no interference from prior tests
    EXPECT_LE(new_key_lookups, 1u)
        << "Should have at most one key lookup (cached after first)";

    // Sanity check: we should have done a meaningful number of validations
    EXPECT_GT(total_attempts.load(), 100u)
        << "Should have completed at least 100 validations in "
        << TEST_DURATION_MS << "ms";

    // unique_cache destructor will clean up the temporary cache directory
}

// Stress test: repeatedly deserialize a token with an invalid issuer (404)
// across multiple threads and verify monitoring counters match actual failure
// counts
TEST_F(IntegrationTest, StressTestInvalidIssuer) {
    char *err_msg = nullptr;

    // Use a unique secure cache directory to ensure no cached keys exist from
    // prior tests
    SecureTempDir unique_cache("stress_invalid_");
    ASSERT_TRUE(unique_cache.valid())
        << "Failed to create temp cache directory";

    int rv = scitoken_config_set_str("keycache.cache_home",
                                     unique_cache.path().c_str(), &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to set cache_home: "
                     << (err_msg ? err_msg : "unknown");
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Reset monitoring stats before the test
    rv = scitoken_reset_monitoring_stats(&err_msg);
    ASSERT_EQ(rv, 0) << "Failed to reset monitoring stats";
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Create a token with an issuer path that returns 404
    // The server returns 404 for paths like /nonexistent-path
    std::string invalid_issuer = issuer_url_ + "/nonexistent-path";

    std::unique_ptr<void, decltype(&scitoken_key_destroy)> key(
        scitoken_key_create("test-key-1", "ES256", public_key_.c_str(),
                            private_key_.c_str(), &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(key.get() != nullptr);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    std::unique_ptr<void, decltype(&scitoken_destroy)> token(
        scitoken_create(key.get()), scitoken_destroy);
    ASSERT_TRUE(token.get() != nullptr);

    rv = scitoken_set_claim_string(token.get(), "iss", invalid_issuer.c_str(),
                                   &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    rv = scitoken_set_claim_string(token.get(), "sub", "stress-test-invalid",
                                   &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    scitoken_set_lifetime(token.get(), 3600);

    char *token_value = nullptr;
    rv = scitoken_serialize(token.get(), &token_value, &err_msg);
    ASSERT_EQ(rv, 0);
    std::string token_str(token_value);
    free(token_value);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Get initial stats for the invalid issuer
    auto stats_before = getCurrentMonitoringStats();
    auto initial_successful =
        stats_before.getIssuerStats(invalid_issuer).successful_validations;
    auto initial_unsuccessful =
        stats_before.getIssuerStats(invalid_issuer).unsuccessful_validations;
    auto initial_key_lookups =
        stats_before.getIssuerStats(invalid_issuer).successful_key_lookups;

    // Stress test parameters
    const int NUM_THREADS = 10;
    const int TEST_DURATION_MS = 5000; // 5 seconds

    std::atomic<uint64_t> total_attempts{0};
    std::atomic<uint64_t> total_successes{0};
    std::atomic<uint64_t> total_failures{0};
    std::atomic<bool> stop_flag{false};

    std::vector<std::thread> threads;
    for (int i = 0; i < NUM_THREADS; i++) {
        threads.emplace_back([&]() {
            while (!stop_flag.load()) {
                total_attempts++;

                char *thread_err = nullptr;
                std::unique_ptr<void, decltype(&scitoken_destroy)> verify_token(
                    scitoken_create(nullptr), scitoken_destroy);

                int result = scitoken_deserialize_v2(token_str.c_str(),
                                                     verify_token.get(),
                                                     nullptr, &thread_err);

                if (result == 0) {
                    total_successes++;
                } else {
                    total_failures++;
                }
                if (thread_err)
                    free(thread_err);
            }
        });
    }

    // Run for the test duration
    std::this_thread::sleep_for(std::chrono::milliseconds(TEST_DURATION_MS));
    stop_flag.store(true);

    // Wait for all threads to complete
    for (auto &t : threads) {
        t.join();
    }

    // Get final stats for the invalid issuer
    auto stats_after = getCurrentMonitoringStats();
    auto issuer_stats = stats_after.getIssuerStats(invalid_issuer);
    auto new_successful =
        issuer_stats.successful_validations - initial_successful;
    auto new_unsuccessful =
        issuer_stats.unsuccessful_validations - initial_unsuccessful;
    auto new_key_lookups =
        issuer_stats.successful_key_lookups - initial_key_lookups;

    std::cout << "Stress test (invalid issuer - 404) results:" << std::endl;
    std::cout << "  Test duration: " << TEST_DURATION_MS << " ms" << std::endl;
    std::cout << "  Threads: " << NUM_THREADS << std::endl;
    std::cout << "  Invalid issuer: " << invalid_issuer << std::endl;
    std::cout << "  Total attempts: " << total_attempts.load() << std::endl;
    std::cout << "  Total successes: " << total_successes.load() << std::endl;
    std::cout << "  Total failures: " << total_failures.load() << std::endl;
    std::cout << "  Monitoring successful_validations: " << new_successful
              << std::endl;
    std::cout << "  Monitoring unsuccessful_validations: " << new_unsuccessful
              << std::endl;
    std::cout << "  Monitoring successful_key_lookups: " << new_key_lookups
              << std::endl;

    // Verify all attempts failed (issuer returns 404)
    EXPECT_EQ(total_successes.load(), 0u)
        << "All deserializations with invalid issuer should fail";

    // Verify monitoring counters match actual counts
    EXPECT_EQ(new_successful, 0u)
        << "There should be no successful validations for invalid issuer";

    EXPECT_EQ(new_unsuccessful, total_failures.load())
        << "Monitoring unsuccessful_validations should match actual failure "
           "count";

    // No successful key lookups expected (issuer returns 404)
    EXPECT_EQ(new_key_lookups, 0u)
        << "Should have no successful key lookups (issuer returns 404)";

    // Sanity check: we should have done a meaningful number of validations
    EXPECT_GT(total_attempts.load(), 100u)
        << "Should have completed at least 100 validations in "
        << TEST_DURATION_MS << "ms";

    // unique_cache destructor will clean up the temporary cache directory
}

// Test that token verification fails with a clear keycache error message
// when the cache directory is not writable and allow_in_memory is NOT set.
TEST_F(IntegrationTest, VerifyFailsWithUnwritableCacheDir) {
    char *err_msg = nullptr;

    // Ensure allow_in_memory is disabled
    int rv = scitoken_config_set_str("keycache.allow_in_memory", "false",
                                     &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Create a temporary directory, then a cache directory with no
    // permissions. This matches common deployment misconfiguration cases.
    SecureTempDir temp_cache("unwritable_cache_");
    ASSERT_TRUE(temp_cache.valid())
        << "Failed to create temp cache directory";
    std::string restricted_cache = temp_cache.path() + "/restricted_cache";
    ASSERT_EQ(mkdir(restricted_cache.c_str(), 0700), 0)
        << "Failed to create restricted cache directory";
    ASSERT_EQ(chmod(restricted_cache.c_str(), 0000), 0)
        << "Failed to remove permissions from cache directory";

    // If we can still write/lookup despite 0000 perms, we're likely running as
    // a privileged user and this permission-based test is not meaningful.
    if (access(restricted_cache.c_str(), W_OK | X_OK) == 0) {
        chmod(restricted_cache.c_str(), 0700);
        GTEST_SKIP() << "Permission-denied cache test requires non-privileged "
                        "execution (directory with mode 0000 is still "
                        "accessible).";
    }

    // Point the keycache at the non-writable directory.
    rv = scitoken_config_set_str("keycache.cache_home", restricted_cache.c_str(),
                                 &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to set cache_home: "
                     << (err_msg ? err_msg : "unknown");
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Create a valid token that would normally verify successfully
    std::unique_ptr<void, decltype(&scitoken_key_destroy)> key(
        scitoken_key_create("test-key-1", "ES256", public_key_.c_str(),
                            private_key_.c_str(), &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(key.get() != nullptr);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    std::unique_ptr<void, decltype(&scitoken_destroy)> token(
        scitoken_create(key.get()), scitoken_destroy);
    ASSERT_TRUE(token.get() != nullptr);

    rv = scitoken_set_claim_string(token.get(), "iss", issuer_url_.c_str(),
                                   &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    rv = scitoken_set_claim_string(token.get(), "sub", "test-subject", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    rv = scitoken_set_claim_string(token.get(), "scope", "read:/test", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    scitoken_set_lifetime(token.get(), 3600);

    char *token_value = nullptr;
    rv = scitoken_serialize(token.get(), &token_value, &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Attempt to verify the token — should fail because the keycache is not
    // writable and the library cannot read/write cached keys
    std::unique_ptr<void, decltype(&scitoken_destroy)> verify_token(
        scitoken_create(nullptr), scitoken_destroy);
    ASSERT_TRUE(verify_token.get() != nullptr);

    rv = scitoken_deserialize_v2(token_value, verify_token.get(), nullptr,
                                 &err_msg);
    ASSERT_NE(rv, 0) << "Deserialization should fail with unwritable cache dir";
    ASSERT_TRUE(err_msg != nullptr) << "Error message should be set";
    std::string error_str(err_msg);
    free(err_msg);
    err_msg = nullptr;

    // The error message must mention "keycache" so operators can diagnose
    // the problem (instead of a misleading "Timeout when loading OIDC metadata")
    EXPECT_NE(error_str.find("keycache"), std::string::npos)
        << "Error message should mention 'keycache', got: " << error_str;

    // Restore permissions so SecureTempDir destructor can clean up.
    chmod(restricted_cache.c_str(), 0700);

    // Reset cache_home to default
    rv = scitoken_config_set_str("keycache.cache_home", "", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg)
        free(err_msg);
}

// Test that token verification succeeds using an in-memory SQLite database
// when the cache directory is not writable and allow_in_memory is enabled.
TEST_F(IntegrationTest, VerifySucceedsWithInMemoryCache) {
    char *err_msg = nullptr;

    // Enable in-memory keycache fallback
    int rv = scitoken_config_set_str("keycache.allow_in_memory", "true",
                                     &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Create a temporary directory, then a cache directory with no
    // permissions. This matches common deployment misconfiguration cases.
    SecureTempDir temp_cache("inmem_cache_");
    ASSERT_TRUE(temp_cache.valid())
        << "Failed to create temp cache directory";
    std::string restricted_cache = temp_cache.path() + "/restricted_cache";
    ASSERT_EQ(mkdir(restricted_cache.c_str(), 0700), 0)
        << "Failed to create restricted cache directory";
    ASSERT_EQ(chmod(restricted_cache.c_str(), 0000), 0)
        << "Failed to remove permissions from cache directory";

    // If we can still write/lookup despite 0000 perms, we're likely running as
    // a privileged user and this permission-based test is not meaningful.
    if (access(restricted_cache.c_str(), W_OK | X_OK) == 0) {
        chmod(restricted_cache.c_str(), 0700);
        GTEST_SKIP() << "Permission-denied cache fallback test requires "
                        "non-privileged execution (directory with mode 0000 "
                        "is still accessible).";
    }

    // Point the keycache at the non-writable directory.
    rv = scitoken_config_set_str("keycache.cache_home", restricted_cache.c_str(),
                                 &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to set cache_home: "
                     << (err_msg ? err_msg : "unknown");
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Create a valid token
    std::unique_ptr<void, decltype(&scitoken_key_destroy)> key(
        scitoken_key_create("test-key-1", "ES256", public_key_.c_str(),
                            private_key_.c_str(), &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(key.get() != nullptr);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    std::unique_ptr<void, decltype(&scitoken_destroy)> token(
        scitoken_create(key.get()), scitoken_destroy);
    ASSERT_TRUE(token.get() != nullptr);

    rv = scitoken_set_claim_string(token.get(), "iss", issuer_url_.c_str(),
                                   &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    rv = scitoken_set_claim_string(token.get(), "sub", "test-subject", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    rv = scitoken_set_claim_string(token.get(), "scope", "read:/test", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    scitoken_set_lifetime(token.get(), 3600);

    char *token_value = nullptr;
    rv = scitoken_serialize(token.get(), &token_value, &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Verify the token — should succeed because the in-memory cache is used
    std::unique_ptr<void, decltype(&scitoken_destroy)> verify_token(
        scitoken_create(nullptr), scitoken_destroy);
    ASSERT_TRUE(verify_token.get() != nullptr);

    rv = scitoken_deserialize_v2(token_value, verify_token.get(), nullptr,
                                 &err_msg);
    ASSERT_EQ(rv, 0) << "Deserialization should succeed with in-memory cache: "
                     << (err_msg ? err_msg : "unknown error");
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    // Verify we can read back the claims
    char *value = nullptr;
    rv = scitoken_get_claim_string(verify_token.get(), "iss", &value, &err_msg);
    ASSERT_EQ(rv, 0);
    ASSERT_TRUE(value != nullptr);
    EXPECT_EQ(std::string(value), issuer_url_);
    free(value);

    // Restore permissions so SecureTempDir destructor can clean up.
    chmod(restricted_cache.c_str(), 0700);

    // Disable in-memory fallback and reset cache_home
    rv = scitoken_config_set_str("keycache.allow_in_memory", "false", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) {
        free(err_msg);
        err_msg = nullptr;
    }

    rv = scitoken_config_set_str("keycache.cache_home", "", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg)
        free(err_msg);
}

} // namespace

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
