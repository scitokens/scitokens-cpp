#include "../src/scitokens.h"

#include <cmath>
#include <fstream>
#include <gtest/gtest.h>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <unistd.h>

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

    // Set up a test file path and zero interval for immediate write
    std::string test_file = "/tmp/scitokens_monitoring_integration_" +
                            std::to_string(time(nullptr)) + ".json";
    scitoken_config_set_str("monitoring.file", test_file.c_str(), &err_msg);
    scitoken_config_set_int("monitoring.file_interval_s", 0, &err_msg);

    // Clean up any existing file
    std::remove(test_file.c_str());

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

    // Clean up
    scitoken_config_set_str("monitoring.file", "", &err_msg);
    scitoken_config_set_int("monitoring.file_interval_s", 60, &err_msg);
    std::remove(test_file.c_str());
}

} // namespace

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
