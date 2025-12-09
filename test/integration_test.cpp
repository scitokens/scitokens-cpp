#include "../src/scitokens.h"

#include <gtest/gtest.h>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <unistd.h>

namespace {

// Helper to read environment variables from setup.sh
class TestEnvironment {
public:
    static TestEnvironment& getInstance() {
        static TestEnvironment instance;
        return instance;
    }

    bool load() {
        if (loaded_) return true;

        const char* binary_dir = getenv("BINARY_DIR");
        if (!binary_dir) {
            std::cerr << "BINARY_DIR not set" << std::endl;
            return false;
        }

        std::string setup_file = std::string(binary_dir) + "/tests/integration/setup.sh";
        std::ifstream file(setup_file);
        if (!file.is_open()) {
            std::cerr << "Could not open " << setup_file << std::endl;
            return false;
        }

        std::string line;
        while (std::getline(file, line)) {
            // Skip comments and empty lines
            if (line.empty() || line[0] == '#') continue;

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

    std::string get(const std::string& key) const {
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
        std::string ca_cert_file = TestEnvironment::getInstance().get("CA_CERT");
        
        ASSERT_FALSE(issuer_url_.empty()) << "ISSUER_URL not set";
        ASSERT_FALSE(signing_key_file_.empty()) << "SIGNING_KEY not set";
        ASSERT_FALSE(signing_pub_file_.empty()) << "SIGNING_PUB not set";
        ASSERT_FALSE(ca_cert_file.empty()) << "CA_CERT not set";
        
        // Set the TLS CA file for scitokens to use
        char *err_msg = nullptr;
        int rv = scitoken_config_set_str("tls.ca_file", ca_cert_file.c_str(), &err_msg);
        ASSERT_EQ(rv, 0) << "Failed to set TLS CA file: " 
            << (err_msg ? err_msg : "unknown error");
        if (err_msg) free(err_msg);
        
        // Load keys
        std::ifstream priv_ifs(signing_key_file_);
        ASSERT_TRUE(priv_ifs.is_open()) << "Failed to open " << signing_key_file_;
        private_key_ = std::string(std::istreambuf_iterator<char>(priv_ifs),
                                   std::istreambuf_iterator<char>());
        
        std::ifstream pub_ifs(signing_pub_file_);
        ASSERT_TRUE(pub_ifs.is_open()) << "Failed to open " << signing_pub_file_;
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
    ASSERT_TRUE(key.get() != nullptr) << "Failed to create key: " 
        << (err_msg ? err_msg : "unknown error");
    if (err_msg) free(err_msg);

    // Create a token
    std::unique_ptr<void, decltype(&scitoken_destroy)> token(
        scitoken_create(key.get()), scitoken_destroy);
    ASSERT_TRUE(token.get() != nullptr) << "Failed to create token";

    // Set issuer
    auto rv = scitoken_set_claim_string(token.get(), "iss", issuer_url_.c_str(), &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to set issuer: " << (err_msg ? err_msg : "unknown error");
    if (err_msg) free(err_msg);

    // Set some claims
    rv = scitoken_set_claim_string(token.get(), "sub", "test-subject", &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to set subject: " << (err_msg ? err_msg : "unknown error");
    if (err_msg) free(err_msg);

    rv = scitoken_set_claim_string(token.get(), "scope", "read:/test", &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to set scope: " << (err_msg ? err_msg : "unknown error");
    if (err_msg) free(err_msg);

    // Set lifetime
    scitoken_set_lifetime(token.get(), 3600);

    // Serialize the token
    char *token_value = nullptr;
    rv = scitoken_serialize(token.get(), &token_value, &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to serialize token: " << (err_msg ? err_msg : "unknown error");
    if (err_msg) free(err_msg);
    
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
    if (err_msg) { free(err_msg); err_msg = nullptr; }

    // Create and sign a token
    std::unique_ptr<void, decltype(&scitoken_destroy)> token(
        scitoken_create(key.get()), scitoken_destroy);
    ASSERT_TRUE(token.get() != nullptr);

    auto rv = scitoken_set_claim_string(token.get(), "iss", issuer_url_.c_str(), &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) { free(err_msg); err_msg = nullptr; }

    rv = scitoken_set_claim_string(token.get(), "sub", "test-subject", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) { free(err_msg); err_msg = nullptr; }

    rv = scitoken_set_claim_string(token.get(), "scope", "read:/test", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) { free(err_msg); err_msg = nullptr; }

    scitoken_set_lifetime(token.get(), 3600);

    char *token_value = nullptr;
    rv = scitoken_serialize(token.get(), &token_value, &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) { free(err_msg); err_msg = nullptr; }
    
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Now verify the token using JWKS discovery
    std::unique_ptr<void, decltype(&scitoken_destroy)> verify_token(
        scitoken_create(nullptr), scitoken_destroy);
    ASSERT_TRUE(verify_token.get() != nullptr);

    // This should fetch the JWKS from the server via discovery
    rv = scitoken_deserialize_v2(token_value, verify_token.get(), nullptr, &err_msg);
    ASSERT_EQ(rv, 0) << "Failed to verify token: " << (err_msg ? err_msg : "unknown error");
    if (err_msg) { free(err_msg); err_msg = nullptr; }

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
    rv = scitoken_get_claim_string(verify_token.get(), "scope", &value, &err_msg);
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
    if (err_msg) { free(err_msg); err_msg = nullptr; }

    std::unique_ptr<void, decltype(&scitoken_destroy)> token(
        scitoken_create(key.get()), scitoken_destroy);
    ASSERT_TRUE(token.get() != nullptr);

    auto rv = scitoken_set_claim_string(token.get(), "iss", issuer_url_.c_str(), &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) { free(err_msg); err_msg = nullptr; }

    rv = scitoken_set_claim_string(token.get(), "aud", "https://test.example.com", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) { free(err_msg); err_msg = nullptr; }

    rv = scitoken_set_claim_string(token.get(), "scope", "read:/data", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) { free(err_msg); err_msg = nullptr; }

    rv = scitoken_set_claim_string(token.get(), "ver", "scitoken:2.0", &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) { free(err_msg); err_msg = nullptr; }

    scitoken_set_lifetime(token.get(), 3600);

    char *token_value = nullptr;
    rv = scitoken_serialize(token.get(), &token_value, &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) { free(err_msg); err_msg = nullptr; }
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Deserialize for verification
    std::unique_ptr<void, decltype(&scitoken_destroy)> verify_token(
        scitoken_create(nullptr), scitoken_destroy);
    ASSERT_TRUE(verify_token.get() != nullptr);

    rv = scitoken_deserialize_v2(token_value, verify_token.get(), nullptr, &err_msg);
    ASSERT_EQ(rv, 0);
    if (err_msg) { free(err_msg); err_msg = nullptr; }

    // Create enforcer
    const char *audiences[] = {"https://test.example.com", nullptr};
    auto enforcer = enforcer_create(issuer_url_.c_str(), audiences, &err_msg);
    ASSERT_TRUE(enforcer != nullptr);
    if (err_msg) { free(err_msg); err_msg = nullptr; }

    // Test with valid ACL
    Acl acl;
    acl.authz = "read";
    acl.resource = "/data/file.txt";

    rv = enforcer_test(enforcer, verify_token.get(), &acl, &err_msg);
    EXPECT_EQ(rv, 0) << "Enforcer should allow read on /data/file.txt";
    if (err_msg) { free(err_msg); err_msg = nullptr; }

    // Test with invalid ACL (wrong authz)
    acl.authz = "write";
    acl.resource = "/data/file.txt";

    rv = enforcer_test(enforcer, verify_token.get(), &acl, &err_msg);
    EXPECT_NE(rv, 0) << "Enforcer should deny write access";
    if (err_msg) { free(err_msg); err_msg = nullptr; }

    enforcer_destroy(enforcer);
}

} // namespace

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
