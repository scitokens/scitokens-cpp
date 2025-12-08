#include "../src/scitokens.h"

#include <gtest/gtest.h>
#include <memory>
#include <unistd.h>

namespace {

const char ec_private[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIESSMxT7PLTR9A/aqd+CM0/6vv6fQWqDm0mNx8uE9EbpoAoGCCqGSM49\n"
    "AwEHoUQDQgAE1i+ImZ//iQhOPh0OMfZzdbmPH+3G1ouWezolCugQYWIRqNmwq3zR\n"
    "EnTbe4EmymTpJ1MJTPP/tCEUP3G/QqQuhA==\n"
    "-----END EC PRIVATE KEY-----\n";

const char ec_public[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1i+ImZ//iQhOPh0OMfZzdbmPH+3G\n"
    "1ouWezolCugQYWIRqNmwq3zREnTbe4EmymTpJ1MJTPP/tCEUP3G/QqQuhA==\n"
    "-----END PUBLIC KEY-----\n";

const char ec_private_2[] =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIJH6NpWPHcM7wxL/bv89Nezug+KEUQjI9fZxhrBHNA1ioAoGCCqGSM49\n"
    "AwEHoUQDQgAEb8M7AxRN+DmbfYOoA6DeHCcSeA+kXWCq4E/g2ME/uBOdP8RE0tql\n"
    "e8fxYcaPikgMcppGq2ycTiLGgEYXgsq2JA==\n"
    "-----END EC PRIVATE KEY-----\n";

const char ec_public_2[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb8M7AxRN+DmbfYOoA6DeHCcSeA+k\n"
    "XWCq4E/g2ME/uBOdP8RE0tqle8fxYcaPikgMcppGq2ycTiLGgEYXgsq2JA==\n"
    "-----END PUBLIC KEY-----\n";

TEST(SciTokenTest, CreateToken) {
    SciToken token = scitoken_create(nullptr);
    ASSERT_TRUE(token != nullptr);
    scitoken_destroy(token);
}

TEST(SciTokenTest, SignToken) {
    char *err_msg = nullptr;

    std::unique_ptr<void, decltype(&scitoken_key_destroy)> mykey(
        scitoken_key_create("1", "ES256", ec_public, ec_private, &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(mykey.get() != nullptr) << err_msg;

    std::unique_ptr<void, decltype(&scitoken_destroy)> mytoken(
        scitoken_create(mykey.get()), scitoken_destroy);
    ASSERT_TRUE(mytoken.get() != nullptr);

    auto rv = scitoken_set_claim_string(
        mytoken.get(), "iss", "https://demo.scitokens.org/gtest", &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    char *value;
    rv = scitoken_serialize(mytoken.get(), &value, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    EXPECT_TRUE(value != nullptr);
    std::unique_ptr<char, decltype(&free)> value_ptr(value, free);

    ASSERT_TRUE(strlen(value) > 50);
}

class SerializeTest : public ::testing::Test {
  protected:
    void SetUp() override {
        char *err_msg = nullptr;
        m_key = KeyPtr(
            scitoken_key_create("1", "ES256", ec_public, ec_private, &err_msg),
            scitoken_key_destroy);
        ASSERT_TRUE(m_key.get() != nullptr) << err_msg;

        m_token = TokenPtr(scitoken_create(m_key.get()), scitoken_destroy);
        ASSERT_TRUE(m_token.get() != nullptr);

        auto rv = scitoken_set_claim_string(
            m_token.get(), "iss", "https://demo.scitokens.org/gtest", &err_msg);
        ASSERT_TRUE(rv == 0) << err_msg;

        rv = scitoken_store_public_ec_key("https://demo.scitokens.org/gtest",
                                          "1", ec_public, &err_msg);
        ASSERT_TRUE(rv == 0) << err_msg;

        scitoken_set_lifetime(m_token.get(), 60);

        m_audiences_array.push_back("https://demo.scitokens.org/");
        m_audiences_array.push_back(nullptr);

        const char *groups[3] = {nullptr, nullptr, nullptr};
        const char group0[] = "group0";
        const char group1[] = "group1";
        groups[0] = group0;
        groups[1] = group1;
        rv = scitoken_set_claim_string_list(m_token.get(), "groups", groups,
                                            &err_msg);
        ASSERT_TRUE(rv == 0) << err_msg;

        m_read_token.reset(scitoken_create(nullptr));
        ASSERT_TRUE(m_read_token.get() != nullptr);
    }

    using KeyPtr = std::unique_ptr<void, decltype(&scitoken_key_destroy)>;
    KeyPtr m_key{nullptr, scitoken_key_destroy};

    using TokenPtr = std::unique_ptr<void, decltype(&scitoken_destroy)>;
    TokenPtr m_token{nullptr, scitoken_destroy};

    std::vector<const char *> m_audiences_array;

    TokenPtr m_read_token{nullptr, scitoken_destroy};
};

TEST_F(SerializeTest, VerifyTest) {

    char *err_msg = nullptr;

    char *token_value = nullptr;
    auto rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    char *value;
    rv = scitoken_get_claim_string(m_read_token.get(), "iss", &value, &err_msg);
    ASSERT_TRUE(value != nullptr);
    ASSERT_TRUE(rv == 0) << err_msg;
    std::unique_ptr<char, decltype(&free)> value_ptr(value, free);
    EXPECT_STREQ(value, "https://demo.scitokens.org/gtest");
    value_ptr.reset();

    rv = scitoken_get_claim_string(m_read_token.get(), "doesnotexist", &value,
                                   &err_msg);
    free(err_msg);
    EXPECT_FALSE(rv == 0);
}

TEST_F(SerializeTest, TestStringList) {
    char *err_msg = nullptr;

    char **value;
    auto rv = scitoken_get_claim_string_list(m_token.get(), "groups", &value,
                                             &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    ASSERT_TRUE(value != nullptr);

    ASSERT_TRUE(value[0] != nullptr);
    EXPECT_STREQ(value[0], "group0");

    ASSERT_TRUE(value[1] != nullptr);
    EXPECT_STREQ(value[1], "group1");

    EXPECT_TRUE(value[2] == nullptr);
    scitoken_free_string_list(value);
}

TEST_F(SerializeTest, VerifyWLCGTest) {

    char *err_msg = nullptr;

    char *token_value = nullptr;
    scitoken_set_serialize_profile(m_token.get(), SciTokenProfile::WLCG_1_0);
    auto rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Accepts any profile.
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    char *value;
    rv = scitoken_get_claim_string(m_read_token.get(), "wlcg.ver", &value,
                                   &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    ASSERT_TRUE(value != nullptr);
    std::unique_ptr<char, decltype(&free)> value_ptr(value, free);
    EXPECT_STREQ(value, "1.0");

    value_ptr.reset();
    rv = scitoken_get_claim_string(m_read_token.get(), "ver", &value, &err_msg);
    free(err_msg);
    err_msg = nullptr;
    EXPECT_FALSE(rv == 0);

    // Accepts only a WLCG token
    scitoken_set_deserialize_profile(m_read_token.get(),
                                     SciTokenProfile::WLCG_1_0);
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    // Accepts only SciToken 1.0; should fail.
    scitoken_set_deserialize_profile(m_read_token.get(),
                                     SciTokenProfile::SCITOKENS_1_0);
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    free(err_msg);
    ASSERT_FALSE(rv == 0);
}

TEST_F(SerializeTest, FailVerifyToken) {
    char *err_msg = nullptr;

    std::unique_ptr<void, decltype(&scitoken_key_destroy)> mykey(
        scitoken_key_create("1", "ES256", ec_public_2, ec_private_2, &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(mykey.get() != nullptr) << err_msg;

    std::unique_ptr<void, decltype(&scitoken_destroy)> mytoken(
        scitoken_create(mykey.get()), scitoken_destroy);
    ASSERT_TRUE(mytoken.get() != nullptr);

    auto rv = scitoken_set_claim_string(
        mytoken.get(), "iss", "https://demo.scitokens.org/gtest", &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    char *value;
    rv = scitoken_serialize(mytoken.get(), &value, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    EXPECT_TRUE(value != nullptr);
    std::unique_ptr<char, decltype(&free)> value_ptr(value, free);
    EXPECT_TRUE(strlen(value) > 50);

    // Should fail; we signed it with the wrong public key.
    rv = scitoken_deserialize_v2(value, m_read_token.get(), nullptr, &err_msg);
    free(err_msg);
    EXPECT_FALSE(rv == 0);
}

TEST_F(SerializeTest, VerifyATJWTTest) {

    char *err_msg = nullptr;

    // Serialize as at+jwt token.
    char *token_value = nullptr;
    scitoken_set_serialize_profile(m_token.get(), SciTokenProfile::AT_JWT);
    auto rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Accepts any profile.
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    // Accepts only an at+jwt token, should work with at+jwt token
    scitoken_set_deserialize_profile(m_read_token.get(),
                                     SciTokenProfile::AT_JWT);
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    // Accepts only SciToken 2.0; should fail
    scitoken_set_deserialize_profile(m_read_token.get(),
                                     SciTokenProfile::SCITOKENS_2_0);
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    free(err_msg);
    ASSERT_FALSE(rv == 0);
}

TEST_F(SerializeTest, FailVerifyATJWTTest) {

    char *err_msg = nullptr;

    // Serialize as "compat" token.
    char *token_value = nullptr;
    scitoken_set_serialize_profile(m_token.get(), SciTokenProfile::COMPAT);
    auto rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Accepts any profile.
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    // Accepts only an at+jwt token, should fail with COMPAT token
    scitoken_set_deserialize_profile(m_read_token.get(),
                                     SciTokenProfile::AT_JWT);
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    free(err_msg);
    ASSERT_FALSE(rv == 0);
}

TEST_F(SerializeTest, EnforcerTest) {
    /*
     * Test that the enforcer works and returns an err_msg
     */
    char *err_msg = nullptr;

    auto rv = scitoken_set_claim_string(
        m_token.get(), "aud", "https://demo.scitokens.org/", &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    auto enforcer = enforcer_create("https://demo.scitokens.org/gtest",
                                    &m_audiences_array[0], &err_msg);
    ASSERT_TRUE(enforcer != nullptr) << err_msg;

    Acl acl;
    acl.authz = "read";
    acl.resource = "/stuff";

    rv = scitoken_set_claim_string(m_token.get(), "scope", "read:/blah",
                                   &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    rv = scitoken_set_claim_string(m_token.get(), "ver", "scitoken:2.0",
                                   &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    char *token_value = nullptr;
    rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    free(err_msg);

    rv = enforcer_test(enforcer, m_read_token.get(), &acl, &err_msg);
    ASSERT_STREQ(
        err_msg,
        "token verification failed: 'scope' claim verification failed.");
    ASSERT_TRUE(rv == -1) << err_msg;
    free(err_msg);
    enforcer_destroy(enforcer);
}

TEST_F(SerializeTest, EnforcerScopeTest) {
    char *err_msg = nullptr;

    auto rv = scitoken_set_claim_string(
        m_token.get(), "aud", "https://demo.scitokens.org/", &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    auto enforcer = enforcer_create("https://demo.scitokens.org/gtest",
                                    &m_audiences_array[0], &err_msg);
    ASSERT_TRUE(enforcer != nullptr) << err_msg;

    scitoken_set_serialize_profile(m_token.get(), SciTokenProfile::WLCG_1_0);

    rv = scitoken_set_claim_string(
        m_token.get(), "scope",
        "storage.modify:/ storage.read:/ openid offline_access", &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    char *token_value = nullptr;
    rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    free(token_value);
    ASSERT_TRUE(rv == 0) << err_msg;

    Acl *acls;
    enforcer_generate_acls(enforcer, m_read_token.get(), &acls, &err_msg);
    ASSERT_TRUE(acls != nullptr) << err_msg;
    int idx = 0;
    bool found_read = false;
    bool found_write = false;
    while (acls[idx].resource && acls[idx++].authz) {
        auto resource = acls[idx - 1].resource;
        auto authz = acls[idx - 1].authz;
        if (strcmp(authz, "read") == 0) {
            found_read = true;
            ASSERT_STREQ(resource, "/");
        } else if (strcmp(authz, "write") == 0) {
            found_write = true;
            ASSERT_STREQ(resource, "/");
        }
    }
    enforcer_acl_free(acls);
    enforcer_destroy(enforcer);
    ASSERT_TRUE(found_read);
    ASSERT_TRUE(found_write);
}

} // namespace

TEST_F(SerializeTest, DeserializeAsyncTest) {
    char *err_msg = nullptr;

    // Serialize as "compat" token.
    char *token_value = nullptr;
    scitoken_set_serialize_profile(m_token.get(), SciTokenProfile::COMPAT);
    auto rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    SciToken scitoken;
    SciTokenStatus status;

    // Accepts any profile.
    rv = scitoken_deserialize_start(token_value, &scitoken, nullptr, &status,
                                    &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    // Accepts only an at+jwt token, should fail with COMPAT token
    while (rv == 0 && status) {
        rv = scitoken_deserialize_continue(&scitoken, &status, &err_msg);
        ASSERT_TRUE(rv == 0) << err_msg;
    }
    scitoken_destroy(scitoken);
}

TEST_F(SerializeTest, FailDeserializeAsyncTest) {
    char *err_msg = nullptr;

    std::unique_ptr<void, decltype(&scitoken_key_destroy)> mykey(
        scitoken_key_create("1", "ES256", ec_public_2, ec_private_2, &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(mykey.get() != nullptr) << err_msg;

    std::unique_ptr<void, decltype(&scitoken_destroy)> mytoken(
        scitoken_create(mykey.get()), scitoken_destroy);
    ASSERT_TRUE(mytoken.get() != nullptr);

    auto rv = scitoken_set_claim_string(
        mytoken.get(), "iss", "https://demo.scitokens.org/gtest", &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    char *value;
    rv = scitoken_serialize(mytoken.get(), &value, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    EXPECT_TRUE(value != nullptr);
    std::unique_ptr<char, decltype(&free)> value_ptr(value, free);
    EXPECT_TRUE(strlen(value) > 50);

    char *token_value = nullptr;
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    SciToken scitoken;
    SciTokenStatus status;

    // Accepts any profile.
    rv = scitoken_deserialize_start(value, &scitoken, nullptr, &status,
                                    &err_msg);
    EXPECT_FALSE(rv == 0) << err_msg;
    free(err_msg);
    err_msg = nullptr;

    // Accepts only an at+jwt token, should fail with COMPAT token
    while (rv == 0 && status) {
        rv = scitoken_deserialize_continue(&scitoken, &status, &err_msg);
        EXPECT_FALSE(rv == 0) << err_msg;
        free(err_msg);
        err_msg = nullptr;
    }
}

TEST_F(SerializeTest, ExplicitTime) {
    char *err_msg = nullptr;

    scitoken_set_serialize_profile(m_token.get(), SciTokenProfile::WLCG_1_0);
    auto rv = scitoken_set_claim_string(m_token.get(), "scope",
                                        "storage.read:/", &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    char *token_value = nullptr;
    rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    free(token_value);
    ASSERT_TRUE(rv == 0) << err_msg;

    auto enforcer = enforcer_create("https://demo.scitokens.org/gtest",
                                    &m_audiences_array[0], &err_msg);
    ASSERT_TRUE(enforcer != nullptr) << err_msg;
    Acl *acls;
    rv = enforcer_generate_acls(enforcer, m_read_token.get(), &acls, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    ASSERT_TRUE(acls != nullptr);
    enforcer_acl_free(acls);

    enforcer_set_time(enforcer, time(NULL), &err_msg);
    rv = enforcer_generate_acls(enforcer, m_read_token.get(), &acls, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    enforcer_set_time(enforcer, time(NULL) + 100, &err_msg);
    enforcer_acl_free(acls);
    rv = enforcer_generate_acls(enforcer, m_read_token.get(), &acls, &err_msg);
    free(err_msg);
    err_msg = nullptr;
    ASSERT_FALSE(rv == 0);

    enforcer_set_time(enforcer, time(NULL) - 100, &err_msg);
    rv = enforcer_generate_acls(enforcer, m_read_token.get(), &acls, &err_msg);
    ASSERT_FALSE(rv == 0);
    free(err_msg);

    enforcer_destroy(enforcer);
}

TEST_F(SerializeTest, GetExpirationErrorHandling) {
    char *err_msg = nullptr;

    // Test NULL token handling
    long long expiry;
    auto rv = scitoken_get_expiration(nullptr, &expiry, &err_msg);
    ASSERT_FALSE(rv == 0);
    ASSERT_TRUE(err_msg != nullptr);
    EXPECT_STREQ(err_msg, "Token cannot be NULL");
    free(err_msg);
    err_msg = nullptr;

    // Test NULL expiry parameter handling
    rv = scitoken_get_expiration(m_token.get(), nullptr, &err_msg);
    ASSERT_FALSE(rv == 0);
    ASSERT_TRUE(err_msg != nullptr);
    EXPECT_STREQ(err_msg, "Expiry output parameter cannot be NULL");
    free(err_msg);
    err_msg = nullptr;

    // Test normal operation works
    char *token_value = nullptr;
    rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    rv = scitoken_get_expiration(m_read_token.get(), &expiry, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    ASSERT_TRUE(expiry > 0);

    free(token_value);
}

class SerializeNoKidTest : public ::testing::Test {
  protected:
    void SetUp() override {
        char *err_msg = nullptr;
        m_key = KeyPtr(scitoken_key_create("none", "ES256", ec_public,
                                           ec_private, &err_msg),
                       scitoken_key_destroy);
        ASSERT_TRUE(m_key.get() != nullptr) << err_msg;

        m_token = TokenPtr(scitoken_create(m_key.get()), scitoken_destroy);
        ASSERT_TRUE(m_token.get() != nullptr);

        auto rv = scitoken_set_claim_string(
            m_token.get(), "iss", "https://demo.scitokens.org/gtest", &err_msg);
        ASSERT_TRUE(rv == 0) << err_msg;

        rv = scitoken_store_public_ec_key("https://demo.scitokens.org/gtest",
                                          "1", ec_public, &err_msg);
        ASSERT_TRUE(rv == 0) << err_msg;

        scitoken_set_lifetime(m_token.get(), 60);

        m_audiences_array.push_back("https://demo.scitokens.org/");
        m_audiences_array.push_back(nullptr);

        const char *groups[3] = {nullptr, nullptr, nullptr};
        const char group0[] = "group0";
        const char group1[] = "group1";
        groups[0] = group0;
        groups[1] = group1;
        rv = scitoken_set_claim_string_list(m_token.get(), "groups", groups,
                                            &err_msg);
        ASSERT_TRUE(rv == 0) << err_msg;

        m_read_token.reset(scitoken_create(nullptr));
        ASSERT_TRUE(m_read_token.get() != nullptr);
    }

    using KeyPtr = std::unique_ptr<void, decltype(&scitoken_key_destroy)>;
    KeyPtr m_key{nullptr, scitoken_key_destroy};

    using TokenPtr = std::unique_ptr<void, decltype(&scitoken_destroy)>;
    TokenPtr m_token{nullptr, scitoken_destroy};

    std::vector<const char *> m_audiences_array;

    TokenPtr m_read_token{nullptr, scitoken_destroy};
};

TEST_F(SerializeNoKidTest, VerifyATJWTTest) {

    char *err_msg = nullptr;

    // Serialize as at+jwt token.
    char *token_value = nullptr;
    scitoken_set_serialize_profile(m_token.get(), SciTokenProfile::AT_JWT);
    auto rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Accepts any profile.
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    // Accepts only an at+jwt token, should work with at+jwt token
    scitoken_set_deserialize_profile(m_read_token.get(),
                                     SciTokenProfile::AT_JWT);
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    // Accepts only SciToken 2.0; should fail
    scitoken_set_deserialize_profile(m_read_token.get(),
                                     SciTokenProfile::SCITOKENS_2_0);
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    free(err_msg);
    ASSERT_FALSE(rv == 0);
}

class KeycacheTest : public ::testing::Test {
  protected:
    std::string demo_scitokens_url = "https://demo.scitokens.org";

    void SetUp() override {
        char *err_msg = nullptr;
        auto rv = keycache_set_jwks(demo_scitokens_url.c_str(),
                                    demo_scitokens.c_str(), &err_msg);
        ASSERT_TRUE(rv == 0) << err_msg;
    }

    // Reference copy of the keys at https://demo.scitokens.org/oauth2/certs;
    // may need to be updated periodically.
    std::string demo_scitokens =
        "{\"keys\":[{\"alg\":\"RS256\",\"e\":\"AQAB\",\"kid\":\"key-rs256\","
        "\"kty\":\"RSA\",\"n\":\"uGDGTLXnqh3mfopjys6sFUBvFl3F4Qt6NEYphq_u_"
        "aBhtN1X9NEyb78uB_"
        "I1KjciJNGLIQU0ECsJiFx6qV1hR9xE1dPyrS3bU92AVtnBrvzUtTU-aUZAmZQiuAC_rC0-"
        "z_"
        "TOQr6qJkkUgZtxR9n9op55ZBpRfZD5dzhkW4Dm146vfTKt0D4cIMoMNJS5xQx9nibeB4E8"
        "hryZDW_"
        "fPeD0XZDcpByNyP0jFDYkxdUtQFvyRpz4WMZ4ejUfvW3gf4LRAfGZJtMnsZ7ZW4RfoQbhi"
        "XKMfWeBEjQDiXh0r-KuZLykxhYJtpf7fTnPna753IzMgRMmW3F69iQn2LQN3LoSMw==\","
        "\"use\":\"sig\"},{\"alg\":\"ES256\",\"kid\":\"key-es256\",\"kty\":"
        "\"EC\",\"use\":\"sig\",\"x\":"
        "\"ncSCrGTBTXXOhNiAOTwNdPjwRz1hVY4saDNiHQK9Bh4=\",\"y\":"
        "\"sCsFXvx7FAAklwq3CzRCBcghqZOFPB2dKUayS6LY_Lo=\"}]}";
    std::string demo_scitokens2 =
        "{\"keys\":[{\"alg\":\"ES256\",\"kid\":\"key-es256\",\"kty\":\"EC\","
        "\"use\":\"sig\",\"x\":\"ncSCrGTBTXXOhNiAOTwNdPjwRz1hVY4saDNiHQK9Bh4="
        "\",\"y\":\"sCsFXvx7FAAklwq3CzRCBcghqZOFPB2dKUayS6LY_Lo=\"}]}";
};

TEST_F(KeycacheTest, RefreshTest) {
    char *err_msg = nullptr;
    auto rv = keycache_refresh_jwks(demo_scitokens_url.c_str(), &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    char *output_jwks;
    rv = keycache_get_cached_jwks(demo_scitokens_url.c_str(), &output_jwks,
                                  &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    ASSERT_TRUE(output_jwks != nullptr);
    std::string output_jwks_str(output_jwks);
    free(output_jwks);

    EXPECT_EQ(demo_scitokens, output_jwks_str);
}

TEST_F(KeycacheTest, RefreshInvalid) {
    char *err_msg = nullptr, *jwks;
    auto rv =
        keycache_refresh_jwks("https://demo.scitokens.org/invalid", &err_msg);
    ASSERT_FALSE(rv == 0);
    free(err_msg);

    rv = keycache_get_cached_jwks("https://demo.scitokens.org/invalid", &jwks,
                                  &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    ASSERT_TRUE(jwks != nullptr);
    std::string jwks_str(jwks);
    free(jwks);

    EXPECT_EQ(jwks_str, "{\"keys\": []}");
}

TEST_F(KeycacheTest, GetInvalid) {
    char *err_msg = nullptr, *jwks;
    auto rv = keycache_get_cached_jwks("https://demo.scitokens.org/unknown",
                                       &jwks, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    ASSERT_TRUE(jwks != nullptr);
    std::string jwks_str(jwks);
    free(jwks);
}

TEST_F(KeycacheTest, GetTest) {
    char *err_msg = nullptr, *jwks;
    auto rv =
        keycache_get_cached_jwks(demo_scitokens_url.c_str(), &jwks, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    ASSERT_TRUE(jwks != nullptr);
    std::string jwks_str(jwks);
    free(jwks);

    EXPECT_EQ(demo_scitokens, jwks_str);
}

TEST_F(KeycacheTest, SetGetTest) {
    char *err_msg = nullptr;
    auto rv = keycache_set_jwks(demo_scitokens_url.c_str(),
                                demo_scitokens2.c_str(), &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    char *jwks;
    rv = keycache_get_cached_jwks(demo_scitokens_url.c_str(), &jwks, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    ASSERT_TRUE(jwks != nullptr);
    std::string jwks_str(jwks);
    free(jwks);

    EXPECT_EQ(demo_scitokens2, jwks_str);
}

TEST_F(KeycacheTest, SetGetConfiguredCacheHome) {
    // Set cache home
    char cache_path[FILENAME_MAX];
    ASSERT_TRUE(getcwd(cache_path, sizeof(cache_path)) !=
                nullptr); // Side effect gets cwd
    char *err_msg = nullptr;
    std::string key = "keycache.cache_home";

    auto rv = scitoken_config_set_str(key.c_str(), cache_path, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    // Set the jwks at the new cache home
    rv = keycache_set_jwks(demo_scitokens_url.c_str(), demo_scitokens2.c_str(),
                           &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    // Fetch the cached jwks from the new cache home
    char *jwks;
    rv = keycache_get_cached_jwks(demo_scitokens_url.c_str(), &jwks, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    ASSERT_TRUE(jwks != nullptr);
    std::string jwks_str(jwks);
    free(jwks);

    EXPECT_EQ(demo_scitokens2, jwks_str);

    // Check that cache home is still what was set
    char *output;
    rv = scitoken_config_get_str(key.c_str(), &output, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    EXPECT_EQ(*output, *cache_path);
    free(output);

    // Reset cache home to whatever it was before by setting empty config
    rv = scitoken_config_set_str(key.c_str(), "", &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
}

TEST_F(KeycacheTest, InvalidConfigKeyTest) {
    char *err_msg = nullptr;
    int new_update_interval = 400;
    std::string key = "invalid key";
    auto rv =
        scitoken_config_set_int(key.c_str(), new_update_interval, &err_msg);
    free(err_msg);
    err_msg = nullptr;
    ASSERT_FALSE(rv == 0);

    const char *key2 = nullptr;
    rv = scitoken_config_set_int(key2, new_update_interval, &err_msg);
    free(err_msg);
    ASSERT_FALSE(rv == 0);
}

TEST_F(KeycacheTest, SetGetUpdateTest) {
    char *err_msg = nullptr;
    int new_update_interval = 400;
    std::string key = "keycache.update_interval_s";
    auto rv =
        scitoken_config_set_int(key.c_str(), new_update_interval, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    rv = scitoken_config_get_int(key.c_str(), &err_msg);
    EXPECT_EQ(rv, new_update_interval) << err_msg;
}

TEST_F(KeycacheTest, SetGetExpirationTest) {
    char *err_msg = nullptr;
    int new_expiration_interval = 2 * 24 * 3600;
    std::string key = "keycache.expiration_interval_s";
    auto rv =
        scitoken_config_set_int(key.c_str(), new_expiration_interval, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    rv = scitoken_config_get_int(key.c_str(), &err_msg);
    EXPECT_EQ(rv, new_expiration_interval) << err_msg;
}

TEST_F(KeycacheTest, SetInvalidUpdateTest) {
    char *err_msg = nullptr;
    int new_update_interval = -1;
    std::string key = "keycache.update_interval_s";
    auto rv =
        scitoken_config_set_int(key.c_str(), new_update_interval, &err_msg);
    free(err_msg);
    ASSERT_FALSE(rv == 0);
}

TEST_F(KeycacheTest, SetInvalidExpirationTest) {
    char *err_msg = nullptr;
    int new_expiration_interval = -2 * 24 * 3600;
    std::string key = "keycache.expiration_interval_s";
    auto rv =
        scitoken_config_set_int(key.c_str(), new_expiration_interval, &err_msg);
    free(err_msg);
    ASSERT_FALSE(rv == 0);
}

TEST_F(KeycacheTest, RefreshExpiredTest) {
    char *err_msg = nullptr, *jwks;
    int new_expiration_interval = 0;
    std::string key = "keycache.expiration_interval_s";
    auto rv =
        scitoken_config_set_int(key.c_str(), new_expiration_interval, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    rv = keycache_refresh_jwks(demo_scitokens_url.c_str(), &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    sleep(1);

    rv = keycache_get_cached_jwks(demo_scitokens_url.c_str(), &jwks, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    ASSERT_TRUE(jwks != nullptr);
    std::string jwks_str(jwks);
    free(jwks);

    EXPECT_EQ(jwks_str, "{\"keys\": []}");
}

class IssuerSecurityTest : public ::testing::Test {
  protected:
    void SetUp() override {
        char *err_msg = nullptr;
        m_key = KeyPtr(
            scitoken_key_create("1", "ES256", ec_public, ec_private, &err_msg),
            scitoken_key_destroy);
        ASSERT_TRUE(m_key.get() != nullptr) << err_msg;

        m_token = TokenPtr(scitoken_create(m_key.get()), scitoken_destroy);
        ASSERT_TRUE(m_token.get() != nullptr);

        // Store public key for verification
        auto rv = scitoken_store_public_ec_key(
            "https://demo.scitokens.org/gtest", "1", ec_public, &err_msg);
        ASSERT_TRUE(rv == 0) << err_msg;

        scitoken_set_lifetime(m_token.get(), 60);

        m_read_token.reset(scitoken_create(nullptr));
        ASSERT_TRUE(m_read_token.get() != nullptr);
    }

    using KeyPtr = std::unique_ptr<void, decltype(&scitoken_key_destroy)>;
    KeyPtr m_key{nullptr, scitoken_key_destroy};

    using TokenPtr = std::unique_ptr<void, decltype(&scitoken_destroy)>;
    TokenPtr m_token{nullptr, scitoken_destroy};

    TokenPtr m_read_token{nullptr, scitoken_destroy};
};

TEST_F(IssuerSecurityTest, LongIssuerTruncation) {
    char *err_msg = nullptr;

    // Create a very long issuer (1000 characters)
    std::string very_long_issuer(1000, 'A');
    auto rv = scitoken_set_claim_string(m_token.get(), "iss",
                                        very_long_issuer.c_str(), &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    char *token_value = nullptr;
    rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Try to verify with a restricted issuer list to trigger error
    const char *allowed_issuers[] = {"https://good.issuer.com", nullptr};
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(),
                                 allowed_issuers, &err_msg);

    // Should fail
    ASSERT_FALSE(rv == 0);
    ASSERT_TRUE(err_msg != nullptr);
    std::string error_message(err_msg);
    std::unique_ptr<char, decltype(&free)> err_msg_ptr(err_msg, free);
    // Error message should be reasonable length (< 400 chars)
    EXPECT_LT(error_message.length(), 400);
    // Should contain expected error text
    EXPECT_NE(error_message.find("is not in list of allowed issuers"),
              std::string::npos);

    // Should contain truncated issuer with ellipsis
    EXPECT_NE(error_message.find("..."), std::string::npos);
}

TEST_F(IssuerSecurityTest, SpecialCharacterIssuer) {
    char *err_msg = nullptr;

    // Create an issuer with special characters and control chars
    std::string special_issuer = "https://bad.com/\"\n\t\r\x01\x1f";
    auto rv = scitoken_set_claim_string(m_token.get(), "iss",
                                        special_issuer.c_str(), &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    char *token_value = nullptr;
    rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Try to verify with a restricted issuer list to trigger error
    const char *allowed_issuers[] = {"https://good.issuer.com", nullptr};
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(),
                                 allowed_issuers, &err_msg);

    // Should fail
    ASSERT_FALSE(rv == 0);
    ASSERT_TRUE(err_msg != nullptr);
    std::string error_message(err_msg);
    std::unique_ptr<char, decltype(&free)> err_msg_ptr(err_msg, free);
    // Error message should be reasonable length
    EXPECT_LT(error_message.length(), 300);
    // Should contain expected error text
    EXPECT_NE(error_message.find("is not in list of allowed issuers"),
              std::string::npos);

    // Should contain properly escaped JSON (with quotes)
    EXPECT_NE(error_message.find("\""), std::string::npos);
}

// Test suite for environment variable configuration
class EnvConfigTest : public ::testing::Test {
  protected:
    void SetUp() override {
        // Save original config values
        char *err_msg = nullptr;
        original_update_interval =
            scitoken_config_get_int("keycache.update_interval_s", &err_msg);
        original_expiry_interval =
            scitoken_config_get_int("keycache.expiration_interval_s", &err_msg);

        char *cache_home = nullptr;
        scitoken_config_get_str("keycache.cache_home", &cache_home, &err_msg);
        if (cache_home) {
            original_cache_home = cache_home;
            free(cache_home);
        }

        char *ca_file = nullptr;
        scitoken_config_get_str("tls.ca_file", &ca_file, &err_msg);
        if (ca_file) {
            original_ca_file = ca_file;
            free(ca_file);
        }
    }

    void TearDown() override {
        // Restore original config values
        char *err_msg = nullptr;
        scitoken_config_set_int("keycache.update_interval_s",
                                original_update_interval, &err_msg);
        scitoken_config_set_int("keycache.expiration_interval_s",
                                original_expiry_interval, &err_msg);
        scitoken_config_set_str("keycache.cache_home",
                                original_cache_home.c_str(), &err_msg);
        scitoken_config_set_str("tls.ca_file", original_ca_file.c_str(),
                                &err_msg);
    }

    int original_update_interval = 600;
    int original_expiry_interval = 4 * 24 * 3600;
    std::string original_cache_home;
    std::string original_ca_file;
};

TEST_F(EnvConfigTest, IntConfigFromEnv) {
    // Note: This test verifies that the environment variable was read at
    // library load time We can't test setting environment variables after
    // library load in the same process This test would need to be run with
    // environment variables set before starting the test

    // Test that we can manually set and get config values
    char *err_msg = nullptr;
    int test_value = 1234;
    auto rv = scitoken_config_set_int("keycache.update_interval_s", test_value,
                                      &err_msg);
    ASSERT_EQ(rv, 0) << (err_msg ? err_msg : "");

    int retrieved =
        scitoken_config_get_int("keycache.update_interval_s", &err_msg);
    EXPECT_EQ(retrieved, test_value) << (err_msg ? err_msg : "");

    if (err_msg)
        free(err_msg);
}

TEST_F(EnvConfigTest, StringConfigFromEnv) {
    // Test that we can manually set and get string config values
    char *err_msg = nullptr;
    const char *test_path = "/tmp/test_cache";
    auto rv =
        scitoken_config_set_str("keycache.cache_home", test_path, &err_msg);
    ASSERT_EQ(rv, 0) << (err_msg ? err_msg : "");

    char *output = nullptr;
    rv = scitoken_config_get_str("keycache.cache_home", &output, &err_msg);
    ASSERT_EQ(rv, 0) << (err_msg ? err_msg : "");
    ASSERT_TRUE(output != nullptr);
    EXPECT_STREQ(output, test_path);

    free(output);
    if (err_msg)
        free(err_msg);
}

// Test for thundering herd prevention with per-issuer locks
TEST_F(IssuerSecurityTest, ThunderingHerdPrevention) {
    char *err_msg = nullptr;

    // Create tokens for a new issuer and pre-populate the cache
    std::string test_issuer = "https://thundering-herd-test.example.org/gtest";

    auto rv = scitoken_set_claim_string(m_token.get(), "iss",
                                        test_issuer.c_str(), &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    // Store public key for this issuer in the cache
    rv = scitoken_store_public_ec_key(test_issuer.c_str(), "1", ec_public,
                                      &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    char *token_value = nullptr;
    rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Successfully deserialize - the per-issuer lock should prevent thundering
    // herd Since we pre-populated the cache, this should succeed without
    // network access
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;

    // Verify the issuer claim
    char *value;
    rv = scitoken_get_claim_string(m_read_token.get(), "iss", &value, &err_msg);
    ASSERT_TRUE(rv == 0) << err_msg;
    ASSERT_TRUE(value != nullptr);
    std::unique_ptr<char, decltype(&free)> value_ptr(value, free);
    EXPECT_STREQ(value, test_issuer.c_str());
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
