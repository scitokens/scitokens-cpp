#include "../src/scitokens.h"

#include <gtest/gtest.h>
#include <memory>

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
    char *err_msg;

    std::unique_ptr<void, decltype(&scitoken_key_destroy)> mykey(
        scitoken_key_create("1", "ES256", ec_public, ec_private, &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(mykey.get() != nullptr);

    std::unique_ptr<void, decltype(&scitoken_destroy)> mytoken(
        scitoken_create(mykey.get()), scitoken_destroy);
    ASSERT_TRUE(mytoken.get() != nullptr);

    auto rv = scitoken_set_claim_string(
        mytoken.get(), "iss", "https://demo.scitokens.org/gtest", &err_msg);
    ASSERT_TRUE(rv == 0);

    char *value;
    rv = scitoken_serialize(mytoken.get(), &value, &err_msg);
    ASSERT_TRUE(rv == 0);
    EXPECT_TRUE(value != nullptr);
    std::unique_ptr<char, decltype(&free)> value_ptr(value, free);

    ASSERT_TRUE(strlen(value) > 50);
}

class KeycacheTest : public ::testing::Test {
  protected:
    std::string demo_scitokens_url = "https://demo.scitokens.org";

    void SetUp() override {
        char *err_msg;
        auto rv = keycache_set_jwks(demo_scitokens_url.c_str(),
                                    demo_scitokens.c_str(), &err_msg);
        ASSERT_TRUE(rv == 0);
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
    char *err_msg, *jwks;
    auto rv =
        keycache_refresh_jwks("https://demo.scitokens.org/invalid", &err_msg);
    ASSERT_FALSE(rv == 0);

    rv = keycache_get_cached_jwks("https://demo.scitokens.org/invalid", &jwks,
                                  &err_msg);
    ASSERT_TRUE(rv == 0);
    ASSERT_TRUE(jwks != nullptr);
    std::string jwks_str(jwks);
    free(jwks);

    EXPECT_EQ(jwks_str, "{\"keys\": []}");
}

TEST_F(KeycacheTest, GetInvalid) {
    char *err_msg, *jwks;
    auto rv = keycache_get_cached_jwks("https://demo.scitokens.org/unknown",
                                       &jwks, &err_msg);
    ASSERT_TRUE(rv == 0);
    ASSERT_TRUE(jwks != nullptr);
    std::string jwks_str(jwks);
    free(jwks);
}

TEST_F(KeycacheTest, GetTest) {
    char *err_msg, *jwks;
    auto rv =
        keycache_get_cached_jwks(demo_scitokens_url.c_str(), &jwks, &err_msg);
    ASSERT_TRUE(rv == 0);
    ASSERT_TRUE(jwks != nullptr);
    std::string jwks_str(jwks);
    free(jwks);

    EXPECT_EQ(demo_scitokens, jwks_str);
}

TEST_F(KeycacheTest, SetGetTest) {
    char *err_msg;
    auto rv = keycache_set_jwks(demo_scitokens_url.c_str(),
                                demo_scitokens2.c_str(), &err_msg);
    ASSERT_TRUE(rv == 0);

    char *jwks;
    rv = keycache_get_cached_jwks(demo_scitokens_url.c_str(), &jwks, &err_msg);
    ASSERT_TRUE(rv == 0);
    ASSERT_TRUE(jwks != nullptr);
    std::string jwks_str(jwks);
    free(jwks);

    EXPECT_EQ(demo_scitokens2, jwks_str);
}

class SerializeTest : public ::testing::Test {
  protected:
    void SetUp() override {
        char *err_msg;
        m_key = KeyPtr(
            scitoken_key_create("1", "ES256", ec_public, ec_private, &err_msg),
            scitoken_key_destroy);
        ASSERT_TRUE(m_key.get() != nullptr);

        m_token = TokenPtr(scitoken_create(m_key.get()), scitoken_destroy);
        ASSERT_TRUE(m_token.get() != nullptr);

        auto rv = scitoken_set_claim_string(
            m_token.get(), "iss", "https://demo.scitokens.org/gtest", &err_msg);
        ASSERT_TRUE(rv == 0);

        rv = scitoken_store_public_ec_key("https://demo.scitokens.org/gtest",
                                          "1", ec_public, &err_msg);
        ASSERT_TRUE(rv == 0);

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
        ASSERT_TRUE(rv == 0);

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
    ASSERT_TRUE(rv == 0);
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0);

    char *value;
    rv = scitoken_get_claim_string(m_read_token.get(), "iss", &value, &err_msg);
    ASSERT_TRUE(value != nullptr);
    ASSERT_TRUE(rv == 0);
    std::unique_ptr<char, decltype(&free)> value_ptr(value, free);
    EXPECT_STREQ(value, "https://demo.scitokens.org/gtest");

    value_ptr.reset();
    rv = scitoken_get_claim_string(m_read_token.get(), "doesnotexist", &value,
                                   &err_msg);
    EXPECT_FALSE(rv == 0);
}

TEST_F(SerializeTest, TestStringList) {
    char *err_msg = nullptr;

    char **value;
    auto rv = scitoken_get_claim_string_list(m_token.get(), "groups", &value,
                                             &err_msg);
    ASSERT_TRUE(rv == 0);
    ASSERT_TRUE(value != nullptr);

    ASSERT_TRUE(value[0] != nullptr);
    EXPECT_STREQ(value[0], "group0");

    ASSERT_TRUE(value[1] != nullptr);
    EXPECT_STREQ(value[1], "group1");

    EXPECT_TRUE(value[2] == nullptr);
}

TEST_F(SerializeTest, VerifyWLCGTest) {

    char *err_msg = nullptr;

    char *token_value = nullptr;
    scitoken_set_serialize_profile(m_token.get(), SciTokenProfile::WLCG_1_0);
    auto rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0);
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Accepts any profile.
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0);

    char *value;
    rv = scitoken_get_claim_string(m_read_token.get(), "wlcg.ver", &value,
                                   &err_msg);
    ASSERT_TRUE(rv == 0);
    ASSERT_TRUE(value != nullptr);
    std::unique_ptr<char, decltype(&free)> value_ptr(value, free);
    EXPECT_STREQ(value, "1.0");

    value_ptr.reset();
    rv = scitoken_get_claim_string(m_read_token.get(), "ver", &value, &err_msg);
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
    ASSERT_FALSE(rv == 0);
}

TEST_F(SerializeTest, FailVerifyToken) {
    char *err_msg;

    std::unique_ptr<void, decltype(&scitoken_key_destroy)> mykey(
        scitoken_key_create("1", "ES256", ec_public_2, ec_private_2, &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(mykey.get() != nullptr);

    std::unique_ptr<void, decltype(&scitoken_destroy)> mytoken(
        scitoken_create(mykey.get()), scitoken_destroy);
    ASSERT_TRUE(mytoken.get() != nullptr);

    auto rv = scitoken_set_claim_string(
        mytoken.get(), "iss", "https://demo.scitokens.org/gtest", &err_msg);
    ASSERT_TRUE(rv == 0);

    char *value;
    rv = scitoken_serialize(mytoken.get(), &value, &err_msg);
    ASSERT_TRUE(rv == 0);
    EXPECT_TRUE(value != nullptr);
    std::unique_ptr<char, decltype(&free)> value_ptr(value, free);
    EXPECT_TRUE(strlen(value) > 50);

    // Should fail; we signed it with the wrong public key.
    rv = scitoken_deserialize_v2(value, m_read_token.get(), nullptr, &err_msg);
    EXPECT_FALSE(rv == 0);
}

TEST_F(SerializeTest, VerifyATJWTTest) {

    char *err_msg = nullptr;

    // Serialize as at+jwt token.
    char *token_value = nullptr;
    scitoken_set_serialize_profile(m_token.get(), SciTokenProfile::AT_JWT);
    auto rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0);
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Accepts any profile.
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0);

    // Accepts only an at+jwt token, should work with at+jwt token
    scitoken_set_deserialize_profile(m_read_token.get(),
                                     SciTokenProfile::AT_JWT);
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0);

    // Accepts only SciToken 2.0; should fail
    scitoken_set_deserialize_profile(m_read_token.get(),
                                     SciTokenProfile::SCITOKENS_2_0);
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_FALSE(rv == 0);
}

TEST_F(SerializeTest, FailVerifyATJWTTest) {

    char *err_msg = nullptr;

    // Serialize as "compat" token.
    char *token_value = nullptr;
    scitoken_set_serialize_profile(m_token.get(), SciTokenProfile::COMPAT);
    auto rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0);
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    // Accepts any profile.
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0);

    // Accepts only an at+jwt token, should fail with COMPAT token
    scitoken_set_deserialize_profile(m_read_token.get(),
                                     SciTokenProfile::AT_JWT);
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_FALSE(rv == 0);
}

TEST_F(SerializeTest, EnforcerTest) {
    /*
     * Test that the enforcer works and returns an err_msg
     */
    char *err_msg = nullptr;

    auto rv = scitoken_set_claim_string(
        m_token.get(), "aud", "https://demo.scitokens.org/", &err_msg);
    ASSERT_TRUE(rv == 0);

    auto enforcer = enforcer_create("https://demo.scitokens.org/gtest",
                                    &m_audiences_array[0], &err_msg);
    ASSERT_TRUE(enforcer != nullptr);

    Acl acl;
    acl.authz = "read";
    acl.resource = "/stuff";

    rv = scitoken_set_claim_string(m_token.get(), "scope", "read:/blah",
                                   &err_msg);
    ASSERT_TRUE(rv == 0);

    rv = scitoken_set_claim_string(m_token.get(), "ver", "scitoken:2.0",
                                   &err_msg);
    ASSERT_TRUE(rv == 0);

    char *token_value = nullptr;
    rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0);
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0);

    rv = enforcer_test(enforcer, m_read_token.get(), &acl, &err_msg);
    ASSERT_STREQ(
        err_msg,
        "token verification failed: 'scope' claim verification failed.");
    ASSERT_TRUE(rv == -1) << err_msg;
}

TEST_F(SerializeTest, EnforcerScopeTest) {
    char *err_msg = nullptr;

    auto rv = scitoken_set_claim_string(
        m_token.get(), "aud", "https://demo.scitokens.org/", &err_msg);
    ASSERT_TRUE(rv == 0);

    auto enforcer = enforcer_create("https://demo.scitokens.org/gtest",
                                    &m_audiences_array[0], &err_msg);
    ASSERT_TRUE(enforcer != nullptr);

    scitoken_set_serialize_profile(m_token.get(), SciTokenProfile::WLCG_1_0);

    rv = scitoken_set_claim_string(
        m_token.get(), "scope",
        "storage.modify:/ storage.read:/ openid offline_access", &err_msg);
    ASSERT_TRUE(rv == 0);

    char *token_value = nullptr;
    rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0);

    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0);

    Acl *acls;
    enforcer_generate_acls(enforcer, m_read_token.get(), &acls, &err_msg);
    ASSERT_TRUE(acls != nullptr);
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
    ASSERT_TRUE(rv == 0);
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
}

TEST_F(SerializeTest, FailDeserializeAsyncTest) {
    char *err_msg = nullptr;

    std::unique_ptr<void, decltype(&scitoken_key_destroy)> mykey(
        scitoken_key_create("1", "ES256", ec_public_2, ec_private_2, &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(mykey.get() != nullptr);

    std::unique_ptr<void, decltype(&scitoken_destroy)> mytoken(
        scitoken_create(mykey.get()), scitoken_destroy);
    ASSERT_TRUE(mytoken.get() != nullptr);

    auto rv = scitoken_set_claim_string(
        mytoken.get(), "iss", "https://demo.scitokens.org/gtest", &err_msg);
    ASSERT_TRUE(rv == 0);

    char *value;
    rv = scitoken_serialize(mytoken.get(), &value, &err_msg);
    ASSERT_TRUE(rv == 0);
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

    // Accepts only an at+jwt token, should fail with COMPAT token
    while (rv == 0 && status) {
        rv = scitoken_deserialize_continue(&scitoken, &status, &err_msg);
        EXPECT_FALSE(rv == 0) << err_msg;
    }
}

TEST_F(SerializeTest, ExplicitTime) {
    time_t now = time(NULL);
    char *err_msg;

    scitoken_set_serialize_profile(m_token.get(), SciTokenProfile::WLCG_1_0);
    auto rv = scitoken_set_claim_string(m_token.get(), "scope",
                                        "storage.read:/", &err_msg);

    char *token_value = nullptr;
    rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0);

    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr,
                                 &err_msg);
    ASSERT_TRUE(rv == 0);

    auto enforcer = enforcer_create("https://demo.scitokens.org/gtest",
                                    &m_audiences_array[0], &err_msg);
    ASSERT_TRUE(enforcer != nullptr);
    Acl *acls;
    rv = enforcer_generate_acls(enforcer, m_read_token.get(), &acls, &err_msg);
    if (rv) {
        printf("Failure when generating ACLs: %s\n", err_msg);
    }
    ASSERT_TRUE(rv == 0);
    ASSERT_TRUE(acls != nullptr);

    enforcer_set_time(enforcer, time(NULL), &err_msg);
    rv = enforcer_generate_acls(enforcer, m_read_token.get(), &acls, &err_msg);
    ASSERT_TRUE(rv == 0);

    enforcer_set_time(enforcer, time(NULL) + 100, &err_msg);
    rv = enforcer_generate_acls(enforcer, m_read_token.get(), &acls, &err_msg);
    ASSERT_FALSE(rv == 0);

    enforcer_set_time(enforcer, time(NULL) - 100, &err_msg);
    rv = enforcer_generate_acls(enforcer, m_read_token.get(), &acls, &err_msg);
    ASSERT_FALSE(rv == 0);

    enforcer_destroy(enforcer);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
