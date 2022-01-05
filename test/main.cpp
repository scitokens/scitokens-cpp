#include "../src/scitokens.h"

#include <gtest/gtest.h>

namespace {

const char ec_private[] = "-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEIESSMxT7PLTR9A/aqd+CM0/6vv6fQWqDm0mNx8uE9EbpoAoGCCqGSM49\n"
"AwEHoUQDQgAE1i+ImZ//iQhOPh0OMfZzdbmPH+3G1ouWezolCugQYWIRqNmwq3zR\n"
"EnTbe4EmymTpJ1MJTPP/tCEUP3G/QqQuhA==\n"
"-----END EC PRIVATE KEY-----\n";

const char ec_public[] = "-----BEGIN PUBLIC KEY-----\n"
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1i+ImZ//iQhOPh0OMfZzdbmPH+3G\n"
"1ouWezolCugQYWIRqNmwq3zREnTbe4EmymTpJ1MJTPP/tCEUP3G/QqQuhA==\n"
"-----END PUBLIC KEY-----\n";

const char ec_private_2[] = "-----BEGIN EC PRIVATE KEY-----\n"
"MHcCAQEEIJH6NpWPHcM7wxL/bv89Nezug+KEUQjI9fZxhrBHNA1ioAoGCCqGSM49\n"
"AwEHoUQDQgAEb8M7AxRN+DmbfYOoA6DeHCcSeA+kXWCq4E/g2ME/uBOdP8RE0tql\n"
"e8fxYcaPikgMcppGq2ycTiLGgEYXgsq2JA==\n"
"-----END EC PRIVATE KEY-----\n";

const char ec_public_2[] = "-----BEGIN PUBLIC KEY-----\n"
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

    std::unique_ptr<void, decltype(&scitoken_destroy)>
        mytoken(scitoken_create(mykey.get()), scitoken_destroy);
    ASSERT_TRUE(mytoken.get() != nullptr);

    auto rv = scitoken_set_claim_string(mytoken.get(), "iss",
        "https://demo.scitokens.org/gtest", &err_msg);
    ASSERT_TRUE(rv == 0);

    char *value;
    rv = scitoken_serialize(mytoken.get(), &value, &err_msg);
    ASSERT_TRUE(rv == 0);
    EXPECT_TRUE(value != nullptr);
    std::unique_ptr<char, decltype(&free)> value_ptr(value, free);

    ASSERT_TRUE(strlen(value) > 50);
}


class SerializeTest : public ::testing::Test {
    protected:
        void SetUp() override {
            char *err_msg;
            m_key = KeyPtr(scitoken_key_create("1", "ES256", ec_public, ec_private, &err_msg),
                scitoken_key_destroy);
            ASSERT_TRUE(m_key.get() != nullptr);

            m_token = TokenPtr(scitoken_create(m_key.get()), scitoken_destroy);
            ASSERT_TRUE(m_token.get() != nullptr);

            auto rv = scitoken_set_claim_string(m_token.get(), "iss",
                "https://demo.scitokens.org/gtest", &err_msg);
            ASSERT_TRUE(rv == 0);

            rv = scitoken_store_public_ec_key("https://demo.scitokens.org/gtest",
                "1", ec_public, &err_msg);
            ASSERT_TRUE(rv == 0);

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

    TokenPtr m_read_token{nullptr, scitoken_destroy};
};


TEST_F(SerializeTest, VerifyTest) {

    char *err_msg = nullptr;

    char *token_value = nullptr;
    auto rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0);
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr, &err_msg);
    ASSERT_TRUE(rv == 0);

    char *value;
    rv = scitoken_get_claim_string(m_read_token.get(), "iss", &value, &err_msg);
    ASSERT_TRUE(value != nullptr);
    ASSERT_TRUE(rv == 0);
    std::unique_ptr<char, decltype(&free)> value_ptr(value, free);
    EXPECT_STREQ(value, "https://demo.scitokens.org/gtest");

    value_ptr.reset();
    rv = scitoken_get_claim_string(m_read_token.get(), "doesnotexist", &value, &err_msg);
    EXPECT_FALSE(rv == 0);
}

TEST_F(SerializeTest, TestStringList) {
    char *err_msg = nullptr;

    char **value;
    auto rv = scitoken_get_claim_string_list(m_token.get(), "groups", &value, &err_msg);
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
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr, &err_msg);
    ASSERT_TRUE(rv == 0);

    char *value;
    rv = scitoken_get_claim_string(m_read_token.get(), "wlcg.ver", &value, &err_msg);
    ASSERT_TRUE(rv == 0);
    ASSERT_TRUE(value != nullptr);
    std::unique_ptr<char, decltype(&free)> value_ptr(value, free);
    EXPECT_STREQ(value, "1.0");

    value_ptr.reset();
    rv = scitoken_get_claim_string(m_read_token.get(), "ver", &value, &err_msg);
    EXPECT_FALSE(rv == 0);

    // Accepts only a WLCG token
    scitoken_set_deserialize_profile(m_read_token.get(), SciTokenProfile::WLCG_1_0);
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr, &err_msg);
    ASSERT_TRUE(rv == 0);

    // Accepts only SciToken 1.0; should fail.
    scitoken_set_deserialize_profile(m_read_token.get(), SciTokenProfile::SCITOKENS_1_0);
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr, &err_msg);
    ASSERT_FALSE(rv == 0);
}


TEST_F(SerializeTest, FailVerifyToken) {
    char *err_msg;

    std::unique_ptr<void, decltype(&scitoken_key_destroy)> mykey(
        scitoken_key_create("1", "ES256", ec_public_2, ec_private_2, &err_msg),
        scitoken_key_destroy);
    ASSERT_TRUE(mykey.get() != nullptr);

    std::unique_ptr<void, decltype(&scitoken_destroy)>
        mytoken(scitoken_create(mykey.get()), scitoken_destroy);
    ASSERT_TRUE(mytoken.get() != nullptr);

    auto rv = scitoken_set_claim_string(mytoken.get(), "iss",
        "https://demo.scitokens.org/gtest", &err_msg);
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
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr, &err_msg);
    ASSERT_TRUE(rv == 0);

    // Accepts only an at+jwt token, should work with at+jwt token
    scitoken_set_deserialize_profile(m_read_token.get(), SciTokenProfile::AT_JWT);
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr, &err_msg);
    ASSERT_TRUE(rv == 0);

    // Accepts only SciToken 2.0; should fail
    scitoken_set_deserialize_profile(m_read_token.get(), SciTokenProfile::SCITOKENS_2_0);
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr, &err_msg);
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
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr, &err_msg);
    ASSERT_TRUE(rv == 0);

    // Accepts only an at+jwt token, should fail with COMPAT token
    scitoken_set_deserialize_profile(m_read_token.get(), SciTokenProfile::AT_JWT);
    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr, &err_msg);
    ASSERT_FALSE(rv == 0);
}

}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
