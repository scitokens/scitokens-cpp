#include "../src/scitokens.h"

#include <pwd.h>
#include <memory>
#include <gtest/gtest.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/pem.h>

#ifndef PICOJSON_USE_INT64
#define PICOJSON_USE_INT64
#endif
#include <picojson/picojson.h>
#include <sqlite3.h>

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

/**
 * Duplicate of get_cache_file from scitokens_cache.cpp; used for direct
 * SQLite manipulation.
 */
std::string
get_cache_file() {

    const char *xdg_cache_home = getenv("XDG_CACHE_HOME");

    auto bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    bufsize = (bufsize == -1) ? 16384 : bufsize;

    std::unique_ptr<char[]> buf(new char[bufsize]);

    std::string home_dir;
    struct passwd pwd, *result = NULL;
    getpwuid_r(geteuid(), &pwd, buf.get(), bufsize, &result);
    if (result && result->pw_dir) {
        home_dir = result->pw_dir;
        home_dir += "/.cache";
    }

    std::string cache_dir(xdg_cache_home ? xdg_cache_home : home_dir.c_str());
    if (cache_dir.size() == 0) {
        return "";
    }

    int r = mkdir(cache_dir.c_str(), 0700);
    if ((r < 0) && errno != EEXIST) {
        return "";
    }

    std::string keycache_dir = cache_dir + "/scitokens";
    r = mkdir(keycache_dir.c_str(), 0700);
    if ((r < 0) && errno != EEXIST) {
        return "";
    }

    std::string keycache_file = keycache_dir + "/scitokens_cpp.sqllite";
    // Assume this isn't needed; we'll trigger it via the "real" cache routines.
    //initialize_cachedb(keycache_file);

    return keycache_file;
}

/**
 * Duplicate of remove_issuer_entry from scitokens_cache.cpp; used for direct cache manipulation
 */
void
remove_issuer_entry(sqlite3 *db, const std::string &issuer, bool new_transaction) {

    if (new_transaction) sqlite3_exec(db, "BEGIN", 0, 0 , 0);

    sqlite3_stmt *stmt;
    int rc = sqlite3_prepare_v2(db, "DELETE FROM keycache WHERE issuer = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return;
    }

    if (sqlite3_bind_text(stmt, 1, issuer.c_str(), issuer.size(), SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return;
    }

    sqlite3_finalize(stmt);

    if (new_transaction) sqlite3_exec(db, "COMMIT", 0, 0 , 0);
}

/**
 * Duplicate of store_public_keys from scitokens_cache.cpp; used for direct cache manipulation.
 */
bool
store_public_keys(const std::string &issuer, const std::string &keys, int64_t next_update, int64_t expires) {

    picojson::value json_obj;
    auto err = picojson::parse(json_obj, keys);
    if (!err.empty() || !json_obj.is<picojson::object>()) {
        return false;
    }

    picojson::object top_obj;
    top_obj["jwks"] = json_obj;
    top_obj["next_update"] = picojson::value(next_update);
    top_obj["expires"] = picojson::value(expires);
    picojson::value db_value(top_obj);
    std::string db_str = db_value.serialize();
    
    auto cache_fname = get_cache_file();
    if (cache_fname.size() == 0) {return false;}
        
    sqlite3 *db;
    int rc = sqlite3_open(cache_fname.c_str(), &db);
    if (rc) {
        sqlite3_close(db);
        return false;
    }   
    
    sqlite3_exec(db, "BEGIN", 0, 0 , 0);
    
    remove_issuer_entry(db, issuer, false);
    
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "INSERT INTO keycache VALUES (?, ?)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }   
    
    if (sqlite3_bind_text(stmt, 1, issuer.c_str(), issuer.size(), SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt); 
        sqlite3_close(db);
        return false;
    }   
    
    if (sqlite3_bind_text(stmt, 2, db_str.c_str(), db_str.size(), SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt); 
        sqlite3_close(db);
        return false;
    }   
    
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }   
    
    sqlite3_exec(db, "COMMIT", 0, 0 , 0);
    
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return true;
}

bool
get_public_keys_from_db(const std::string issuer, int64_t &expires, int64_t &next_update) {
    auto cache_fname = get_cache_file();
    if (cache_fname.size() == 0) {return false;}

    sqlite3 *db;
    int rc = sqlite3_open(cache_fname.c_str(), &db);
    if (rc) {
        sqlite3_close(db);
        return false;
    }

    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "SELECT keys from keycache where issuer = ?", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        sqlite3_close(db);
        return false;
    }

    if (sqlite3_bind_text(stmt, 1, issuer.c_str(), issuer.size(), SQLITE_STATIC) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const unsigned char * data = sqlite3_column_text(stmt, 0);
        std::string metadata(reinterpret_cast<const char *>(data));
        sqlite3_finalize(stmt);
        picojson::value json_obj;
        auto err = picojson::parse(json_obj, metadata);
        if (!err.empty() || !json_obj.is<picojson::object>()) {
            sqlite3_close(db);
            return false;
        }
        auto top_obj = json_obj.get<picojson::object>();
        auto iter = top_obj.find("jwks");
        auto keys_local = iter->second;
        iter = top_obj.find("expires");
        if (iter == top_obj.end() || !iter->second.is<int64_t>()) {
            sqlite3_close(db);
            return false;
        }
        auto expiry = iter->second.get<int64_t>();
        sqlite3_close(db);
        iter = top_obj.find("next_update");
        if (iter == top_obj.end() || !iter->second.is<int64_t>()) {
            next_update = expiry - 4*3600;
        } else {
            next_update = iter->second.get<int64_t>();
        }
        expires = expiry;
        return true;
    } else if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    } else {
        // TODO: log error?
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return false;
    }
}

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


class KeycacheTest : public ::testing::Test
{
    protected:
        std::string demo_scitokens_url = "https://demo.scitokens.org";
        std::string demo_invalid_url = "https://demo.scitokens.org/invalid";

        void SetUp() override {
            char *err_msg;
            auto rv = keycache_set_jwks(demo_scitokens_url.c_str(), demo_scitokens.c_str(), &err_msg);
            ASSERT_TRUE(rv == 0);
        }

        // Reference copy of the keys at https://demo.scitokens.org/oauth2/certs; may need
        // to be updated periodically.
        std::string demo_scitokens = "{\"keys\":[{\"alg\":\"RS256\",\"e\":\"AQAB\",\"kid\":\"key-rs256\",\"kty\":\"RSA\",\"n\":\"uGDGTLXnqh3mfopjys6sFUBvFl3F4Qt6NEYphq_u_aBhtN1X9NEyb78uB_I1KjciJNGLIQU0ECsJiFx6qV1hR9xE1dPyrS3bU92AVtnBrvzUtTU-aUZAmZQiuAC_rC0-z_TOQr6qJkkUgZtxR9n9op55ZBpRfZD5dzhkW4Dm146vfTKt0D4cIMoMNJS5xQx9nibeB4E8hryZDW_fPeD0XZDcpByNyP0jFDYkxdUtQFvyRpz4WMZ4ejUfvW3gf4LRAfGZJtMnsZ7ZW4RfoQbhiXKMfWeBEjQDiXh0r-KuZLykxhYJtpf7fTnPna753IzMgRMmW3F69iQn2LQN3LoSMw==\",\"use\":\"sig\"},{\"alg\":\"ES256\",\"kid\":\"key-es256\",\"kty\":\"EC\",\"use\":\"sig\",\"x\":\"ncSCrGTBTXXOhNiAOTwNdPjwRz1hVY4saDNiHQK9Bh4=\",\"y\":\"sCsFXvx7FAAklwq3CzRCBcghqZOFPB2dKUayS6LY_Lo=\"}]}";
        std::string demo_scitokens2 = "{\"keys\":[{\"alg\":\"ES256\",\"kid\":\"key-es256\",\"kty\":\"EC\",\"use\":\"sig\",\"x\":\"ncSCrGTBTXXOhNiAOTwNdPjwRz1hVY4saDNiHQK9Bh4=\",\"y\":\"sCsFXvx7FAAklwq3CzRCBcghqZOFPB2dKUayS6LY_Lo=\"}]}";
};


// Emulate the case of an issuer failure.  Store a public key that
// is in the need of an update. Make sure, on failure, the next_update
// is 5 minutes ahead of the present.
TEST_F(KeycacheTest, FailureTest) {
    time_t now = time(NULL);
    const time_t expiry = now + 86400;
    // Insert a public key that requires an update on next token verification.
    ASSERT_TRUE(store_public_keys(demo_invalid_url, demo_scitokens2, now - 600, expiry));

    // Create a new token with an invalid signature.
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    auto outbio = BIO_new(BIO_s_mem());
    ASSERT_TRUE(outbio != nullptr);
    auto eccgrp = OBJ_txt2nid("secp256k1");
    auto ecc = EC_KEY_new_by_curve_name(eccgrp);
    ASSERT_TRUE(1 == EC_KEY_generate_key(ecc));

    auto pkey = EVP_PKEY_new();
    ASSERT_TRUE(1 == EVP_PKEY_assign_EC_KEY(pkey, ecc));
    ASSERT_TRUE(1 == PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL));

    char *pem_data;
    long pem_len = BIO_get_mem_data(outbio, &pem_data);
    std::string pem_str(pem_data, pem_len);

    // Generate a serialized token from the new key.
    auto key = scitoken_key_create("test_key", "ES256", "", pem_str.c_str(), nullptr);
    ASSERT_TRUE(key != nullptr);

    auto token = scitoken_create(key);
    ASSERT_TRUE(token != nullptr);

    auto rv = scitoken_set_claim_string(token, "iss", demo_invalid_url.c_str(), nullptr);
    ASSERT_TRUE(rv == 0);

    rv = scitoken_set_claim_string(token, "sub", "test_user", nullptr);
    ASSERT_TRUE(rv == 0);

    scitoken_set_lifetime(token, 86400);

    char *token_encoded;
    rv = scitoken_serialize(token, &token_encoded, nullptr);
    ASSERT_TRUE(rv == 0);
    std::string token_str(token_encoded);
    free(token_encoded);

    // Try to deserialize the newly generated token.  Should fail as the key doesn't match.
    auto token_read = scitoken_create(nullptr);
    ASSERT_TRUE(token_read != nullptr);
    rv = scitoken_deserialize_v2(token_str.c_str(), token_read, nullptr, nullptr);
    ASSERT_FALSE(rv == 0);

    // Now, for the real test -- what's the value of expired and next_update?
    int64_t new_expiry, new_next_update;
    ASSERT_TRUE(get_public_keys_from_db(demo_invalid_url, new_expiry, new_next_update));

    EXPECT_EQ(new_expiry, expiry);
    EXPECT_GE(new_next_update, now + 300);

    // Second test: if the expiration is behind us, fetching the key should trigger
    // a deletion of the key cache.
    ASSERT_TRUE(store_public_keys(demo_invalid_url, demo_scitokens2, now - 600, now - 600));

    rv = scitoken_deserialize_v2(token_str.c_str(), token_read, nullptr, nullptr);

    ASSERT_FALSE(get_public_keys_from_db(demo_invalid_url, new_expiry, new_next_update));
}

TEST_F(KeycacheTest, RefreshTest) {
    char *err_msg;
    auto rv = keycache_refresh_jwks(demo_scitokens_url.c_str(), &err_msg);
    ASSERT_TRUE(rv == 0);

    char *output_jwks;
    rv = keycache_get_cached_jwks(demo_scitokens_url.c_str(), &output_jwks, &err_msg);
    ASSERT_TRUE(rv == 0);
    ASSERT_TRUE(output_jwks != nullptr);
    std::string output_jwks_str(output_jwks);
    free(output_jwks);

    EXPECT_EQ(demo_scitokens, output_jwks_str);
}


TEST_F(KeycacheTest, RefreshInvalid)
{
    char *err_msg, *jwks;
    auto rv = keycache_refresh_jwks("https://demo.scitokens.org/invalid", &err_msg);
    ASSERT_FALSE(rv == 0);

    rv = keycache_get_cached_jwks("https://demo.scitokens.org/invalid", &jwks, &err_msg);
    ASSERT_TRUE(rv == 0);
    ASSERT_TRUE(jwks != nullptr);
    std::string jwks_str(jwks);
    free(jwks);

    EXPECT_EQ(jwks_str, "{\"keys\": []}");
}


TEST_F(KeycacheTest, GetInvalid)
{
    char *err_msg, *jwks;
    auto rv = keycache_get_cached_jwks("https://demo.scitokens.org/unknown", &jwks, &err_msg);
    ASSERT_TRUE(rv == 0);
    ASSERT_TRUE(jwks != nullptr);
    std::string jwks_str(jwks);
    free(jwks);
}


TEST_F(KeycacheTest, GetTest) {
    char *err_msg, *jwks;
    auto rv = keycache_get_cached_jwks(demo_scitokens_url.c_str(), &jwks, &err_msg);
    ASSERT_TRUE(rv == 0);
    ASSERT_TRUE(jwks != nullptr);
    std::string jwks_str(jwks);
    free(jwks);

    EXPECT_EQ(demo_scitokens, jwks_str);
}


TEST_F(KeycacheTest, SetGetTest) {
    char *err_msg;
    auto rv = keycache_set_jwks(demo_scitokens_url.c_str(), demo_scitokens2.c_str(), &err_msg);
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

TEST_F(SerializeTest, EnforcerTest) {
    /*
    * Test that the enforcer works and returns an err_msg
    */
    char *err_msg = nullptr;

    auto rv = scitoken_set_claim_string(m_token.get(), "aud",
                "https://demo.scitokens.org/", &err_msg);
    ASSERT_TRUE(rv == 0);

    auto enforcer = enforcer_create("https://demo.scitokens.org/gtest", &m_audiences_array[0], &err_msg);
    ASSERT_TRUE(enforcer != nullptr);
    
    Acl acl;
    acl.authz = "read";
    acl.resource = "/stuff";

    rv = scitoken_set_claim_string(m_token.get(), "scope",
                "read:/blah", &err_msg);
    ASSERT_TRUE(rv == 0);

    rv = scitoken_set_claim_string(m_token.get(), "ver",
                "scitoken:2.0", &err_msg);
    ASSERT_TRUE(rv == 0);

    char *token_value = nullptr;
    rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0);
    std::unique_ptr<char, decltype(&free)> token_value_ptr(token_value, free);

    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr, &err_msg);
    ASSERT_TRUE(rv == 0);

    rv = enforcer_test(enforcer, m_read_token.get(), &acl, &err_msg);
    ASSERT_STREQ(err_msg, "token verification failed: 'scope' claim verification failed.");
    ASSERT_TRUE(rv == -1) << err_msg;

}

TEST_F(SerializeTest, EnforcerScopeTest) {
    char *err_msg = nullptr;

    auto rv = scitoken_set_claim_string(m_token.get(), "aud",
                "https://demo.scitokens.org/", &err_msg);
    ASSERT_TRUE(rv == 0);

    auto enforcer = enforcer_create("https://demo.scitokens.org/gtest", &m_audiences_array[0], &err_msg);
    ASSERT_TRUE(enforcer != nullptr);

    scitoken_set_serialize_profile(m_token.get(), SciTokenProfile::WLCG_1_0);
    
    rv = scitoken_set_claim_string(m_token.get(), "scope",
                "storage.modify:/ storage.read:/ openid offline_access", &err_msg);
    ASSERT_TRUE(rv == 0);

    char *token_value = nullptr;
    rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0);

    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr, &err_msg);
    ASSERT_TRUE(rv == 0);

    Acl *acls;
    enforcer_generate_acls(enforcer, m_read_token.get(), &acls, &err_msg);
    ASSERT_TRUE(acls != nullptr);
    int idx = 0;
    bool found_read = false;
    bool found_write = false;
    while (acls[idx].resource && acls[idx++].authz) {
        auto resource = acls[idx-1].resource;
        auto authz = acls[idx-1].authz;
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

TEST_F(SerializeTest, ExplicitTime) {
    time_t now = time(NULL);
    char *err_msg;

    scitoken_set_serialize_profile(m_token.get(), SciTokenProfile::WLCG_1_0);
    auto rv = scitoken_set_claim_string(m_token.get(), "scope",
                "storage.read:/", &err_msg);

    char *token_value = nullptr;
    rv = scitoken_serialize(m_token.get(), &token_value, &err_msg);
    ASSERT_TRUE(rv == 0);

    rv = scitoken_deserialize_v2(token_value, m_read_token.get(), nullptr, &err_msg);
    ASSERT_TRUE(rv == 0);

    auto enforcer = enforcer_create("https://demo.scitokens.org/gtest", &m_audiences_array[0], &err_msg);
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

}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
