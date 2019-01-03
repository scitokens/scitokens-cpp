
#include <memory>
#include <sstream>

#include <curl/curl.h>
#include <jwt-cpp/base.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/picojson.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "scitokens_internal.h"

using namespace scitokens;

namespace {

struct CurlRaii {

CurlRaii() {curl_global_init(CURL_GLOBAL_DEFAULT);}

~CurlRaii() {curl_global_cleanup();}
};

CurlRaii myCurl;


class SimpleCurlGet {

    int m_maxbytes;
    std::vector<char> m_data;
    size_t m_len{0};

public:
    SimpleCurlGet(int maxbytes=1024*1024)
      : m_maxbytes(maxbytes)
    {}

    int perform(const std::string &url) {
        m_len = 0;

        auto curl = curl_easy_init();
        if (!curl) {
            CurlException("Failed to create a new curl handle.");
        }

        if (m_maxbytes > 0) {
            m_data.reserve(std::min(m_maxbytes, 8*1024));
        }

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, this);

        auto res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            curl_easy_cleanup(curl);
            throw CurlException(curl_easy_strerror(res));
        }
        long status_code;
        res = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status_code);
        if (res != CURLE_OK) {
            curl_easy_cleanup(curl);
            throw CurlException(curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl);
        return status_code;
    }

    void get_data(char *&buffer, size_t &len) {
        buffer = &m_data[0];
        len = m_len;
    }

private:
    static size_t write_data(void *buffer, size_t size, size_t nmemb, void *userp) {
        SimpleCurlGet *myself = reinterpret_cast<SimpleCurlGet*>(userp);
        size_t new_data = size * nmemb;
        size_t new_length = myself->m_len + new_data;

        if (myself->m_maxbytes > 0 && (new_length > static_cast<size_t>(myself->m_maxbytes))) {
            return 0;
        }
        myself->m_data.reserve(new_length);
        memcpy(&(myself->m_data[0]), buffer, new_data);
        myself->m_len = new_length;
        return new_data;
    }
};


void
parse_url(const std::string &url, std::string &schema, std::string &netloc,
                std::string &path)
{
    const std::string prot_end("://");
    std::string::const_iterator prot_iter =
        std::search(url.begin(), url.end(),
                    prot_end.begin(), prot_end.end());
    schema.reserve(distance(url.begin(), prot_iter));
    std::transform(url.begin(), prot_iter,
                  std::back_inserter(schema),
                  std::ptr_fun<int,int>(tolower));
    if (prot_iter == url.end() )
    {
        throw InvalidIssuerException("Issuer URL missing hostname.");
    }
    std::advance(prot_iter, prot_end.length());
    std::string::const_iterator path_iter = std::find(prot_iter, url.end(), '/');
    netloc.reserve(std::distance(prot_iter, path_iter));
    std::transform(prot_iter, path_iter,
                   std::back_inserter(netloc),
                   std::ptr_fun<int,int>(tolower));
    std::string::const_iterator query_iter = std::find(path_iter, url.end(), '?');
    path.assign(path_iter, query_iter);
}


void
get_metadata_endpoint(const std::string &issuer, std::string &openid_metadata, std::string &oauth_metadata)
{
    std::string schema, netloc, path;
    parse_url(issuer, schema, netloc, path);
    if (schema != "https")
    {
        throw InvalidIssuerException("Issuer URL must be HTTPS");
    }
    if (path == "/")
    {
        path = "";
    }
    std::string new_path = "/.well-known/oauth-authorization-server" + path;
    oauth_metadata = "https://" + netloc + new_path;

    openid_metadata = issuer + "/.well-known/openid-configuration";
}

/*
  "keys": [
    {
      "alg": "RS256", 
      "e": "AQAB", 
      "kid": "key-rs256", 
      "kty": "RSA", 
      "n": "uGDGTLXnqh3mfopjys6sFUBvFl3F4Qt6NEYphq_u_aBhtN1X9NEyb78uB_I1KjciJNGLIQU0ECsJiFx6qV1hR9xE1dPyrS3bU92AVtnBrvzUtTU-aUZAmZQiuAC_rC0-z_TOQr6qJkkUgZtxR9n9op55ZBpRfZD5dzhkW4Dm146vfTKt0D4cIMoMNJS5xQx9nibeB4E8hryZDW_fPeD0XZDcpByNyP0jFDYkxdUtQFvyRpz4WMZ4ejUfvW3gf4LRAfGZJtMnsZ7ZW4RfoQbhiXKMfWeBEjQDiXh0r-KuZLykxhYJtpf7fTnPna753IzMgRMmW3F69iQn2LQN3LoSMw==", 
      "use": "sig"
    }, 
    {
      "alg": "ES256", 
      "kid": "key-es356", 
      "kty": "EC", 
      "use": "sig", 
      "x": "ncSCrGTBTXXOhNiAOTwNdPjwRz1hVY4saDNiHQK9Bh4=", 
      "y": "sCsFXvx7FAAklwq3CzRCBcghqZOFPB2dKUayS6LY_Lo="
    }
  ]
}
*/
picojson::value::object find_key_id(const picojson::value json, const std::string &kid) {
    if (!json.is<picojson::object>()) {
        throw JsonException("Top-level JSON is not an object.");
    }
    auto top_obj = json.get<picojson::object>();
    auto iter = top_obj.find("keys");
    if (iter == top_obj.end() || (!iter->second.is<picojson::array>())) {
        throw JsonException("Metadata resource is missing 'keys' array value");
    }
    auto keys_array = iter->second.get<picojson::array>();
    for (auto &key : keys_array) {
        if (!key.is<picojson::object>()) {continue;}

        auto key_obj = key.get<picojson::object>();
        iter = key_obj.find("kid");
        if (iter == key_obj.end() || (!iter->second.is<std::string>())) {continue;}

        std::string cur_kid = iter->second.get<std::string>();

        if (cur_kid == kid) {return key_obj;}
    }
    throw JsonException("Key ID is not published by the issuer.");
}


struct local_base64url : public jwt::alphabet::base64url {
    static const std::string &fill() {
        static std::string fill = "=";
        return fill;
    }
};


std::string
es256_from_coords(const std::string &x_str, const std::string &y_str) {
    auto x_decode = jwt::base::decode<local_base64url>(x_str);
    auto y_decode = jwt::base::decode<local_base64url>(y_str);

    std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> ec(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1), EC_KEY_free);
    if (!ec.get()) {
        throw UnsupportedKeyException("OpenSSL does not support the P-256 curve");
    }

    EC_GROUP *params = (EC_GROUP *)EC_KEY_get0_group(ec.get());
    if (!params) {
        throw UnsupportedKeyException("Unable to get OpenSSL EC group");
    }

    std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> Q_point(EC_POINT_new(params), EC_POINT_free);
    if (!Q_point.get()) {
        throw UnsupportedKeyException("Unable to allocate new EC point");
    }
    std::unique_ptr<BIGNUM, decltype(&BN_free)> x_bignum(BN_bin2bn(reinterpret_cast<const unsigned char *>(x_decode.c_str()), x_decode.size(), nullptr), BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> y_bignum(BN_bin2bn(reinterpret_cast<const unsigned char *>(y_decode.c_str()), y_decode.size(), nullptr), BN_free);
    if (EC_POINT_set_affine_coordinates_GFp(params, Q_point.get(), x_bignum.get(), y_bignum.get(), NULL) != 1) {
        throw UnsupportedKeyException("Invalid elliptic curve point in key");
    }

    if (EC_KEY_set_public_key(ec.get(), Q_point.get()) != 1) {
        throw UnsupportedKeyException("Unable to set the EC public key");
    }

    std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
    if (PEM_write_bio_EC_PUBKEY(pubkey_bio.get(), ec.get()) == 0) {
        throw UnsupportedKeyException("Failed to serialize EC public key");
    }

    char *mem_data;
    size_t mem_len = BIO_get_mem_data(pubkey_bio.get(), &mem_data);
    std::string result = std::string(mem_data, mem_len);
    return result;
}


std::string
rs256_from_coords(const std::string &e_str, const std::string &n_str) {
    auto e_decode = jwt::base::decode<local_base64url>(e_str);
    auto n_decode = jwt::base::decode<local_base64url>(n_str);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> e_bignum(BN_bin2bn(reinterpret_cast<const unsigned char *>(e_decode.c_str()), e_decode.size(), nullptr), BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> n_bignum(BN_bin2bn(reinterpret_cast<const unsigned char *>(n_decode.c_str()), n_decode.size(), nullptr), BN_free);

    std::unique_ptr<RSA, decltype(&RSA_free)> rsa(RSA_new(), RSA_free);
    rsa->e = e_bignum.get();
    rsa->n = n_bignum.get();
    rsa->d = nullptr;
    e_bignum.release();
    n_bignum.release();

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(EVP_PKEY_new(), EVP_PKEY_free);
    if (EVP_PKEY_set1_RSA(pkey.get(), rsa.get()) != 1) {
        throw UnsupportedKeyException("Failed to set the public key");
    }

    std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(BIO_new(BIO_s_mem()), BIO_free_all);
    if (PEM_write_bio_PUBKEY(pubkey_bio.get(), pkey.get()) == 0) {
        throw UnsupportedKeyException("Failed to serialize RSA public key");
    }

    char *mem_data;
    size_t mem_len = BIO_get_mem_data(pubkey_bio.get(), &mem_data);
    std::string result = std::string(mem_data, mem_len);
    return result;
}


/**
 * Normalize path: collapse etc.
 * >>> normalize_path('/a/b///c')
 * '/a/b/c'
 */
std::string
normalize_absolute_path(const std::string &path) {
    if ((path == "//") || (path == "/") || (path == "")) {
        return "/";
    }
    std::vector<std::string> path_components;
    auto path_iter = path.begin();
    while (path_iter != path.end()) {
        while (*path_iter == '/') {path_iter++;}
        auto next_path_iter = std::find(path_iter, path.end(), '/');
        std::string component;
        component.reserve(std::distance(path_iter, next_path_iter));
        component.assign(path_iter, next_path_iter);
        path_components.push_back(component);    
        path_iter = next_path_iter;
    }
    std::vector<std::string> path_components_filtered;
    path_components_filtered.reserve(path_components.size());
    for (const auto &component : path_components) {
        if (component == "..") {
            path_components_filtered.pop_back();
        } else if (!component.empty() && component != ".") {
            path_components_filtered.push_back(component);
        }
    }
    std::stringstream ss;
    for (const auto &component : path_components_filtered) {
        ss << "/" << component;
    }
    std::string result = ss.str();
    return result.empty() ? "/" : result;
}


int empty_validator(const char *, char **) {
    return 0;
}


}


void
SciToken::deserialize(const std::string &data, const std::vector<std::string> allowed_issuers) {
    m_decoded.reset(new jwt::decoded_jwt(data));

    scitokens::Validator val;
    val.add_allowed_issuers(allowed_issuers);
    val.set_validate_all_claims_scitokens_1(false);
    val.verify(*m_decoded);
}


void
Validator::get_public_keys_from_web(const std::string &issuer, picojson::value &keys, int64_t &next_update, int64_t &expires)
{
    std::string openid_metadata, oauth_metadata;
    get_metadata_endpoint(issuer, openid_metadata, oauth_metadata);

    SimpleCurlGet cget;
    auto status_code = cget.perform(openid_metadata);

    if (status_code != 200) {
        status_code = cget.perform(oauth_metadata);
        if (status_code != 200) {
            throw CurlException("Failed to retrieve metadata provider information for issuer.");
        }
    }
    char *buffer;
    size_t len;
    cget.get_data(buffer, len);
    std::string metadata(buffer, len);
    picojson::value json_obj;
    auto err = picojson::parse(json_obj, metadata);
    if (!err.empty()) {
        throw JsonException(err);
    }
    if (!json_obj.is<picojson::object>()) {
        throw JsonException("Metadata resource contains improperly-formatted JSON.");
    }
    auto top_obj = json_obj.get<picojson::object>();
    auto iter = top_obj.find("jwks_uri");
    if (iter == top_obj.end() || (!iter->second.is<std::string>())) {
        throw JsonException("Metadata resource is missing 'jwks_uri' string value");
    }
    std::string jwks_uri = iter->second.get<std::string>();

    status_code = cget.perform(jwks_uri);
    if (status_code != 200) {
        throw CurlException("Failed to retrieve the issuer's key set");
    }

    cget.get_data(buffer, len);
    metadata = std::string(buffer, len);
    err = picojson::parse(json_obj, metadata);
    if (!err.empty()) {
        throw JsonException(err);
    }

    auto now = std::time(NULL);
    // TODO: take expiration time from the cache-control header in the response.

    keys = json_obj;

    next_update = now + 600;
    expires = now + 4*3600;
}

void
Validator::get_public_key_pem(const std::string &issuer, const std::string &kid, std::string &public_pem, std::string &algorithm) {

    picojson::value keys;
    int64_t next_update, expires;
    auto now = std::time(NULL);
    if (get_public_keys_from_db(issuer, now, keys, next_update)) {
        if (now > next_update) {
            try {
                get_public_keys_from_web(issuer, keys, next_update, expires);
                store_public_keys(issuer, keys, next_update, expires);
            } catch (std::runtime_error &) {
                // ignore the exception: we have a valid set of keys already/
            }
        }
    } else {
        get_public_keys_from_web(issuer, keys, next_update, expires);
        store_public_keys(issuer, keys, next_update, expires);
    }

    auto key_obj = find_key_id(keys, kid);
    
    auto iter = key_obj.find("alg");
    if (iter == key_obj.end() || (!iter->second.is<std::string>())) {
        throw JsonException("Key is missing algorithm name");
    }   
    auto alg = iter->second.get<std::string>();
    if (alg != "RS256" and alg != "ES256") {
        throw UnsupportedKeyException("Issuer is using an unsupported algorithm");
    }   
    std::string pem;

    if (alg == "ES256")
    {
        iter = key_obj.find("x");
        if (iter == key_obj.end() || (!iter->second.is<std::string>())) {
            throw JsonException("Elliptic curve is missing x-coordinate");
        }   
        auto x = iter->second.get<std::string>();
        iter = key_obj.find("y");
        if (iter == key_obj.end() || (!iter->second.is<std::string>())) {
            throw JsonException("Elliptic curve is missing y-coordinate");
        }   
        auto y = iter->second.get<std::string>();
        pem = es256_from_coords(x, y);
    } else {
        iter = key_obj.find("e");
        if (iter == key_obj.end() || (!iter->second.is<std::string>())) {
            throw JsonException("Public key is missing exponent");
        }   
        auto e = iter->second.get<std::string>();
        iter = key_obj.find("n");
        if (iter == key_obj.end() || (!iter->second.is<std::string>())) {
            throw JsonException("Public key is missing n-value");
        }   
        auto n = iter->second.get<std::string>();
        pem = rs256_from_coords(e, n);
    }   
    
    public_pem = pem;
    algorithm = alg;
}


bool
scitokens::Enforcer::scope_validator(const jwt::claim &claim, void *myself) {
    auto me = reinterpret_cast<scitokens::Enforcer*>(myself);
    if (claim.get_type() != jwt::claim::type::string) {
        return false;
    }
    std::string scope = claim.as_string();
    std::string requested_path = normalize_absolute_path(me->m_test_path);
    auto scope_iter = scope.begin();
    //std::cout << "Comparing scope " << scope << " against test accesses " << me->m_test_authz << ":" << requested_path << std::endl;
    while (scope_iter != scope.end()) {
        while (*scope_iter == ' ') {scope_iter++;}
        auto next_scope_iter = std::find(scope_iter, scope.end(), ' ');
        std::string full_authz;
        full_authz.reserve(std::distance(scope_iter, next_scope_iter));
        full_authz.assign(scope_iter, next_scope_iter);
        auto sep_iter = full_authz.find(':');
        std::string authz = full_authz.substr(0, sep_iter);
        std::string path;
        if (sep_iter == std::string::npos) {
            path = "/";
        } else {
            path = full_authz.substr((++sep_iter));
        }
        path = normalize_absolute_path(path);

        if (me->m_test_authz.empty()) {
            me->m_gen_acls.emplace_back(authz, path);
        } else if ((me->m_test_authz == authz) &&
                   (requested_path.substr(0, path.size()) == path)) {
            return true;
        }

        scope_iter = next_scope_iter;
    }
    return me->m_test_authz.empty();
}
