
#include <functional>
#include <memory>
#include <sstream>

#include <jwt-cpp/base.h>
#include <jwt-cpp/jwt.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <picojson/picojson.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/evp.h>
#include <openssl/param_build.h>
#endif
#define EC_NAME NID_X9_62_prime256v1

#include "scitokens_internal.h"

using namespace scitokens;

namespace {

struct CurlRaii {

    CurlRaii() { curl_global_init(CURL_GLOBAL_DEFAULT); }

    ~CurlRaii() { curl_global_cleanup(); }
};

CurlRaii myCurl;

} // namespace

namespace scitokens {

namespace internal {

SimpleCurlGet::GetStatus SimpleCurlGet::perform_start(const std::string &url) {
    m_len = 0;

    m_curl_multi.reset(curl_multi_init());
    if (!m_curl_multi) {
        throw CurlException("Failed to create a new curl async handle.");
    }
    m_curl.reset(curl_easy_init());
    if (!m_curl) {
        throw CurlException("Failed to create a new curl handle.");
    }

    if (m_maxbytes > 0) {
        size_t new_size = std::min(m_maxbytes, 8 * 1024);
        if (m_data.size() < new_size) {
            m_data.resize(new_size);
        }
    }

    long timeout = m_timeout > 120 ? 120 : m_timeout;

    CURLcode rv = curl_easy_setopt(m_curl.get(), CURLOPT_URL, url.c_str());
    if (rv != CURLE_OK) {
        throw CurlException("Failed to set CURLOPT_URL.");
    }
    rv = curl_easy_setopt(m_curl.get(), CURLOPT_WRITEFUNCTION, &write_data);
    if (rv != CURLE_OK) {
        throw CurlException("Failed to set CURLOPT_WRITEFUNCTION.");
    }
    rv = curl_easy_setopt(m_curl.get(), CURLOPT_WRITEDATA, this);
    if (rv != CURLE_OK) {
        throw CurlException("Failed to set CURLOPT_WRITEDATA.");
    }
    rv = curl_easy_setopt(m_curl.get(), CURLOPT_TIMEOUT, timeout);
    if (rv != CURLE_OK) {
        throw CurlException("Failed to set CURLOPT_TIMEOUT.");
    }

    {
        auto mres = curl_multi_add_handle(m_curl_multi.get(), m_curl.get());
        if (mres) {
            throw CurlException("Failed to add curl handle to async object");
        }
    }

    return perform_continue();
}

SimpleCurlGet::GetStatus SimpleCurlGet::perform_continue() {
    int still_running;
    auto resm = curl_multi_perform(m_curl_multi.get(), &still_running);
    if (!resm && still_running) {
        resm = curl_multi_timeout(m_curl_multi.get(), &m_timeout_ms);
        if (resm) {
            throw CurlException(curl_multi_strerror(resm));
        }
        if (m_timeout_ms < 0) {
            m_timeout_ms = 100;
        }
        FD_ZERO(m_read_fd_set);
        FD_ZERO(m_write_fd_set);
        FD_ZERO(m_exc_fd_set);
        resm = curl_multi_fdset(m_curl_multi.get(), m_read_fd_set,
                                m_write_fd_set, m_exc_fd_set, &m_max_fd);
        if (resm) {
            throw CurlException(curl_multi_strerror(resm));
        }
        if (m_max_fd < 0)
            m_timeout_ms = 100;
        return GetStatus();
    }
    if (resm) {
        throw CurlException(curl_multi_strerror(resm));
    }

    CURLMsg *msg;
    CURLcode res = static_cast<CURLcode>(-1);
    do {
        int msgq = 0;
        msg = curl_multi_info_read(m_curl_multi.get(), &msgq);
        if (msg && (msg->msg == CURLMSG_DONE)) {
            CURL *easy_handle = msg->easy_handle;
            res = msg->data.result;
            curl_multi_remove_handle(m_curl_multi.get(), easy_handle);
        }
    } while (msg);
    if (res) {
        throw CurlException(curl_easy_strerror(res));
    }

    long status_code;
    res = curl_easy_getinfo(m_curl.get(), CURLINFO_RESPONSE_CODE, &status_code);
    if (res != CURLE_OK) {
        throw CurlException(curl_easy_strerror(res));
    }
    GetStatus status;
    status.m_done = true;
    status.m_status_code = status_code;
    return status;
}

int SimpleCurlGet::perform(const std::string &url, time_t expiry_time) {
    GetStatus status = perform_start(url);
    while (!status.m_done) {
        auto now = time(NULL);
        int timeout_ms = 1000 * (expiry_time - now);
        if (timeout_ms < 0)
            timeout_ms = 0;
        if (m_timeout_ms < timeout_ms)
            timeout_ms = m_timeout_ms;
        struct timeval timeout;
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        // Return value of select is ignored; curl will take care of it.
        select(m_max_fd + 1, m_read_fd_set, m_write_fd_set, m_exc_fd_set,
               &timeout);
        status = perform_continue();
    }
    return status.m_status_code;
}

void SimpleCurlGet::get_data(char *&buffer, size_t &len) {
    buffer = &m_data[0];
    len = m_len;
}

size_t SimpleCurlGet::write_data(void *buffer, size_t size, size_t nmemb,
                                 void *userp) {
    SimpleCurlGet *myself = reinterpret_cast<SimpleCurlGet *>(userp);
    size_t new_data = size * nmemb;
    size_t new_length = myself->m_len + new_data;

    if (myself->m_maxbytes > 0 &&
        (new_length > static_cast<size_t>(myself->m_maxbytes))) {
        return 0;
    }
    if (myself->m_data.size() < new_length) {
        myself->m_data.resize(new_length);
    }
    memcpy(&(myself->m_data[myself->m_len]), buffer, new_data);
    myself->m_len = new_length;
    return new_data;
}

} // namespace internal

} // namespace scitokens

namespace {

void parse_url(const std::string &url, std::string &schema, std::string &netloc,
               std::string &path) {
    const std::string prot_end("://");
    std::string::const_iterator prot_iter =
        std::search(url.begin(), url.end(), prot_end.begin(), prot_end.end());
    schema.reserve(distance(url.begin(), prot_iter));
    std::transform(url.begin(), prot_iter, std::back_inserter(schema),
                   std::function<int(int)>(tolower));
    if (prot_iter == url.end()) {
        throw InvalidIssuerException("Issuer URL missing hostname.");
    }
    std::advance(prot_iter, prot_end.length());
    std::string::const_iterator path_iter =
        std::find(prot_iter, url.end(), '/');
    netloc.reserve(std::distance(prot_iter, path_iter));
    std::transform(prot_iter, path_iter, std::back_inserter(netloc),
                   std::function<int(int)>(tolower));
    std::string::const_iterator query_iter =
        std::find(path_iter, url.end(), '?');
    path.assign(path_iter, query_iter);
}

void get_metadata_endpoint(const std::string &issuer,
                           std::string &openid_metadata,
                           std::string &oauth_metadata) {
    std::string schema, netloc, path;
    parse_url(issuer, schema, netloc, path);
    if (schema != "https") {
        throw InvalidIssuerException("Issuer URL must be HTTPS");
    }
    if (path == "/") {
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
      "n":
"uGDGTLXnqh3mfopjys6sFUBvFl3F4Qt6NEYphq_u_aBhtN1X9NEyb78uB_I1KjciJNGLIQU0ECsJiFx6qV1hR9xE1dPyrS3bU92AVtnBrvzUtTU-aUZAmZQiuAC_rC0-z_TOQr6qJkkUgZtxR9n9op55ZBpRfZD5dzhkW4Dm146vfTKt0D4cIMoMNJS5xQx9nibeB4E8hryZDW_fPeD0XZDcpByNyP0jFDYkxdUtQFvyRpz4WMZ4ejUfvW3gf4LRAfGZJtMnsZ7ZW4RfoQbhiXKMfWeBEjQDiXh0r-KuZLykxhYJtpf7fTnPna753IzMgRMmW3F69iQn2LQN3LoSMw==",
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
picojson::value::object find_key_id(const picojson::value json,
                                    const std::string &kid) {
    if (!json.is<picojson::object>()) {
        throw JsonException("Top-level JSON is not an object.");
    }
    auto top_obj = json.get<picojson::object>();
    auto iter = top_obj.find("keys");
    if (iter == top_obj.end() || (!iter->second.is<picojson::array>())) {
        throw JsonException("Metadata resource is missing 'keys' array value");
    }
    auto keys_array = iter->second.get<picojson::array>();
    if (kid.empty()) {
        if (keys_array.size() != 1) {
            throw JsonException("Key ID empty but multiple keys published.");
        }
        auto &key = keys_array.at(0);
        return key.get<picojson::object>();
    } else {
        for (auto &key : keys_array) {
            if (!key.is<picojson::object>()) {
                continue;
            }

            auto key_obj = key.get<picojson::object>();
            iter = key_obj.find("kid");
            if (iter == key_obj.end() || (!iter->second.is<std::string>())) {
                continue;
            }

            std::string cur_kid = iter->second.get<std::string>();

            if (cur_kid == kid) {
                return key_obj;
            }
        }
        throw JsonException("Key ID is not published by the issuer.");
    }
}

struct local_base64url : public jwt::alphabet::base64url {
    static const std::string &fill() {
        static std::string fill = "=";
        return fill;
    }
};

// Assuming a padding, decode
std::string b64url_decode_nopadding(const std::string &input) {
    std::string result = input;
    switch (result.size() % 4) {
    case 1:
        result += "="; // fallthrough
    case 2:
        result += "="; // fallthrough
    case 3:
        result += "="; // fallthrough
    default:
        break;
    }
    return jwt::base::decode<local_base64url>(result);
}

// Base64-encode without padding.
std::string b64url_encode_nopadding(const std::string &input) {
    std::string result = jwt::base::encode<local_base64url>(input);
    auto pos = result.find("=");
    return result.substr(0, pos);
}

std::string es256_from_coords(const std::string &x_str,
                              const std::string &y_str) {
    auto x_decode = b64url_decode_nopadding(x_str);
    auto y_decode = b64url_decode_nopadding(y_str);
    std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(
        BIO_new(BIO_s_mem()), BIO_free_all);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> x_bignum(
        BN_bin2bn(reinterpret_cast<const unsigned char *>(x_decode.c_str()),
                  x_decode.size(), nullptr),
        BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> y_bignum(
        BN_bin2bn(reinterpret_cast<const unsigned char *>(y_decode.c_str()),
                  y_decode.size(), nullptr),
        BN_free);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    unsigned char *buf;
    OSSL_PARAM *params;
    std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> ec_group(
        EC_GROUP_new_by_curve_name(EC_NAME), EC_GROUP_free);
    if (!ec_group.get()) {
        throw UnsupportedKeyException("Unable to get OpenSSL EC group");
    }

    std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> Q_point(
        EC_POINT_new(ec_group.get()), EC_POINT_free);
    if (!Q_point.get()) {
        throw UnsupportedKeyException("Unable to allocate new EC point");
    }

    if (!EC_POINT_set_affine_coordinates(ec_group.get(), Q_point.get(),
                                         x_bignum.get(), y_bignum.get(),
                                         NULL)) {
        throw UnsupportedKeyException("Invalid elliptic curve point in key");
    }

    size_t out_len =
        EC_POINT_point2buf(ec_group.get(), Q_point.get(),
                           POINT_CONVERSION_UNCOMPRESSED, &buf, NULL);
    if (out_len == 0) {
        throw UnsupportedKeyException(
            "Failed to convert EC point to octet base buffer");
    }

    std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> param_build(
        OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
    if (!param_build.get() ||
        !OSSL_PARAM_BLD_push_utf8_string(param_build.get(), "group",
                                         "prime256v1", 0) ||
        !OSSL_PARAM_BLD_push_octet_string(param_build.get(), "pub", buf,
                                          out_len) ||
        (params = OSSL_PARAM_BLD_to_param(param_build.get())) == NULL) {
        throw UnsupportedKeyException(
            "Failed to build EC public key parameters");
    }

    EVP_PKEY *pkey = NULL;
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ec_ctx(
        EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL), EVP_PKEY_CTX_free);
    if (!ec_ctx.get()) {
        throw UnsupportedKeyException("Failed to set EC PKEY context");
    }

    if (EVP_PKEY_fromdata_init(ec_ctx.get()) <= 0 ||
        EVP_PKEY_fromdata(ec_ctx.get(), &pkey, EVP_PKEY_PUBLIC_KEY, params) <=
            0 ||
        pkey == NULL) {
        throw UnsupportedKeyException("Failed to set the EC public key");
    }

    if (PEM_write_bio_PUBKEY(pubkey_bio.get(), pkey) == 0) {
        throw UnsupportedKeyException("Failed to serialize EC public key");
    }
    EVP_PKEY_free(pkey);
    OSSL_PARAM_free(params);
    OPENSSL_free(buf);
#else
    std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> ec(
        EC_KEY_new_by_curve_name(EC_NAME), EC_KEY_free);
    if (!ec.get()) {
        throw UnsupportedKeyException(
            "OpenSSL does not support the P-256 curve");
    }

    EC_GROUP *params = (EC_GROUP *)EC_KEY_get0_group(ec.get());
    if (!params) {
        throw UnsupportedKeyException("Unable to get OpenSSL EC group");
    }

    std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> Q_point(
        EC_POINT_new(params), EC_POINT_free);
    if (!Q_point.get()) {
        throw UnsupportedKeyException("Unable to allocate new EC point");
    }

    if (EC_POINT_set_affine_coordinates_GFp(
            params, Q_point.get(), x_bignum.get(), y_bignum.get(), NULL) != 1) {
        throw UnsupportedKeyException("Invalid elliptic curve point in key");
    }

    if (EC_KEY_set_public_key(ec.get(), Q_point.get()) != 1) {
        throw UnsupportedKeyException("Unable to set the EC public key");
    }

    if (PEM_write_bio_EC_PUBKEY(pubkey_bio.get(), ec.get()) == 0) {
        throw UnsupportedKeyException("Failed to serialize EC public key");
    }
#endif

    char *mem_data;
    size_t mem_len = BIO_get_mem_data(pubkey_bio.get(), &mem_data);
    std::string result = std::string(mem_data, mem_len);
    return result;
}

std::string rs256_from_coords(const std::string &e_str,
                              const std::string &n_str) {
    auto e_decode = b64url_decode_nopadding(e_str);
    auto n_decode = b64url_decode_nopadding(n_str);
    std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(
        BIO_new(BIO_s_mem()), BIO_free_all);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> e_bignum(
        BN_bin2bn(reinterpret_cast<const unsigned char *>(e_decode.c_str()),
                  e_decode.size(), nullptr),
        BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> n_bignum(
        BN_bin2bn(reinterpret_cast<const unsigned char *>(n_decode.c_str()),
                  n_decode.size(), nullptr),
        BN_free);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PARAM *params;
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> rsa_ctx(
        EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL), EVP_PKEY_CTX_free);
    if (!rsa_ctx.get()) {
        throw UnsupportedKeyException("Failed to set RSA PKEY context");
    }

    std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)> param_build(
        OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
    if (!param_build.get() ||
        !OSSL_PARAM_BLD_push_BN_pad(param_build.get(), "e", e_bignum.get(),
                                    BN_num_bytes(e_bignum.get())) ||
        !OSSL_PARAM_BLD_push_BN_pad(param_build.get(), "n", n_bignum.get(),
                                    BN_num_bytes(n_bignum.get())) ||
        (params = OSSL_PARAM_BLD_to_param(param_build.get())) == NULL) {
        throw UnsupportedKeyException(
            "Failed to build RSA public key parameters");
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_fromdata_init(rsa_ctx.get()) <= 0 ||
        EVP_PKEY_fromdata(rsa_ctx.get(), &pkey, EVP_PKEY_PUBLIC_KEY, params) <=
            0 ||
        pkey == NULL) {
        throw UnsupportedKeyException("Failed to set the RSA public key");
    }

    if (PEM_write_bio_PUBKEY(pubkey_bio.get(), pkey) == 0) {
        throw UnsupportedKeyException("Failed to serialize RSA public key");
    }
    EVP_PKEY_free(pkey);
    OSSL_PARAM_free(params);
#else
    std::unique_ptr<RSA, decltype(&RSA_free)> rsa(RSA_new(), RSA_free);
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
    rsa->e = e_bignum.get();
    rsa->n = n_bignum.get();
    rsa->d = nullptr;
#else
    RSA_set0_key(rsa.get(), n_bignum.get(), e_bignum.get(), nullptr);
#endif
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(EVP_PKEY_new(),
                                                             EVP_PKEY_free);
    if (EVP_PKEY_set1_RSA(pkey.get(), rsa.get()) != 1) {
        throw UnsupportedKeyException("Failed to set the public key");
    }

    if (PEM_write_bio_PUBKEY(pubkey_bio.get(), pkey.get()) == 0) {
        throw UnsupportedKeyException("Failed to serialize RSA public key");
    }
#endif
    e_bignum.release();
    n_bignum.release();

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
std::string normalize_absolute_path(const std::string &path) {
    if ((path == "//") || (path == "/") || (path == "")) {
        return "/";
    }
    std::vector<std::string> path_components;
    auto path_iter = path.begin();
    while (path_iter != path.end()) {
        while (*path_iter == '/') {
            path_iter++;
        }
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

void get_default_expiry_time(int &next_update_delta, int &expiry_delta) {
    next_update_delta = 600;
    expiry_delta = 4 * 24 * 3600;
}

} // namespace

void SciToken::deserialize(const std::string &data,
                           const std::vector<std::string> allowed_issuers) {
    m_decoded.reset(new jwt::decoded_jwt<jwt::traits::kazuho_picojson>(data));

    scitokens::Validator val;
    val.add_allowed_issuers(allowed_issuers);
    val.set_validate_all_claims_scitokens_1(false);
    val.set_validate_profile(m_deserialize_profile);
    val.verify(*m_decoded);

    // Set all the claims
    m_claims = m_decoded->get_payload_claims();

    // Copy over the profile
    m_profile = val.get_profile();
}

std::unique_ptr<SciTokenAsyncStatus>
SciToken::deserialize_start(const std::string &data,
                            const std::vector<std::string> allowed_issuers) {
    m_decoded.reset(new jwt::decoded_jwt<jwt::traits::kazuho_picojson>(data));

    std::unique_ptr<SciTokenAsyncStatus> status(new SciTokenAsyncStatus());
    status->m_validator.reset(new scitokens::Validator());
    status->m_validator->add_allowed_issuers(allowed_issuers);
    status->m_validator->set_validate_all_claims_scitokens_1(false);
    status->m_validator->set_validate_profile(m_deserialize_profile);

    status->m_status = status->m_validator->verify_async(*m_decoded);

    return deserialize_continue(std::move(status));
}

std::unique_ptr<SciTokenAsyncStatus>
SciToken::deserialize_continue(std::unique_ptr<SciTokenAsyncStatus> status) {

    // Check if the status is completed (verification is complete)
    if (status->m_status) {
        // Set all the claims
        m_claims = m_decoded->get_payload_claims();

        // Copy over the profile
        m_profile = status->m_validator->get_profile();
    } else {
        status->m_status = status->m_validator->verify_async_continue(
            std::move(status->m_status));
    }

    return std::move(status);
}

std::unique_ptr<AsyncStatus>
Validator::get_public_keys_from_web(const std::string &issuer,
                                    unsigned timeout) {
    std::string openid_metadata, oauth_metadata;
    get_metadata_endpoint(issuer, openid_metadata, oauth_metadata);

    std::unique_ptr<AsyncStatus> status(new AsyncStatus());
    status->m_oauth_metadata_url = oauth_metadata;
    status->m_cget.reset(new internal::SimpleCurlGet(1024 * 1024, timeout));
    auto cget_status = status->m_cget->perform_start(openid_metadata);
    status->m_continue_fetch = true;
    if (!cget_status.m_done) {
        return std::move(status);
    }
    return get_public_keys_from_web_continue(std::move(status));
}

std::unique_ptr<AsyncStatus> Validator::get_public_keys_from_web_continue(
    std::unique_ptr<AsyncStatus> status) {
    char *buffer;
    size_t len;

    switch (status->m_state) {

    case AsyncStatus::DOWNLOAD_METADATA: {
        auto cget_status = status->m_cget->perform_continue();
        if (!cget_status.m_done) {
            return std::move(status);
        }
        if (cget_status.m_status_code != 200) {
            if (status->m_oauth_fallback) {
                throw CurlException("Failed to retrieve metadata provider "
                                    "information for issuer.");
            } else {
                status->m_oauth_fallback = true;
                status->m_cget.reset(new internal::SimpleCurlGet());
                cget_status =
                    status->m_cget->perform_start(status->m_oauth_metadata_url);
                if (!cget_status.m_done) {
                    return status;
                }
                return get_public_keys_from_web_continue(std::move(status));
            }
        }
        status->m_cget->get_data(buffer, len);
        std::string metadata(buffer, len);
        picojson::value json_obj;
        auto err = picojson::parse(json_obj, metadata);
        if (!err.empty()) {
            throw JsonException(err);
        }
        if (!json_obj.is<picojson::object>()) {
            throw JsonException(
                "Metadata resource contains improperly-formatted JSON.");
        }
        auto top_obj = json_obj.get<picojson::object>();
        auto iter = top_obj.find("jwks_uri");
        if (iter == top_obj.end() || (!iter->second.is<std::string>())) {
            throw JsonException(
                "Metadata resource is missing 'jwks_uri' string value");
        }
        auto jwks_uri = iter->second.get<std::string>();
        status->m_has_metadata = true;
        status->m_state = AsyncStatus::DOWNLOAD_PUBLIC_KEY;
        status->m_cget.reset(new internal::SimpleCurlGet());
        status->m_cget->perform_start(jwks_uri);
        // This should also fall through the next state
    }

    case AsyncStatus::DOWNLOAD_PUBLIC_KEY: {
        auto cget_status = status->m_cget->perform_continue();
        if (!cget_status.m_done) {
            return std::move(status);
        }
        if (cget_status.m_status_code != 200) {
            throw CurlException("Failed to retrieve the issuer's key set");
        }

        status->m_cget->get_data(buffer, len);
        auto metadata = std::string(buffer, len);
        picojson::value json_obj;
        auto err = picojson::parse(json_obj, metadata);
        status->m_cget.reset();
        if (!err.empty()) {
            throw JsonException(err);
        }

        auto now = std::time(NULL);
        // TODO: take expiration time from the cache-control header in the
        // response.

        int next_update_delta, expiry_delta;
        get_default_expiry_time(next_update_delta, expiry_delta);
        status->m_next_update = now + next_update_delta;
        status->m_expires = now + expiry_delta;
        status->m_keys = json_obj;
        status->m_continue_fetch = false;
        status->m_done = true;
        status->m_state = AsyncStatus::DONE;
    }
    case AsyncStatus::DONE:
        status->m_done = true;

    } // Switch
    return std::move(status);
}

std::string Validator::get_jwks(const std::string &issuer) {
    auto now = std::time(NULL);
    picojson::value jwks;
    int64_t next_update;
    if (get_public_keys_from_db(issuer, now, jwks, next_update)) {
        return jwks.serialize();
    }
    return std::string("{\"keys\": []}");
}

bool Validator::refresh_jwks(const std::string &issuer) {
    int64_t next_update, expires;
    picojson::value keys;
    std::unique_ptr<scitokens::AsyncStatus> status = get_public_keys_from_web(
        issuer, internal::SimpleCurlGet::extended_timeout);
    while (!status->m_done) {
        status = get_public_keys_from_web_continue(std::move(status));
    }
    return store_public_keys(issuer, status->m_keys, status->m_next_update,
                             status->m_expires);
}

bool Validator::store_jwks(const std::string &issuer,
                           const std::string &jwks_str) {
    picojson::value jwks;
    std::string err = picojson::parse(jwks, jwks_str);
    auto now = std::time(NULL);
    int next_update_delta, expiry_delta;
    get_default_expiry_time(next_update_delta, expiry_delta);
    int64_t next_update = now + next_update_delta, expires = now + expiry_delta;
    if (!err.empty()) {
        throw JsonException(err);
    }
    return store_public_keys(issuer, jwks, next_update, expires);
}

std::unique_ptr<AsyncStatus>
Validator::get_public_key_pem(const std::string &issuer, const std::string &kid,
                              std::string &public_pem, std::string &algorithm) {

    auto now = std::time(NULL);
    std::unique_ptr<AsyncStatus> result(new AsyncStatus());

    if (get_public_keys_from_db(issuer, now, result->m_keys,
                                result->m_next_update)) {
        if (now > result->m_next_update) {
            try {
                result->m_ignore_error = true;
                result = get_public_keys_from_web(
                    issuer, internal::SimpleCurlGet::default_timeout);
            } catch (std::runtime_error &) {
                result->m_do_store = false;
                // ignore the exception: we have a valid set of keys already
            }
        } else {
            // Got the keys from the DB, and they are still valid.
            result->m_continue_fetch = false;
            result->m_do_store = false;
            result->m_done = true;
        }
    } else {
        // No keys in the DB, or they are expired, so get them from the web.
        result = get_public_keys_from_web(
            issuer, internal::SimpleCurlGet::default_timeout);
    }
    result->m_issuer = issuer;
    result->m_kid = kid;

    // Always call the continue because it formats the public_pem and algorithm
    return get_public_key_pem_continue(std::move(result), public_pem,
                                       algorithm);
}

std::unique_ptr<AsyncStatus>
Validator::get_public_key_pem_continue(std::unique_ptr<AsyncStatus> status,
                                       std::string &public_pem,
                                       std::string &algorithm) {

    if (status->m_continue_fetch) {
        status = get_public_keys_from_web_continue(std::move(status));
        if (status->m_continue_fetch) {
            return std::move(status);
        }
    }
    if (status->m_do_store) {
        store_public_keys(status->m_issuer, status->m_keys,
                          status->m_next_update, status->m_expires);
    }
    status->m_done = true;

    auto key_obj = find_key_id(status->m_keys, status->m_kid);

    auto iter = key_obj.find("alg");
    std::string alg;
    if (iter == key_obj.end() || (!iter->second.is<std::string>())) {
        auto iter2 = key_obj.find("kty");
        if (iter2 == key_obj.end() || !iter2->second.is<std::string>()) {
            throw JsonException("Key is missing key type");
        } else {
            auto kty = iter2->second.get<std::string>();
            if (kty == "RSA") {
                alg = "RS256";
            } else if (kty == "EC") {
                auto iter3 = key_obj.find("crv");
                if (iter3 == key_obj.end() ||
                    !iter3->second.is<std::string>()) {
                    throw JsonException("EC key is missing curve name");
                }
                auto crv = iter3->second.get<std::string>();
                if (crv == "P-256") {
                    alg = "ES256";
                } else {
                    throw JsonException("Unsupported EC curve in public key");
                }
            } else {
                throw JsonException("Unknown public key type");
            }
        }
    } else {
        alg = iter->second.get<std::string>();
    }
    if (alg != "RS256" and alg != "ES256") {
        throw UnsupportedKeyException(
            "Issuer is using an unsupported algorithm");
    }
    std::string pem;

    if (alg == "ES256") {
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

    return std::move(status);
}

bool scitokens::Validator::store_public_ec_key(const std::string &issuer,
                                               const std::string &keyid,
                                               const std::string &public_key) {
    std::unique_ptr<BIO, decltype(&BIO_free_all)> pubkey_bio(
        BIO_new(BIO_s_mem()), BIO_free_all);
    if ((size_t)BIO_write(pubkey_bio.get(), public_key.data(),
                          public_key.size()) != public_key.size()) {
        return false;
    }

    std::unique_ptr<BIGNUM, decltype(&BN_free)> x_bignum(BN_new(), BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> y_bignum(BN_new(), BN_free);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(
        PEM_read_bio_PUBKEY(pubkey_bio.get(), nullptr, nullptr, nullptr),
        EVP_PKEY_free);
    if (!pkey.get()) {
        return false;
    }

    std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)> ec_group(
        EC_GROUP_new_by_curve_name(EC_NAME), EC_GROUP_free);
    if (!ec_group.get()) {
        throw UnsupportedKeyException("Unable to get OpenSSL EC group");
    }

    std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)> q_point(
        EC_POINT_new(ec_group.get()), EC_POINT_free);
    if (!q_point.get()) {
        throw UnsupportedKeyException("Unable to get OpenSSL EC point");
    }

    OSSL_PARAM *params;
    if (!EVP_PKEY_todata(pkey.get(), EVP_PKEY_PUBLIC_KEY, &params)) {
        throw UnsupportedKeyException(
            "Unable to get OpenSSL public key parameters");
    }

    void *buf = NULL;
    size_t buf_len, max_len = 256;
    OSSL_PARAM *p = OSSL_PARAM_locate(params, "pub");
    if (!p || !OSSL_PARAM_get_octet_string(p, &buf, max_len, &buf_len) ||
        !EC_POINT_oct2point(ec_group.get(), q_point.get(),
                            static_cast<unsigned char *>(buf), buf_len,
                            nullptr)) {
        throw UnsupportedKeyException(
            "Failed to to set OpenSSL EC point with public key information");
    }

    if (!EC_POINT_get_affine_coordinates(ec_group.get(), q_point.get(),
                                         x_bignum.get(), y_bignum.get(),
                                         NULL)) {
        throw UnsupportedKeyException(
            "Unable to get OpenSSL affine coordinates");
    }

    OSSL_PARAM_free(params);
#else
    std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> pkey(
        PEM_read_bio_EC_PUBKEY(pubkey_bio.get(), nullptr, nullptr, nullptr),
        EC_KEY_free);
    if (!pkey) {
        return false;
    }

    EC_GROUP *params = (EC_GROUP *)EC_KEY_get0_group(pkey.get());
    if (!params) {
        throw UnsupportedKeyException("Unable to get OpenSSL EC group");
    }

    const EC_POINT *point = EC_KEY_get0_public_key(pkey.get());
    if (!point) {
        throw UnsupportedKeyException("Unable to get OpenSSL EC point");
    }

    if (!EC_POINT_get_affine_coordinates_GFp(params, point, x_bignum.get(),
                                             y_bignum.get(), nullptr)) {
        throw UnsupportedKeyException(
            "Unable to get OpenSSL affine coordinates");
    }
#endif

    auto x_num = BN_num_bytes(x_bignum.get());
    auto y_num = BN_num_bytes(y_bignum.get());
    std::vector<unsigned char> x_bin;
    x_bin.reserve(x_num);
    std::vector<unsigned char> y_bin;
    y_bin.reserve(y_num);
    BN_bn2bin(x_bignum.get(), &x_bin[0]);
    BN_bn2bin(y_bignum.get(), &y_bin[0]);
    std::string x_str(reinterpret_cast<char *>(&x_bin[0]), x_num);
    std::string y_str(reinterpret_cast<char *>(&y_bin[0]), y_num);

    picojson::object key_obj;
    key_obj["alg"] = picojson::value("ES256");
    key_obj["kid"] = picojson::value(keyid);
    key_obj["use"] = picojson::value("sig");
    key_obj["kty"] = picojson::value("EC");
    key_obj["x"] = picojson::value(b64url_encode_nopadding(x_str));
    key_obj["y"] = picojson::value(b64url_encode_nopadding(y_str));
    std::vector<picojson::value> key_list;
    key_list.emplace_back(key_obj);

    picojson::object top_obj;
    top_obj["keys"] = picojson::value(key_list);

    picojson::value top_value(top_obj);

    auto now = std::time(NULL);
    int next_update_delta, expiry_delta;
    get_default_expiry_time(next_update_delta, expiry_delta);
    return store_public_keys(issuer, top_value, now + next_update_delta,
                             now + expiry_delta);
}

bool scitokens::Enforcer::scope_validator(const jwt::claim &claim,
                                          void *myself) {
    auto me = reinterpret_cast<scitokens::Enforcer *>(myself);
    if (claim.get_type() != jwt::json::type::string) {
        return false;
    }
    std::string scope = claim.as_string();
    std::string requested_path = normalize_absolute_path(me->m_test_path);
    auto scope_iter = scope.begin();
    // std::cout << "Comparing scope " << scope << " against test accesses " <<
    // me->m_test_authz << ":" << requested_path << std::endl;
    bool compat_modify = false, compat_create = false, compat_cancel = false;
    while (scope_iter != scope.end()) {
        while (*scope_iter == ' ') {
            scope_iter++;
        }
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

        // If we are in compatibility mode and this is a WLCG token, then
        // translate the authorization names to utilize the SciToken-style
        // names.
        std::string alt_authz;
        if (me->m_validate_profile == SciToken::Profile::COMPAT &&
            me->m_validator.get_profile() == SciToken::Profile::WLCG_1_0) {
            if (authz == "storage.read") {
                authz = "read";
            } else if (authz == "storage.create") {
                authz = "write";
                alt_authz = "create";
            } else if (authz == "storage.modify") {
                authz = "write";
                alt_authz = "modify";
            } else if (authz == "compute.read") {
                authz = "condor";
                path = "/READ";
            } else if (authz == "compute.modify") {
                compat_modify = true;
            } else if (authz == "compute.create") {
                compat_create = true;
            } else if (authz == "compute.cancel") {
                compat_cancel = true;
            }
        }

        if (me->m_test_authz.empty()) {
            me->m_gen_acls.emplace_back(authz, path);
            if (!alt_authz.empty())
                me->m_gen_acls.emplace_back(alt_authz, path);
        } else if (((me->m_test_authz == authz) ||
                    (!alt_authz.empty() && (me->m_test_authz == alt_authz))) &&
                   (requested_path.substr(0, path.size()) == path)) {
            return true;
        }

        scope_iter = next_scope_iter;
    }

    // Compatibility mode: the combination on compute modify, create, and cancel
    // mode are equivalent to the condor:/WRITE authorization.
    if (compat_modify && compat_create && compat_cancel) {
        if (me->m_test_authz.empty()) {
            me->m_gen_acls.emplace_back("condor", "/WRITE");
        } else if ((me->m_test_authz == "condor") &&
                   (requested_path.substr(0, 6) == "/WRITE")) {
            return true;
        }
    }

    return me->m_test_authz.empty();
}
