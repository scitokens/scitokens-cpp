
#include <memory>
#include <sstream>
#include <unordered_map>

#include <curl/curl.h>
#include <jwt-cpp/jwt.h>
#include <uuid/uuid.h>

#if defined(__GNUC__)
#define WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#else
#define WARN_UNUSED_RESULT
#endif

namespace {

struct FixedClock {
    jwt::date m_now;
    jwt::date now() const { return m_now; }
};

} // namespace

namespace jwt {
template <typename json_traits> class decoded_jwt;
namespace traits {
struct kazuho_picojson;
}
} // namespace jwt

namespace scitokens {

namespace internal {

class SimpleCurlGet {

    int m_maxbytes{1048576};
    unsigned m_timeout;
    std::vector<char> m_data;
    size_t m_len{0};
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> m_curl;
    std::unique_ptr<CURLM, decltype(&curl_multi_cleanup)> m_curl_multi;
    fd_set m_read_fd_set[FD_SETSIZE];
    fd_set m_write_fd_set[FD_SETSIZE];
    fd_set m_exc_fd_set[FD_SETSIZE];
    int m_max_fd{-1};
    long m_timeout_ms{0};

  public:
    static const unsigned default_timeout = 4;
    static const unsigned extended_timeout = 30;

    SimpleCurlGet(int maxbytes = 1024 * 1024, unsigned timeout = 30)
        : m_maxbytes(maxbytes), m_timeout(timeout),
          m_curl(nullptr, &curl_easy_cleanup),
          m_curl_multi(nullptr, &curl_multi_cleanup) {}

    struct GetStatus {
        bool m_done{false};
        int m_status_code{-1};
    };

    GetStatus perform_start(const std::string &url);
    GetStatus perform_continue();
    int perform(const std::string &url, time_t expiry_time);
    void get_data(char *&buffer, size_t &len);

    long get_timeout_ms() const { return m_timeout_ms; }
    int get_max_fd() const { return m_max_fd; }
    fd_set *get_read_fd_set() { return m_read_fd_set; }
    fd_set *get_write_fd_set() { return m_write_fd_set; }
    fd_set *get_exc_fd_set() { return m_exc_fd_set; }

  private:
    static size_t write_data(void *buffer, size_t size, size_t nmemb,
                             void *userp);
};

} // namespace internal

class UnsupportedKeyException : public std::runtime_error {
  public:
    explicit UnsupportedKeyException(const std::string &msg)
        : std::runtime_error(msg) {}
};

class JWTVerificationException : public std::runtime_error {
  public:
    explicit JWTVerificationException(const std::string &msg)
        : std::runtime_error("token verification failed: " + msg) {}
};

class CurlException : public std::runtime_error {
  public:
    explicit CurlException(const std::string &msg) : std::runtime_error(msg) {}
};

class MissingIssuerException : public std::runtime_error {
  public:
    MissingIssuerException()
        : std::runtime_error("Issuer not specified in claims") {}
};

class InvalidIssuerException : public std::runtime_error {
  public:
    InvalidIssuerException(const std::string &msg) : std::runtime_error(msg) {}
};

class JsonException : public std::runtime_error {
  public:
    JsonException(const std::string &msg) : std::runtime_error(msg) {}
};

class SciTokenKey {

  public:
    SciTokenKey() : m_kid("none"), m_name("none") {}

    SciTokenKey(const std::string &key_id, const std::string &algorithm,
                const std::string &public_contents,
                const std::string &private_contents)
        : m_kid(key_id), m_name(algorithm), m_public(public_contents),
          m_private(private_contents) {}

    std::string serialize(jwt::builder<jwt::traits::kazuho_picojson> &builder) {
        std::error_code ec;
        builder.set_key_id(m_kid);
        return builder.sign(*this);
    }

    std::string sign(const std::string &data, std::error_code &ec) const {
        if (m_name == "RS256") {
            return jwt::algorithm::rs256(m_public, m_private).sign(data, ec);
        } else if (m_name == "ES256") {
            return jwt::algorithm::es256(m_public, m_private).sign(data, ec);
        }
        throw UnsupportedKeyException(
            "Provided algorithm name is not supported");
    }

    std::string name() const { return m_name; }

    void verify(const std::string &data, const std::string &signature,
                std::error_code &ec) const {
        if (m_name == "RS256") {
            jwt::algorithm::rs256(m_public, m_private)
                .verify(data, signature, ec);
        } else if (m_name == "ES256") {
            jwt::algorithm::es256(m_public, m_private)
                .verify(data, signature, ec);
        } else {
            throw UnsupportedKeyException(
                "Provided algorithm is not supported.");
        }
    }

  private:
    std::string m_kid;
    std::string m_name;
    std::string m_public;
    std::string m_private;
};

class Validator;

class AsyncStatus {
  public:
    AsyncStatus() = default;
    AsyncStatus(const AsyncStatus &) = delete;
    AsyncStatus &operator=(const AsyncStatus &) = delete;

    enum AsyncState { DOWNLOAD_METADATA, DOWNLOAD_PUBLIC_KEY, DONE };

    bool m_done{false};
    bool m_continue_fetch{false};
    bool m_ignore_error{false};
    bool m_do_store{true};
    bool m_has_metadata{false};
    bool m_oauth_fallback{false};
    AsyncState m_state{DOWNLOAD_METADATA};

    int64_t m_next_update{-1};
    int64_t m_expires{-1};
    picojson::value m_keys;
    std::string m_issuer;
    std::string m_kid;
    std::string m_oauth_metadata_url;
    std::unique_ptr<internal::SimpleCurlGet> m_cget;
    std::string m_jwt_string;
    std::string m_public_pem;
    std::string m_algorithm;

    struct timeval get_timeout_val(time_t expiry_time) const {
        auto now = time(NULL);
        long timeout_ms = 100 * (expiry_time - now);
        if (m_cget && (m_cget->get_timeout_ms() < timeout_ms))
            timeout_ms = m_cget->get_timeout_ms();
        struct timeval timeout;
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        return timeout;
    }

    int get_max_fd() const { return m_cget ? m_cget->get_max_fd() : -1; }
    fd_set *get_read_fd_set() {
        return m_cget ? m_cget->get_read_fd_set() : nullptr;
    }
    fd_set *get_write_fd_set() {
        return m_cget ? m_cget->get_write_fd_set() : nullptr;
    }
    fd_set *get_exc_fd_set() {
        return m_cget ? m_cget->get_exc_fd_set() : nullptr;
    }
};

class SciTokenAsyncStatus {
  public:
    SciTokenAsyncStatus() = default;
    SciTokenAsyncStatus(const SciTokenAsyncStatus &) = delete;
    SciTokenAsyncStatus &operator=(const SciTokenAsyncStatus &) = delete;

    std::unique_ptr<Validator> m_validator;
    std::unique_ptr<AsyncStatus> m_status;
};

class SciToken {

    friend class scitokens::Validator;

  public:
    enum class Profile {
        COMPAT = 0,
        SCITOKENS_1_0,
        SCITOKENS_2_0,
        WLCG_1_0,
        AT_JWT
    };

    SciToken(SciTokenKey &signing_algorithm) : m_key(signing_algorithm) {}

    void set_claim(const std::string &key, const jwt::claim &value) {
        m_claims[key] = value;
        if (key == "iss") {
            m_issuer_set = true;
        }
    }

    void set_serialize_mode(Profile profile) { m_serialize_profile = profile; }

    void set_deserialize_mode(Profile profile) {
        m_deserialize_profile = profile;
    }

    const jwt::claim get_claim(const std::string &key) { return m_claims[key]; }

    bool has_claim(const std::string &key) const {
        return m_claims.find(key) != m_claims.end();
    }

    void set_claim_list(const std::string &claim,
                        std::vector<std::string> &claim_list) {
        picojson::array array;
        array.reserve(claim_list.size());
        for (const auto &entry : claim_list) {
            array.emplace_back(entry);
        }
        m_claims[claim] = jwt::claim(picojson::value(array));
    }

    // Return a claim as a string
    // If the claim is not a string, it can throw
    // a std::bad_cast() exception.
    const std::string get_claim_string(const std::string &key) {
        return m_claims[key].as_string();
    }

    const std::vector<std::string> get_claim_list(const std::string &key) {
        picojson::array array;
        try {
            array = m_claims[key].as_array();
        } catch (std::bad_cast &) {
            throw JsonException("Claim's value is not a JSON list");
        }
        std::vector<std::string> result;
        for (const auto &value : array) {
            result.emplace_back(value.get<std::string>());
        }
        return result;
    }

    void set_lifetime(int lifetime) { m_lifetime = lifetime; }

    std::string serialize() {
        jwt::builder<jwt::traits::kazuho_picojson> builder(jwt::create());

        if (!m_issuer_set) {
            throw MissingIssuerException();
        }
        auto time = std::chrono::system_clock::now();
        builder.set_issued_at(time);
        builder.set_not_before(time);
        builder.set_expires_at(time + std::chrono::seconds(m_lifetime));
        if (m_serialize_profile == Profile::AT_JWT) {
            builder.set_type("at+jwt");
        }

        uuid_t uuid;
        uuid_generate(uuid);
        char uuid_str[37];
        uuid_unparse_lower(uuid, uuid_str);
        m_claims["jti"] = jwt::claim(std::string(uuid_str));

        if (m_serialize_profile == Profile::SCITOKENS_2_0) {
            m_claims["ver"] = jwt::claim(std::string("scitoken:2.0"));
            auto iter = m_claims.find("aud");
            if (iter == m_claims.end()) {
                m_claims["aud"] = jwt::claim(std::string("ANY"));
            }
        } else if (m_serialize_profile == Profile::WLCG_1_0) {
            m_claims["wlcg.ver"] = jwt::claim(std::string("1.0"));
            auto iter = m_claims.find("aud");
            if (iter == m_claims.end()) {
                m_claims["aud"] =
                    jwt::claim(std::string("https://wlcg.cern.ch/jwt/v1/any"));
            }
        }

        // Set all the payload claims
        for (auto it : m_claims) {
            builder.set_payload_claim(it.first, it.second);
        }

        return m_key.serialize(builder);
    }

    void deserialize(const std::string &data,
                     std::vector<std::string> allowed_issuers = {});

    std::unique_ptr<SciTokenAsyncStatus>
    deserialize_start(const std::string &data,
                      std::vector<std::string> allowed_issuers = {});

    std::unique_ptr<SciTokenAsyncStatus>
    deserialize_continue(std::unique_ptr<SciTokenAsyncStatus> status);

  private:
    bool m_issuer_set{false};
    int m_lifetime{600};
    Profile m_profile{Profile::SCITOKENS_1_0};
    Profile m_serialize_profile{Profile::COMPAT};
    Profile m_deserialize_profile{Profile::COMPAT};
    std::unordered_map<std::string, jwt::claim> m_claims;
    std::unique_ptr<jwt::decoded_jwt<jwt::traits::kazuho_picojson>> m_decoded;
    SciTokenKey &m_key;
};

class Validator {

    typedef int (*StringValidatorFunction)(const char *value, char **err_msg);
    typedef bool (*ClaimValidatorFunction)(const jwt::claim &claim_value,
                                           void *data);
    typedef std::map<std::string, std::vector<StringValidatorFunction>>
        ClaimStringValidatorMap;
    typedef std::map<std::string,
                     std::vector<std::pair<ClaimValidatorFunction, void *>>>
        ClaimValidatorMap;

  public:
    Validator() : m_now(std::chrono::system_clock::now()) {}

    void set_now(std::chrono::system_clock::time_point now) { m_now = now; }

    std::unique_ptr<AsyncStatus> verify_async(const SciToken &scitoken) {
        const jwt::decoded_jwt<jwt::traits::kazuho_picojson> *jwt_decoded =
            scitoken.m_decoded.get();
        if (!jwt_decoded) {
            throw JWTVerificationException(
                "Token is not deserialized from string.");
        }
        return verify_async(*jwt_decoded);
    }

    void verify(const SciToken &scitoken, time_t expiry_time) {
        auto result = verify_async(scitoken);
        while (!result->m_done) {
            auto timeout_val = result->get_timeout_val(expiry_time);
            select(result->get_max_fd(), result->get_read_fd_set(),
                   result->get_write_fd_set(), result->get_exc_fd_set(),
                   &timeout_val);
            if (time(NULL) >= expiry_time) {
                throw CurlException("Timeout when loading the OIDC metadata.");
            }

            result = verify_async_continue(std::move(result));
        }
    }

    void verify(const jwt::decoded_jwt<jwt::traits::kazuho_picojson> &jwt) {
        auto result = verify_async(jwt);
        while (!result->m_done) {
            result = verify_async_continue(std::move(result));
        }
    }

    std::unique_ptr<AsyncStatus>
    verify_async(const jwt::decoded_jwt<jwt::traits::kazuho_picojson> &jwt) {
        // If token has a typ header claim (RFC8725 Section 3.11), trust that in
        // COMPAT mode.
        if (jwt.has_type()) {
            std::string t_type = jwt.get_type();
            if (m_validate_profile == SciToken::Profile::COMPAT) {
                if (t_type == "at+jwt" || t_type == "application/at+jwt") {
                    m_profile = SciToken::Profile::AT_JWT;
                }
            } else if (m_validate_profile == SciToken::Profile::AT_JWT) {
                if (t_type != "at+jwt" && t_type != "application/at+jwt") {
                    throw JWTVerificationException(
                        "'typ' header claim must be at+jwt");
                }
                m_profile = SciToken::Profile::AT_JWT;
            }
        } else {
            if (m_validate_profile == SciToken::Profile::AT_JWT) {
                throw JWTVerificationException(
                    "'typ' header claim must be set for at+jwt tokens");
            }
        }
        if (!jwt.has_payload_claim("iat")) {
            throw JWTVerificationException("'iat' claim is mandatory");
        }
        if (m_profile != SciToken::Profile::AT_JWT) {
            if (!jwt.has_payload_claim("nbf")) {
                throw JWTVerificationException("'nbf' claim is mandatory");
            }
        }
        if (!jwt.has_payload_claim("exp")) {
            throw JWTVerificationException("'exp' claim is mandatory");
        }
        if (!jwt.has_payload_claim("iss")) {
            throw JWTVerificationException("'iss' claim is mandatory");
        }
        if (!m_allowed_issuers.empty()) {
            std::string issuer = jwt.get_issuer();
            bool permitted = false;
            for (const auto &allowed_issuer : m_allowed_issuers) {
                if (issuer == allowed_issuer) {
                    permitted = true;
                    break;
                }
            }
            if (!permitted) {
                throw JWTVerificationException(
                    "Token issuer is not in list of allowed issuers.");
            }
        }

        for (const auto &claim : m_critical_claims) {
            if (!jwt.has_payload_claim(claim)) {
                std::stringstream ss;
                ss << "'" << claim << "' claim is mandatory";
                throw JWTVerificationException(ss.str());
            }
        }

        std::string public_pem;
        std::string algorithm;
        // Key id is optional in the RFC, set to blank if it doesn't exist
        std::string key_id;
        try {
            key_id = jwt.get_key_id();
        } catch (const std::runtime_error &) {
            // Don't do anything, key_id is empty, as it should be.
        }
        auto status =
            get_public_key_pem(jwt.get_issuer(), key_id, public_pem, algorithm);
        status->m_jwt_string = jwt.get_token();
        status->m_public_pem = public_pem;
        status->m_algorithm = algorithm;

        return verify_async_continue(std::move(status));
    }

    std::unique_ptr<AsyncStatus>
    verify_async_continue(std::unique_ptr<AsyncStatus> status) {
        if (!status->m_done) {
            std::string public_pem, algorithm;
            status = get_public_key_pem_continue(std::move(status), public_pem,
                                                 algorithm);
            status->m_public_pem = public_pem;
            status->m_algorithm = algorithm;
            if (!status->m_done) {
                return std::move(status);
            }
        }

        // std::cout << "Public PEM: " << public_pem << std::endl << "Algorithm:
        // " << algorithm << std::endl;
        SciTokenKey key(status->m_kid, status->m_algorithm,
                        status->m_public_pem, "");

        auto verifier =
            jwt::verify<FixedClock, jwt::traits::kazuho_picojson>({m_now})
                .allow_algorithm(key);

        const jwt::decoded_jwt<jwt::traits::kazuho_picojson> jwt(
            status->m_jwt_string);
        verifier.verify(jwt);

        bool must_verify_everything = true;
        if (jwt.has_payload_claim("ver")) {
            const jwt::claim &claim = jwt.get_payload_claim("ver");
            if (claim.get_type() != jwt::json::type::string) {
                throw JWTVerificationException(
                    "'ver' claim value must be a string (if present)");
            }
            std::string ver_string = claim.as_string();
            if ((ver_string == "scitokens:2.0") ||
                (ver_string == "scitoken:2.0")) {
                must_verify_everything = false;
                if ((m_validate_profile != SciToken::Profile::COMPAT) &&
                    (m_validate_profile != SciToken::Profile::SCITOKENS_2_0)) {
                    throw JWTVerificationException(
                        "Invalidate token type; not expecting a SciToken 2.0.");
                }
                m_profile = SciToken::Profile::SCITOKENS_2_0;
                if (!jwt.has_payload_claim("aud")) {
                    throw JWTVerificationException(
                        "'aud' claim required for SciTokens 2.0 profile");
                }
            } else if (ver_string == "scitokens:1.0") {
                must_verify_everything = m_validate_all_claims;
                if ((m_validate_profile != SciToken::Profile::COMPAT) &&
                    (m_validate_profile != SciToken::Profile::SCITOKENS_1_0)) {
                    throw JWTVerificationException(
                        "Invalidate token type; not expecting a SciToken 1.0.");
                }
                m_profile = SciToken::Profile::SCITOKENS_1_0;
            } else {
                std::stringstream ss;
                ss << "Unknown profile version in token: " << ver_string;
                throw JWTVerificationException(ss.str());
            }
            // Handle WLCG common JWT profile.
        } else if (jwt.has_payload_claim("wlcg.ver")) {
            if ((m_validate_profile != SciToken::Profile::COMPAT) &&
                (m_validate_profile != SciToken::Profile::WLCG_1_0)) {
                throw JWTVerificationException(
                    "Invalidate token type; not expecting a WLCG 1.0.");
            }

            m_profile = SciToken::Profile::WLCG_1_0;
            must_verify_everything = false;
            const jwt::claim &claim = jwt.get_payload_claim("wlcg.ver");
            if (claim.get_type() != jwt::json::type::string) {
                throw JWTVerificationException(
                    "'ver' claim value must be a string (if present)");
            }
            std::string ver_string = claim.as_string();
            if (ver_string != "1.0") {
                std::stringstream ss;
                ss << "Unknown WLCG profile version in token: " << ver_string;
                throw JWTVerificationException(ss.str());
            }
            if (!jwt.has_payload_claim("aud")) {
                throw JWTVerificationException(
                    "Malformed token: 'aud' claim required for WLCG profile");
            }
        } else if (m_profile == SciToken::Profile::AT_JWT) {
            // detected early above from typ header claim.
            must_verify_everything = false;
        } else {
            if ((m_validate_profile != SciToken::Profile::COMPAT) &&
                (m_validate_profile != SciToken::Profile::SCITOKENS_1_0)) {
                throw JWTVerificationException(
                    "Invalidate token type; not expecting a SciToken 1.0.");
            }

            m_profile = SciToken::Profile::SCITOKENS_1_0;
            must_verify_everything = m_validate_all_claims;
        }

        auto claims = jwt.get_payload_claims();
        for (const auto &claim_pair : claims) {
            if (claim_pair.first == "iat" || claim_pair.first == "nbf" ||
                claim_pair.first == "exp" || claim_pair.first == "ver") {
                continue;
            }
            auto iter = m_validators.find(claim_pair.first);
            auto iter_claim = m_claim_validators.find(claim_pair.first);
            if ((iter == m_validators.end() || iter->second.empty()) &&
                (iter_claim == m_claim_validators.end() ||
                 iter_claim->second.empty())) {
                bool is_issuer = claim_pair.first == "iss";
                if (is_issuer && !m_allowed_issuers.empty()) {
                    // skip; we verified it above
                } else if (must_verify_everything) {
                    std::stringstream ss;
                    ss << "'" << claim_pair.first
                       << "' claim verification is mandatory";
                    // std::cout << ss.str() << std::endl;
                    throw JWTVerificationException(ss.str());
                }
            }
            // std::cout << "Running claim " << claim_pair.first << " through
            // validation." << std::endl;
            if (iter != m_validators.end())
                for (const auto &verification_func : iter->second) {
                    const jwt::claim &claim =
                        jwt.get_payload_claim(claim_pair.first);
                    if (claim.get_type() != jwt::json::type::string) {
                        std::stringstream ss;
                        ss << "'" << claim_pair.first
                           << "' claim value must be a string to verify.";
                        throw JWTVerificationException(ss.str());
                    }
                    std::string value = claim.as_string();
                    char *err_msg = nullptr;
                    if (verification_func(value.c_str(), &err_msg)) {
                        if (err_msg) {
                            throw JWTVerificationException(err_msg);
                        } else {
                            std::stringstream ss;
                            ss << "'" << claim_pair.first
                               << "' claim verification failed.";
                            throw JWTVerificationException(ss.str());
                        }
                    }
                }
            if (iter_claim != m_claim_validators.end())
                for (const auto &verification_pair : iter_claim->second) {
                    const jwt::claim &claim =
                        jwt.get_payload_claim(claim_pair.first);
                    if (verification_pair.first(
                            claim, verification_pair.second) == false) {
                        std::stringstream ss;
                        ss << "'" << claim_pair.first
                           << "' claim verification failed.";
                        throw JWTVerificationException(ss.str());
                    }
                }
        }
        std::unique_ptr<AsyncStatus> result(new AsyncStatus());
        result->m_done = true;
        return std::move(result);
    }

    void add_critical_claims(const std::vector<std::string> &claims) {
        std::copy(claims.begin(), claims.end(),
                  std::back_inserter(m_critical_claims));
    }

    void add_allowed_issuers(const std::vector<std::string> &allowed_issuers) {
        std::copy(allowed_issuers.begin(), allowed_issuers.end(),
                  std::back_inserter(m_allowed_issuers));
    }

    void add_string_validator(const std::string &claim,
                              StringValidatorFunction func) {
        auto result = m_validators.insert(
            {claim, std::vector<StringValidatorFunction>()});
        result.first->second.push_back(func);
    }

    void add_claim_validator(const std::string &claim,
                             ClaimValidatorFunction func, void *data) {
        auto result = m_claim_validators.insert(
            {claim, std::vector<std::pair<ClaimValidatorFunction, void *>>()});
        result.first->second.push_back({func, data});
    }

    void set_validate_all_claims_scitokens_1(bool new_val) {
        m_validate_all_claims = new_val;
    }

    /**
     * Get the profile of the last validated token.
     *
     * If there has been no validation - or the validation failed,
     * then the return value is unspecified.
     *
     * Will not return Profile::COMPAT.
     */
    SciToken::Profile get_profile() const {
        if (m_profile == SciToken::Profile::COMPAT) {
            throw JWTVerificationException("Token profile has not been set.");
        }
        return m_profile;
    }

    /**
     * Set the profile that will be used for validation; COMPAT indicates any
     * supported profile is allowable.
     */
    void set_validate_profile(SciToken::Profile profile) {
        m_validate_profile = profile;
    }

    /**
     * Store the contents of a public EC key for a given issuer.
     */
    static bool store_public_ec_key(const std::string &issuer,
                                    const std::string &kid,
                                    const std::string &key);

    /**
     * Store the contents of a JWKS for a given issuer.
     */
    static bool store_jwks(const std::string &issuer, const std::string &jwks);

    /**
     * Trigger a refresh of the JWKS or a given issuer.
     */
    static bool refresh_jwks(const std::string &issuer);

    /**
     * Fetch the contents of fa JWKS for a given issuer (do not trigger a
     * refresh). Will return an empty JWKS if no valid JWKS is available.
     */
    static std::string get_jwks(const std::string &issuer);

  private:
    static std::unique_ptr<AsyncStatus>
    get_public_key_pem(const std::string &issuer, const std::string &kid,
                       std::string &public_pem, std::string &algorithm);
    static std::unique_ptr<AsyncStatus>
    get_public_key_pem_continue(std::unique_ptr<AsyncStatus> status,
                                std::string &public_pem,
                                std::string &algorithm);
    static std::unique_ptr<AsyncStatus>
    get_public_keys_from_web(const std::string &issuer, unsigned timeout);
    static std::unique_ptr<AsyncStatus>
    get_public_keys_from_web_continue(std::unique_ptr<AsyncStatus> status);
    static bool get_public_keys_from_db(const std::string issuer, int64_t now,
                                        picojson::value &keys,
                                        int64_t &next_update);
    static bool store_public_keys(const std::string &issuer,
                                  const picojson::value &keys,
                                  int64_t next_update, int64_t expires);

    bool m_validate_all_claims{true};
    SciToken::Profile m_profile{SciToken::Profile::COMPAT};
    SciToken::Profile m_validate_profile{SciToken::Profile::COMPAT};
    ClaimStringValidatorMap m_validators;
    ClaimValidatorMap m_claim_validators;

    std::chrono::system_clock::time_point m_now;

    std::vector<std::string> m_critical_claims;
    std::vector<std::string> m_allowed_issuers;
};

class Enforcer {

  public:
    typedef std::vector<std::pair<std::string, std::string>> AclsList;

    Enforcer(std::string issuer, std::vector<std::string> audience_list)
        : m_issuer(issuer), m_audiences(audience_list) {
        m_validator.add_allowed_issuers({m_issuer});
        m_validator.add_claim_validator("jti", &Enforcer::str_validator,
                                        nullptr);
        m_validator.add_claim_validator("sub", &Enforcer::str_validator,
                                        nullptr);
        m_validator.add_claim_validator("opt", &Enforcer::all_validator,
                                        nullptr);
        m_validator.add_claim_validator("aud", &Enforcer::aud_validator, this);
        m_validator.add_claim_validator("scope", &Enforcer::scope_validator,
                                        this);
        std::vector<std::string> critical_claims = {"scope"};

        // If any audiences are in the given to us, then force the validator to
        // check it.
        if (!m_audiences.empty()) {
            critical_claims.push_back("aud");
        }
        m_validator.add_critical_claims(critical_claims);
    }

    void set_now(std::chrono::system_clock::time_point now) {
        m_validator.set_now(now);
    }

    void set_validate_profile(SciToken::Profile profile) {
        m_validate_profile = profile;
    }

    bool test(const SciToken &scitoken, const std::string &authz,
              const std::string &path) {
        reset_state();
        m_test_path = path;
        m_test_authz = authz;
        try {
            m_validator.verify(scitoken, time(NULL) + 20);
            return true;
        } catch (std::runtime_error &) {
            throw;
        }
    }

    AclsList generate_acls(const SciToken &scitoken) {
        reset_state();
        m_validator.verify(scitoken, time(NULL) + 20);
        return m_gen_acls;
    }

    std::unique_ptr<AsyncStatus> generate_acls_start(const SciToken &scitoken,
                                                     AclsList &acls) {
        reset_state();
        auto status = m_validator.verify_async(scitoken);
        if (status->m_done) {
            acls = m_gen_acls;
        }
        return status;
    }

    std::unique_ptr<AsyncStatus>
    generate_acls_continue(std::unique_ptr<AsyncStatus> status,
                           AclsList &acls) {
        auto result = m_validator.verify_async_continue(std::move(status));
        if (result->m_done) {
            acls = m_gen_acls;
        }
        return result;
    }

  private:
    static bool all_validator(const jwt::claim &, void *) { return true; }

    static bool str_validator(const jwt::claim &claim, void *) {
        return claim.get_type() == jwt::json::type::string;
    }

    static bool scope_validator(const jwt::claim &claim, void *myself);

    static bool aud_validator(const jwt::claim &claim, void *myself) {
        auto me = reinterpret_cast<scitokens::Enforcer *>(myself);
        std::vector<std::string> jwt_audiences;
        if (claim.get_type() == jwt::json::type::string) {
            const std::string &audience = claim.as_string();
            jwt_audiences.push_back(audience);
        } else if (claim.get_type() == jwt::json::type::array) {
            const picojson::array &audiences = claim.as_array();
            for (const auto &aud_value : audiences) {
                const std::string &audience = aud_value.get<std::string>();
                jwt_audiences.push_back(audience);
            }
        }
        for (const auto &aud_value : jwt_audiences) {
            if (((me->m_validator.get_profile() ==
                  SciToken::Profile::SCITOKENS_2_0) &&
                 (aud_value == "ANY")) ||
                ((me->m_validator.get_profile() ==
                  SciToken::Profile::WLCG_1_0) &&
                 (aud_value == "https://wlcg.cern.ch/jwt/v1/any"))) {
                return true;
            }
            for (const auto &aud : me->m_audiences) {
                if (aud == aud_value) {
                    return true;
                }
            }
        }
        return false;
    }

    void reset_state() {
        m_test_path = "";
        m_test_authz = "";
        m_gen_acls.clear();
        m_validator.set_validate_profile(m_validate_profile);
    }

    SciToken::Profile m_validate_profile{SciToken::Profile::COMPAT};

    std::string m_test_path;
    std::string m_test_authz;
    AclsList m_gen_acls;

    std::string m_issuer;
    std::vector<std::string> m_audiences;
    scitokens::Validator m_validator;
};

} // namespace scitokens
