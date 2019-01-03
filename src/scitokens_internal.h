
#include <memory>
#include <sstream>

#include <jwt-cpp/jwt.h>

namespace scitokens {

class UnsupportedKeyException : public std::runtime_error {
public:
    explicit UnsupportedKeyException(const std::string &msg)
        : std::runtime_error(msg)
    {}
};


class CurlException : public std::runtime_error {
public:
    explicit CurlException(const std::string &msg)
        : std::runtime_error(msg)
    {}
};


class MissingIssuerException : public std::runtime_error {
public:
    MissingIssuerException()
        : std::runtime_error("Issuer not specific in claims")
    {}  
};


class InvalidIssuerException : public std::runtime_error {
public:
    InvalidIssuerException(const std::string &msg)
        : std::runtime_error(msg)
    {}
};


class JsonException : public std::runtime_error {
public:
    JsonException(const std::string &msg)
        : std::runtime_error(msg)
    {}
};


class SciTokenKey {

public:
    SciTokenKey()
      : m_kid("none"),
        m_name("none")
    {}

    SciTokenKey(const std::string &key_id, const std::string &algorithm, const std::string &public_contents, const std::string &private_contents)
      : m_kid(key_id),
        m_name(algorithm),
        m_public(public_contents),
        m_private(private_contents)
    {}

    std::string
    serialize(jwt::builder &builder) {
        builder.set_key_id(m_kid);
        return builder.sign(*this);
    }

    std::string
    sign(const std::string &data) const {
        if (m_name == "RS256") {
            return jwt::algorithm::rs256(m_public, m_private).sign(data);
        } else if (m_name == "ES256") {
            return jwt::algorithm::es256(m_public, m_private).sign(data);
        }
        throw UnsupportedKeyException("Provided algorithm name is not supported");
    }

    std::string
    name() const {
        return m_name;
    }

    void
    verify(const std::string &data, const std::string &signature) const {
        if (m_name == "RS256") {
            jwt::algorithm::rs256(m_public, m_private).verify(data, signature);
        } else if (m_name == "ES256") {
            jwt::algorithm::rs256(m_public, m_private).verify(data, signature);
        } else {
            throw jwt::signature_verification_exception("Provided algorithm is not supported.");
        }
    }

private:
    std::string m_kid;
    std::string m_name;
    std::string m_public;
    std::string m_private;
};


class Validator;


class SciToken {

friend class scitokens::Validator;

public:
    SciToken(SciTokenKey &signing_algorithm)
        : m_builder(jwt::create()),
          m_key(signing_algorithm)
    {}

    void
    set_claim(const std::string &key, const jwt::claim &value) {
        m_builder.set_payload_claim(key, value);
        if (key == "iss") {m_issuer_set = true;}
    }

    void
    set_lifetime(int lifetime) {
        m_lifetime = lifetime;
    }

    std::string
    serialize() {
        if (!m_issuer_set) {
            throw MissingIssuerException();
        }
        auto time = std::chrono::system_clock::now();
        m_builder.set_issued_at(time);
        m_builder.set_not_before(time);
        m_builder.set_expires_at(time + std::chrono::seconds(m_lifetime));

        // TODO: handle JTI
        return m_key.serialize(m_builder);
    }

    void
    deserialize(const std::string &data, std::vector<std::string> allowed_issuers={});

private:
    bool m_issuer_set{false};
    int m_lifetime{600};
    jwt::builder m_builder;
    std::unique_ptr<jwt::decoded_jwt> m_decoded;
    SciTokenKey &m_key;
};

class Validator {

    typedef int (*StringValidatorFunction)(const char *value, char **err_msg);
    typedef bool (*ClaimValidatorFunction)(const jwt::claim &claim_value, void *data);
    typedef std::map<std::string, std::vector<StringValidatorFunction>> ClaimStringValidatorMap;
    typedef std::map<std::string, std::vector<std::pair<ClaimValidatorFunction, void*>>> ClaimValidatorMap;

public:
    void verify(const SciToken &scitoken) {
        const jwt::decoded_jwt *jwt_decoded = scitoken.m_decoded.get();
        if (!jwt_decoded) {
            throw jwt::token_verification_exception("Token is not deserialized from string.");
        }
        verify(*jwt_decoded);
    }

    void verify(const jwt::decoded_jwt &jwt) {
        if (!jwt.has_payload_claim("iat")) {
            throw jwt::token_verification_exception("'iat' claim is mandatory");
        }
        if (!jwt.has_payload_claim("nbf")) {
            throw jwt::token_verification_exception("'nbf' claim is mandatory");
        }
        if (!jwt.has_payload_claim("exp")) {
            throw jwt::token_verification_exception("'exp' claim is mandatory");
        }
        if (!jwt.has_payload_claim("iss")) {
            throw jwt::token_verification_exception("'iss' claim is mandatory");
        }
        if (!jwt.has_header_claim("kid")) {
            throw jwt::token_verification_exception("'kid' claim is mandatory");
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
                throw jwt::token_verification_exception("Token issuer is not in list of allowed issuers.");
            }
        }

        for (const auto &claim : m_critical_claims) {
            if (!jwt.has_payload_claim(claim)) {
                std::stringstream ss;
                ss << "'" << claim << "' claim is mandatory";
                throw jwt::token_verification_exception(ss.str());
            }
        }

        std::string public_pem;
        std::string algorithm;
        get_public_key_pem(jwt.get_issuer(), jwt.get_key_id(), public_pem, algorithm);
        // std::cout << "Public PEM: " << public_pem << std::endl << "Algorithm: " << algorithm << std::endl;
        SciTokenKey key(jwt.get_key_id(), algorithm, public_pem, "");
        auto verifier = jwt::verify()
            .allow_algorithm(key);

        verifier.verify(jwt);

        bool must_verify_everything = true;
        if (jwt.has_payload_claim("ver")) {
            const jwt::claim &claim = jwt.get_payload_claim("ver");
            if (claim.get_type() != jwt::claim::type::string) {
                throw jwt::token_verification_exception("'ver' claim value must be a string (if present)");
            }
            std::string ver_string = claim.as_string();
            if (ver_string == "scitoken:2.0") {
                must_verify_everything = false;
                if (!jwt.has_payload_claim("aud")) {
                    throw jwt::token_verification_exception("'aud' claim required for SciTokens 2.0 profile");
                }
            }
            else if (ver_string == "scitokens:1.0") must_verify_everything = m_validate_all_claims;
            else {
                std::stringstream ss;
                ss << "Unknown profile version in token: " << ver_string;
                throw jwt::token_verification_exception(ss.str());
            }
        } else {
            must_verify_everything = m_validate_all_claims;
        }

        auto claims = jwt.get_payload_claims();
        for (const auto &claim_pair : claims) {
             if (claim_pair.first == "iat" || claim_pair.first == "nbf" || claim_pair.first == "exp" || claim_pair.first == "ver") {
                 continue;
             }
             auto iter = m_validators.find(claim_pair.first);
             auto iter_claim = m_claim_validators.find(claim_pair.first);
             if ((iter == m_validators.end() || iter->second.empty()) && (iter_claim == m_claim_validators.end() || iter_claim->second.empty())) {
                 bool is_issuer = claim_pair.first == "iss";
                 if (is_issuer && !m_allowed_issuers.empty()) {
                     // skip; we verified it above
                 } else if (must_verify_everything) {
                     std::stringstream ss;
                     ss << "'" << claim_pair.first << "' claim verification is mandatory";
                     // std::cout << ss.str() << std::endl;
                     throw jwt::token_verification_exception(ss.str());
                 }
             }
             // std::cout << "Running claim " << claim_pair.first << " through validation." << std::endl;
             if (iter != m_validators.end()) for (const auto verification_func : iter->second) {
                 const jwt::claim &claim = jwt.get_payload_claim(claim_pair.first);
                 if (claim.get_type() != jwt::claim::type::string) {
                     std::stringstream ss;
                     ss << "'" << claim_pair.first << "' claim value must be a string to verify.";
                     throw jwt::token_verification_exception(ss.str());
                 }
                 std::string value = claim.as_string();
                 char *err_msg = nullptr;
                 if (verification_func(value.c_str(), &err_msg)) {
                     if (err_msg) {
                         throw jwt::token_verification_exception(err_msg);
                     } else {
                         std::stringstream ss;
                         ss << "'" << claim_pair.first << "' claim verification failed.";
                         throw jwt::token_verification_exception(ss.str());
                     }
                 }
             }
             if (iter_claim != m_claim_validators.end()) for (const auto verification_pair : iter_claim->second) {
                 const jwt::claim &claim = jwt.get_payload_claim(claim_pair.first);
                 if (verification_pair.first(claim, verification_pair.second) == false) {
                     std::stringstream ss;
                     ss << "'" << claim_pair.first << "' claim verification failed.";
                     throw jwt::token_verification_exception(ss.str());
                 }
             }
        }
    }

    void add_critical_claims(const std::vector<std::string> &claims) {
        std::copy(claims.begin(), claims.end(), std::back_inserter(m_critical_claims));
    }

    void add_allowed_issuers(const std::vector<std::string> &allowed_issuers) {
        std::copy(allowed_issuers.begin(), allowed_issuers.end(), std::back_inserter(m_allowed_issuers));
    }

    void add_string_validator(const std::string &claim, StringValidatorFunction func) {
        auto result = m_validators.insert({claim, std::vector<StringValidatorFunction>()});
        result.first->second.push_back(func);
    }

    void add_claim_validator(const std::string &claim, ClaimValidatorFunction func, void *data) {
        auto result = m_claim_validators.insert({claim, std::vector<std::pair<ClaimValidatorFunction, void*>>()});
        result.first->second.push_back({func, data});
    }

    void set_validate_all_claims_scitokens_1(bool new_val) {
        m_validate_all_claims = new_val;
    }

private:
    void get_public_key_pem(const std::string &issuer, const std::string &kid, std::string &public_pem, std::string &algorithm);
    void get_public_keys_from_web(const std::string &issuer, picojson::value &keys, int64_t &next_update, int64_t &expires);
    bool get_public_keys_from_db(const std::string issuer, int64_t now, picojson::value &keys, int64_t &next_update);
    bool store_public_keys(const std::string &issuer, const picojson::value &keys, int64_t next_update, int64_t expires);

    bool m_validate_all_claims{true};
    ClaimStringValidatorMap m_validators;
    ClaimValidatorMap m_claim_validators;

    std::vector<std::string> m_critical_claims;
    std::vector<std::string> m_allowed_issuers;
};


class Enforcer {

public:
    typedef std::vector<std::pair<std::string, std::string>> AclsList;

    Enforcer(std::string issuer, std::vector<std::string> audience_list)
      : m_issuer(issuer), m_audiences(audience_list)
    {
        m_validator.add_allowed_issuers({m_issuer});
        m_validator.add_claim_validator("jti", &Enforcer::str_validator, nullptr);
        m_validator.add_claim_validator("sub", &Enforcer::str_validator, nullptr);
        m_validator.add_claim_validator("opt", &Enforcer::all_validator, nullptr);
        m_validator.add_claim_validator("aud", &Enforcer::aud_validator, this);
        m_validator.add_claim_validator("scope", &Enforcer::scope_validator, this);
        std::vector<std::string> critical_claims = {"scope"};
        m_validator.add_critical_claims(critical_claims);
    }

    bool test(const SciToken &scitoken, const std::string &authz, const std::string &path) {
        reset_state();
        m_test_path = path;
        m_test_authz = authz;
        try {
            m_validator.verify(scitoken);
            return true;
        } catch (std::runtime_error) {
            return false;
        }
    }

    AclsList generate_acls(const SciToken &scitoken) {
        reset_state();
        m_validator.verify(scitoken);
        return m_gen_acls;
    }

private:

    static bool all_validator(const jwt::claim &, void *) {return true;}

    static bool str_validator(const jwt::claim &claim, void *) {
        return claim.get_type() == jwt::claim::type::string;
    }

    static bool scope_validator(const jwt::claim &claim, void *myself);

    static bool aud_validator(const jwt::claim &claim, void *myself) {
        auto me = reinterpret_cast<scitokens::Enforcer*>(myself);
        if (claim.get_type() == jwt::claim::type::string) {
            const std::string &audience = claim.as_string();
            if ((audience == "ANY") && !me->m_audiences.empty()) {return true;}
            for (const auto &aud : me->m_audiences) {
                if (aud == audience) {return true;}
            }
        } else if (claim.get_type() == jwt::claim::type::array) {
            const picojson::array &audiences = claim.as_array();
            for (const auto &aud_value : audiences) {
                if (!aud_value.is<std::string>()) {continue;}
                std::string audience = aud_value.get<std::string>();
                if ((audience == "ANY") && !me->m_audiences.empty()) {return true;}
                for (const auto &aud : me->m_audiences) {
                    if (aud == audience) {return true;}
                }
            }
        }
        return false;
    }

    void reset_state() {
        m_test_path = "";
        m_test_authz = "";
        m_gen_acls.clear();
    }

    std::string m_test_path;
    std::string m_test_authz;
    AclsList m_gen_acls;

    std::string m_issuer;
    std::vector<std::string> m_audiences;
    scitokens::Validator m_validator;
};

}
