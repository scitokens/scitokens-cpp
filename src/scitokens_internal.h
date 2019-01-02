
#include <memory>

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

class SciToken {

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
    deserialize(const std::string &data);

private:
    bool m_issuer_set{false};
    int m_lifetime{600};
    jwt::builder m_builder;
    std::unique_ptr<jwt::decoded_jwt> m_decoded;
    SciTokenKey &m_key;
};

class Validator {

public:
    void verify(jwt::decoded_jwt &jwt) {
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

        std::string public_pem;
        std::string algorithm;
        get_public_key_pem(jwt.get_issuer(), jwt.get_key_id(), public_pem, algorithm);
        // std::cout << "Public PEM: " << public_pem << std::endl << "Algorithm: " << algorithm << std::endl;
        SciTokenKey key(jwt.get_key_id(), algorithm, public_pem, "");
        auto verifier = jwt::verify()
            .allow_algorithm(key);

        verifier.verify(jwt);
    }

private:
    void get_public_key_pem(const std::string &issuer, const std::string &kid, std::string &public_pem, std::string &algorithm);
};

}
