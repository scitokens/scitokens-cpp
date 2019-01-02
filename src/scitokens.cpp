
#include <exception>

#include <string.h>

#include "scitokens.h"
#include "scitokens_internal.h"

SciTokenKey scitoken_key_create(const char *key_id, const char *alg, const char *public_contents, const char *private_contents, char **err_msg) {
    if (key_id == nullptr) {
        if (err_msg) {*err_msg = strdup("Key ID cannot be NULL.");}
        return nullptr;
    }
    if (alg == nullptr) {
        if (err_msg) {*err_msg = strdup("Algorithm cannot be NULL.");}
        return nullptr;
    }
    if (public_contents == nullptr) {
        if (err_msg) {*err_msg = strdup("Public key contents cannot be NULL.");}
        return nullptr;
    }
    if (private_contents == nullptr) {
        if (err_msg) {*err_msg = strdup("Private key contents cannot be NULL.");}
        return nullptr;
    }
    return new scitokens::SciTokenKey(key_id, alg, public_contents, private_contents);
}

void scitoken_key_destroy(SciTokenKey token) {
    scitokens::SciTokenKey *real_token = reinterpret_cast<scitokens::SciTokenKey*>(token);
    delete real_token;
}

SciToken scitoken_create(SciTokenKey private_key) {
    scitokens::SciTokenKey *key = reinterpret_cast<scitokens::SciTokenKey*>(private_key);
    return new scitokens::SciToken(*key);
}

void scitoken_destroy(SciToken token) {
    scitokens::SciToken *real_token = reinterpret_cast<scitokens::SciToken*>(token);
    delete real_token;
}

int scitoken_set_claim_string(SciToken token, const char *key, const char *value, char **err_msg) {
    scitokens::SciToken *real_token = reinterpret_cast<scitokens::SciToken*>(token);
    if (real_token == nullptr) {
        if (err_msg) {*err_msg = strdup("Token passed is not initialized.");}
        return -1;
    }
    if (key == nullptr) {
        if (err_msg) {*err_msg = strdup("Claim key passed is not initialized.");}
        return -1;
    }
    if (value == nullptr) {
        if (err_msg) {*err_msg = strdup("Claim value passed is not initialized.");}
        return -1;
    }
    try {
        real_token->set_claim(key, std::string(value));
    } catch (std::exception &exc) {
        if (err_msg) {
            *err_msg = strdup(exc.what());
        }
        return -1;
    }
    return 0;
}

int scitoken_get_claim_string(const SciToken token, const char *key, char **value, char **err_msg) {
    if (err_msg) {
        *err_msg = strdup("This function is not implemented");
    }
    return -1;
}


void scitoken_set_lifetime(SciToken token, int lifetime) {
    if (token == nullptr) {return;}
    scitokens::SciToken *real_token = reinterpret_cast<scitokens::SciToken*>(token);
    real_token->set_lifetime(lifetime);
}


int scitoken_serialize(const SciToken token, char **value, char **err_msg) {
    if (value == nullptr) {
        if (err_msg) {*err_msg = strdup("Output variable not provided");}
        return -1;
    }
    scitokens::SciToken *real_token = reinterpret_cast<scitokens::SciToken*>(token);
    try {
        std::string serialized = real_token->serialize();
        *value = strdup(serialized.c_str());
    } catch (std::exception &exc) {
        if (err_msg) {
            *err_msg = strdup(exc.what());
        }
        return -1;
    }
    return 0;
}

int scitoken_deserialize(const char *value, SciToken *token, char **err_msg) {
    if (value == nullptr) {
        if (err_msg) {*err_msg = strdup("Token may not be NULL");}
        return -1;
    }
    if (token == nullptr) {
        if (err_msg) {*err_msg = strdup("Output token not provided");}
        return -1;
    }

    scitokens::SciTokenKey key;
    scitokens::SciToken *real_token = new scitokens::SciToken(key);

    try {
        real_token->deserialize(value);
    } catch (std::exception &exc) {
        if (err_msg) {
            *err_msg = strdup(exc.what());
        }
        return -1;
    }
    *token = real_token;
    return 0;
}

Validator validator_create() {
    return nullptr;
}

int validator_add(ValidatorFunction validator_func) {
    return -1;
}

Enforcer enforcer(const char *issuer, const char **audience) {
    return nullptr;
}

int enforcer_generate_acls(const Enforcer enf, const SciToken sci, char **Acl, char **err_msg) {
    if (err_msg) {
        *err_msg = strdup("This function is not implemented");
    }
    return -1;
}

int enforcer_test(const Enforcer enf, const SciToken sci, const Acl *acl) {
    return -1;
}

