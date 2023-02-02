#include <iostream>

#include "scitokens.h"

int main(int argc, const char **argv) {
    if (argc < 6) {
        std::cerr << "Usage: " << argv[0]
                  << " (TOKEN) (ISSUER) (AUDIENCE) (AUTHZ) (PATH)" << std::endl;
        return 1;
    }
    std::string token(argv[1]);
    std::string issuer(argv[2]);
    std::string audience(argv[3]);
    std::string authz(argv[4]);
    std::string path(argv[5]);

    const char *aud_list[2];
    aud_list[0] = audience.c_str();
    aud_list[1] = nullptr;

    SciToken scitoken;
    char *err_msg = nullptr;
    if (scitoken_deserialize(token.c_str(), &scitoken, nullptr, &err_msg)) {
        std::cout << "Failed to deserialize a token: " << err_msg << std::endl;
        return 1;
    }
    std::cout << "Token deserialization successful.  Checking authorizations."
              << std::endl;
    Enforcer enf;
    if (!(enf = enforcer_create(issuer.c_str(), aud_list, &err_msg))) {
        std::cout << "Failed to create a new enforcer object: " << err_msg
                  << std::endl;
        return 1;
    }
    const Acl acl{authz.c_str(), path.c_str()};
    if (enforcer_test(enf, scitoken, &acl, &err_msg)) {
        if (err_msg) {
            std::cout << "Access test failed: " << err_msg << std::endl;
        } else {
            std::cout << "Access test failed." << std::endl;
        }
        return 1;
    }
    std::cout << "Access test successful." << std::endl;

    enforcer_destroy(enf);
    return 0;
}
