#include <iostream>

#include "scitokens.h"

int main(int argc, const char **argv) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " (TOKEN) (ISSUER) (AUDIENCE)"
                  << std::endl;
        return 1;
    }
    std::string token(argv[1]);
    std::string issuer(argv[2]);
    std::string audience(argv[3]);

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
    Acl *acls;
    if (enforcer_generate_acls(enf, scitoken, &acls, &err_msg)) {
        std::cout << "ACL generation failed: " << err_msg << std::endl;
        return 1;
    }
    std::cout << "Start of ACLs:" << std::endl;
    for (int idx = 0; acls[idx].authz && acls[idx].resource; idx++) {
        std::cout << "ACL: " << acls[idx].authz << ":" << acls[idx].resource
                  << std::endl;
    }
    std::cout << "End of ACLs:" << std::endl;

    enforcer_destroy(enf);
    return 0;
}
