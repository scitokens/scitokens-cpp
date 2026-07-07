#include "scitokens.h"

#include <fstream>
#include <getopt.h>
#include <iostream>
#include <string>

namespace {

const char usage[] =
    "\n"
    "Syntax: %s [--cred cred_file] < TOKENFILE\n"
    "\n"
    " Options\n"
    "    -h | --help                  Display usage\n"
    "    -c | --cred     <cred_file>  File containing the signing credential.\n"
    "    -i | --issuer      <issuer>  Issuer of the token to verify.\n"
    "    -K | --keyid          <kid>  Name of the token key.\n"
    "    -p | --profile    <profile>  Profile to enforce (wlcg, scitokens1, "
    "scitokens2, atjwt).\n"
    "\n"
    "    The token to verify must be provided via standard input (stdin).\n";

const struct option long_options[] = {{"help", no_argument, NULL, 'h'},
                                      {"cred", required_argument, NULL, 'c'},
                                      {"issuer", required_argument, NULL, 'i'},
                                      {"keyid", required_argument, NULL, 'K'},
                                      {"profile", required_argument, NULL, 'p'},
                                      {0, 0, 0, 0}};

const char short_options[] = "hc:i:K:p:";

std::string g_cred, g_issuer, g_keyid, g_profile;

int init_arguments(int argc, char *const argv[]) {
    int arg;
    while ((arg = getopt_long(argc, argv, short_options, long_options,
                              nullptr)) != -1) {
        switch (arg) {
        case 'h':
            printf(usage, argv[0]);
            exit(0);
            break;
        case 'c':
            g_cred = optarg;
            break;
        case 'i':
            g_issuer = optarg;
            break;
        case 'K':
            g_keyid = optarg;
            break;
        case 'p':
            g_profile = optarg;
            break;
        default:
            fprintf(stderr, usage, argv[0]);
            exit(1);
            break;
        }
    }

    if (optind < argc - 1) {
        fprintf(stderr, "%s: invalid option -- %s\n", argv[0], argv[optind]);
        fprintf(stderr, usage, argv[0]);
        exit(1);
    }

    if ((!g_cred.empty() || !g_issuer.empty() || !g_keyid.empty()) &&
        (g_cred.empty() || g_issuer.empty() || g_keyid.empty())) {
        fprintf(stderr,
                "%s: If --cred, --keyid, or --issuer are set, then all must be "
                "set.\n",
                argv[0]);
        fprintf(stderr, usage, argv[0]);
        exit(1);
    }

    return 0;
}

} // namespace

int main(int argc, char *const *argv) {

    if (init_arguments(argc, argv)) {
        return 1;
    }

    std::string token;
    // If a positional argument is present, treat it as the token (with warning)
    if (optind < argc) {
        std::cout << argv[0]
                  << ": Warning: Providing the token on the command line is "
                  << "insecure. Please use stdin instead." << std::endl;
        token = argv[optind];
    } else {
        // Read token from stdin
        std::getline(std::cin, token);
    }
    if (token.empty()) {
        fprintf(stderr, "%s: No token provided on stdin or command line.\n",
                argv[0]);
        fprintf(stderr, usage, argv[0]);
        return 1;
    }

    if (!g_issuer.empty()) {
        char *err_msg;

        std::ifstream pub_ifs(g_cred);
        std::string public_contents((std::istreambuf_iterator<char>(pub_ifs)),
                                    (std::istreambuf_iterator<char>()));

        auto rv =
            scitoken_store_public_ec_key(g_issuer.c_str(), g_keyid.c_str(),
                                         public_contents.c_str(), &err_msg);
        if (rv) {
            fprintf(stderr, "%s: %s\n", argv[0], err_msg);
            free(err_msg);
            return 1;
        }
    }

    char *err_msg = nullptr;
    SciToken scitoken = nullptr;
    SciTokenKey dummy_key = nullptr;
    if (g_profile.empty()) {
        if (scitoken_deserialize(token.c_str(), &scitoken, nullptr, &err_msg)) {
            std::cout << "Failed to deserialize a token: " << err_msg
                      << std::endl;
            free(err_msg);
            return 1;
        }
    } else {
        // The --profile option restricts which token profile is acceptable;
        // it requires creating the token object up front so the deserialize
        // profile can be set before parsing.
        SciTokenProfile profile;
        if (g_profile == "wlcg") {
            profile = SciTokenProfile::WLCG_1_0;
        } else if (g_profile == "scitokens1") {
            profile = SciTokenProfile::SCITOKENS_1_0;
        } else if (g_profile == "scitokens2") {
            profile = SciTokenProfile::SCITOKENS_2_0;
        } else if (g_profile == "atjwt") {
            profile = SciTokenProfile::AT_JWT;
        } else {
            fprintf(stderr, "%s: unknown token profile: %s\n", argv[0],
                    g_profile.c_str());
            return 1;
        }

        // No signing key is needed for verification.
        dummy_key = scitoken_key_create("none", "none", "", "", &err_msg);
        if (dummy_key == nullptr) {
            fprintf(stderr, "%s: %s\n", argv[0], err_msg);
            free(err_msg);
            return 1;
        }
        scitoken = scitoken_create(dummy_key);
        scitoken_set_deserialize_profile(scitoken, profile);
        if (scitoken_deserialize_v2(token.c_str(), scitoken, nullptr,
                                    &err_msg)) {
            std::cout << "Failed to deserialize a token: " << err_msg
                      << std::endl;
            free(err_msg);
            scitoken_destroy(scitoken);
            scitoken_key_destroy(dummy_key);
            return 1;
        }
    }
    scitoken_destroy(scitoken);
    if (dummy_key != nullptr) {
        scitoken_key_destroy(dummy_key);
    }
    std::cout << "Token deserialization successful." << std::endl;

    return 0;
}
