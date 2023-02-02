
#include "scitokens.h"

#include <getopt.h>
#include <stdlib.h>

#include <cstdio>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace {

const char usage[] =
    "\n"
    "Syntax: %s [--cred cred_file] [--key key_file] [--keyid kid]\n"
    "           [--claim key=val] ...\n"
    "\n"
    " Options\n"
    "    -h | --help                        Display usage\n"
    "    -c | --cred           <cred_file>  File containing signing "
    "credential.\n"
    "    -k | --key             <key_file>  File containing the signing "
    "private key.\n"
    "    -K | --keyid                <kid>  Name of the token key.\n"
    "    -i | --issuer            <issuer>  Issuer for the token.\n"
    "    -p | --profile          <profile>  Token profile (wlcg, scitokens1, "
    "scitokens2, atjwt).\n"
    "\n";

const struct option long_options[] = {{"help", no_argument, NULL, 'h'},
                                      {"cred", required_argument, NULL, 'c'},
                                      {"key", required_argument, NULL, 'k'},
                                      {"keyid", required_argument, NULL, 'K'},
                                      {"issuer", required_argument, NULL, 'i'},
                                      {"claim", required_argument, NULL, 'C'},
                                      {"profile", required_argument, NULL, 'p'},
                                      {0, 0, 0, 0}};

const char short_options[] = "hc:k:K:i:C:p:";

std::string g_cred, g_key, g_kid, g_issuer, g_profile;
std::vector<std::string> g_claims;

int init_arguments(int argc, char *argv[]) {

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
        case 'k':
            g_key = optarg;
            break;
        case 'K':
            g_kid = optarg;
            break;
        case 'i':
            g_issuer = optarg;
            break;
        case 'C':
            g_claims.emplace_back(optarg);
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

    if (optind != argc) {
        fprintf(stderr, "%s: invalid option -- %s\n", argv[0], argv[optind]);
        fprintf(stderr, usage, argv[0]);
        exit(1);
    }

    if (g_cred.empty()) {
        fprintf(stderr, "%s: missing --cred option\n", argv[0]);
        fprintf(stderr, usage, argv[0]);
        exit(1);
    }

    if (g_key.empty()) {
        fprintf(stderr, "%s: missing --key option\n", argv[0]);
        fprintf(stderr, usage, argv[0]);
        exit(1);
    }

    if (g_kid.empty()) {
        fprintf(stderr, "%s: missing --keyid option\n", argv[0]);
        fprintf(stderr, usage, argv[0]);
        exit(1);
    }

    if (g_issuer.empty()) {
        fprintf(stderr, "%s: missing --issuer option\n", argv[0]);
        fprintf(stderr, usage, argv[0]);
        exit(1);
    }

    return 0;
}

} // namespace

int main(int argc, char *argv[]) {

    int rv = init_arguments(argc, argv);
    if (rv) {
        return rv;
    }

    std::ifstream priv_ifs(g_key);
    std::string private_contents((std::istreambuf_iterator<char>(priv_ifs)),
                                 (std::istreambuf_iterator<char>()));
    std::ifstream pub_ifs(g_cred);
    std::string public_contents((std::istreambuf_iterator<char>(pub_ifs)),
                                (std::istreambuf_iterator<char>()));

    char *err_msg;
    auto key_raw =
        scitoken_key_create(g_kid.c_str(), "ES256", public_contents.c_str(),
                            private_contents.c_str(), &err_msg);
    std::unique_ptr<void, decltype(&scitoken_key_destroy)> key(
        key_raw, scitoken_key_destroy);
    if (key_raw == nullptr) {
        fprintf(stderr, "Failed to generate a key: %s\n", err_msg);
        free(err_msg);
        return 1;
    }

    std::unique_ptr<void, decltype(&scitoken_destroy)> token(
        scitoken_create(key_raw), scitoken_destroy);
    if (token.get() == nullptr) {
        fprintf(stderr, "Failed to generate a new token.\n");
        return 1;
    }

    rv = scitoken_set_claim_string(token.get(), "iss", g_issuer.c_str(),
                                   &err_msg);
    if (rv) {
        fprintf(stderr, "Failed to set issuer: %s\n", err_msg);
        free(err_msg);
        return 1;
    }

    for (const auto &claim : g_claims) {
        auto pos = claim.find("=");
        if (pos == std::string::npos) {
            fprintf(stderr, "Claim must contain a '=' character: %s\n",
                    claim.c_str());
            return 1;
        }
        auto key = claim.substr(0, pos);
        auto val = claim.substr(pos + 1);

        rv = scitoken_set_claim_string(token.get(), key.c_str(), val.c_str(),
                                       &err_msg);
        if (rv) {
            fprintf(stderr, "Failed to set claim (%s=%s): %s\n", key.c_str(),
                    val.c_str(), err_msg);
            free(err_msg);
            return 1;
        }
    }

    if (!g_profile.empty()) {
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
            fprintf(stderr, "Unknown token profile: %s\n", g_profile.c_str());
            return 1;
        }
        scitoken_set_serialize_mode(token.get(), profile);
    }

    char *value;
    rv = scitoken_serialize(token.get(), &value, &err_msg);
    if (rv) {
        fprintf(stderr, "Failed to serialize the token: %s\n", err_msg);
        free(err_msg);
        return 1;
    }

    printf("%s\n", value);
}
