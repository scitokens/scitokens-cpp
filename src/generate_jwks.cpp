#include <cstdio>
#include <cstring>
#include <fstream>
#include <getopt.h>
#include <memory>
#include <sstream>
#include <string>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#define EC_NAME NID_X9_62_prime256v1

namespace {

const char usage[] =
    "\n"
    "Generate an EC key pair and output in JWKS and PEM formats.\n"
    "\n"
    "Syntax: %s [--kid key_id] [--jwks jwks_file] [--private private_file] "
    "[--public public_file]\n"
    "\n"
    " Options\n"
    "    -h | --help                    Display usage\n"
    "    -k | --kid        <key_id>     Key ID for the JWKS (default: "
    "\"key-es256\")\n"
    "    -j | --jwks    <jwks_file>     Output file for JWKS (default: "
    "\"jwks.json\")\n"
    "    -p | --private <private_file>  Output file for private key PEM "
    "(default: \"private.pem\")\n"
    "    -P | --public  <public_file>   Output file for public key PEM "
    "(default: \"public.pem\")\n"
    "\n";

const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"kid", required_argument, NULL, 'k'},
    {"jwks", required_argument, NULL, 'j'},
    {"private", required_argument, NULL, 'p'},
    {"public", required_argument, NULL, 'P'},
    {0, 0, 0, 0}};

const char short_options[] = "hk:j:p:P:";

std::string g_kid = "key-es256";
std::string g_jwks_file = "jwks.json";
std::string g_private_file = "private.pem";
std::string g_public_file = "public.pem";

int init_arguments(int argc, char *argv[]) {
    int arg;
    while ((arg = getopt_long(argc, argv, short_options, long_options,
                              nullptr)) != -1) {
        switch (arg) {
        case 'h':
            printf(usage, argv[0]);
            exit(0);
            break;
        case 'k':
            g_kid = optarg;
            break;
        case 'j':
            g_jwks_file = optarg;
            break;
        case 'p':
            g_private_file = optarg;
            break;
        case 'P':
            g_public_file = optarg;
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

    return 0;
}

// Base64url encode without padding
std::string base64url_encode(const unsigned char *data, size_t len) {
    static const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    std::string result;
    result.reserve(((len + 2) / 3) * 4);

    for (size_t i = 0; i < len; i += 3) {
        unsigned int val = data[i] << 16;
        if (i + 1 < len)
            val |= data[i + 1] << 8;
        if (i + 2 < len)
            val |= data[i + 2];

        result.push_back(base64_chars[(val >> 18) & 0x3F]);
        result.push_back(base64_chars[(val >> 12) & 0x3F]);
        if (i + 1 < len) {
            result.push_back(base64_chars[(val >> 6) & 0x3F]);
        }
        if (i + 2 < len) {
            result.push_back(base64_chars[val & 0x3F]);
        }
    }

    // Remove padding
    return result;
}

// Extract coordinates from EC key for JWKS
bool extract_ec_coordinates(EVP_PKEY *pkey, std::string &x_coord,
                            std::string &y_coord) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    unsigned char *pub_key_buf = nullptr;
    size_t pub_key_len = 0;

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        nullptr, 0, &pub_key_len) != 1) {
        return false;
    }

    pub_key_buf = (unsigned char *)malloc(pub_key_len);
    if (!pub_key_buf) {
        return false;
    }

    if (EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        pub_key_buf, pub_key_len,
                                        &pub_key_len) != 1) {
        free(pub_key_buf);
        return false;
    }

    // For uncompressed EC point format: 0x04 || X || Y
    if (pub_key_len != 65 || pub_key_buf[0] != 0x04) {
        free(pub_key_buf);
        return false;
    }

    x_coord = base64url_encode(pub_key_buf + 1, 32);
    y_coord = base64url_encode(pub_key_buf + 33, 32);
    free(pub_key_buf);
#else
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey);
    if (!ec_key) {
        return false;
    }

    const EC_POINT *pub_key = EC_KEY_get0_public_key(ec_key);
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    if (!pub_key || !group) {
        EC_KEY_free(ec_key);
        return false;
    }

    std::unique_ptr<BIGNUM, decltype(&BN_free)> x(BN_new(), BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> y(BN_new(), BN_free);

    if (!EC_POINT_get_affine_coordinates_GFp(group, pub_key, x.get(), y.get(),
                                             nullptr)) {
        EC_KEY_free(ec_key);
        return false;
    }

    // Convert BIGNUMs to fixed-size byte arrays (32 bytes for P-256)
    unsigned char x_buf[32] = {0};
    unsigned char y_buf[32] = {0};

    int x_len = BN_num_bytes(x.get());
    int y_len = BN_num_bytes(y.get());

    BN_bn2bin(x.get(), x_buf + (32 - x_len));
    BN_bn2bin(y.get(), y_buf + (32 - y_len));

    x_coord = base64url_encode(x_buf, 32);
    y_coord = base64url_encode(y_buf, 32);

    EC_KEY_free(ec_key);
#endif

    return true;
}

} // namespace

int main(int argc, char *argv[]) {
    if (init_arguments(argc, argv)) {
        return 1;
    }

    // Generate EC key
    EVP_PKEY *pkey = nullptr;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(
        EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);

    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) {
        fprintf(stderr, "Failed to initialize EC key generation context\n");
        return 1;
    }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 (char *)"prime256v1", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(ctx.get(), params) <= 0) {
        fprintf(stderr, "Failed to set EC curve parameters\n");
        return 1;
    }

    if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) {
        fprintf(stderr, "Failed to generate EC key\n");
        return 1;
    }
#else
    std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> ec_key(
        EC_KEY_new_by_curve_name(EC_NAME), EC_KEY_free);

    if (!ec_key) {
        fprintf(stderr, "Failed to create EC key\n");
        return 1;
    }

    if (EC_KEY_generate_key(ec_key.get()) != 1) {
        fprintf(stderr, "Failed to generate EC key\n");
        return 1;
    }

    pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_assign_EC_KEY(pkey, ec_key.release()) != 1) {
        fprintf(stderr, "Failed to create EVP_PKEY\n");
        if (pkey) {
            EVP_PKEY_free(pkey);
        }
        return 1;
    }
#endif

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_ptr(
        pkey, EVP_PKEY_free);

    // Extract EC coordinates for JWKS
    std::string x_coord, y_coord;
    if (!extract_ec_coordinates(pkey, x_coord, y_coord)) {
        fprintf(stderr, "Failed to extract EC coordinates\n");
        return 1;
    }

    // Write JWKS file
    std::ofstream jwks_out(g_jwks_file);
    if (!jwks_out) {
        fprintf(stderr, "Failed to open %s for writing\n",
                g_jwks_file.c_str());
        return 1;
    }

    jwks_out << "{\n";
    jwks_out << "  \"keys\": [\n";
    jwks_out << "    {\n";
    jwks_out << "      \"alg\": \"ES256\",\n";
    jwks_out << "      \"kty\": \"EC\",\n";
    jwks_out << "      \"use\": \"sig\",\n";
    jwks_out << "      \"crv\": \"P-256\",\n";
    jwks_out << "      \"kid\": \"" << g_kid << "\",\n";
    jwks_out << "      \"x\": \"" << x_coord << "\",\n";
    jwks_out << "      \"y\": \"" << y_coord << "\"\n";
    jwks_out << "    }\n";
    jwks_out << "  ]\n";
    jwks_out << "}\n";
    jwks_out.close();

    printf("JWKS written to: %s\n", g_jwks_file.c_str());

    // Write public key PEM
    std::unique_ptr<BIO, decltype(&BIO_free_all)> pub_bio(BIO_new_file(
                                                               g_public_file.c_str(), "w"),
                                                           BIO_free_all);
    if (!pub_bio) {
        fprintf(stderr, "Failed to open %s for writing\n",
                g_public_file.c_str());
        return 1;
    }

    if (PEM_write_bio_PUBKEY(pub_bio.get(), pkey) != 1) {
        fprintf(stderr, "Failed to write public key\n");
        return 1;
    }

    printf("Public key written to: %s\n", g_public_file.c_str());

    // Write private key PEM
    std::unique_ptr<BIO, decltype(&BIO_free_all)> priv_bio(BIO_new_file(
                                                                g_private_file.c_str(), "w"),
                                                            BIO_free_all);
    if (!priv_bio) {
        fprintf(stderr, "Failed to open %s for writing\n",
                g_private_file.c_str());
        return 1;
    }

    if (PEM_write_bio_PrivateKey(priv_bio.get(), pkey, nullptr, nullptr, 0,
                                 nullptr, nullptr) != 1) {
        fprintf(stderr, "Failed to write private key\n");
        return 1;
    }

    printf("Private key written to: %s\n", g_private_file.c_str());

    return 0;
}
