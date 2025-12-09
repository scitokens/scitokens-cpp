#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <getopt.h>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

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
    "generated from public key fingerprint)\n"
    "    -j | --jwks    <jwks_file>     Output file for JWKS (default: "
    "\"jwks.json\")\n"
    "    -p | --private <private_file>  Output file for private key PEM "
    "(default: \"private.pem\")\n"
    "    -P | --public  <public_file>   Output file for public key PEM "
    "(default: \"public.pem\")\n"
    "\n";

const struct option long_options[] = {{"help", no_argument, NULL, 'h'},
                                      {"kid", required_argument, NULL, 'k'},
                                      {"jwks", required_argument, NULL, 'j'},
                                      {"private", required_argument, NULL, 'p'},
                                      {"public", required_argument, NULL, 'P'},
                                      {0, 0, 0, 0}};

const char short_options[] = "hk:j:p:P:";

std::string g_kid = ""; // Empty by default, will be generated from fingerprint
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
    // For OpenSSL 3.0+, use the BIGNUM parameter API which is more reliable
    BIGNUM *x_bn = nullptr;
    BIGNUM *y_bn = nullptr;

    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x_bn) != 1 ||
        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y_bn) != 1) {
        BN_free(x_bn);
        BN_free(y_bn);
        return false;
    }

    std::unique_ptr<BIGNUM, decltype(&BN_free)> x(x_bn, BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> y(y_bn, BN_free);

    // Convert BIGNUMs to fixed-size byte arrays (32 bytes for P-256)
    unsigned char x_buf[32] = {0};
    unsigned char y_buf[32] = {0};

    int x_len = BN_num_bytes(x.get());
    int y_len = BN_num_bytes(y.get());

    // Pad with zeros on the left if necessary
    BN_bn2bin(x.get(), x_buf + (32 - x_len));
    BN_bn2bin(y.get(), y_buf + (32 - y_len));

    x_coord = base64url_encode(x_buf, 32);
    y_coord = base64url_encode(y_buf, 32);
#else
    std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> ec_key(
        EVP_PKEY_get1_EC_KEY(pkey), EC_KEY_free);
    if (!ec_key) {
        return false;
    }

    const EC_POINT *pub_key = EC_KEY_get0_public_key(ec_key.get());
    const EC_GROUP *group = EC_KEY_get0_group(ec_key.get());
    if (!pub_key || !group) {
        return false;
    }

    std::unique_ptr<BIGNUM, decltype(&BN_free)> x(BN_new(), BN_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> y(BN_new(), BN_free);

    // Use EC_POINT_get_affine_coordinates for OpenSSL 1.1.1+
    // or EC_POINT_get_affine_coordinates_GFp for older versions
    int result = 0;
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    result = EC_POINT_get_affine_coordinates(group, pub_key, x.get(), y.get(),
                                             nullptr);
#else
    result = EC_POINT_get_affine_coordinates_GFp(group, pub_key, x.get(),
                                                 y.get(), nullptr);
#endif

    if (result != 1) {
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
#endif

    return true;
}

// Generate a key ID from the public key fingerprint
std::string generate_key_id(EVP_PKEY *pkey) {
    // Get the public key in DER format
    std::unique_ptr<BIO, decltype(&BIO_free_all)> bio(BIO_new(BIO_s_mem()),
                                                      BIO_free_all);
    if (!bio) {
        return "";
    }

    if (i2d_PUBKEY_bio(bio.get(), pkey) != 1) {
        return "";
    }

    // Get the DER data
    char *der_data = nullptr;
    long der_len = BIO_get_mem_data(bio.get(), &der_data);
    if (der_len <= 0 || !der_data) {
        return "";
    }

    // Compute SHA256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(der_data), der_len, hash);

    // Convert first 4 bytes to hex (8 characters)
    std::ostringstream oss;
    for (int i = 0; i < 4; i++) {
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(hash[i]);
    }

    return oss.str();
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
    const char *curve_name = "prime256v1";
    params[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_PKEY_PARAM_GROUP_NAME, const_cast<char *>(curve_name), 0);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(ctx.get(), params) <= 0) {
        fprintf(stderr, "Failed to set EC curve parameters\n");
        return 1;
    }

    if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) {
        fprintf(stderr, "Failed to generate EC key\n");
        return 1;
    }

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_ptr(pkey,
                                                                 EVP_PKEY_free);
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

    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey_ptr(EVP_PKEY_new(),
                                                                 EVP_PKEY_free);
    if (!pkey_ptr) {
        fprintf(stderr, "Failed to create EVP_PKEY\n");
        return 1;
    }

    if (EVP_PKEY_assign_EC_KEY(pkey_ptr.get(), ec_key.get()) != 1) {
        fprintf(stderr, "Failed to assign EC key to EVP_PKEY\n");
        return 1;
    }
    // Successfully assigned; release ownership from ec_key
    ec_key.release();
#endif

    // Extract EC coordinates for JWKS
    std::string x_coord, y_coord;
    if (!extract_ec_coordinates(pkey_ptr.get(), x_coord, y_coord)) {
        fprintf(stderr, "Failed to extract EC coordinates\n");
        return 1;
    }

    // Generate key ID from fingerprint if not specified
    if (g_kid.empty()) {
        g_kid = generate_key_id(pkey_ptr.get());
        if (g_kid.empty()) {
            fprintf(stderr, "Failed to generate key ID from fingerprint\n");
            return 1;
        }
    }

    // Write JWKS file
    std::ofstream jwks_out(g_jwks_file);
    if (!jwks_out) {
        fprintf(stderr, "Failed to open %s for writing\n", g_jwks_file.c_str());
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

    printf("JWKS written to: %s\n", g_jwks_file.c_str());

    // Write public key PEM
    std::unique_ptr<BIO, decltype(&BIO_free_all)> pub_bio(
        BIO_new_file(g_public_file.c_str(), "w"), BIO_free_all);
    if (!pub_bio) {
        fprintf(stderr, "Failed to open %s for writing\n",
                g_public_file.c_str());
        return 1;
    }

    if (PEM_write_bio_PUBKEY(pub_bio.get(), pkey_ptr.get()) != 1) {
        fprintf(stderr, "Failed to write public key\n");
        return 1;
    }

    printf("Public key written to: %s\n", g_public_file.c_str());

    // Write private key PEM with secure permissions (0600)
    // First, create the file with restrictive permissions
    int fd = open(g_private_file.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        fprintf(stderr, "Failed to create %s with secure permissions\n",
                g_private_file.c_str());
        return 1;
    }
    close(fd);

    std::unique_ptr<BIO, decltype(&BIO_free_all)> priv_bio(
        BIO_new_file(g_private_file.c_str(), "w"), BIO_free_all);
    if (!priv_bio) {
        fprintf(stderr, "Failed to open %s for writing\n",
                g_private_file.c_str());
        return 1;
    }

    if (PEM_write_bio_PrivateKey(priv_bio.get(), pkey_ptr.get(), nullptr,
                                 nullptr, 0, nullptr, nullptr) != 1) {
        fprintf(stderr, "Failed to write private key\n");
        return 1;
    }

    printf("Private key written to: %s\n", g_private_file.c_str());

    return 0;
}
