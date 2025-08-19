/**
 * Public header for the SciTokens C library.
 *
 *
 */

#include <sys/select.h>
#include <time.h>

#ifdef __cplusplus
#include <ctime>
extern "C" {
#else
#include <time.h>
#endif

/** @brief Opaque handle for cryptographic keys used to sign/verify tokens */
typedef void *SciTokenKey;

/** @brief Opaque handle for SciToken objects */
typedef void *SciToken;

/** @brief Opaque handle for token validators */
typedef void *Validator;

/** @brief Opaque handle for token enforcers that generate ACLs */
typedef void *Enforcer;

/** @brief Opaque handle for asynchronous operation status */
typedef void *SciTokenStatus;

/** @brief Opaque handle for configuration objects */
typedef void *Configuration;

/** @brief Function pointer type for custom string validation */
typedef int (*StringValidatorFunction)(const char *value, char **err_msg);

/** @brief Access Control List entry containing authorization and resource */
typedef struct Acl_s {
    const char *authz;    /**< Authorization type (e.g., "read", "write") */
    const char *resource; /**< Resource path or pattern */
} Acl;

/**
 * Determine the mode we will use to validate tokens.
 * - COMPAT mode (default) indicates any supported token format
 *   is acceptable.  Where possible, the scope names are translated into
 *   equivalent SciTokens 1.0 claim names (i.e., storage.read -> read;
 * storage.write -> write). If a typ header claim is present, use that to deduce
 * type (RFC8725 Section 3.11).
 * - SCITOKENS_1_0, SCITOKENS_2_0, WLCG_1_0, AT_JWT: only accept these specific
 * profiles. No automatic translation is performed.
 */
typedef enum _profile {
    COMPAT = 0,
    SCITOKENS_1_0,
    SCITOKENS_2_0,
    WLCG_1_0,
    AT_JWT
} SciTokenProfile;

/**
 * @brief Create a cryptographic key for signing tokens
 *
 * @param key_id Identifier for the key (used in 'kid' header)
 * @param algorithm Signing algorithm (e.g., "ES256", "RS256")
 * @param public_contents PEM-encoded public key
 * @param private_contents PEM-encoded private key
 * @param err_msg Output parameter for error messages (caller must free)
 * @return SciTokenKey handle on success, NULL on failure
 */
SciTokenKey scitoken_key_create(const char *key_id, const char *algorithm,
                                const char *public_contents,
                                const char *private_contents, char **err_msg);

/**
 * @brief Destroy a key object and free associated memory
 *
 * @param private_key Key handle to destroy
 */
void scitoken_key_destroy(SciTokenKey private_key);

/**
 * @brief Create a new SciToken
 *
 * @param private_key Key to use for signing, or NULL for unsigned token
 * @return SciToken handle on success, NULL on failure
 */
SciToken scitoken_create(SciTokenKey private_key);

/**
 * @brief Destroy a token object and free associated memory
 *
 * @param token Token handle to destroy
 */
void scitoken_destroy(SciToken token);

/**
 * @brief Set a string claim in the token
 *
 * @param token Token to modify
 * @param key Claim name (e.g., "iss", "aud", "scope")
 * @param value Claim value
 * @param err_msg Output parameter for error messages (caller must free)
 * @return 0 on success, non-zero on failure
 */
int scitoken_set_claim_string(SciToken token, const char *key,
                              const char *value, char **err_msg);

/**
 * @brief Get a string claim from the token
 *
 * @param token Token to query
 * @param key Claim name to retrieve
 * @param value Output parameter for claim value (caller must free)
 * @param err_msg Output parameter for error messages (caller must free)
 * @return 0 on success, non-zero on failure
 */
int scitoken_get_claim_string(const SciToken token, const char *key,
                              char **value, char **err_msg);

/**
 * Given a SciToken object, parse a specific claim's value as a list of strings.
 * If the JSON value is not actually a list of strings - or the claim is not set
 * - returns an error and sets the err_msg appropriately.
 *
 * The returned value is a list of strings that ends with a nullptr.
 */
int scitoken_get_claim_string_list(const SciToken token, const char *key,
                                   char ***value, char **err_msg);

/**
 * Given a list of strings that was returned by scitoken_get_claim_string_list,
 * free all the associated memory.
 */
void scitoken_free_string_list(char **value);

/**
 * Set the value of a claim to a list of strings.
 */
int scitoken_set_claim_string_list(const SciToken token, const char *key,
                                   const char **values, char **err_msg);

/**
 * @brief Get the expiration time of the token
 *
 * @param token Token to query
 * @param value Output parameter for expiration time (Unix timestamp)
 * @param err_msg Output parameter for error messages (caller must free)
 * @return 0 on success, non-zero on failure
 */
int scitoken_get_expiration(const SciToken token, long long *value,
                            char **err_msg);

/**
 * @brief Set the lifetime of the token in seconds
 *
 * @param token Token to modify
 * @param lifetime Lifetime in seconds from creation
 */
void scitoken_set_lifetime(SciToken token, int lifetime);

/**
 * @brief Serialize the token to a JWT string
 *
 * @param token Token to serialize
 * @param value Output parameter for JWT string (caller must free)
 * @param err_msg Output parameter for error messages (caller must free)
 * @return 0 on success, non-zero on failure
 */
int scitoken_serialize(const SciToken token, char **value, char **err_msg);

/**
 * Set the profile used for serialization; if COMPAT mode is used, then
 * the library default is utilized (currently, scitokens 1.0).
 */
void scitoken_set_serialize_profile(SciToken token, SciTokenProfile profile);

void scitoken_set_serialize_mode(SciToken token, SciTokenProfile profile);

void scitoken_set_deserialize_profile(SciToken token, SciTokenProfile profile);

/**
 * @brief Deserialize a JWT string into a SciToken
 *
 * @param value JWT string to parse
 * @param token Output parameter for created token (caller must destroy)
 * @param allowed_issuers NULL-terminated array of allowed issuer URLs, or NULL
 * for any
 * @param err_msg Output parameter for error messages (caller must free)
 * @return 0 on success, non-zero on failure
 */
int scitoken_deserialize(const char *value, SciToken *token,
                         char const *const *allowed_issuers, char **err_msg);

/**
 * @brief Start the deserialization process for a token, returning a status
 * object.
 *
 * @param value The serialized token.
 * @param token Destination for the token object.
 * @param allowed_issuers List of allowed issuers, or nullptr for no issuer
 * check.
 * @param status Destination for the status object.
 * @param err_msg Destination for error message.
 * @return int 0 on success, -1 on error.
 */

int scitoken_deserialize_start(const char *value, SciToken *token,
                               char const *const *allowed_issuers,
                               SciTokenStatus *status, char **err_msg);

/**
 * @brief Continue the deserialization process for a token, updating the status
 * object.
 *
 * If the status object indicates that the token is complete, the token object
 * will be populated and the status object will be nullptr.
 *
 * @param token The token object, returned from scitoken_deserialize_start.
 * @param status Status object for the deserialize.
 * @param err_msg Destination for error message.
 * @return int 0 on success, -1 on error.
 */

int scitoken_deserialize_continue(SciToken *token, SciTokenStatus *status,
                                  char **err_msg);

int scitoken_deserialize_v2(const char *value, SciToken token,
                            char const *const *allowed_issuers, char **err_msg);

/**
 * @brief Store a public EC key for token verification
 *
 * @param issuer Issuer URL that will use this key
 * @param keyid Key identifier
 * @param value PEM-encoded public key
 * @param err_msg Output parameter for error messages (caller must free)
 * @return 0 on success, non-zero on failure
 */
int scitoken_store_public_ec_key(const char *issuer, const char *keyid,
                                 const char *value, char **err_msg);

/**
 * @brief Create a new token validator
 *
 * @return Validator handle on success, NULL on failure
 */
Validator validator_create();

/**
 * Set the profile used for validating the tokens; COMPAT (default) will accept
 * any known token type while others will only support that specific profile.
 */
void validator_set_token_profile(Validator, SciTokenProfile profile);

/**
 * Set the time to use with the validator.  Useful if you want to see if the
 * token would have been valid at some time in the past.
 */
int validator_set_time(Validator validator, time_t now, char **err_msg);

int validator_add(Validator validator, const char *claim,
                  StringValidatorFunction validator_func, char **err_msg);

int validator_add_critical_claims(Validator validator, const char **claims,
                                  char **err_msg);

/**
 * @brief Validate a SciToken using the configured validator
 *
 * @param validator Validator to use
 * @param scitoken Token to validate
 * @param err_msg Output parameter for error messages (caller must free)
 * @return 0 on success, non-zero on failure
 */
int validator_validate(Validator validator, SciToken scitoken, char **err_msg);

/**
 * @brief Destroy a validator object and free associated memory
 *
 * @param validator Validator handle to destroy
 */
void validator_destroy(Validator validator);

/**
 * @brief Create a new token enforcer
 *
 * @param issuer Required issuer URL for tokens
 * @param audience NULL-terminated array of acceptable audience values
 * @param err_msg Output parameter for error messages (caller must free)
 * @return Enforcer handle on success, NULL on failure
 */
Enforcer enforcer_create(const char *issuer, const char **audience,
                         char **err_msg);

/**
 * @brief Destroy an enforcer object and free associated memory
 *
 * @param enforcer Enforcer handle to destroy
 */
void enforcer_destroy(Enforcer enforcer);

/**
 * Set the profile used for enforcing ACLs; when set to COMPAT (default), then
 * the authorizations will be converted to SciTokens 1.0-style authorizations
 * (so, WLCG's storage.read becomes read).
 */
void enforcer_set_validate_profile(Enforcer, SciTokenProfile profile);

/**
 * Set the time to use with the enforcer.  Useful if you want to see if the
 * token would have been valid at some time in the past.
 */
int enforcer_set_time(Enforcer enf, time_t now, char **err_msg);

/**
 * @brief Generate Access Control Lists from a token
 *
 * @param enf Enforcer to use
 * @param scitokens Token to process
 * @param acls Output parameter for ACL array (caller must free with
 * enforcer_acl_free)
 * @param err_msg Output parameter for error messages (caller must free)
 * @return 0 on success, non-zero on failure
 */
int enforcer_generate_acls(const Enforcer enf, const SciToken scitokens,
                           Acl **acls, char **err_msg);

/**
 * The asynchronous versions of enforcer_generate_acls.
 */
int enforcer_generate_acls_start(const Enforcer enf, const SciToken scitokens,
                                 SciTokenStatus *status, Acl **acls,
                                 char **err_msg);
int enforcer_generate_acls_continue(const Enforcer enf, SciTokenStatus *status,
                                    Acl **acls, char **err_msg);

/**
 * @brief Free an array of ACLs returned by enforcer_generate_acls
 *
 * @param acls ACL array to free
 */
void enforcer_acl_free(Acl *acls);

/**
 * @brief Test if a token grants access for a specific ACL
 *
 * @param enf Enforcer to use
 * @param sci Token to test
 * @param acl ACL to test against
 * @param err_msg Output parameter for error messages (caller must free)
 * @return 0 if access granted, non-zero if denied or error
 */
int enforcer_test(const Enforcer enf, const SciToken sci, const Acl *acl,
                  char **err_msg);

void scitoken_status_free(SciTokenStatus *status);

/**
 * Get the suggested timeout val.  After the timeout value has passed, the
 * asynchronous operation should continue.
 *
 * - `expiry_time`: the expiration time (in Unix epoch seconds) for the
 * operation in total. The returned timeout value will never take the operation
 * past the expiration time.
 */
int scitoken_status_get_timeout_val(const SciTokenStatus *status,
                                    time_t expiry_time, struct timeval *timeout,
                                    char **err_msg);

/**
 * Get the set of read file descriptors.  This will return a borrowed pointer
 * (whose lifetime matches the status object) pointing at a fd_set array of size
 * FD_SETSIZE.  Any file descriptors owned by the status operation will be set
 * and the returned fd_set can be used for select() operations.
 *
 * IMPLEMENTATION NOTE: If the file descriptor monitored by libcurl are too high
 * to be stored in this set, libcurl should give a corresponding low timeout val
 * (100ms) and effectively switch to polling.  See:
 * <https://curl.se/libcurl/c/curl_multi_fdset.html> for more information.
 */
int scitoken_status_get_read_fd_set(SciTokenStatus *status,
                                    fd_set **read_fd_set, char **err_msg);

/**
 * Get the set of write FDs; see documentation for
 * scitoken_status_get_read_fd_set.
 */
int scitoken_status_get_write_fd_set(SciTokenStatus *status,
                                     fd_set **write_fd_set, char **err_msg);

/**
 * Get the set of exception FDs; see documentation for
 * scitoken_status_get_exc_fd_set.
 */
int scitoken_status_get_exc_fd_set(SciTokenStatus *status, fd_set **exc_fd_set,
                                   char **err_msg);

/**
 * Get the maximum FD in the status set.
 *
 * IMPLEMENTATION NOTE: If the max FD is -1 then it implies libcurl is something
 * that cannot be modelled by a socket.  In such a case, the libcurl docs
 * suggest using a 100ms timeout for select operations. See
 * <https://curl.se/libcurl/c/curl_multi_fdset.html>.
 */
int scitoken_status_get_max_fd(const SciTokenStatus *status, int *max_fd,
                               char **err_msg);

/**
 * API for explicity managing the key cache.
 *
 * This manipulates the keycache for the current eUID.
 */

/**
 * Refresh the JWKS in the keycache for a given issuer; the refresh will occur
 * even if the JWKS is not otherwise due for updates.
 * - Returns 0 on success, nonzero on failure.
 */
int keycache_refresh_jwks(const char *issuer, char **err_msg);

/**
 * Retrieve the JWKS from the keycache for a given issuer.
 * - Returns 0 if successful, nonzero on failure.
 * - If the existing JWKS has expired - or does not exist - this does not
 * trigger a new download of the JWKS from the issuer.  Instead, it will return
 * a JWKS object with an empty set of keys.
 * - `jwks` is an output variable set to the contents of the JWKS in the key
 * cache.
 */
int keycache_get_cached_jwks(const char *issuer, char **jwks, char **err_msg);

/**
 * Replace any existing key cache entry with one provided by the user.
 * The expiration and next update time of the user-provided JWKS will utilize
 * the same rules as a download from an issuer with no explicit cache lifetime
 * directives.
 * - `jwks` is value that will be set in the cache.
 */
int keycache_set_jwks(const char *issuer, const char *jwks, char **err_msg);

/**
 * APIs for managing scitokens configuration parameters.
 */

// On its way to deprecation
int config_set_int(const char *key, int value, char **err_msg);

/**
 * Update scitokens int parameters.
 * Takes in key/value pairs and assigns the input value to whatever
 * configuration variable is indicated by the key.
 * Returns 0 on success, and non-zero for invalid keys or values.
 */
int scitoken_config_set_int(const char *key, int value, char **err_msg);

// on its way to deprecation
int config_get_int(const char *key, char **err_msg);

/**
 * Get current scitokens int parameters.
 * Returns the value associated with the supplied input key on success, and -1
 * on failure. This assumes there are no keys for which a negative return value
 * is permissible.
 */
int scitoken_config_get_int(const char *key, char **err_msg);

/**
 * Set current scitokens str parameters.
 * Returns 0 on success, nonzero on failure
 */
int scitoken_config_set_str(const char *key, const char *value, char **err_msg);

/**
 * Get current scitokens str parameters.
 * Returns 0 on success, nonzero on failure, and populates the value associated
 * with the input key to output.
 */
int scitoken_config_get_str(const char *key, char **output, char **err_msg);

#ifdef __cplusplus
}
#endif
