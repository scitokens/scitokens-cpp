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

typedef void *SciTokenKey;
typedef void *SciToken;
typedef void *Validator;
typedef void *Enforcer;
typedef void *SciTokenStatus;
typedef void *Configuration;

typedef int (*StringValidatorFunction)(const char *value, char **err_msg);
typedef struct Acl_s {
    const char *authz;
    const char *resource;
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

SciTokenKey scitoken_key_create(const char *key_id, const char *algorithm,
                                const char *public_contents,
                                const char *private_contents, char **err_msg);

void scitoken_key_destroy(SciTokenKey private_key);

SciToken scitoken_create(SciTokenKey private_key);

void scitoken_destroy(SciToken token);

int scitoken_set_claim_string(SciToken token, const char *key,
                              const char *value, char **err_msg);

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

int scitoken_get_expiration(const SciToken token, long long *value,
                            char **err_msg);

void scitoken_set_lifetime(SciToken token, int lifetime);

int scitoken_serialize(const SciToken token, char **value, char **err_msg);

/**
 * Set the profile used for serialization; if COMPAT mode is used, then
 * the library default is utilized (currently, scitokens 1.0).
 */
void scitoken_set_serialize_profile(SciToken token, SciTokenProfile profile);

void scitoken_set_serialize_mode(SciToken token, SciTokenProfile profile);

void scitoken_set_deserialize_profile(SciToken token, SciTokenProfile profile);

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

int scitoken_store_public_ec_key(const char *issuer, const char *keyid,
                                 const char *value, char **err_msg);

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

int validator_validate(Validator validator, SciToken scitoken, char **err_msg);

/**
 * Destroy a validator object.
 */
void validator_destroy(Validator);

Enforcer enforcer_create(const char *issuer, const char **audience,
                         char **err_msg);

void enforcer_destroy(Enforcer);

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

void enforcer_acl_free(Acl *acls);

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
 * Enable or disable the background refresh thread for JWKS.
 * - When enabled, a background thread will periodically check if any known
 *   issuers need their JWKS refreshed based on the configured refresh interval
 *   and threshold.
 * - If enabled=1 and the thread is not running, it will be started.
 * - If enabled=0 and the thread is running, it will be stopped gracefully.
 * - Returns 0 on success, nonzero on failure.
 */
int keycache_set_background_refresh(int enabled, char **err_msg);

/**
 * Stop the background refresh thread if it is running.
 * - This is a convenience function equivalent to
 *   keycache_set_background_refresh(0, err_msg).
 * - Returns 0 on success, nonzero on failure.
 */
int keycache_stop_background_refresh(char **err_msg);

/**
 * Load the JWKS from the keycache for a given issuer, refreshing only if
 * needed.
 * - Returns 0 if successful, nonzero on failure.
 * - If the existing JWKS has not expired, this will return the cached JWKS
 *   without triggering a download.
 * - If the JWKS has expired or does not exist, this will attempt to refresh
 *   it from the issuer.
 * - `jwks` is an output variable set to the contents of the JWKS.
 */
int keycache_load_jwks(const char *issuer, char **jwks, char **err_msg);

/**
 * Get metadata for a cached JWKS entry.
 * - Returns 0 if successful, nonzero on failure.
 * - `metadata` is an output variable set to a JSON string containing:
 *   - "expires": expiration time (Unix epoch seconds)
 *   - "next_update": next update time (Unix epoch seconds)
 * - If the issuer does not exist in the cache, returns an error.
 */
int keycache_get_jwks_metadata(const char *issuer, char **metadata,
                               char **err_msg);

/**
 * Delete a JWKS entry from the keycache.
 * - Returns 0 if successful, nonzero on failure.
 * - If the issuer does not exist in the cache, this is not considered an error.
 */
int keycache_delete_jwks(const char *issuer, char **err_msg);

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
 *
 * Supported keys:
 * - "keycache.update_interval_s": Interval between key cache updates (seconds)
 * - "keycache.expiration_interval_s": Key cache expiration time (seconds)
 * - "monitoring.file_interval_s": Interval between monitoring file writes
 * (seconds, default 60)
 * - "keycache.refresh_interval_ms": Background refresh thread check interval
 * (milliseconds, default 60000)
 * - "keycache.refresh_threshold_ms": Time before next_update when background
 * refresh triggers (milliseconds, default 600000)
 */
int scitoken_config_set_int(const char *key, int value, char **err_msg);

// on its way to deprecation
int config_get_int(const char *key, char **err_msg);

/**
 * Get current scitokens int parameters.
 * Returns the value associated with the supplied input key on success, and -1
 * on failure. This assumes there are no keys for which a negative return value
 * is permissible.
 *
 * Supported keys:
 * - "keycache.update_interval_s": Interval between key cache updates (seconds)
 * - "keycache.expiration_interval_s": Key cache expiration time (seconds)
 * - "monitoring.file_interval_s": Interval between monitoring file writes
 * (seconds, default 60)
 * - "keycache.refresh_interval_ms": Background refresh thread check interval
 * (milliseconds, default 60000)
 * - "keycache.refresh_threshold_ms": Time before next_update when background
 * refresh triggers (milliseconds, default 600000)
 */
int scitoken_config_get_int(const char *key, char **err_msg);

/**
 * Set current scitokens str parameters.
 * Returns 0 on success, nonzero on failure
 *
 * Supported keys:
 * - "keycache.cache_home": Directory for the key cache
 * - "tls.ca_file": Path to TLS CA certificate file
 * - "monitoring.file": Path to write monitoring JSON (empty to disable, default
 * disabled) When enabled, monitoring stats are written periodically during
 * verify() calls. The write interval is controlled by
 * "monitoring.file_interval_s".
 */
int scitoken_config_set_str(const char *key, const char *value, char **err_msg);

/**
 * Get current scitokens str parameters.
 * Returns 0 on success, nonzero on failure, and populates the value associated
 * with the input key to output.
 *
 * Supported keys:
 * - "keycache.cache_home": Directory for the key cache
 * - "tls.ca_file": Path to TLS CA certificate file
 * - "monitoring.file": Path to write monitoring JSON (empty if disabled)
 */
int scitoken_config_get_str(const char *key, char **output, char **err_msg);

/**
 * Get monitoring statistics as a JSON string.
 * Returns a JSON object containing per-issuer validation statistics.
 *
 * Per-issuer statistics (under "issuers" key):
 * - successful_validations: count of successful token validations
 * - unsuccessful_validations: count of failed token validations
 * - expired_tokens: count of expired tokens encountered
 * - sync_validations_started: count of validations started via blocking API
 * - async_validations_started: count of validations started via async API
 * - sync_total_time_s: time spent in blocking verify() calls (updated every
 * 50ms)
 * - async_total_time_s: time spent in async validations (updated on completion)
 * - total_validation_time_s: sum of sync and async time
 * - successful_key_lookups: count of successful JWKS web refreshes
 * - failed_key_lookups: count of failed JWKS web refreshes
 * - failed_key_lookup_time_s: total time spent on failed key lookups
 * - expired_keys: count of times keys expired before refresh completed
 * - failed_refreshes: count of failed key refresh attempts (used cached keys)
 * - stale_key_uses: count of times keys were used past their next_update time
 *
 * Failed issuer lookups (under "failed_issuer_lookups" key):
 * - Per unknown issuer: count and total_time_s of failed lookup attempts
 * - Limited to 100 entries to prevent resource exhaustion from DDoS attacks
 *
 * The returned string must be freed by the caller using free().
 * Returns 0 on success, nonzero on failure.
 */
int scitoken_get_monitoring_json(char **json_out, char **err_msg);

/**
 * Reset all monitoring statistics.
 * Returns 0 on success, nonzero on failure.
 */
int scitoken_reset_monitoring_stats(char **err_msg);

#ifdef __cplusplus
}
#endif
