/**
 * Public header for the SciTokens C library.
 *
 * 
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef void * SciTokenKey;
typedef void * SciToken;
typedef void * Validator;
typedef void * Enforcer;

typedef int (*StringValidatorFunction)(const char *value, char **err_msg);
typedef struct Acl_s {
    const char *authz;
    const char *resource;
}
Acl;

/**
 * Determine the mode we will use to validate tokens.
 * - COMPAT mode (default) indicates any supported token format
 *   is acceptable.  Where possible, the scope names are translated into
 *   equivalent SciTokens 1.0 claim names (i.e., storage.read -> read; storage.write -> write).
 *   If a typ header claim is present, use that to deduce type (RFC8725 Section 3.11).
 * - SCITOKENS_1_0, SCITOKENS_2_0, WLCG_1_0, AT_JWT: only accept these specific profiles.
 *   No automatic translation is performed.
 */
typedef enum _profile {
    COMPAT = 0,
    SCITOKENS_1_0,
    SCITOKENS_2_0,
    WLCG_1_0,
    AT_JWT
} SciTokenProfile;

SciTokenKey scitoken_key_create(const char *key_id, const char *algorithm, const char *public_contents, const char *private_contents, char **err_msg);

void scitoken_key_destroy(SciTokenKey private_key);

SciToken scitoken_create(SciTokenKey private_key);

void scitoken_destroy(SciToken token);

int scitoken_set_claim_string(SciToken token, const char *key, const char *value, char **err_msg);

int scitoken_get_claim_string(const SciToken token, const char *key, char **value, char **err_msg);

/**
 * Given a SciToken object, parse a specific claim's value as a list of strings.  If the JSON value
 * is not actually a list of strings - or the claim is not set - returns an error and sets the
 * err_msg appropriately.
 *
 * The returned value is a list of strings that ends with a nullptr.
 */
int scitoken_get_claim_string_list(const SciToken token, const char *key, char ***value, char **err_msg);

/**
 * Given a list of strings that was returned by scitoken_get_claim_string_list, free all the associated
 * memory.
 */
void scitoken_free_string_list(char **value);

/**
 * Set the value of a claim to a list of strings.
 */
int scitoken_set_claim_string_list(const SciToken token, const char *key,
    const char **values, char **err_msg);

int scitoken_get_expiration(const SciToken token, long long *value, char **err_msg);

void scitoken_set_lifetime(SciToken token, int lifetime);

int scitoken_serialize(const SciToken token, char **value, char **err_msg);

/**
 * Set the profile used for serialization; if COMPAT mode is used, then
 * the library default is utilized (currently, scitokens 1.0).
 */
void scitoken_set_serialize_profile(SciToken token, SciTokenProfile profile);

void scitoken_set_serialize_mode(SciToken token, SciTokenProfile profile);

void scitoken_set_deserialize_profile(SciToken token, SciTokenProfile profile);

int scitoken_deserialize(const char *value, SciToken *token, char const* const* allowed_issuers, char **err_msg);

int scitoken_deserialize_v2(const char *value, SciToken token, char const* const* allowed_issuers, char **err_msg);

int scitoken_store_public_ec_key(const char *issuer, const char *keyid, const char *value, char **err_msg);

Validator validator_create();

/**
 * Set the profile used for validating the tokens; COMPAT (default) will accept any known token
 * type while others will only support that specific profile.
 */
void validator_set_token_profile(Validator, SciTokenProfile profile);

int validator_add(Validator validator, const char *claim, StringValidatorFunction validator_func, char **err_msg);

int validator_add_critical_claims(Validator validator, const char **claims, char **err_msg);

int validator_validate(Validator validator, SciToken scitoken, char **err_msg);

/**
 * Destroy a validator object.
 */
void validator_destroy(Validator);

Enforcer enforcer_create(const char *issuer, const char **audience, char **err_msg);

void enforcer_destroy(Enforcer);

/**
 * Set the profile used for enforcing ACLs; when set to COMPAT (default), then the authorizations
 * will be converted to SciTokens 1.0-style authorizations (so, WLCG's storage.read becomes read).
 */
void enforcer_set_validate_profile(Enforcer, SciTokenProfile profile);

int enforcer_generate_acls(const Enforcer enf, const SciToken scitokens, Acl **acls, char **err_msg);

void enforcer_acl_free(Acl *acls);

int enforcer_test(const Enforcer enf, const SciToken sci, const Acl *acl, char **err_msg);

#ifdef __cplusplus
}
#endif
