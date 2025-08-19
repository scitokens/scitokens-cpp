Examples
========

This page provides practical examples of using the SciTokens C++ library for common tasks.

Simple Token Creation
---------------------

This example shows how to create a basic SciToken without signing:

.. code-block:: c

    #include <scitokens.h>
    #include <stdio.h>
    
    int main() {
        // Create a token without a key (for testing)
        SciToken token = scitoken_create(NULL);
        if (token == NULL) {
            fprintf(stderr, "Failed to create token\n");
            return 1;
        }
        
        // Clean up
        scitoken_destroy(token);
        printf("Token created successfully\n");
        return 0;
    }

Creating and Signing a Token
----------------------------

This example demonstrates how to create a key pair and sign a token:

.. code-block:: c

    #include <scitokens.h>
    #include <stdio.h>
    #include <stdlib.h>
    
    // Example EC private key
    const char ec_private[] = 
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHcCAQEEIESSMxT7PLTR9A/aqd+CM0/6vv6fQWqDm0mNx8uE9EbpoAoGCCqGSM49\n"
        "AwEHoUQDQgAE1i+ImZ//iQhOPh0OMfZzdbmPH+3G1ouWezolCugQYWIRqNmwq3zR\n"
        "EnTbe4EmymTpJ1MJTPP/tCEUP3G/QqQuhA==\n"
        "-----END EC PRIVATE KEY-----\n";
    
    // Example EC public key
    const char ec_public[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1i+ImZ//iQhOPh0OMfZzdbmPH+3G\n"
        "1ouWezolCugQYWIRqNmwq3zREnTbe4EmymTpJ1MJTPP/tCEUP3G/QqQuhA==\n"
        "-----END PUBLIC KEY-----\n";
    
    int main() {
        char *err_msg = NULL;
        
        // Create a key for signing
        SciTokenKey key = scitoken_key_create("test-key", "ES256", 
                                             ec_public, ec_private, &err_msg);
        if (key == NULL) {
            fprintf(stderr, "Failed to create key: %s\n", err_msg);
            free(err_msg);
            return 1;
        }
        
        // Create a token with the key
        SciToken token = scitoken_create(key);
        if (token == NULL) {
            fprintf(stderr, "Failed to create token\n");
            scitoken_key_destroy(key);
            return 1;
        }
        
        // Set issuer claim
        int rv = scitoken_set_claim_string(token, "iss", 
                                          "https://example.org", &err_msg);
        if (rv != 0) {
            fprintf(stderr, "Failed to set issuer: %s\n", err_msg);
            free(err_msg);
            scitoken_destroy(token);
            scitoken_key_destroy(key);
            return 1;
        }
        
        // Serialize the token
        char *serialized_token;
        rv = scitoken_serialize(token, &serialized_token, &err_msg);
        if (rv != 0) {
            fprintf(stderr, "Failed to serialize: %s\n", err_msg);
            free(err_msg);
        } else {
            printf("Serialized token: %s\n", serialized_token);
            free(serialized_token);
        }
        
        // Clean up
        scitoken_destroy(token);
        scitoken_key_destroy(key);
        
        return 0;
    }

Token Validation with Enforcer
------------------------------

This example shows how to use an Enforcer to generate ACLs from a token:

.. code-block:: c

    #include <scitokens.h>
    #include <stdio.h>
    #include <stdlib.h>
    
    int main() {
        char *err_msg = NULL;
        
        // First, create and serialize a token (see previous example)
        // For this example, we'll assume we have a token
        
        // Create an enforcer
        const char *audiences[] = {"https://example.org/", NULL};
        Enforcer enforcer = enforcer_create("https://example.org", 
                                           audiences, &err_msg);
        if (enforcer == NULL) {
            fprintf(stderr, "Failed to create enforcer: %s\n", err_msg);
            free(err_msg);
            return 1;
        }
        
        // Assuming we have a valid token from previous steps
        SciToken token = NULL; // This would be your deserialized token
        
        // Generate ACLs from the token
        Acl *acls = NULL;
        int rv = enforcer_generate_acls(enforcer, token, &acls, &err_msg);
        if (rv != 0) {
            fprintf(stderr, "Failed to generate ACLs: %s\n", err_msg);
            free(err_msg);
        } else {
            // Print the ACLs
            for (int i = 0; acls[i].authz != NULL || acls[i].resource != NULL; i++) {
                printf("ACL %d: %s on %s\n", i, 
                       acls[i].authz ? acls[i].authz : "(null)",
                       acls[i].resource ? acls[i].resource : "(null)");
            }
            
            // Free the ACLs
            enforcer_acl_free(acls);
        }
        
        // Clean up
        enforcer_destroy(enforcer);
        if (token) scitoken_destroy(token);
        
        return 0;
    }

Complete Example: Create, Sign, and Validate
--------------------------------------------

This comprehensive example demonstrates the full workflow:

.. code-block:: c

    #include <scitokens.h>
    #include <stdio.h>
    #include <stdlib.h>
    
    int main() {
        char *err_msg = NULL;
        int rv;
        
        // Keys for this example
        const char ec_private[] = "-----BEGIN EC PRIVATE KEY-----\n"
            "MHcCAQEEIESSMxT7PLTR9A/aqd+CM0/6vv6fQWqDm0mNx8uE9EbpoAoGCCqGSM49\n"
            "AwEHoUQDQgAE1i+ImZ//iQhOPh0OMfZzdbmPH+3G1ouWezolCugQYWIRqNmwq3zR\n"
            "EnTbe4EmymTpJ1MJTPP/tCEUP3G/QqQuhA==\n"
            "-----END EC PRIVATE KEY-----\n";
        
        const char ec_public[] = "-----BEGIN PUBLIC KEY-----\n"
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1i+ImZ//iQhOPh0OMfZzdbmPH+3G\n"
            "1ouWezolCugQYWIRqNmwq3zREnTbe4EmymTpJ1MJTPP/tCEUP3G/QqQuhA==\n"
            "-----END PUBLIC KEY-----\n";
        
        // Step 1: Create signing key
        SciTokenKey key = scitoken_key_create("1", "ES256", 
                                             ec_public, ec_private, &err_msg);
        if (!key) {
            fprintf(stderr, "Failed to create key: %s\n", err_msg);
            free(err_msg);
            return 1;
        }
        
        // Step 2: Create and configure token
        SciToken token = scitoken_create(key);
        if (!token) {
            fprintf(stderr, "Failed to create token\n");
            scitoken_key_destroy(key);
            return 1;
        }
        
        // Set token claims
        rv = scitoken_set_claim_string(token, "iss", 
                                      "https://demo.scitokens.org/gtest", &err_msg);
        if (rv != 0) {
            fprintf(stderr, "Failed to set issuer: %s\n", err_msg);
            goto cleanup;
        }
        
        rv = scitoken_set_claim_string(token, "aud", 
                                      "https://demo.scitokens.org/", &err_msg);
        if (rv != 0) {
            fprintf(stderr, "Failed to set audience: %s\n", err_msg);
            goto cleanup;
        }
        
        rv = scitoken_set_claim_string(token, "scope", "read:/data", &err_msg);
        if (rv != 0) {
            fprintf(stderr, "Failed to set scope: %s\n", err_msg);
            goto cleanup;
        }
        
        // Step 3: Serialize token
        char *serialized;
        rv = scitoken_serialize(token, &serialized, &err_msg);
        if (rv != 0) {
            fprintf(stderr, "Failed to serialize: %s\n", err_msg);
            goto cleanup;
        }
        
        printf("Created token: %s\n", serialized);
        
        // Step 4: Store public key for validation
        rv = scitoken_store_public_ec_key("https://demo.scitokens.org/gtest",
                                         "1", ec_public, &err_msg);
        if (rv != 0) {
            fprintf(stderr, "Failed to store public key: %s\n", err_msg);
            free(serialized);
            goto cleanup;
        }
        
        // Step 5: Deserialize and validate
        SciToken parsed_token;
        const char *allowed_issuers[] = {"https://demo.scitokens.org/gtest", NULL};
        rv = scitoken_deserialize(serialized, &parsed_token, 
                                 allowed_issuers, &err_msg);
        free(serialized);
        
        if (rv != 0) {
            fprintf(stderr, "Failed to deserialize: %s\n", err_msg);
            goto cleanup;
        }
        
        printf("Token validation successful!\n");
        
        // Step 6: Create enforcer and generate ACLs
        const char *audiences[] = {"https://demo.scitokens.org/", NULL};
        Enforcer enforcer = enforcer_create("https://demo.scitokens.org/gtest",
                                           audiences, &err_msg);
        if (enforcer) {
            Acl *acls;
            rv = enforcer_generate_acls(enforcer, parsed_token, &acls, &err_msg);
            if (rv == 0) {
                printf("Generated ACLs:\n");
                for (int i = 0; acls[i].authz || acls[i].resource; i++) {
                    printf("  %s: %s\n", 
                           acls[i].authz ? acls[i].authz : "(null)",
                           acls[i].resource ? acls[i].resource : "(null)");
                }
                enforcer_acl_free(acls);
            }
            enforcer_destroy(enforcer);
        }
        
        scitoken_destroy(parsed_token);
        
    cleanup:
        if (err_msg) free(err_msg);
        scitoken_destroy(token);
        scitoken_key_destroy(key);
        
        return rv;
    }