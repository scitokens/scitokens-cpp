#include <fstream>
#include <iostream>
#include <stdio.h>

#include <jwt-cpp/jwt.h>

#include "scitokens.h"

int main(int argc, const char **argv) {
    std::string token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9."
        "AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
    if (argc == 2) {
        token = argv[1];
    }

    auto decoded = jwt::decode(token);

    for (auto &e : decoded.get_payload_claims())
        std::cout << e.first << " = " << e.second.to_json() << std::endl;

    std::ifstream priv_ifs("test.pem");
    std::string private_contents((std::istreambuf_iterator<char>(priv_ifs)),
                                 (std::istreambuf_iterator<char>()));
    std::ifstream pub_ifs("test.pem.pub");
    std::string public_contents((std::istreambuf_iterator<char>(pub_ifs)),
                                (std::istreambuf_iterator<char>()));

    char *err_msg;
    SciTokenKey key =
        scitoken_key_create("key-es356", "RS256", public_contents.c_str(),
                            private_contents.c_str(), &err_msg);
    if (!key) {
        std::cout << "Failed to generate a key: " << err_msg << std::endl;
        return 1;
    }
    SciToken scitoken = scitoken_create(key);
    if (scitoken_set_claim_string(scitoken, "iss", "https://demo.scitokens.org",
                                  &err_msg)) {
        std::cout << "Failed to set a claim: " << err_msg << std::endl;
    }

    // Test setting and getting a claim
    char *value;
    if (scitoken_get_claim_string(scitoken, "iss", &value, &err_msg)) {
        std::cout << "Failed to get a claim: " << err_msg << std::endl;
    }
    if (strcmp(value, "https://demo.scitokens.org") != 0) {
        std::cout << "Failed to get same claim a claim: " << err_msg
                  << std::endl;
    }

    if (scitoken_serialize(scitoken, &value, &err_msg)) {
        std::cout << "Failed to generate a token: " << err_msg << std::endl;
        return 1;
    }
    std::cout << "SciToken: " << value << std::endl;
    auto decoded2 = jwt::decode(value);

    for (auto &e : decoded2.get_payload_claims())
        std::cout << e.first << " = " << e.second.to_json() << std::endl;

    scitoken_destroy(scitoken);
    scitoken_key_destroy(key);

    // Get updated strings from https://demo.scitokens.org/
    // std::string test_value =
    // "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtleS1lczI1NiJ9.eyJpc3MiOiJodHRwczovL2RlbW8uc2NpdG9rZW5zLm9yZyIsImV4cCI6MTU0NjM4OTU5MiwiaWF0IjoxNTQ2Mzg4OTkyLCJuYmYiOjE1NDYzODg5OTIsImp0aSI6IjRkMzM2MTU5LWMxMDEtNGRhYy1iYzI5LWI5NDQ3ZDRkY2IxZSJ9.VfSCPj79IfdVCZHw8n0RJJupbaSU0OqMWxRVAnVUNvk1SCz0Ep3O06Boe5I0SRiZR8_0jzHw9vHZ0YOT_0kPAw";
    std::string test_value =
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6ImtleS1yczI1NiJ9."
        "eyJpc3MiOiJodHRwczovL2RlbW8uc2NpdG9rZW5zLm9yZyIsImV4cCI6MTU0NjM5MjAwOS"
        "wiaWF0IjoxNTQ2MzkxNDA5LCJuYmYiOjE1NDYzOTE0MDksImp0aSI6ImFkYTk2MjdiLWEx"
        "MGYtNGMyYS05Nzc2LTE4ZThkN2JmN2M4NSJ9.cNMG5zI2-JHh7l_"
        "PUPUAxom5Vi6Q3akKmv6q57CoVKHtxZAZRc47Uoix_"
        "AH3Xzr42qohr2FPamRTxUMsfZjrAFDJ_4JhJ-kKjJ3cRXXF-"
        "gj7lbniCDGOBuPXeMsVmeED15nauZ3XKXUHTGLEsg5O6RjS7sGKM_"
        "e9YiYvcTvWXcdkrkxZ2dPPU-R3IxdK6PtE9OB2XOk85H670OAJT3qimKm8Dk_"
        "Ri6DEEty1Su_"
        "1Tov3ac5B19iZkbhhVPMVP0cRolR9UNLhMxQAsbgEmArQOcs046AOzqQz6osOkdYOrVVO7"
        "lO2owUyMol94mB_39y1M8jcf5WNq3ukMMIzMCAPwA";

    if (scitoken_deserialize(test_value.c_str(), &scitoken, nullptr,
                             &err_msg)) {
        std::cout << "Failed to deserialize a token: " << err_msg << std::endl;
        return 1;
    }
    return 0;
}
