#include <iostream>

#include "scitokens.h"

int main(int argc, const char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " (TOKEN)" << std::endl;
        return 1;
    }
    std::string token(argv[1]);

    SciToken scitoken;
    char *err_msg = nullptr;
    if (scitoken_deserialize(token.c_str(), &scitoken, nullptr, &err_msg)) {
        std::cout << "Failed to deserialize a token: " << err_msg << std::endl;
        return 1;
    }
    std::cout << "Token deserialization successful." << std::endl;
    return 0;
}

