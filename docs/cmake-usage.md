# Using SciTokens-cpp with Modern CMake

## Overview

Starting with version 1.3.0, scitokens-cpp provides modern CMake package configuration files that make it easy to integrate into your CMake-based projects.

## Finding the Package

After installing scitokens-cpp (via RPM or from source), you can find and use it in your CMakeLists.txt:

```cmake
find_package(SciTokens REQUIRED)
```

### Version Requirements

You can also specify minimum version requirements:

```cmake
find_package(SciTokens 1.3.0 REQUIRED)
```

## Linking Against SciTokens

The modern CMake configuration exports the `SciTokens::SciTokens` target which you can link against:

```cmake
add_executable(my_application main.cpp)
target_link_libraries(my_application SciTokens::SciTokens)
```

This automatically handles:
- Include directories
- Required compile features (C++11)
- Transitive dependencies (OpenSSL, CURL, SQLite3, etc.)

## Complete Example

Here's a complete minimal example:

```cmake
cmake_minimum_required(VERSION 3.10)
project(MyApp CXX)

# Find SciTokens package
find_package(SciTokens 1.3.0 REQUIRED)

# Create executable
add_executable(my_app src/main.cpp)

# Link against SciTokens using modern target
target_link_libraries(my_app PRIVATE SciTokens::SciTokens)
```

And a simple C++ file:

```cpp
#include <scitokens/scitokens.h>
#include <iostream>

int main() {
    Enforcer* enf = nullptr;
    char* err_msg = nullptr;
    
    if (enforcer_create("https://my-issuer.example.com", &enf, &err_msg) == 0) {
        std::cout << "Enforcer created successfully" << std::endl;
        enforcer_destroy(enf);
        return 0;
    }
    
    std::cerr << "Failed to create enforcer" << std::endl;
    return 1;
}
```

## Backward Compatibility

For projects that need to maintain compatibility with older CMake patterns, the following variables are also set:

- `SCITOKENS_LIBRARIES` - The library target (set to `SciTokens::SciTokens`)
- `SCITOKENS_INCLUDE_DIRS` - Include directories

However, we recommend using the modern target-based approach as it provides better dependency management.

## Installing from Source

When building and installing from source, CMake will automatically install the package configuration files:

```bash
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
make
sudo make install
```

The CMake configuration files will be installed to:
- `/usr/local/lib/cmake/SciTokens/SciTokensConfig.cmake`
- `/usr/local/lib/cmake/SciTokens/SciTokensConfigVersion.cmake`
- `/usr/local/lib/cmake/SciTokens/SciTokensTargets.cmake`

## Exported Targets

The package exports the following targets:

- `SciTokens::SciTokens` - The main SciTokens shared library

All required dependencies and include directories are propagated automatically when linking against these targets.

## Version Information

The package configuration includes version information that can be queried:

```cmake
find_package(SciTokens 1.3.0 REQUIRED)
message(STATUS "Found SciTokens version: ${SciTokens_VERSION}")
```

The version compatibility mode is set to `SameMajorVersion`, meaning packages requesting version 1.x will be compatible with any 1.y installation where y >= x.
