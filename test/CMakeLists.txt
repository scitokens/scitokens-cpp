
add_executable(scitokens-gtest main.cpp)
add_dependencies(scitokens-gtest gtest)
include_directories("${PROJECT_SOURCE_DIR}/vendor/gtest/googletest/include")

target_link_libraries(scitokens-gtest SciTokens "${CMAKE_BINARY_DIR}/external/gtest/src/gtest-build/lib/libgtest.a")
