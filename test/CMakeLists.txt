
add_executable(scitokens-gtest main.cpp)
add_dependencies(scitokens-gtest gtest)
include_directories("${PROJECT_SOURCE_DIR}/vendor/gtest/googletest/include")

target_link_libraries(scitokens-gtest SciTokens "${CMAKE_BINARY_DIR}/external/gtest/src/gtest-build/lib/libgtest.a" -lpthread)

add_test(
  NAME
    unit
  COMMAND
    ${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}/test/scitokens-gtest
  )
