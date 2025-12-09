
add_executable(scitokens-gtest main.cpp)
if( NOT SCITOKENS_EXTERNAL_GTEST )
    add_dependencies(scitokens-gtest gtest)
    include_directories("${PROJECT_SOURCE_DIR}/vendor/gtest/googletest/include")
endif()

if(SCITOKENS_EXTERNAL_GTEST)
    set(LIBGTEST "gtest")
else()
    set(LIBGTEST "${CMAKE_BINARY_DIR}/external/gtest/src/gtest-build/lib/libgtest.a")
endif()

target_link_libraries(scitokens-gtest SciTokens "${LIBGTEST}" pthread)

add_test(
  NAME
    unit
  COMMAND
    ${CMAKE_CURRENT_BINARY_DIR}/scitokens-gtest
  )

# Monitoring unit tests
add_executable(scitokens-monitoring-test monitoring_test.cpp)
if( NOT SCITOKENS_EXTERNAL_GTEST )
    add_dependencies(scitokens-monitoring-test gtest)
endif()
target_link_libraries(scitokens-monitoring-test SciTokens "${LIBGTEST}" pthread)

add_test(
  NAME
    monitoring
  COMMAND
    ${CMAKE_CURRENT_BINARY_DIR}/scitokens-monitoring-test
  )

# Integration test executable
add_executable(scitokens-integration-test integration_test.cpp)
if( NOT SCITOKENS_EXTERNAL_GTEST )
    add_dependencies(scitokens-integration-test gtest)
endif()
target_link_libraries(scitokens-integration-test SciTokens "${LIBGTEST}" pthread)

# Integration test fixture - setup
add_test(
  NAME
    integration::setup
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/integration-test-setup.sh integration
)

set_tests_properties(integration::setup
  PROPERTIES
    FIXTURES_SETUP integration
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR};SOURCE_DIR=${PROJECT_SOURCE_DIR}"
)

# Integration test fixture - teardown
add_test(
  NAME
    integration::teardown
  COMMAND
    ${CMAKE_CURRENT_SOURCE_DIR}/integration-test-teardown.sh integration
)

set_tests_properties(integration::teardown
  PROPERTIES
    FIXTURES_CLEANUP integration
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR}"
)

# Integration test
add_test(
  NAME
    integration::test
  COMMAND
    ${CMAKE_CURRENT_BINARY_DIR}/scitokens-integration-test
)

set_tests_properties(integration::test
  PROPERTIES
    FIXTURES_REQUIRED integration
    ENVIRONMENT "BINARY_DIR=${CMAKE_BINARY_DIR};CURL_CA_BUNDLE=${CMAKE_BINARY_DIR}/tests/integration/current/ca-cert.pem"
)
