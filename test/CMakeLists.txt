
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
