
cmake_minimum_required( VERSION 3.10)

project( scitokens-cpp 
	DESCRIPTION "A C++ Library to interface to scitokens"
	VERSION 1.0.2
	LANGUAGES CXX)

option( SCITOKENS_BUILD_UNITTESTS "Build the scitokens-cpp unit tests" OFF )
option( SCITOKENS_EXTERNAL_GTEST "Use an external/pre-installed copy of GTest" OFF )
option( SCITOKENS_WITH_ASAN       "Build with the address sanitizer" OFF )

set( CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake;${CMAKE_MODULE_PATH}" )

set( CMAKE_BUILD_TYPE RelWithDebInfo) # -g -O2

set( CMAKE_UNITY_BUILD False)

if( SCITOKENS_WITH_ASAN )
  add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address)
endif()

include(GNUInstallDirs)

find_package( jwt-cpp REQUIRED )
find_package( Atomic REQUIRED )
find_package( CURL REQUIRED )
find_package( UUID REQUIRED )

if( APPLE )

find_package( OpenSSL REQUIRED )
find_package( Sqlite3 REQUIRED )
set(LIBCRYPTO_INCLUDE_DIRS ${OPENSSL_INCLUDE_DIR})
set(LIBCRYPTO_LIBRARIES ${OPENSSL_CRYPTO_LIBRARY})
set(CMAKE_MACOSX_RPATH ON)

elseif( UNIX )

include (FindPkgConfig)
pkg_check_modules(LIBCRYPTO REQUIRED libcrypto)
pkg_check_modules(OPENSSL REQUIRED openssl)
pkg_check_modules(SQLITE REQUIRED sqlite3)

endif()

add_library(SciTokens SHARED src/scitokens.cpp src/scitokens_internal.cpp src/scitokens_cache.cpp src/scitokens_monitoring.cpp)
target_compile_features(SciTokens PUBLIC cxx_std_11) # Use at least C++11 for building and when linking to scitokens
target_include_directories(SciTokens PUBLIC ${JWT_CPP_INCLUDES} "${PROJECT_SOURCE_DIR}/src" PRIVATE ${CURL_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIRS} ${LIBCRYPTO_INCLUDE_DIRS} ${SQLITE_INCLUDE_DIRS}  ${UUID_INCLUDE_DIRS})

# Find threading library
find_package(Threads REQUIRED)

target_link_libraries(SciTokens PUBLIC ${OPENSSL_LIBRARIES} ${LIBCRYPTO_LIBRARIES} ${CURL_LIBRARIES} ${SQLITE_LIBRARIES} ${UUID_LIBRARIES} Threads::Threads std::atomic)
if (UNIX)
# pkg_check_modules fails to return an absolute path on RHEL7.  Set the
# link directories accordingly.
target_link_directories(SciTokens PUBLIC ${OPENSSL_LIBRARY_DIRS} ${LIBCRYPTO_LIBRARY_DIRS})
endif()

if ( NOT APPLE AND UNIX )
set_target_properties(SciTokens PROPERTIES LINK_FLAGS "-Wl,--version-script=${PROJECT_SOURCE_DIR}/configs/export-symbols")
endif()

add_executable(scitokens-test src/test.cpp)
target_include_directories(scitokens-test PRIVATE "${PROJECT_SOURCE_DIR}" ${JWT_CPP_INCLUDES} ${LIBCRYPTO_INCLUDE_DIRS})
target_link_libraries(scitokens-test SciTokens)

add_executable(scitokens-verify src/verify.cpp)
target_link_libraries(scitokens-verify SciTokens)

add_executable(scitokens-test-access src/test_access.cpp)
target_link_libraries(scitokens-test-access SciTokens)

add_executable(scitokens-list-access src/list_access.cpp)
target_link_libraries(scitokens-list-access SciTokens)

add_executable(scitokens-create src/create.cpp)
target_link_libraries(scitokens-create SciTokens)


add_executable(scitokens-generate-jwks src/generate_jwks.cpp)
target_include_directories(scitokens-generate-jwks PRIVATE ${OPENSSL_INCLUDE_DIRS} ${LIBCRYPTO_INCLUDE_DIRS})
target_link_libraries(scitokens-generate-jwks ${OPENSSL_LIBRARIES} ${LIBCRYPTO_LIBRARIES})

get_directory_property(TARGETS BUILDSYSTEM_TARGETS)
install(
  TARGETS ${TARGETS} 
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} )

install(
  FILES src/scitokens.h
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/scitokens )

set_target_properties(
  SciTokens
  PROPERTIES
  VERSION   "0.0.2"
  SOVERSION "0"
  )

if( SCITOKENS_BUILD_UNITTESTS )
	if( NOT SCITOKENS_EXTERNAL_GTEST )
include(ExternalProject)
ExternalProject_Add(gtest
    PREFIX external/gtest
    URL ${CMAKE_CURRENT_SOURCE_DIR}/vendor/gtest
    INSTALL_COMMAND :
)
endif()
enable_testing()
add_subdirectory(test)
endif()
