
cmake_minimum_required( VERSION 2.6 )
project( scitokens-cpp )

set( CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake )

find_package( jwt-cpp REQUIRED )
find_package( CURL REQUIRED )

if( CMAKE_COMPILER_IS_GNUCXX )
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror" )
endif()

if( CMAKE_COMPILER_IS_GNUCC )
  set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror" )
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")

include (FindPkgConfig)
pkg_check_modules(LIBCRYPTO REQUIRED libcrypto)
set (INCLUDE_DIRECTORIES ${INCLUDE_DIRECTORIES} ${LIBCRYPTO_INCLUDE_DIRS})

include_directories( "${PROJECT_SOURCE_DIR}" ${JWT_CPP_INCLUDES} ${CURL_INCLUDES})

add_library(SciTokens SHARED src/scitokens.cpp src/scitokens_internal.cpp)
target_link_libraries(SciTokens ${LIBCRYPTO_LIBRARIES} ${CURL_LIBRARIES})
set_target_properties(SciTokens PROPERTIES LINK_FLAGS "-Wl,--version-script=${PROJECT_SOURCE_DIR}/configs/export-symbols")

add_executable(scitokens-test src/test.cpp)
target_link_libraries(scitokens-test SciTokens ${LIBCRYPTO_LIB})

if (NOT DEFINED LIB_INSTALL_DIR)
  SET(LIB_INSTALL_DIR "lib")
endif()

install(
  TARGETS SciTokens
  LIBRARY DESTINATION ${LIB_INSTALL_DIR} )

set_target_properties(
  SciTokens
  PROPERTIES
  VERSION   "0.0.2"
  SOVERSION "0"
  )

