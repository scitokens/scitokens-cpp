
FIND_PATH(JWT_CPP_INCLUDES jwt-cpp/jwt.h
  HINTS
  ${JWT_CPP_DIR}
  $ENV{JWT_CPP_DIR}
  /usr
  ${PROJECT_SOURCE_DIR}/vendor/jwt-cpp
  PATH_SUFFIXES include
)
