if(TARGET kazuho_picojson)
  return()
endif()

unset(PICOJSON_INCLUDE_DIR CACHE)
find_path(PICOJSON_INCLUDE_DIR "picojson/picojson.h")
if(EXISTS "${PICOJSON_INCLUDE_DIR}/picojson/picojson.h")
  add_library(kazuho_picojson INTERFACE "${PICOJSON_INCLUDE_DIR}/picojson/picojson.h")
  target_include_directories(kazuho_picojson INTERFACE ${PICOJSON_INCLUDE_DIR})
endif()
