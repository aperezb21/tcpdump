
#
# Try to find cryptopANT.
# 

# Try to find the header
find_path(CRYPTOPANT_INCLUDE_DIR cryptopANT.h)

if(CRYPTOPANT_INCLUDE_DIR)
    message(STATUS "Found cryptoPANT header: ${CRYPTOPANT_INCLUDE_DIR}")
else()
    message(FATAL_ERROR "libcryptopANT header not found")
endif()

# Try to find the library
find_library(CRYPTOPANT_LIBRARY cryptopANT PATHS /usr/local/lib NO_DEFAULT_PATH)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CRYPTOPANT
  DEFAULT_MSG
  CRYPTOPANT_INCLUDE_DIR
  CRYPTOPANT_LIBRARY
)

mark_as_advanced(
  CRYPTOPANT_INCLUDE_DIR
  CRYPTOPANT_LIBRARY
)

set(CRYPTOPANT_INCLUDE_DIRS ${CRYPTOPANT_INCLUDE_DIR})
set(CRYPTOPANT_LIBRARIES ${CRYPTOPANT_LIBRARY})
