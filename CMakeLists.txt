cmake_minimum_required (VERSION 3.0)

# Project name
set (PROJECT_NAME "rkdeveloptool")
project (${PROJECT_NAME} VERSION 1.0.0)

# The version number.
set (rkdeveloptool_PACKAGE_VERSION "1.3")

file (GLOB LOCAL_CPP_FILES *.cpp)
set (SOURCE_FILES ${SOURCE_FILES} ${LOCAL_CPP_FILES})

file (GLOB LOCAL_H_FILES *.h)
set (HEADER_FILES ${HEADER_FILES} ${LOCAL_H_FILES})

# Turn off build log
# set (CMAKE_VERBOSE_MAKEFILE ON)

# Configure a header file to pass some of the CMake settings
# to the source code
configure_file (
    "${PROJECT_SOURCE_DIR}/config.h.in"
    "${PROJECT_BINARY_DIR}/config.h"
    )

include(FindIconv)

# Find LIBUSB
if (LIBUSB_INCLUDE_DIR AND LIBUSB_LIBRARIES)
  # in cache already
  set(LIBUSB_FOUND TRUE)
else (LIBUSB_INCLUDE_DIR AND LIBUSB_LIBRARIES)
  IF (NOT WIN32)
    # use pkg-config to get the directories and then use these values
    # in the FIND_PATH() and FIND_LIBRARY() calls
    find_package(PkgConfig)
    pkg_check_modules(PC_LIBUSB libusb-1.0)
  ENDIF(NOT WIN32)
  FIND_PATH(LIBUSB_INCLUDE_DIR libusb.h
    PATHS ${PC_LIBUSB_INCLUDEDIR} ${PC_LIBUSB_INCLUDE_DIRS})
  FIND_LIBRARY(LIBUSB_LIBRARIES NAMES usb-1.0
    PATHS ${PC_LIBUSB_LIBDIR} ${PC_LIBUSB_LIBRARY_DIRS})
  include(FindPackageHandleStandardArgs)
  FIND_PACKAGE_HANDLE_STANDARD_ARGS(LIBUSB DEFAULT_MSG LIBUSB_LIBRARIES LIBUSB_INCLUDE_DIR)
  MARK_AS_ADVANCED(LIBUSB_INCLUDE_DIR LIBUSB_LIBRARIES)
endif (LIBUSB_INCLUDE_DIR AND LIBUSB_LIBRARIES)

add_executable (${PROJECT_NAME} ${SOURCE_FILES})

target_link_libraries(${PROJECT_NAME} ${Iconv_LIBRARIES} ${LIBUSB_LIBRARIES})

# add the binary tree to the search path for include files
# so that we will find config.h
target_include_directories (${PROJECT_NAME} PRIVATE
    "${PROJECT_BINARY_DIR}"
    "${PROJECT_SOURCE_DIR}"
    "${LIBUSB_INCLUDE_DIR}"
    "${Iconv_INCLUDE_DIRS}"
    )

# Man pages
add_custom_target(doc ALL
        COMMAND scdoc < ${PROJECT_SOURCE_DIR}/doc/rkdeveloptool.1.scd > ${CMAKE_BINARY_DIR}/rkdeveloptool.1
        COMMAND gzip -f ${CMAKE_BINARY_DIR}/rkdeveloptool.1
        BYPRODUCTS ${CMAKE_BINARY_DIR}/rkdeveloptool.1 ${CMAKE_BINARY_DIR}/rkdeveloptool.1.gz
        DEPENDS ${PROJECT_SOURCE_DIR}/doc/rkdeveloptool.1.scd)

# Install
install(FILES ${PROJECT_SOURCE_DIR}/99-rk-rockusb.rules DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/udev/rules.d)
install(FILES ${CMAKE_BINARY_DIR}/rkdeveloptool.1.gz DESTINATION ${CMAKE_INSTALL_PREFIX}/man/man1)
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
