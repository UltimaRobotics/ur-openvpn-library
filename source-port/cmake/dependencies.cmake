# Find required packages
find_package(PkgConfig REQUIRED)

# OpenSSL
find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    set(OPTIONAL_CRYPTO_LIBS ${OPENSSL_LIBRARIES})
    set(OPTIONAL_CRYPTO_CFLAGS ${OPENSSL_INCLUDE_DIR})
    include_directories(${OPENSSL_INCLUDE_DIR})
    message(STATUS "OpenSSL found:")
    message(STATUS "  OPTIONAL_CRYPTO_LIBS = ${OPTIONAL_CRYPTO_LIBS}")
    message(STATUS "  OPTIONAL_CRYPTO_CFLAGS = ${OPTIONAL_CRYPTO_CFLAGS}")
else()
    message(WARNING "OpenSSL not found!")
endif()

# libcap-ng
pkg_check_modules(LIBCAPNG libcap-ng)
if(LIBCAPNG_FOUND)
    set(OPTIONAL_LIBCAPNG_LIBS ${LIBCAPNG_LIBRARIES})
    set(OPTIONAL_LIBCAPNG_CFLAGS ${LIBCAPNG_CFLAGS})
    message(STATUS "libcap-ng found:")
    message(STATUS "  OPTIONAL_LIBCAPNG_LIBS = ${OPTIONAL_LIBCAPNG_LIBS}")
    message(STATUS "  OPTIONAL_LIBCAPNG_CFLAGS = ${OPTIONAL_LIBCAPNG_CFLAGS}")
else()
    message(WARNING "libcap-ng not found!")
endif()

# libnl (for Linux) - Check for both libnl-3.0 and libnl-genl-3.0
if(NOT WIN32)
    pkg_check_modules(LIBNL libnl-3.0>=3.4.0)
    pkg_check_modules(LIBNL_GENL libnl-genl-3.0>=3.4.0)
    if(LIBNL_FOUND AND LIBNL_GENL_FOUND)
        set(OPTIONAL_LIBNL_GENL_LIBS ${LIBNL_LIBRARIES} ${LIBNL_GENL_LIBRARIES})
        set(OPTIONAL_LIBNL_GENL_CFLAGS ${LIBNL_CFLAGS_OTHER} ${LIBNL_GENL_CFLAGS_OTHER})
        include_directories(${LIBNL_INCLUDE_DIRS} ${LIBNL_GENL_INCLUDE_DIRS})
        link_directories(${LIBNL_LIBRARY_DIRS} ${LIBNL_GENL_LIBRARY_DIRS})
        # add_definitions(-DENABLE_DCO=1)
        message(STATUS "libnl and libnl-genl found:")
        message(STATUS "  OPTIONAL_LIBNL_GENL_LIBS = ${OPTIONAL_LIBNL_GENL_LIBS}")
        message(STATUS "  OPTIONAL_LIBNL_GENL_CFLAGS = ${OPTIONAL_LIBNL_GENL_CFLAGS}")
        message(STATUS "  DCO support enabled")
    else()
        message(WARNING "libnl libraries not found - DCO support will be disabled")
        add_definitions(-DENABLE_DCO=0)
    endif()
else()
    add_definitions(-DENABLE_DCO=0)
    message(STATUS "Windows detected - DCO support disabled")
endif()

# LZO compression
pkg_check_modules(LZO lzo2)
if(LZO_FOUND)
    set(OPTIONAL_LZO_LIBS ${LZO_LIBRARIES})
    set(OPTIONAL_LZO_CFLAGS ${LZO_CFLAGS})
    include_directories(${LZO_INCLUDE_DIRS})
    message(STATUS "LZO found:")
    message(STATUS "  OPTIONAL_LZO_LIBS = ${OPTIONAL_LZO_LIBS}")
    message(STATUS "  OPTIONAL_LZO_CFLAGS = ${OPTIONAL_LZO_CFLAGS}")
else()
    message(WARNING "LZO not found!")
endif()

# LZ4 compression
pkg_check_modules(LZ4 liblz4)
if(LZ4_FOUND)
    set(OPTIONAL_LZ4_LIBS ${LZ4_LIBRARIES})
    set(OPTIONAL_LZ4_CFLAGS ${LZ4_CFLAGS})
    include_directories(${LZ4_INCLUDE_DIRS})
    message(STATUS "LZ4 found:")
    message(STATUS "  OPTIONAL_LZ4_LIBS = ${OPTIONAL_LZ4_LIBS}")
    message(STATUS "  OPTIONAL_LZ4_CFLAGS = ${OPTIONAL_LZ4_CFLAGS}")
else()
    message(WARNING "LZ4 not found!")
endif()

# PAM
pkg_check_modules(LIBPAM libpam)
if(LIBPAM_FOUND)
    set(OPTIONAL_PAM_LIBS ${LIBPAM_LIBRARIES})
    message(STATUS "PAM found:")
    message(STATUS "  OPTIONAL_PAM_LIBS = ${OPTIONAL_PAM_LIBS}")
else()
    message(WARNING "PAM not found!")
endif()

# Socket libraries (for some systems)
if(NOT WIN32)
    find_library(NSL_LIB nsl)
    find_library(RESOLV_LIB resolv)
    set(SOCKETS_LIBS "")
    if(NSL_LIB)
        list(APPEND SOCKETS_LIBS ${NSL_LIB})
        message(STATUS "NSL library found: ${NSL_LIB}")
    else()
        message(STATUS "NSL library not found")
    endif()
    if(RESOLV_LIB)
        list(APPEND SOCKETS_LIBS ${RESOLV_LIB})
        message(STATUS "RESOLV library found: ${RESOLV_LIB}")
    else()
        message(STATUS "RESOLV library not found")
    endif()
endif()

# DL library
find_library(DL_LIB dl)
if(DL_LIB)
    set(OPTIONAL_DL_LIBS ${DL_LIB})
    message(STATUS "DL library found: ${DL_LIB}")
else()
    message(STATUS "DL library not found")
endif()

# Collect all optional libraries
set(ALL_OPTIONAL_LIBS
    ${OPTIONAL_CRYPTO_LIBS}
    ${OPTIONAL_LIBCAPNG_LIBS}
    ${OPTIONAL_LIBNL_GENL_LIBS}
    ${OPTIONAL_LZO_LIBS}
    ${OPTIONAL_LZ4_LIBS}
    ${OPTIONAL_DL_LIBS}
    ${SOCKETS_LIBS}
)

message(STATUS "All optional libs collected: ${ALL_OPTIONAL_LIBS}")
